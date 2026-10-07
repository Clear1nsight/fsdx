"""Exhaustive current-allocation JSONL inventory with disk-backed address lookup.

No reachability or geological relationship claims are made. A failed cluster
retains its verified prefix and does not prevent independent cluster traversal.
"""
from __future__ import annotations
import argparse
from collections import Counter
from dataclasses import asdict, is_dataclass
import hashlib
import json
from pathlib import Path
import shutil
import signal
import sqlite3
from contextlib import closing
import sys
import tempfile
import time
import zlib
from fsd_decoder.native.native_database import NativeDatabase
from fsd_decoder.native.native_allocations import NativeAllocationReader, build_native_types
from fsd_decoder.schema.native_fields import NativeFields
from fsd_decoder.exports.fsd_export import publish_directory
HERE = Path(__file__).resolve().parent
ERRORS = (ValueError, KeyError, IndexError, NotImplementedError, OverflowError)

def plain(value):
    if is_dataclass(value):
        return plain(asdict(value))
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(plain(value), indent=2, sort_keys=True) + '\n')

class ClusterView:

    def __init__(self, database, cluster):
        self.database, self.cluster = (database, cluster)

    def __getattr__(self, name):
        return getattr(self.database, name)

    def iter_clusters(self):
        return iter([self.cluster])

def create_index(connection):
    connection.execute('CREATE TABLE allocations(segment INTEGER, cluster INTEGER, start INTEGER, end INTEGER, record BLOB NOT NULL, PRIMARY KEY(segment,cluster,start)) WITHOUT ROWID')

def add_allocation(connection, record):
    a = plain(record)
    segment, cluster, start, size = (a[k] for k in ('segment', 'cluster', 'logical_offset', 'size'))
    if any((type(v) is not int or v < 0 for v in (segment, cluster, start))) or type(size) is not int or size <= 0:
        raise ValueError('Invalid allocation interval')
    before = connection.execute('SELECT end FROM allocations WHERE segment=? AND cluster=? AND start<=? ORDER BY start DESC LIMIT 1', (segment, cluster, start)).fetchone()
    after = connection.execute('SELECT start FROM allocations WHERE segment=? AND cluster=? AND start>? ORDER BY start LIMIT 1', (segment, cluster, start)).fetchone()
    if before and before[0] > start or (after and after[0] < start + size):
        raise ValueError('Overlapping allocation interval')
    encoded = json.dumps(a, separators=(',', ':'), sort_keys=True)
    connection.execute('INSERT INTO allocations VALUES(?,?,?,?,?)', (segment, cluster, start, start + size, zlib.compress(encoded.encode(), level=1)))
    return encoded

def classify(connection, target, *, database_id, complete):
    if target['database'] != database_id:
        return dict(status='EXTERNAL_DATABASE_NOT_INDEXED', target=target)
    for k in ('segment', 'cluster', 'offset'):
        if type(target[k]) is not int or target[k] < 0:
            raise ValueError('Invalid target address')
    row = connection.execute('SELECT end,record FROM allocations WHERE segment=? AND cluster=? AND start<=? ORDER BY start DESC LIMIT 1', (target['segment'], target['cluster'], target['offset'])).fetchone()
    if row is None or target['offset'] >= row[0]:
        return dict(status='NO_CURRENT_ALLOCATION_AT_ADDRESS' if complete else 'NOT_INDEXED_COVERAGE_INCOMPLETE', target=target, reachability='NOT_EVALUATED', absence_scope='Current nonfree allocations only; no deleted-data conclusion')
    a = json.loads(zlib.decompress(row[1]))
    delta = target['offset'] - a['logical_offset']
    result = dict(status='EXACT_ALLOCATION_START' if delta == 0 else 'INTERIOR_OF_CURRENT_ALLOCATION', target=target, allocation=a, byte_displacement=delta, reachability='NOT_EVALUATED')
    header = a.get('array_header_size', 0)
    end = a.get('terminal_padding_offset', a['size'])
    if delta < header:
        result['region'] = 'ARRAY_HEADER'
    elif delta >= end:
        result['region'] = 'TERMINAL_PADDING'
    elif a['name'] == 'inline_char_bytes':
        result.update(region='INLINE_CHARACTER', character_index=delta)
    else:
        stride = a.get('element_stride', a.get('element_size', a['size']))
        size = a.get('element_size', a['size'])
        index, within = divmod(delta - header, stride)
        result.update(element_index=index, element_byte_displacement=within, region=('ELEMENT_START' if within == 0 else 'ELEMENT_INTERIOR') if within < size else 'INTER_ELEMENT_PADDING')
    return result

def inventory(source, output, *, schema=True, progress=None, max_input_bytes=1000000000):
    source, output = (Path(source).resolve(), Path(output).absolute())
    if output.exists() or output.is_symlink():
        raise ValueError('Choose a new output directory')
    if type(max_input_bytes) is not int or max_input_bytes <= 0:
        raise ValueError('Invalid input limit')
    if source.stat().st_size > max_input_bytes:
        raise ValueError('Input exceeds configured size limit')
    with source.open('rb') as stream:
        data = stream.read(max_input_bytes + 1)
    if len(data) > max_input_bytes:
        raise ValueError('Input grew beyond configured size limit')
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.fsd-inventory-', dir=output.parent))
    connection = None
    try:
        report = dict(format='FSD_CURRENT_ALLOCATION_INVENTORY_V1', source_path=str(source), source_size=len(data), source_sha256=hashlib.sha256(data).hexdigest(), complete=False, database_id=None, representation_complete=None, representation_errors=[], allocations=0, allocated_bytes=0, element_count=0, clusters=[], diagnostics=[], reachability='NOT_EVALUATED', relationship_graph='NOT_ENUMERATED', fallback='Run fsd_recover.py to preserve every physical byte when interpretation is incomplete.', bytes_preserved_here='Metadata and allocation provenance; payload remains in source FSD.')
        connection = sqlite3.connect(staging / 'index.sqlite')
        create_index(connection)
        counts = Counter()
        last_progress = time.monotonic()
        phase = 'database_initialization'
        with (staging / 'allocations.jsonl').open('x') as stream:
            try:
                db = NativeDatabase(data)
                db.source_path = source
                report['database_id'] = db.database_id
                phase = 'native_type_discovery'
                types, evidence = build_native_types(data, db.directory, allow_partial_representations=True)
                report['representation_complete'] = evidence.get('representation_complete')
                report['representation_errors'] = plain(evidence.get('representation_errors', []))
                if report['representation_errors']:
                    report['diagnostics'].append(dict(phase=phase, status='PARTIAL_TYPE_CATALOG', message='Unsupported representations excluded; allocation traversal uses only verified known types.', errors=report['representation_errors']))
                write_json(staging / 'native_types.json', dict(types=types, evidence=evidence))
                if schema:
                    try:
                        write_json(staging / 'schema.json', NativeFields(db, allow_partial_representations=True).schema_report())
                    except ERRORS as exc:
                        report['diagnostics'].append(dict(phase='optional_schema', error_type=type(exc).__name__, message=str(exc)))
                try:
                    write_json(staging / 'roots.json', db.roots())
                except ERRORS as exc:
                    report['diagnostics'].append(dict(phase='optional_roots', error_type=type(exc).__name__, message=str(exc)))
                phase = 'allocation_traversal'
                for cluster in db.iter_clusters():
                    coverage = dict(segment=cluster['segment'], cluster=cluster['cluster'], complete=False, allocations=0, last_successful_address=None)
                    reader = NativeAllocationReader(ClusterView(db, cluster), types)
                    try:
                        for a in reader.iter_allocations():
                            encoded = add_allocation(connection, a)
                            stream.write(encoded + '\n')
                            coverage['allocations'] += 1
                            coverage['last_successful_address'] = plain(a['address'])
                            report['allocations'] += 1
                            report['allocated_bytes'] += a['size']
                            report['element_count'] += a['count']
                            counts[a['native_tag'], a['name']] += 1
                            if report['allocations'] % 10000 == 0:
                                connection.commit()
                            if progress and time.monotonic() - last_progress > 10:
                                progress(dict(phase=phase, allocations=report['allocations'], segment=cluster['segment'], cluster=cluster['cluster']))
                                last_progress = time.monotonic()
                        coverage['complete'] = True
                    except ERRORS as exc:
                        coverage.update(status='UNPARSED_ALLOCATION_TAIL', error_type=type(exc).__name__, message=str(exc))
                    coverage['reader_stats'] = reader.stats
                    report['clusters'].append(coverage)
                report['complete'] = all((c['complete'] for c in report['clusters']))
            except ERRORS as exc:
                report['diagnostics'].append(dict(phase=phase, error_type=type(exc).__name__, message=str(exc)))
        connection.commit()
        connection.close()
        connection = None
        report['source_unchanged'] = digest(source) == report['source_sha256']
        if not report['source_unchanged']:
            raise ValueError('Source changed during inventory')
        report['status'] = 'COMPLETE_CURRENT_ALLOCATION_INVENTORY' if report['complete'] else 'PARTIAL_CURRENT_ALLOCATION_INVENTORY'
        report['types'] = [dict(native_tag=k[0], name=k[1], allocations=v) for k, v in sorted(counts.items())]
        report['code_sha256'] = {str(p.relative_to(HERE)): digest(p) for p in sorted(HERE.rglob('*.py')) if '__pycache__' not in p.parts}
        report['artifacts'] = {p.name: dict(bytes=p.stat().st_size, sha256=digest(p)) for p in sorted(staging.iterdir())}
        write_json(staging / 'manifest.json', report)
        publish_directory(staging, output)
        return report
    finally:
        if connection:
            connection.close()
        if staging.exists():
            shutil.rmtree(staging)

def lookup(bundle, address, *, source=None, pointer_width=None):
    bundle = Path(bundle).resolve()
    manifest = json.loads((bundle / 'manifest.json').read_text())
    index = bundle / 'index.sqlite'
    if digest(index) != manifest['artifacts']['index.sqlite']['sha256']:
        raise ValueError('Inventory index hash differs from manifest')
    db = None
    if source is not None:
        source = Path(source).resolve()
        source_data = source.read_bytes()
        if hashlib.sha256(source_data).hexdigest() != manifest['source_sha256']:
            raise ValueError('Source hash differs from inventory')
        db = NativeDatabase(source_data)
        db.source_path = source
    if pointer_width and db is None:
        raise ValueError('Pointer lookup requires matching source')
    target = dict(database=manifest['database_id'], segment=address[0], cluster=address[1], offset=address[2])
    evidence = None
    if pointer_width:
        if pointer_width not in (4, 8):
            raise ValueError('Pointer width must be 4 or 8')
        raw = db.read(db.address(*address), pointer_width)
        resolved = db.resolve(db.address(*address), width=pointer_width, raw=raw)
        evidence = dict(source_address=target, width=pointer_width, raw_hex=raw.hex(), status='CURRENT_NATIVE_PRM')
        if resolved is None:
            db.verify_source()
            return dict(status='NULL_REFERENCE', reference=evidence)
        target = asdict(resolved)
    with closing(sqlite3.connect(index.as_uri() + '?mode=ro', uri=True)) as connection, connection:
        result = classify(connection, target, database_id=manifest['database_id'], complete=manifest['complete'])
    if evidence:
        result['reference'] = evidence
    if db and result.get('region') in ('ELEMENT_START', 'ELEMENT_INTERIOR'):
        a = result['allocation']
        if a.get('element_size', a['size']) > 65536:
            result['field_lookup'] = 'ELEMENT_TOO_LARGE_FOR_BOUNDED_FIELD_INSPECTION'
        else:
            try:
                fields = NativeFields(db, allow_partial_representations=True)
                decoded = fields.decode(a, result['element_index'])
                items = fields.decoder.source_items(decoded.get('fields', []))
                result['member_views_at_target'] = [f for f in items if f.get('source_address', {}).get('offset', -1) <= target['offset'] < f.get('source_address', {}).get('offset', -1) + f.get('size', 0)]
                result['field_decode_status'] = decoded.get('status')
                result['member_views_semantics'] = 'All covering declared views; union active member may be unknown'
            except ERRORS as exc:
                result['field_lookup_error'] = dict(error_type=type(exc).__name__, message=str(exc))
    if db:
        db.verify_source()
    return result

def address_arg(value):
    try:
        parts = tuple((int(x, 0) for x in value.split(':')))
        if len(parts) != 3 or min(parts) < 0:
            raise ValueError()
        return parts
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Address must be segment:cluster:offset, with decimal or 0x hex values') from exc

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('source', type=Path)
    build.add_argument('--output', required=True, type=Path)
    build.add_argument('--no-schema', action='store_true')
    build.add_argument('--max-input-bytes', type=int, default=1000000000)
    query = commands.add_parser('lookup')
    query.add_argument('bundle', type=Path)
    query.add_argument('address', type=address_arg)
    query.add_argument('--source', type=Path)
    query.add_argument('--pointer-width', type=int, choices=(4, 8))
    args = parser.parse_args()
    try:
        if args.command == 'build':

            def terminate(signum, frame):
                raise KeyboardInterrupt('Inventory build terminated')
            previous_handler = signal.signal(signal.SIGTERM, terminate)
            try:
                result = inventory(args.source, args.output, schema=not args.no_schema, max_input_bytes=args.max_input_bytes, progress=lambda x: print(json.dumps(x), file=sys.stderr))
                print(json.dumps(dict(status=result['status'], allocations=result['allocations'], output=str(args.output))))
                return 0 if result['complete'] else 2
            finally:
                signal.signal(signal.SIGTERM, previous_handler)
        print(json.dumps(lookup(args.bundle, args.address, source=args.source, pointer_width=args.pointer_width), indent=2))
        return 0
    except KeyboardInterrupt:
        print('Inventory interrupted; any unpublished staging output removed.', file=sys.stderr)
        return 130
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1
if __name__ == '__main__':
    sys.exit(main())
