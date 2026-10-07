"""Independently compare streamed native text bytes and values with its FSD.

Validates source hash, allocation extent spans, every VALUE's source bytes,
every typed field including union views, and decimal IEEE floating roundtrips.
No recovered geometry recipe or companion export is used as source truth.
"""
import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import struct
import time
from fsd_decoder.native.native_database import NativeDatabase

def walk(value):
    if isinstance(value, dict):
        yield value
        for key in ('fields', 'declared_views', 'uninterpreted_regions'):
            if key in value:
                yield from walk(value[key])
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)

def check_bitfield(field, raw):
    """Independently verify the named value against its retained storage bits."""
    offset, width = (field['bit_offset'], field['bit_width'])
    if type(offset) is not int or type(width) is not int or offset < 0 or (width <= 0) or (offset + width > len(raw) * 8) or (type(field['signed']) is not bool):
        raise ValueError('Invalid bitfield extent/signedness')
    mask = (1 << width) - 1 << offset
    if field['mask_hex'] != mask.to_bytes(len(raw), 'little').hex():
        raise ValueError('Bitfield mask mismatch')
    stored = int.from_bytes(raw, 'little')
    unsigned = stored >> offset & (1 << width) - 1
    value = unsigned - (1 << width) if field['signed'] and unsigned & 1 << width - 1 else unsigned
    if field['stored_unsigned'] != stored or field['unsigned_value'] != unsigned or field['value'] != value:
        raise ValueError('Bitfield value mismatch')

def validate(source, text, progress=None):
    from fsd_decoder.native.native_allocations import iter_native_allocations
    db = NativeDatabase.from_path(source)
    expected_allocations = iter(iter_native_allocations(db))
    expected_roots = db.roots()['roots']
    counts = Counter()
    current = None
    next_index = 0
    header = None
    summary = None
    last_update = time.monotonic()

    def check_finished():
        if current is not None and next_index != (current['count'] if current.get('vector') else 1):
            raise ValueError('Missing allocation values')
    with Path(text).open(encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            kind, encoded = line.rstrip('\n').split(' ', 1)
            value = json.loads(encoded)
            if summary is not None:
                raise ValueError('Record after SUMMARY')
            if kind == 'HEADER':
                if line_number != 1 or header is not None:
                    raise ValueError('Invalid HEADER order')
                header = value
                if value['source_sha256'] != db.sha256 or value['database_id'] != db.database_id:
                    raise ValueError('Source identity mismatch')
            elif kind == 'ALLOCATION':
                check_finished()
                current, next_index = (value, 0)
                expected_allocation = next(expected_allocations, None)
                if expected_allocation is None:
                    raise ValueError('Unexpected allocation')
                for key in ('segment', 'cluster', 'logical_offset', 'native_tag', 'size', 'count', 'vector'):
                    if value[key] != expected_allocation[key]:
                        raise ValueError('Allocation differs from current native tags')
                address = db.address(value['segment'], value['cluster'], value['logical_offset'])
                if value['address'] != asdict(address):
                    raise ValueError('Allocation address mismatch')
                if value['physical_spans'] != [asdict(s) for s in db.spans(address, value['size'])]:
                    raise ValueError('Allocation physical spans mismatch')
                if value.get('array_header_size', 0):
                    if bytes.fromhex(value['array_header_raw_hex']) != db.read(address, value['array_header_size']):
                        raise ValueError('Array header bytes mismatch')
                if value.get('terminal_padding_size', 0):
                    padding_address = db.address(address.segment, address.cluster, address.offset + value['terminal_padding_offset'])
                    if bytes.fromhex(value['terminal_padding_hex']) != db.read(padding_address, value['terminal_padding_size']):
                        raise ValueError('Terminal padding bytes mismatch')
                counts['allocations'] += 1
            elif kind == 'VALUE':
                if current is None:
                    raise ValueError('VALUE before ALLOCATION')
                base = current['logical_offset'] + current.get('array_header_size', 0)
                offset = base + next_index * current.get('element_stride', current['size'])
                address = db.address(current['segment'], current['cluster'], offset)
                if value['source_address'] != asdict(address):
                    raise ValueError('VALUE address/order mismatch')
                expected = db.read(address, current.get('element_size', current['size']) if current.get('vector') else current['size'])
                raw = bytes.fromhex(value['raw_hex'])
                if raw != expected:
                    raise ValueError('VALUE bytes mismatch')
                padding = current.get('inter_element_padding_size', 0)
                if padding and next_index + 1 < current['count']:
                    padding_address = db.address(address.segment, address.cluster, offset + len(expected))
                    if bytes.fromhex(value['stride_padding_raw_hex']) != db.read(padding_address, padding):
                        raise ValueError('Array stride padding mismatch')
                for field in walk(value):
                    if 'raw_hex' not in field or 'source_address' not in field:
                        continue
                    a = field['source_address']
                    if a is None:
                        raise ValueError('Missing typed field address')
                    observed = bytes.fromhex(field['raw_hex'])
                    relative = a['offset'] - address.offset
                    if a['database'] != address.database or a['segment'] != address.segment or a['cluster'] != address.cluster or (relative < 0) or (relative + len(observed) > len(expected)):
                        raise ValueError('Typed field lies outside its native element')
                    if expected[relative:relative + len(observed)] != observed:
                        raise ValueError('Typed field bytes mismatch')
                    counts['checked_spans'] += 1
                    if field.get('kind') == 'bitfield':
                        check_bitfield(field, observed)
                        counts['bitfield_values'] += 1
                    if field.get('encoding') == 'IEEE754_LITTLE_ENDIAN' and 'decimal' in field:
                        packed = struct.pack('<f' if len(observed) == 4 else '<d', float(field['decimal']))
                        if packed != observed:
                            raise ValueError('Floating decimal roundtrip mismatch')
                        counts['floating_values'] += 1
                    if field.get('kind') == 'stored_reference':
                        if '::<' in field.get('path', '') and field.get('target_status') == 'UNRESOLVED':
                            continue
                        target = db.resolve(db.address(a['segment'], a['cluster'], a['offset']), len(observed), observed)
                        exported_target = field.get('target')
                        if isinstance(exported_target, dict) and 'address' in exported_target:
                            exported_target = exported_target['address']
                        if exported_target != (None if target is None else asdict(target)):
                            raise ValueError('Reference target mismatch')
                        counts['references'] += 1
                next_index += 1
                counts['values'] += 1
                if progress and counts['values'] % 4096 == 0 and (time.monotonic() - last_update >= 10):
                    progress(dict(counts))
                    last_update = time.monotonic()
            elif kind == 'ROOT':
                if counts['roots'] >= len(expected_roots) or value != json.loads(json.dumps(expected_roots[counts['roots']])):
                    raise ValueError('Native root mismatch')
                counts['roots'] += 1
            elif kind == 'SUMMARY':
                check_finished()
                summary = value
            elif kind not in ('EXTENT', 'SCHEMA'):
                raise ValueError('Unknown text record kind')
    if header is None or summary is None:
        raise ValueError('Missing HEADER or SUMMARY')
    if next(expected_allocations, None) is not None:
        raise ValueError('Missing current native allocations')
    for key in ('allocations', 'values', 'roots'):
        if counts[key] != summary.get(key, 0):
            raise ValueError('SUMMARY count mismatch')
    if db.roots()['roots']:
        if counts['roots'] != len(db.roots()['roots']):
            raise ValueError('Native root count mismatch')
    db.verify_source()
    return dict(counts, source_sha256=db.sha256, source_unchanged=True, status=summary['status'], text=str(Path(text).resolve()))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('text', type=Path)
    p.add_argument('--report', type=Path)
    args = p.parse_args()
    import sys
    report = validate(args.source, args.text, progress=lambda counts: print(f'Checked {counts['allocations']:,} allocations / {counts['values']:,} values', file=sys.stderr, flush=True))
    if args.report:
        with args.report.open('x') as f:
            json.dump(report, f, indent=2)
            f.write('\n')
    print(json.dumps(report, sort_keys=True))
if __name__ == '__main__':
    main()
