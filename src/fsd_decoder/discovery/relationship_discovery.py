"""Bounded, source-independent exploration of current FSDX reference evidence.

The derivative graph captures every PRM binding without decoding allocation
payloads or constructing a Python object graph. Links describe stored references;
neither reverse reachability nor a class/member name establishes ownership.
Typed field inspection is separate and bounded to one element at a time.
"""
from __future__ import annotations
import argparse
from collections import deque
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import tempfile
from fsd_decoder.portable.facade import PortableDatabase
from fsd_decoder.portable.format import Store
from fsd_decoder.core.diagnostics import contextual, command_errors, failure_record, require_source_failure
from fsd_decoder.core.interpretation import interpretation_facets
VERSION = 1
MAX_PAGE = 1000

class RelationshipError(ValueError):
    pass

def _hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def _limit(limit):
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise RelationshipError(f'limit must be between 1 and {MAX_PAGE}')
    return limit

def build_graph(source, output, *, progress=None):
    """Stream scalar SQLite rows into a new indexed derivative; FSDX stays read-only.

    Correlated predecessor probes use the unique logical allocation address
    index. No allocation JSON, pointer-page documents or NativeFields are loaded
    per pointer. The output must not already exist.
    """
    source, output = (Path(source).resolve(), Path(output).absolute())
    if os.path.lexists(output):
        raise RelationshipError('Graph output already exists: ' + str(output))
    started = time.monotonic()
    with Store(source) as store:
        if progress:
            progress(dict(phase='verify_store_integrity'))
        integrity = store.verify(full=True)
        counts = store.manifest['counts']
        source_info = store.manifest['source']
        source_sha = _hash(source)
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, stage_name = tempfile.mkstemp(prefix='.' + output.name + '.', suffix='.partial', dir=output.parent)
        os.close(descriptor)
        stage = Path(stage_name)
        # Explicit URI handling also applies to ATTACH. SQLite builds differ
        # in their default URI policy; the attached snapshot must use mode=ro.
        connection = sqlite3.connect(stage, uri=True)
        try:
            connection.execute('PRAGMA temp_store=FILE')
            connection.execute('ATTACH DATABASE ? AS snapshot', (source.as_uri() + '?mode=ro',))
            connection.executescript('\n                CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);\n                CREATE TABLE allocations(id INTEGER PRIMARY KEY,segment INTEGER,cluster INTEGER,\n                    logical_offset INTEGER,size INTEGER,name TEXT,native_tag INTEGER,\n                    element_count INTEGER,vector INTEGER,element_size INTEGER,\n                    element_stride INTEGER,array_header_size INTEGER);\n                CREATE UNIQUE INDEX allocation_address ON allocations(segment,cluster,logical_offset);\n                CREATE INDEX allocation_type ON allocations(name,id);\n                CREATE TABLE links(id INTEGER PRIMARY KEY,source_segment INTEGER,source_cluster INTEGER,\n                    source_offset INTEGER,width INTEGER,raw BLOB,status TEXT,source_id INTEGER,\n                    source_displacement INTEGER,target_segment INTEGER,target_cluster INTEGER,\n                    target_offset INTEGER,target_id INTEGER,target_displacement INTEGER,\n                    resolution_metadata TEXT);\n            ')
            connection.execute("INSERT INTO allocations\n                SELECT a.id,a.segment,a.cluster,a.logical_offset,a.size,n.name,a.native_tag,\n                    a.element_count,a.vector,json_extract(t.metadata,'$.element_size'),\n                    json_extract(t.metadata,'$.element_stride'),json_extract(t.metadata,'$.array_header_size')\n                FROM snapshot.allocations a JOIN snapshot.names n ON n.id=a.name_id\n                JOIN snapshot.allocation_templates t ON t.id=a.template_id")
            if progress:
                progress(dict(phase='allocation_index_copied', allocations=counts['allocations']))
            connection.execute('INSERT INTO links\n                SELECT NULL,p.segment,p.cluster,p.logical_offset,p.width,p.raw,p.status,\n                    s.id,CASE WHEN s.id IS NOT NULL THEN p.logical_offset-s.logical_offset END,\n                    p.target_segment,p.target_cluster,p.target_offset,t.id,\n                    CASE WHEN t.id IS NOT NULL THEN p.target_offset-t.logical_offset END,p.metadata\n                FROM snapshot.pointers p\n                LEFT JOIN allocations s ON s.id=(\n                    SELECT a.id FROM allocations a WHERE a.segment=p.segment AND a.cluster=p.cluster\n                    AND a.logical_offset<=p.logical_offset ORDER BY a.logical_offset DESC LIMIT 1)\n                    AND p.logical_offset+p.width<=s.logical_offset+s.size\n                LEFT JOIN allocations t ON t.id=(\n                    SELECT a.id FROM allocations a WHERE a.segment=p.target_segment AND a.cluster=p.target_cluster\n                    AND a.logical_offset<=p.target_offset ORDER BY a.logical_offset DESC LIMIT 1)\n                    AND p.target_offset<t.logical_offset+t.size\n                ORDER BY p.segment,p.cluster,p.logical_offset')
            connection.executescript('\n                CREATE INDEX link_source ON links(source_id,id);\n                CREATE INDEX link_target ON links(target_id,id);\n                CREATE UNIQUE INDEX link_slot ON links(source_segment,source_cluster,source_offset);\n            ')
            actual_allocations = connection.execute('SELECT count(*) FROM allocations').fetchone()[0]
            actual_links = connection.execute('SELECT count(*) FROM links').fetchone()[0]
            if actual_allocations != counts['allocations'] or actual_links != counts['pointers']:
                raise RelationshipError('Derivative census differs from complete FSDX capture')
            summary = dict(version=VERSION, store_path=str(source), store_sha256=source_sha, source=source_info, store_integrity=integrity, original_source_accessed=False, allocation_count=actual_allocations, pointer_binding_count=actual_links, pointer_status_counts=dict(connection.execute('SELECT status,count(*) FROM links GROUP BY status')), source_without_allocation=connection.execute('SELECT count(*) FROM links WHERE source_id IS NULL').fetchone()[0], resolved_target_without_allocation=connection.execute("SELECT count(*) FROM links WHERE status='RESOLVED' AND target_id IS NULL").fetchone()[0], null_slot_policy='Graph captures recorded bindings; implicit zero/null schema slots require typed inspection.', relationship_policy='CURRENT_REFERENCE_EVIDENCE_ONLY; OWNERSHIP_NOT_INFERRED', elapsed_seconds=round(time.monotonic() - started, 3))
            for key, value in summary.items():
                connection.execute('INSERT INTO metadata VALUES (?,?)', (key, json.dumps(value, sort_keys=True)))
            connection.commit()
            connection.close()
            with stage.open('rb') as stream:
                os.fsync(stream.fileno())
            os.link(stage, output)
            if progress:
                progress(dict(phase='graph_complete', pointer_bindings=actual_links))
            return summary
        finally:
            connection.close()
            stage.unlink(missing_ok=True)

class RelationshipGraph:
    """Read-only index with strict result bounds and stable link-id pagination."""

    def __init__(self, path):
        self.path = Path(path).resolve()
        self.connection = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA query_only=ON')
        self.metadata = {r[0]: json.loads(r[1]) for r in self.connection.execute('SELECT key,value FROM metadata')}
        if self.metadata.get('version') != VERSION:
            self.close()
            raise RelationshipError('Unsupported relationship graph version')

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def allocation_at(self, segment, cluster, offset):
        row = self.connection.execute('SELECT * FROM allocations WHERE segment=? AND cluster=?\n            AND logical_offset<=? ORDER BY logical_offset DESC LIMIT 1', (segment, cluster, offset)).fetchone()
        return dict(row) if row and offset < row['logical_offset'] + row['size'] else None

    def allocations(self, name, *, after_id=0, limit=100):
        return [dict(r) for r in self.connection.execute('SELECT * FROM allocations WHERE name=? AND id>? ORDER BY id LIMIT ?', (name, after_id, _limit(limit)))]

    def links(self, allocation_id, *, direction='outgoing', after_id=0, limit=100):
        if direction not in ('outgoing', 'incoming'):
            raise RelationshipError('direction must be outgoing or incoming')
        column = 'source_id' if direction == 'outgoing' else 'target_id'
        rows = self.connection.execute(f'SELECT l.*,s.name AS source_type,t.name AS target_type,\n            s.logical_offset AS source_allocation_offset,t.logical_offset AS target_allocation_offset\n            FROM links l LEFT JOIN allocations s ON s.id=l.source_id LEFT JOIN allocations t ON t.id=l.target_id\n            WHERE l.{column}=? AND l.id>? ORDER BY l.id LIMIT ?', (allocation_id, after_id, _limit(limit)))
        result = []
        for row in rows:
            link = dict(row)
            link['raw_hex'] = link.pop('raw').hex()
            link['resolution_metadata'] = json.loads(link['resolution_metadata'])
            link['meaning'] = 'OBSERVED_REFERENCE; OWNERSHIP_NOT_INFERRED'
            result.append(link)
        return result

    def walk(self, allocation_id, *, direction='incoming', max_nodes=100, max_links=500, max_depth=4):
        """Bounded reference reachability; never labels reached nodes as owners."""
        _limit(max_nodes)
        _limit(max_links)
        if direction not in ('outgoing', 'incoming'):
            raise RelationshipError('direction must be outgoing or incoming')
        if type(max_depth) is not int or not 0 <= max_depth <= 64:
            raise RelationshipError('max_depth must be between 0 and 64')
        pending = deque([(allocation_id, 0)])
        seen = {allocation_id}
        edges = []
        truncated = False
        while pending:
            current, depth = pending.popleft()
            if depth >= max_depth:
                continue
            remaining = max_links - len(edges)
            if remaining <= 0:
                truncated = True
                break
            page = self.links(current, direction=direction, limit=min(MAX_PAGE, remaining + 1))
            if len(page) > remaining:
                page = page[:remaining]
                truncated = True
            elif remaining == MAX_PAGE and len(page) == MAX_PAGE:
                truncated = truncated or bool(self.links(current, direction=direction, after_id=page[-1]['id'], limit=1))
            for edge in page:
                edges.append(edge)
                next_id = edge['source_id' if direction == 'incoming' else 'target_id']
                if next_id is not None and next_id not in seen:
                    if len(seen) >= max_nodes:
                        truncated = True
                    else:
                        seen.add(next_id)
                        pending.append((next_id, depth + 1))
        return dict(start_allocation_id=allocation_id, direction=direction, max_depth=max_depth, allocation_ids=sorted(seen), links=edges, truncated=truncated, meaning='REFERENCE_REACHABILITY; OWNERSHIP_NOT_ESTABLISHED')

def _target_view(database, allocation, offset):
    """Describe exact element/base views without relocating an interior target."""
    delta = offset - allocation['logical_offset'] - allocation.get('array_header_size', 0)
    stride = allocation.get('element_stride', allocation.get('element_size', allocation['size']))
    if delta < 0 or stride <= 0:
        return dict(status='ALLOCATION_HEADER_OR_UNKNOWN_STRIDE')
    index, within = divmod(delta, stride)
    if index >= allocation.get('count', 1):
        return dict(status='ALLOCATION_PADDING_OR_OUTSIDE_ELEMENT_COUNT')
    name = allocation['name'].removesuffix('[]')
    matches = []
    admission = database.fields.schema_admission(allocation)
    if admission['admitted']:

        def visit(layout, at=0, depth=0):
            if depth > 64:
                raise RelationshipError('Excessive base-subobject nesting')
            if at == within:
                matches.append(layout['name'])
            for base in layout['bases']:
                visit(base['layout'], at + base['offset'], depth + 1)
        visit(database.fields.schema.layout(name))
    return dict(status='EXACT_BASE_SUBOBJECT_VIEW' if matches else 'EXACT_ELEMENT_START' if within == 0 else 'INTERIOR_WITHOUT_VERIFIED_BASE_VIEW', element_index=index, element_displacement=within, matching_schema_base_types=matches, schema_admission=admission)

@contextual('inspect_element', segment='segment', cluster='cluster', offset='offset')
def inspect_element(database, segment, cluster, offset, *, max_element_bytes=65536, include_scalars=False, pointer_policy='strict'):
    """Decode one exact current element and retain pointer fields, including nulls.

    Interior addresses are reported as such. Unresolved bindings or unsupported
    layouts remain diagnostics; no substitute pointers or active union view are
    invented. NativeFields is the sole typed interpreter.
    """
    from fsd_decoder.schema.native_fields import validate_pointer_policy
    pointer_policy = validate_pointer_policy(pointer_policy)
    if type(max_element_bytes) is not int or not 1 <= max_element_bytes <= 1024 * 1024:
        raise RelationshipError('max_element_bytes must be between 1 and 1048576')
    allocation = database.allocation(segment, cluster, offset)
    if allocation is None:
        return dict(status='NO_CURRENT_ALLOCATION', address=dict(segment=segment, cluster=cluster, offset=offset))
    start = allocation['logical_offset']
    header = allocation.get('array_header_size', 0)
    stride = allocation.get('element_stride', allocation.get('element_size', allocation['size']))
    relative = offset - start - header
    common = dict(allocation_id=allocation['store_allocation_id'], allocation_type=allocation['name'], source_sha256=database.sha256, address=asdict(database.address(segment, cluster, offset)), ownership_status='NOT_INFERRED')
    if relative < 0 or stride <= 0 or relative % stride:
        return dict(common, status='INTERIOR_OR_HEADER_ADDRESS', allocation_displacement=offset - start)
    index = relative // stride
    if index >= allocation.get('count', 1):
        return dict(common, status='OUTSIDE_NATIVE_ELEMENT_COUNT')
    size = allocation.get('element_size', allocation['size']) if allocation.get('vector') else allocation['size']
    if size > max_element_bytes:
        return dict(common, status='ELEMENT_SIZE_BOUND', element_size=size, max_element_bytes=max_element_bytes)
    try:
        decoded = database.fields.decode(allocation, index) if pointer_policy == 'strict' else database.fields.decode(allocation, index, pointer_policy=pointer_policy)
    except Exception as exc:
        if pointer_policy != 'strict':
            raise
        context = dict(phase='decode_element', address=common['address'], name=allocation['name'], element_index=index)
        require_source_failure(exc, context)
        detail = failure_record(exc, status='TYPED_DECODE_UNRESOLVED', context=context)
        retained = dict(status='TYPED_DECODE_UNRESOLVED', raw_hex=database.read(database.address(segment, cluster, offset), size).hex())
        return dict(common, **retained, interpretation=interpretation_facets(retained), error_type=type(exc).__name__, error=str(exc),
                    **{k: detail[k] for k in ('error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})
    fields = decoded.get('fields', [decoded])
    references = []
    for field in fields:
        if field.get('kind') != 'stored_reference':
            continue
        slot = field.get('source_address')
        if slot is None:
            slot = dict(common['address'], offset=offset + field['record_relative_offset'])
        row = database.store.connection.execute('SELECT status,metadata FROM pointers WHERE segment=? AND cluster=? AND logical_offset=?', (slot['segment'], slot['cluster'], slot['offset'])).fetchone()
        item = dict(field, source_address=slot, meaning='TYPED_STORED_REFERENCE; OWNERSHIP_NOT_INFERRED')
        if row:
            item.update(binding_status=row['status'], binding_evidence='EXPLICIT_CAPTURED_PRM_BINDING', resolution_metadata=json.loads(row['metadata']))
        elif field.get('stored_word') == 0 and database.store.manifest.get('pointer_resolution_complete'):
            item.update(binding_status='NULL', binding_evidence='ZERO_SLOT_WITH_COMPLETE_PRM_CAPTURE')
        else:
            item.update(binding_status='MISSING', binding_evidence='NO_CAPTURED_BINDING')
        target = item.get('target')
        if target:
            target = target.get('address', target)
            target_allocation = database.allocation(target['segment'], target['cluster'], target['offset'])
            item['target_allocation'] = None if target_allocation is None else dict(id=target_allocation['store_allocation_id'], type=target_allocation['name'], offset=target_allocation['logical_offset'], displacement=target['offset'] - target_allocation['logical_offset'])
            item['target_view'] = None if target_allocation is None else _target_view(database, target_allocation, target['offset'])
        references.append(item)
    result = dict(common, status=decoded['status'], element_index=index, references=references, unsupported_reasons=decoded.get('unsupported_reasons', []), union_policy='UNESTABLISHED_ALTERNATIVE_VIEWS_ARE_NOT_REFERENCE_EDGES')
    # Keep the native interpreter's evidence separate from the reference-edge
    # projection. Conditional union fields are never promoted to graph edges.
    for key in ('fields', 'raw_hex', 'record_hex', 'value_raw_hex', 'padding_raw_hex',
                'uninterpreted_regions', 'tag_discriminants', 'discriminant_status',
                'schema_declarations', 'member_names_status', 'schema_admission'):
        if key in decoded:
            result[key] = decoded[key]
    result['interpretation'] = interpretation_facets(decoded)
    if pointer_policy != 'strict':
        unresolved = result['interpretation']['unresolved_reference_count']
        result.update(pointer_policy=pointer_policy,
            discovery_status='PARTIAL' if not result['interpretation']['typed_fields_complete'] else 'TYPED_FIELDS_COMPLETE',
            pointer_target_resolution_complete=result['interpretation']['typed_fields_complete'] and not unresolved,
            native_graph_closed=False)
    if include_scalars:
        result['scalars'] = [{k: field[k] for k in ('path', 'kind', 'record_relative_offset', 'type_name', 'value', 'decimal', 'raw_hex', 'status', 'encoding', 'unsigned_value', 'signed_value') if k in field}
                             for field in fields if field.get('kind') in ('primitive', 'enum', 'bitfield', 'integer', 'floating', 'character', 'character_bytes', 'ordinal_storage', 'alignment_byte')]
    return result

@command_errors('RELATIONSHIP_FAILED')
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    build = subs.add_parser('build')
    build.add_argument('store', type=Path)
    build.add_argument('graph', type=Path)
    links = subs.add_parser('links')
    links.add_argument('graph', type=Path)
    links.add_argument('allocation_id', type=int)
    links.add_argument('--direction', choices=['incoming', 'outgoing'], default='outgoing')
    links.add_argument('--after-id', type=int, default=0)
    links.add_argument('--limit', type=int, default=100)
    walk = subs.add_parser('walk')
    walk.add_argument('graph', type=Path)
    walk.add_argument('allocation_id', type=int)
    walk.add_argument('--direction', choices=['incoming', 'outgoing'], default='incoming')
    walk.add_argument('--max-nodes', type=int, default=100)
    walk.add_argument('--max-links', type=int, default=500)
    walk.add_argument('--max-depth', type=int, default=4)
    allocations = subs.add_parser('allocations')
    allocations.add_argument('graph', type=Path)
    allocations.add_argument('name')
    allocations.add_argument('--after-id', type=int, default=0)
    allocations.add_argument('--limit', type=int, default=100)
    inspect = subs.add_parser('inspect')
    inspect.add_argument('store', type=Path)
    inspect.add_argument('segment', type=int)
    inspect.add_argument('cluster', type=int)
    inspect.add_argument('offset', type=lambda n: int(n, 0))
    args = parser.parse_args(argv)
    if args.command == 'build':
        result = build_graph(args.store, args.graph)
    elif args.command == 'links':
        with RelationshipGraph(args.graph) as graph:
            result = graph.links(args.allocation_id, direction=args.direction, after_id=args.after_id, limit=args.limit)
    elif args.command == 'walk':
        with RelationshipGraph(args.graph) as graph:
            result = graph.walk(args.allocation_id, direction=args.direction, max_nodes=args.max_nodes, max_links=args.max_links, max_depth=args.max_depth)
    elif args.command == 'allocations':
        with RelationshipGraph(args.graph) as graph:
            result = graph.allocations(args.name, after_id=args.after_id, limit=args.limit)
    else:
        with PortableDatabase(args.store) as db:
            result = inspect_element(db, args.segment, args.cluster, args.offset)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get('status') == 'TYPED_DECODE_UNRESOLVED' else 0
if __name__ == '__main__':
    raise SystemExit(main())
