"""Streaming text and mesh CSV exports from a restored portable-store facade.

This module never opens an FSD, parses ObjectStore metadata, or constructs the
native field/allocation decoders. The caller supplies the already restored
``db.fields`` and indexed allocation/reference facade.
"""
from collections import Counter
from dataclasses import asdict, is_dataclass
from pathlib import Path
import csv
import hashlib
import json
import math
import os
import shutil
import struct
import tempfile
from fsd_decoder.core.json_io import dump_json
from fsd_decoder.core.interpretation import interpretation_facets
from fsd_decoder.core.diagnostics import require_source_failure, error_category

class ExportError(ValueError):
    pass

def _json_default(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {'encoding': 'hex', 'hex': value.hex()}
    raise TypeError(f'Cannot serialize {type(value).__name__}')

def _record(stream, kind, value):
    stream.write(kind + ' ')
    dump_json(value, stream, default=_json_default, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    stream.write('\n')

def _digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()

def _token(address):
    if isinstance(address, dict):
        return (address['segment'], address['cluster'], address.get('offset', address.get('logical_offset')))
    if hasattr(address, 'segment'):
        return (address.segment, address.cluster, address.offset)
    if len(address) != 3:
        raise ExportError('Selection requires segment, cluster and offset')
    return tuple(address)

def _allocations(db, selected=None):
    if selected is None:
        yield from db.iter_allocations()
        return
    seen = set()
    for address in selected:
        database = address.get('database') if isinstance(address, dict) else getattr(address, 'database', None)
        if database is not None and database != db.database_id:
            raise ExportError('Selection belongs to another database')
        token = _token(address)
        if token in seen:
            continue
        seen.add(token)
        allocation = db.allocation(*token)
        if allocation is None or allocation['logical_offset'] != token[2]:
            raise ExportError('Selection is not an exact allocation start')
        yield allocation

def _source(db):
    return dict(sha256=db.sha256, database_id=db.database_id, access='PORTABLE_STORE_ONLY', original_fsd_required=False,
                full_store_verification_performed=False, integrity_scope='ACCESSED_BLOBS_ONLY')

def _unsupported(value):
    if isinstance(value, dict):
        facets = interpretation_facets(value)
        return bool(facets['unresolved_status_counts']) or any(facets[key] for key in (
            'unresolved_union_count', 'uninterpreted_field_count', 'uninterpreted_region_count',
            'unresolved_reference_count', 'unapplied_discriminant_count', 'uninterpreted_padding_region_count'))
    return isinstance(value, list) and any(_unsupported(child) for child in value)


def _decode_source_value(db, allocation, index):
    """Only recognized source failures become explicit raw-fallback evidence."""
    try:
        return db.fields.decode(allocation,element_index=index), None
    except Exception as exc:
        require_source_failure(exc,dict(phase='plaintext_element',name=allocation['name'],
            element_index=index,segment=allocation['segment'],cluster=allocation['cluster'],
            logical_offset=allocation['logical_offset']))
        return None, dict(status='SOURCE_DECODE_FAILED',error_type=type(exc).__name__,
            error_category=error_category(exc),message=str(exc)[:1024],context=exc.context)


def _raw_value_chunks(db, allocation, index, diagnostic, stream):
    """Legacy single-file fallback reads fixed chunks, never a whole allocation."""
    size = allocation.get('element_size',allocation['size']) if allocation.get('vector') else allocation['size']
    stride = allocation.get('element_stride',size)
    first = allocation['logical_offset']+allocation.get('array_header_size',0)+index*stride
    for offset in range(0,size,32768):
        address = db.address(allocation['segment'],allocation['cluster'],first+offset)
        take = min(32768,size-offset)
        _record(stream,'RAW_VALUE_BYTES',dict(type=allocation['name'],native_tag=allocation['native_tag'],
            element_index=index,address=address,element_byte_offset=offset,element_bytes=size,
            bytes=take,raw_hex=db.read(address,take).hex(),diagnostic=diagnostic,
            status='RAW_SOURCE_FAILURE_FALLBACK',application_semantics_complete=False))
    if allocation.get('vector') and index+1 < allocation['count'] and stride > size:
        for offset in range(0,stride-size,32768):
            address = db.address(allocation['segment'],allocation['cluster'],first+size+offset)
            take = min(32768,stride-size-offset)
            _record(stream,'RAW_STRIDE_PADDING_BYTES',dict(type=allocation['name'],element_index=index,
                address=address,padding_byte_offset=offset,padding_bytes=stride-size,bytes=take,
                raw_hex=db.read(address,take).hex(),status='UNINTERPRETED_STRIDE_PADDING'))

def write_text(db, stream, *, allocation_addresses=None, progress=None):
    """Stream stored metadata and restored typed values without native parsing."""
    fields = db.fields
    counts = Counter()
    _record(stream, 'HEADER', dict(format='fsdx-text', format_version=1, source=_source(db), selection='ALL_ALLOCATIONS' if allocation_addresses is None else 'SELECTED_ALLOCATIONS'))
    if hasattr(db, 'source_info'):
        _record(stream, 'SOURCE', db.source_info)
    if hasattr(db, 'directory'):
        _record(stream, 'DIRECTORY', db.directory)
    report_document = getattr(fields, 'schema_report_document', None)
    schema = report_document() if callable(report_document) else fields.schema_report()
    _record(stream, 'SCHEMA', schema)
    counts['representation_errors'] = len(schema.get('representation_errors', []))
    counts['schema_incomplete'] = not schema.get('schema_complete', True)
    for root in db.roots()['roots']:
        _record(stream, 'ROOT', root)
        counts['roots'] += 1
    for allocation in _allocations(db, allocation_addresses):
        _record(stream, 'ALLOCATION', allocation)
        counts['allocations'] += 1
        count = allocation['count'] if allocation.get('vector') else 1
        for index in range(count):
            value, diagnostic = _decode_source_value(db,allocation,index)
            if diagnostic is not None:
                _record(stream,'VALUE_DIAGNOSTIC',dict(type=allocation['name'],element_index=index,
                    diagnostic=diagnostic,typed_fields_complete=False,application_semantics_complete=False))
                _raw_value_chunks(db,allocation,index,diagnostic,stream)
                counts['values'] += 1
                counts['raw_fallback_values'] += 1
                counts['unresolved'] += 1
                counts['typed_fields_incomplete'] += 1
                if progress and counts['values'] % 4096 == 0:progress(dict(counts))
                continue
            padding = allocation.get('inter_element_padding_size', 0)
            if padding and index + 1 < count:
                offset = allocation['logical_offset'] + allocation.get('array_header_size', 0) + index * allocation['element_stride'] + allocation['element_size']
                address = db.address(allocation['segment'], allocation['cluster'], offset)
                value['stride_padding_raw_hex'] = db.read(address, padding).hex()
            value['interpretation'] = interpretation_facets(value)
            _record(stream, 'VALUE', value)
            counts['values'] += 1
            counts['unresolved'] += _unsupported(value)
            counts['typed_fields_incomplete'] += not value['interpretation']['typed_fields_complete']
            if progress and counts['values'] % 4096 == 0:
                progress(dict(counts))
    complete = not any(counts[k] for k in ('unresolved', 'representation_errors', 'schema_incomplete'))
    summary = dict(counts, status='COMPLETE' if complete else 'INCOMPLETE',
        enumeration_complete=True, typed_values_complete=complete and not counts['typed_fields_incomplete'], application_semantics_complete=False,
        completion_scope='ALLOCATION_VALUE_ENUMERATION_WITH_UNRESOLVED_EVIDENCE_COUNTS; APPLICATION_SEMANTICS_NOT_ESTABLISHED')
    _record(stream, 'SUMMARY', summary)
    return summary

def export_text(db, new_path, *, allocation_addresses=None, progress=None):
    """Atomically publish a new text file; existing paths are never replaced."""
    output = Path(new_path).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n', dir=output.parent, prefix='.fsdx-text-', delete=False) as stream:
            temporary = Path(stream.name)
            summary = write_text(db, stream, allocation_addresses=allocation_addresses, progress=progress)
            stream.flush()
            os.fsync(stream.fileno())
        digest = _digest(temporary)
        os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return dict(summary, source=_source(db), output=str(output), output_sha256=digest, output_bytes=output.stat().st_size)

def _members(layout, base=0):
    result = {member['name']: (base + member['offset'], member['type']) for member in layout['members']}
    for parent in layout['bases']:
        for name, definition in _members(parent['layout'], base + parent['offset']).items():
            if name in result:
                raise ExportError('Ambiguous inherited schema member')
            result[name] = definition
    return result

class PortableMeshReader:
    """Resolve mesh fields using only compiled schema and indexed store rows."""

    def __init__(self, db):
        self.db = db
        self.surface_members = _members(db.fields.schema.layout('Fs::Spatial::Geom::TriSurface'))
        self.coordinate_members = _members(db.fields.schema.layout('Fs::Spatial::ProjectedCoord'))

    def allocation(self, address):
        a = self.db.allocation(address.segment, address.cluster, address.offset)
        if a is None or a['logical_offset'] != address.offset:
            raise ExportError('Pointer target is not an exact indexed allocation start')
        return a

    def field(self, address, layout, name):
        if name not in layout:
            raise ExportError(f'Unsupported compiled mesh layout: missing {name}')
        offset, typ = layout[name]
        if typ['size'] != 4:
            raise ExportError('Unsupported compiled mesh field width')
        return self.db.address(address.segment, address.cluster, address.offset + offset)

    def uint(self, address, layout, name):
        return struct.unpack('<I', self.db.read(self.field(address, layout, name), 4))[0]

    def pointer(self, address, layout, name):
        return self.db.resolve(self.field(address, layout, name))

    def array(self, address, kind, count):
        if address is None:
            if count == 0:
                return
            raise ExportError('Positive array length has null reference')
        a = self.allocation(address)
        tags, width = {'pointer': ((8,), 4), 'double': ((6, 21), 8), 'uint32': ((3,), 4)}[kind]
        if not a['vector'] or a['native_tag'] not in tags or a['count'] != count:
            raise ExportError('Compiled array type/count mismatch')
        if a['size'] != count * width or a.get('array_header_size', 0):
            raise ExportError('Unsupported compiled primitive array padding/header')

    def vertices(self, pointer_array, count):
        for index in range(count):
            slot = self.db.address(pointer_array.segment, pointer_array.cluster, pointer_array.offset + index * 4)
            point = self.db.resolve(slot)
            if point is None or self.allocation(point)['name'] != 'Fs::Spatial::ProjectedCoord':
                raise ExportError('Vertex target is not a compiled ProjectedCoord allocation')
            if self.uint(point, self.coordinate_members, 'm_dimension') != 3:
                raise ExportError('Unsupported coordinate dimension')
            values = self.pointer(point, self.coordinate_members, 'm_pValues')
            self.array(values, 'double', 3)
            raw = self.db.read(values, 24)
            xyz = struct.unpack('<3d', raw)
            if not all((math.isfinite(x) for x in xyz)):
                raise ExportError('Mesh CSV requires finite coordinates; exact bytes remain in store')
            if struct.pack('<3d', *(float(repr(x)) for x in xyz)) != raw:
                raise ExportError('Coordinate decimal representation does not roundtrip')
            yield (index, xyz, raw, point, values)

def _mesh_csv(db, reader, allocation, directory):
    address = db.address(allocation['segment'], allocation['cluster'], allocation['logical_offset'])
    ident = f's{address.segment}_c{address.cluster}_o{address.offset:x}'
    layout = reader.surface_members
    nv = reader.uint(address, layout, 'm_numVertex')
    nt = reader.uint(address, layout, 'm_numTri')
    vertices = reader.pointer(address, layout, 'm_ppVertexArray')
    faces = reader.pointer(address, layout, 'm_pTriVertexIndexArray')
    cs = reader.pointer(address, layout, 'm_pCoordinateSystem')
    reader.array(vertices, 'pointer', nv)
    reader.array(faces, 'uint32', nt * 3)
    paths = {kind: directory / f'{ident}.{kind}.csv' for kind in ('vertices', 'triangles')}
    xyz_digest, face_digest = (hashlib.sha256(), hashlib.sha256())
    lo, hi = ([math.inf] * 3, [-math.inf] * 3)
    try:
        with paths['vertices'].open('x', newline='') as f:
            writer = csv.writer(f, lineterminator='\n')
            writer.writerow(['vertex_index', 'x', 'y', 'z', 'point_segment', 'point_cluster', 'point_offset', 'values_segment', 'values_cluster', 'values_offset', 'xyz_f64le_hex'])
            for index, xyz, raw, point, values in reader.vertices(vertices, nv):
                writer.writerow([index, *(repr(x) for x in xyz), point.segment, point.cluster, point.offset, values.segment, values.cluster, values.offset, raw.hex()])
                xyz_digest.update(raw)
                for i, x in enumerate(xyz):
                    lo[i], hi[i] = (min(lo[i], x), max(hi[i], x))
        with paths['triangles'].open('x', newline='') as f:
            writer = csv.writer(f, lineterminator='\n')
            writer.writerow(['triangle_index', 'vertex_0', 'vertex_1', 'vertex_2'])
            for start in range(0, nt, 4096):
                n = min(4096, nt - start)
                at = db.address(faces.segment, faces.cluster, faces.offset + start * 12)
                raw = db.read(at, n * 12)
                face_digest.update(raw)
                for index, triple in enumerate(struct.iter_unpack('<III', raw), start):
                    if max(triple) >= nv:
                        raise ExportError('Triangle index exceeds vertex count')
                    writer.writerow([index, *triple])
    except BaseException:
        for path in paths.values():
            path.unlink(missing_ok=True)
        raise
    return dict(id=ident, source_address=address, coordinate_system_address=cs, vertex_array_address=vertices, triangle_array_address=faces, vertex_count=nv, triangle_count=nt, bounds=dict(min=lo, max=hi) if nv else None, paths={k: p.name for k, p in paths.items()}, hashes={k: _digest(p) for k, p in paths.items()}, packed_xyz_sha256=xyz_digest.hexdigest(), packed_triangles_sha256=face_digest.hexdigest())

def export_mesh_csv(db, new_directory, *, surface_addresses=None, progress=None):
    """Publish mesh CSVs in a fresh directory, resolved only from the FSDX store."""
    output = Path(new_directory).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.fsdx-mesh-', dir=output.parent))
    reserved = False
    try:
        reader = PortableMeshReader(db)
        report = dict(format='fsdx-mesh-csv', format_version=1, source=_source(db), coordinate_policy='Original stored XYZ and index order; no transform or coordinate-system inference', meshes=[], unsupported=[])
        allocations = db.iter_allocations(name='Fs::Spatial::Geom::TriSurface') if surface_addresses is None else _allocations(db, surface_addresses)
        for allocation in allocations:
            if allocation['name'] != 'Fs::Spatial::Geom::TriSurface':
                if surface_addresses is not None:
                    raise ExportError('Selected allocation is not a TriSurface')
                continue
            try:
                if allocation.get('vector'):
                    raise ExportError('TriSurface vector allocation unsupported')
                entry = _mesh_csv(db, reader, allocation, staging)
                report['meshes'].append(entry)
            except ExportError as exc:
                report['unsupported'].append(dict(address=db.address(allocation['segment'], allocation['cluster'], allocation['logical_offset']), error=str(exc)))
            if progress:
                progress(dict(meshes=len(report['meshes']), unsupported=len(report['unsupported'])))
        report.update(complete=not report['unsupported'], mesh_count=len(report['meshes']), vertex_count=sum((m['vertex_count'] for m in report['meshes'])), triangle_count=sum((m['triangle_count'] for m in report['meshes'])))
        with (staging / 'manifest.json').open('x') as f:
            json.dump(report, f, default=_json_default, indent=2, allow_nan=False)
            f.write('\n')
        output.mkdir()
        reserved = True
        os.replace(staging, output)
        reserved = False
        return output / 'manifest.json'
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if reserved:
            output.rmdir()
