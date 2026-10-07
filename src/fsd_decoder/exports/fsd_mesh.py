"""Export native TriSurface arrays as OBJ or source-exact plaintext CSV."""
from collections import OrderedDict
from contextlib import nullcontext
import csv
from dataclasses import asdict
from pathlib import Path
import argparse
import json
import math
import struct
from fsd_decoder.native.native_database import NativeDatabase
from fsd_decoder.native.native_allocations import NativeAllocationReader
from fsd_decoder.schema.native_fields import NativeFields
from fsd_decoder.exports.fsd_export import digest

class MeshError(ValueError):
    pass

def members(layout, base=0):
    result = {m['name']: (base + m['offset'], m['type']) for m in layout['members']}
    for parent in layout['bases']:
        for name, value in members(parent['layout'], base + parent['offset']).items():
            if name in result:
                raise MeshError('Ambiguous inherited member name')
            result[name] = value
    return result

class MeshReader:

    def __init__(self, db):
        self.db = db
        self.allocations = NativeAllocationReader(db)
        self.fields = NativeFields(db)
        self.surface_members = members(self.fields.schema.layout('Fs::Spatial::Geom::TriSurface'))
        self.coord_members = members(self.fields.schema.layout('Fs::Spatial::ProjectedCoord'))
        self.pages = OrderedDict()

    def allocation(self, address):
        token = (address.segment, address.cluster, address.offset & ~4095)
        if token not in self.pages:
            records = {}
            for kind in (16, 17):
                trace = self.db.tags(*token, self.allocations.types, key_kind=kind)
                if trace is not None:
                    for r in trace['records']:
                        offset = token[2] + r['page_offset']
                        if offset in records and records[offset] != r:
                            raise MeshError('Conflicting native allocation tags')
                        records[offset] = r
            self.pages[token] = records
            while len(self.pages) > 512:
                self.pages.popitem(last=False)
        else:
            self.pages.move_to_end(token)
        try:
            return self.pages[token][address.offset]
        except KeyError as exc:
            raise MeshError('Pointer target is not an exact current native allocation start') from exc

    def field_address(self, address, definition, name):
        offset, typ = definition[name]
        if typ['size'] != 4:
            raise MeshError('Unsupported native member width')
        return self.db.address(address.segment, address.cluster, address.offset + offset)

    def uint(self, address, definition, name):
        return struct.unpack('<I', self.db.read(self.field_address(address, definition, name), 4))[0]

    def pointer(self, address, definition, name):
        return self.db.resolve(self.field_address(address, definition, name))

    def array(self, target, tag, count):
        if target is None:
            if count == 0:
                return None
            raise MeshError('Nonnull array required for positive count')
        a = self.allocation(target)
        accepted_tags = (6, 21) if tag == 6 else (tag,)
        if not a['vector'] or a['native_tag'] not in accepted_tags or a['count'] != count:
            raise MeshError('Native array type/count mismatch')
        width = {8: 4, 3: 4, 6: 8}[tag]
        if a['size'] != count * width or a.get('array_header_size', 0):
            raise MeshError('Unsupported native primitive array padding/header')
        return a

    def surfaces(self):
        for a in self.allocations.iter_allocations():
            if a['name'] == 'Fs::Spatial::Geom::TriSurface':
                if a['vector']:
                    raise MeshError('TriSurface vector allocation unsupported')
                yield a

    def xyz(self, pointer_array, count):
        for i in range(count):
            source = self.db.address(pointer_array.segment, pointer_array.cluster, pointer_array.offset + 4 * i)
            point = self.db.resolve(source)
            if point is None or self.allocation(point)['name'] != 'Fs::Spatial::ProjectedCoord':
                raise MeshError('Vertex does not target native ProjectedCoord')
            if self.uint(point, self.coord_members, 'm_dimension') != 3:
                raise MeshError('Only three-dimensional ProjectedCoord is supported')
            values = self.pointer(point, self.coord_members, 'm_pValues')
            self.array(values, 6, 3)
            raw = self.db.read(values, 24)
            xyz = struct.unpack('<3d', raw)
            if not all((math.isfinite(v) for v in xyz)):
                raise MeshError('OBJ cannot represent nonfinite coordinates')
            if struct.pack('<3d', *(float(repr(v)) for v in xyz)) != raw:
                raise MeshError('Coordinate decimal representation did not roundtrip')
            yield (raw, xyz)

def export_meshes(db, new_directory, *, export_obj=True):
    """Write each current native TriSurface; return the saved manifest Path.

    No source coordinate transformation is applied. Array binaries preserve exact
    stored values and order; OBJ uses one-based faces as required by that format.
    With export_obj=False, CSV coordinates include exact little-endian raw bits,
    triangle indices stay zero-based, and no OBJ file is ever opened.
    Unsupported surfaces are reported explicitly and never replaced by guesses.
    """
    directory = Path(new_directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    reader = MeshReader(db)
    report = dict(format_version=1, source=dict(sha256=db.sha256, database_id=db.database_id), export_obj=export_obj, coordinate_policy='Original stored XYZ in world OBJ and binaries; additional local OBJ uses one documented common translation only' if export_obj else 'Original stored XYZ in CSV and binary arrays; zero-based triangle indices; no coordinate transformation', meshes=[], unsupported=[], limitations=['Current allocation does not establish application-root reachability.', 'Normals and coordinate-system transforms are not applied; stored XYZ and face order are preserved.'])
    for surface in reader.surfaces():
        address = surface['address']
        ident = f's{address.segment}_c{address.cluster}_o{address.offset:x}'
        formats = [('vertices_f64le', '.xyz.f64le'), ('triangles_u32le', '.triangles.u32le')]
        formats += [('obj', '.obj')] if export_obj else [('vertices_csv', '.vertices.csv'), ('triangles_csv', '.triangles.csv')]
        paths = {k: directory / (ident + suffix) for k, suffix in formats}
        try:
            nv = reader.uint(address, reader.surface_members, 'm_numVertex')
            nt = reader.uint(address, reader.surface_members, 'm_numTri')
            normal_count = reader.uint(address, reader.surface_members, 'm_numNormal')
            coordinate_system = reader.pointer(address, reader.surface_members, 'm_pCoordinateSystem')
            vertices = reader.pointer(address, reader.surface_members, 'm_ppVertexArray')
            triangles = reader.pointer(address, reader.surface_members, 'm_pTriVertexIndexArray')
            reader.array(vertices, 8, nv)
            reader.array(triangles, 3, nt * 3)
            faces = db.read(triangles, nt * 12) if nt else b''
            for triple in struct.iter_unpack('<III', faces):
                if max(triple) >= nv:
                    raise MeshError('Native triangle index exceeds vertex count')
            lo, hi = ([math.inf] * 3, [-math.inf] * 3)
            with paths['obj'].open('x') if export_obj else nullcontext() as obj, paths['vertices_f64le'].open('xb') as binary, paths['vertices_csv'].open('x', newline='') if not export_obj else nullcontext() as vertex_text:
                if obj:
                    obj.write(f'# Source SHA256 {db.sha256}\n# Native address {ident}\n# Original stored coordinates; units/CRS unspecified\no {ident}\n')
                writer = csv.writer(vertex_text, lineterminator='\n') if vertex_text else None
                if writer:
                    writer.writerow(['index', 'x', 'y', 'z', 'x_raw_hex', 'y_raw_hex', 'z_raw_hex'])
                for index, (raw, xyz) in enumerate(reader.xyz(vertices, nv)):
                    binary.write(raw)
                    if obj:
                        obj.write('v ' + ' '.join((repr(v) for v in xyz)) + '\n')
                    if writer:
                        writer.writerow([index, *(repr(v) for v in xyz), *(raw[j:j + 8].hex() for j in (0, 8, 16))])
                    for j, value in enumerate(xyz):
                        lo[j] = min(lo[j], value)
                        hi[j] = max(hi[j], value)
                if obj:
                    for triple in struct.iter_unpack('<III', faces):
                        obj.write('f ' + ' '.join((str(v + 1) for v in triple)) + '\n')
            if not export_obj:
                with paths['triangles_csv'].open('x', newline='') as triangle_text:
                    writer = csv.writer(triangle_text, lineterminator='\n')
                    writer.writerow(['index', 'v0', 'v1', 'v2'])
                    writer.writerows(((index, *triple) for index, triple in enumerate(struct.iter_unpack('<III', faces))))
            with paths['triangles_u32le'].open('xb') as f:
                f.write(faces)
            entry = dict(id=ident, source_address=asdict(address), vertex_count=nv, triangle_count=nt, stored_normal_count=normal_count, bounds=dict(min=lo, max=hi) if nv else None, coordinate_system_address=asdict(coordinate_system) if coordinate_system else None, vertex_array_address=asdict(vertices) if vertices else None, triangle_array_address=asdict(triangles) if triangles else None, paths={k: p.name for k, p in paths.items()}, hashes={k: digest(p) for k, p in paths.items()})
            report['meshes'].append(entry)
            print(f'Exported {ident}: {nv} vertices, {nt} triangles', flush=True)
        except (ValueError, KeyError) as exc:
            for path in paths.values():
                if path.exists():
                    path.unlink()
            report['unsupported'].append(dict(id=ident, source_address=asdict(address), error=str(exc)))
    if export_obj:
        add_local_objs(directory, report)
    else:
        report['local_coordinate_transform'] = None
    db.verify_source()
    report.update(source_unchanged=True, mesh_count=len(report['meshes']), vertex_count=sum((m['vertex_count'] for m in report['meshes'])), triangle_count=sum((m['triangle_count'] for m in report['meshes'])), complete=not report['unsupported'])
    with (directory / 'manifest.json').open('x') as f:
        json.dump(report, f, indent=2, allow_nan=False)
        f.write('\n')
    return directory / 'manifest.json'

def add_local_objs(directory, report):
    """Add aligned local OBJ copies for float32-oriented 3D applications.

    Original OBJ and binary64 bytes remain the source-coordinate authority.
    Every local mesh shares one explicitly recorded origin; no CRS is inferred.
    """
    nonempty = [m for m in report['meshes'] if m['vertex_count']]
    if not nonempty:
        report['local_coordinate_transform'] = None
        return
    low = [min((m['bounds']['min'][j] for m in nonempty)) for j in range(3)]
    high = [max((m['bounds']['max'][j] for m in nonempty)) for j in range(3)]
    origin = [lo + (hi - lo) / 2 for lo, hi in zip(low, high)]
    report['local_coordinate_transform'] = dict(origin_source_xyz=origin, forward='local_xyz = source_xyz - origin_source_xyz', inverse='source_xyz = local_xyz + origin_source_xyz', purpose='Shared origin for importing aligned meshes in float32-oriented 3D applications', authority='Original world-coordinate OBJ and binary64 arrays retain source values')
    for mesh in report['meshes']:
        output = directory / (mesh['id'] + '.local.obj')
        maximum_error = 0.0
        with output.open('x') as obj:
            obj.write(f'# Source SHA256 {report['source']['sha256']}\n# Common origin XYZ {origin!r}\no {mesh['id']}\n')
            source = (directory / mesh['paths']['vertices_f64le']).read_bytes()
            for xyz in struct.iter_unpack('<3d', source):
                local = [x - o for x, o in zip(xyz, origin)]
                maximum_error = max(maximum_error, *(abs(x - (v + o)) for x, v, o in zip(xyz, local, origin)))
                obj.write('v ' + ' '.join((repr(v) for v in local)) + '\n')
            faces = (directory / mesh['paths']['triangles_u32le']).read_bytes()
            for triple in struct.iter_unpack('<III', faces):
                obj.write('f ' + ' '.join((str(v + 1) for v in triple)) + '\n')
        mesh['paths']['local_obj'] = output.name
        mesh['hashes']['local_obj'] = digest(output)
        mesh['recommended_3d_path'] = output.name
        mesh['local_to_source_maximum_float64_error'] = maximum_error

def validate_no_obj_meshes(db, manifest_path):
    """Re-read all exported CSV/binary values against native source pointers.

    Checks exact world-coordinate double bytes, raw hex, zero-based index order,
    every current surface, manifest pointers/counts and streaming file hashes.
    Raises MeshError for partial exports or any disagreement. No OBJ is needed.
    """
    manifest_path = Path(manifest_path)
    directory = manifest_path.parent
    report = json.loads(manifest_path.read_text())

    def require(condition, message):
        if not condition:
            raise MeshError(message)
    require(report.get('export_obj') is False, 'Manifest must explicitly disable OBJ')
    require(report.get('complete') and (not report.get('unsupported')), 'Mesh export is incomplete')
    require(report.get('source') == dict(sha256=db.sha256, database_id=db.database_id), 'Source identity mismatch')
    require(not list(directory.rglob('*.obj')), 'Unexpected OBJ file')
    reader = MeshReader(db)
    surfaces = {(a['address'].segment, a['address'].cluster, a['address'].offset): a for a in reader.surfaces()}
    checked_vertices = checked_triangles = checked_files = 0
    expected_paths = {'vertices_csv', 'triangles_csv', 'vertices_f64le', 'triangles_u32le'}
    for mesh in report['meshes']:
        source_address = mesh['source_address']
        key = tuple((source_address[k] for k in ('segment', 'cluster', 'offset')))
        require(key in surfaces, 'Duplicate or non-current surface')
        address = surfaces.pop(key)['address']
        require(source_address == asdict(address), 'Surface address identity mismatch')
        nv = reader.uint(address, reader.surface_members, 'm_numVertex')
        nt = reader.uint(address, reader.surface_members, 'm_numTri')
        vertices = reader.pointer(address, reader.surface_members, 'm_ppVertexArray')
        triangles = reader.pointer(address, reader.surface_members, 'm_pTriVertexIndexArray')
        coordinate_system = reader.pointer(address, reader.surface_members, 'm_pCoordinateSystem')
        require(mesh['vertex_count'] == nv and mesh['triangle_count'] == nt, 'Source count mismatch')
        require(mesh['stored_normal_count'] == reader.uint(address, reader.surface_members, 'm_numNormal'), 'Normal count mismatch')
        for name, target in [('vertex_array_address', vertices), ('triangle_array_address', triangles), ('coordinate_system_address', coordinate_system)]:
            require(mesh[name] == (asdict(target) if target else None), 'Source pointer mismatch: ' + name)
        reader.array(vertices, 8, nv)
        reader.array(triangles, 3, nt * 3)
        require(set(mesh['paths']) == expected_paths and set(mesh['hashes']) == expected_paths, 'Unexpected mesh formats')
        paths = {}
        for name, relative in mesh['paths'].items():
            require(isinstance(relative, str) and Path(relative).name == relative and (not Path(relative).is_absolute()), 'Unsafe mesh path')
            path = directory / relative
            require(not path.is_symlink(), 'Mesh artifact must not be symlink')
            require(digest(path) == mesh['hashes'][name], 'Mesh artifact hash mismatch: ' + name)
            paths[name] = path
            checked_files += 1
        lo, hi = ([math.inf] * 3, [-math.inf] * 3)
        with paths['vertices_csv'].open(newline='') as text, paths['vertices_f64le'].open('rb') as binary:
            rows = csv.reader(text)
            require(next(rows, None) == ['index', 'x', 'y', 'z', 'x_raw_hex', 'y_raw_hex', 'z_raw_hex'], 'Vertex CSV header mismatch')
            for index, (raw, xyz) in enumerate(reader.xyz(vertices, nv)):
                row = next(rows, None)
                require(row is not None and len(row) == 7 and (row[0] == str(index)), 'Vertex CSV order/count mismatch')
                require(struct.pack('<3d', *(float(v) for v in row[1:4])) == raw, 'Vertex CSV decimals differ from source bytes')
                require(bytes.fromhex(''.join(row[4:])) == raw, 'Vertex CSV raw bytes differ from source')
                require(binary.read(24) == raw, 'Vertex binary differs from source')
                for j, value in enumerate(xyz):
                    lo[j] = min(lo[j], value)
                    hi[j] = max(hi[j], value)
            require(next(rows, None) is None and binary.read(1) == b'', 'Extra vertex data')
        require(mesh['bounds'] == (dict(min=lo, max=hi) if nv else None), 'Source bounds mismatch')
        with paths['triangles_csv'].open(newline='') as text, paths['triangles_u32le'].open('rb') as binary:
            rows = csv.reader(text)
            require(next(rows, None) == ['index', 'v0', 'v1', 'v2'], 'Triangle CSV header mismatch')
            for index in range(nt):
                raw = db.read(db.address(triangles.segment, triangles.cluster, triangles.offset + 12 * index), 12)
                triple = struct.unpack('<III', raw)
                require(max(triple) < nv, 'Source triangle outside vertices')
                require(next(rows, None) == [str(index), *(str(v) for v in triple)], 'Triangle CSV differs from source order/indices')
                require(binary.read(12) == raw, 'Triangle binary differs from source')
            require(next(rows, None) is None and binary.read(1) == b'', 'Extra triangle data')
        checked_vertices += nv
        checked_triangles += nt
    require(not surfaces, 'Current surfaces omitted from manifest')
    require(report['mesh_count'] == len(report['meshes']) and report['vertex_count'] == checked_vertices and (report['triangle_count'] == checked_triangles), 'Aggregate counts mismatch')
    require(report.get('local_coordinate_transform') is None, 'Unexpected coordinate transformation')
    db.verify_source()
    return dict(status='PASS', source_sha256=db.sha256, source_unchanged=True, export_obj=False, meshes=len(report['meshes']), vertices=checked_vertices, triangles=checked_triangles, files=checked_files, scope='All current native TriSurface owners and every CSV/binary value checked against source pointers and bytes')
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--no-obj', action='store_true', help='write exact plaintext CSV arrays instead of OBJ')
    args = parser.parse_args()
    manifest = export_meshes(NativeDatabase.from_path(args.source), args.output_dir, export_obj=not args.no_obj)
    result = json.loads(manifest.read_text())
    print(json.dumps({k: result[k] for k in ('complete', 'mesh_count', 'vertex_count', 'triangle_count')}))
    raise SystemExit(0 if result['complete'] else 2)
