"""Source-exact plaintext export of native point/line and regular-grid storage.

Discovery uses current allocations and each file's embedded schema. No hardcoded
source offsets, filename decisions, coordinate transformations or grid meshing.
"""
import argparse
from collections import Counter, OrderedDict
from contextlib import nullcontext
from dataclasses import asdict
import json
import math
from pathlib import Path
import struct
import shutil
import sys
import tempfile
from fsd_decoder.native.native_allocations import NativeAllocationReader
from fsd_decoder.native.native_database import NativeDatabase
from fsd_decoder.schema.native_fields import NativeFields
from fsd_decoder.exports.fsd_mesh import MeshReader, MeshError, members
from fsd_decoder.exports.fsd_export import digest, publish_directory
from fsd_decoder.cli.dump import install_termination_handler
PREFIX = 'Fs::Spatial::Geom::'
SUPPORTED = {PREFIX + n for n in ('LineString', 'LinearRing', 'PointSet', 'RegularGrid3')} | {'Fs::Grid3ScalarData'}

def exact_doubles(raw):
    if len(raw) % 8:
        raise MeshError('Double array has incomplete storage')
    result = []
    for (value,), (bits,) in zip(struct.iter_unpack('<d', raw), struct.iter_unpack('<Q', raw)):
        decimal = repr(value)
        if math.isfinite(value) and struct.pack('<d', float(decimal)) != struct.pack('<Q', bits):
            raise MeshError('Coordinate decimal did not roundtrip')
        result.append(dict(decimal=decimal, raw_hex=struct.pack('<Q', bits).hex(), finite=math.isfinite(value)))
    return result

def dump_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')

class GeometryReader(MeshReader):

    def __init__(self, db):
        self.db = db
        self.fields = NativeFields(db)
        self.allocations = NativeAllocationReader(db, self.fields.types)
        self.pages = OrderedDict()

    def definition(self, name):
        if self.fields._layout_problems(name):
            raise MeshError('Embedded schema layout is incomplete: ' + name)
        return members(self.fields.schema.layout(name))

    def coordinate(self, target):
        if target is None:
            raise MeshError('Coordinate reference is null')
        allocation = self.allocation(target)
        if not self.fields.schema_admission(allocation)['admitted']:
            raise MeshError('Coordinate native storage does not corroborate source layout')
        name = allocation['name']

        def coordinate_base(layout):
            return layout['name'] == 'Fs::Spatial::Coordinate' or any((coordinate_base(b['layout']) for b in layout['bases']))
        if allocation['vector'] or name not in self.fields.schema.classes or (not coordinate_base(self.fields.schema.layout(name))):
            raise MeshError('Coordinate reference does not target a current Coordinate-derived scalar')
        definition = self.definition(name)
        dimension = self.uint(target, definition, 'm_dimension')
        values = self.pointer(target, definition, 'm_pValues')
        self.array(values, 6, dimension)
        raw = self.db.read(values, dimension * 8) if dimension else b''
        return dict(type=name, source_address=asdict(target), dimension=dimension, values_address=asdict(values) if values else None, values=exact_doubles(raw))

    def points(self, allocation, directory, ident, *, export_obj=True):
        if not self.fields.schema_admission(allocation)['admitted']:
            raise MeshError('Geometry native storage does not corroborate source layout')
        address = allocation['address']
        definition = self.definition(allocation['name'])
        count = self.uint(address, definition, 'm_numPoints')
        target = self.pointer(address, definition, 'm_ppPointArray')
        self.array(target, 8, count)
        jsonpath = directory / (ident + '.coordinates.jsonl')
        objpath = directory / (ident + '.obj')
        valid_obj = export_obj
        with jsonpath.open('x') as out, objpath.open('x') if export_obj else nullcontext() as obj:
            if obj:
                obj.write(f'# Source SHA256 {self.db.sha256}\n# Original stored coordinates; CRS and units unspecified\no {ident}\n')
            for i in range(count):
                slot = self.db.address(target.segment, target.cluster, target.offset + 4 * i)
                coordinate = self.coordinate(self.db.resolve(slot))
                record = dict(index=i, reference_source=asdict(slot), reference_raw_hex=self.db.read(slot, 4).hex(), **coordinate)
                out.write(json.dumps(record, allow_nan=False) + '\n')
                if obj and coordinate['dimension'] == 3 and all((v['finite'] for v in coordinate['values'])):
                    obj.write('v ' + ' '.join((v['decimal'] for v in coordinate['values'])) + '\n')
                else:
                    valid_obj = False
            if valid_obj:
                if allocation['name'] == PREFIX + 'PointSet':
                    for i in range(count):
                        obj.write(f'p {i + 1}\n')
                else:
                    for i in range(1, count):
                        obj.write(f'l {i} {i + 1}\n')
        if export_obj and (not valid_obj):
            objpath.unlink()
        return dict(kind='stored_point_sequence', point_count=count, coordinate_array_address=asdict(target) if target else None, obj_status='DISABLED' if not export_obj else 'EXPORTED' if valid_obj else 'UNSUPPORTED_DIMENSION_OR_NONFINITE', sequence_policy='Stored order; consecutive edges for lines/rings; no added closing edge', paths=[jsonpath.name] + ([objpath.name] if valid_obj else []))

    def grid(self, allocation, directory, ident):
        if not self.fields.schema_admission(allocation)['admitted']:
            raise MeshError('Grid native storage does not corroborate source layout')
        address = allocation['address']
        definition = self.definition(allocation['name'])
        vectors = {name: self.coordinate(self.pointer(address, definition, name)) for name in ('m_pOriginPoint', 'm_pBasisVector1', 'm_pBasisVector2', 'm_pBasisVector3')}
        return dict(kind='regular_grid_parameters', stored_extents={name: self.uint(address, definition, name) for name in ('m_extent1', 'm_extent2', 'm_extent3')}, coordinates=vectors, topology_status='NOT_GENERATED', scalar_owner_status='NOT_INFERRED', paths=[])

    def scalar_grid(self, allocation, directory, ident, maximum):
        if not self.fields.schema_admission(allocation)['admitted']:
            raise MeshError('Scalar grid native storage does not corroborate source layout')
        address = allocation['address']
        definition = self.definition(allocation['name'])
        dims = [self.uint(address, definition, n) for n in ('m_numLayers', 'm_numRows', 'm_numColumns')]
        layers, rows, columns = dims
        target = self.pointer(address, definition, 'm_pppValues')
        self.array(target, 8, layers)
        output = directory / (ident + '.scalar_values.csv')
        provenance = directory / (ident + '.scalar_rows.jsonl')
        written = 0
        checked_rows = 0
        truncated = False
        with output.open('x') as out, provenance.open('x') as links:
            out.write('layer_index,row_index,column_index,decimal,f64le_hex,segment,cluster,logical_offset\n')
            for layer in range(layers):
                layer_slot = self.db.address(target.segment, target.cluster, target.offset + 4 * layer)
                row_array = self.db.resolve(layer_slot)
                self.array(row_array, 8, rows)
                for row in range(rows):
                    if maximum is not None and written >= maximum:
                        truncated = True
                        break
                    row_slot = self.db.address(row_array.segment, row_array.cluster, row_array.offset + 4 * row)
                    data = self.db.resolve(row_slot)
                    self.array(data, 6, columns)
                    checked_rows += 1
                    links.write(json.dumps(dict(layer_index=layer, row_index=row, layer_reference_source=asdict(layer_slot), layer_reference_raw_hex=self.db.read(layer_slot, 4).hex(), row_array_address=asdict(row_array), row_reference_source=asdict(row_slot), row_reference_raw_hex=self.db.read(row_slot, 4).hex(), values_address=asdict(data) if data else None, column_count=columns)) + '\n')
                    n = columns if maximum is None else min(columns, maximum - written)
                    raw = self.db.read(data, n * 8) if n else b''
                    for column, value in enumerate(exact_doubles(raw)):
                        out.write(f'{layer},{row},{column},{value['decimal']},{value['raw_hex']},{data.segment},{data.cluster},{data.offset + 8 * column}\n')
                    written += n
                    if n < columns:
                        truncated = True
                if truncated:
                    break
        total = layers * rows * columns
        return dict(kind='grid_scalar_pointer_arrays', stored_dimensions=dict(layers=layers, rows=rows, columns=columns), total_declared_values=total, exported_values=written, validated_rows=checked_rows, values_complete=written == total and (not truncated), value_pointer_address=asdict(target) if target else None, semantics='Indices follow stored layer/row/column pointer arrays; no spatial-axis, units, cell topology or geometry-owner mapping inferred', paths=[output.name, provenance.name])

def _write_geometry(db, output, types=None, max_per_type=None, max_grid_values=None, export_obj=True):
    selected = set(SUPPORTED if types is None else types)
    if not selected or selected - SUPPORTED:
        raise ValueError('Unsupported requested geometry types')
    for value in (max_per_type, max_grid_values):
        if value is not None and (type(value) is not int or value <= 0):
            raise ValueError('Limits must be positive integers')
    directory = Path(output).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    reader = GeometryReader(db)
    counts = Counter()
    observed = Counter()
    scanned = 0
    complete_scan = True
    report = dict(format='FSD_ADDITIONAL_GEOMETRY', format_version=1, source_sha256=db.sha256, database_id=db.database_id, export_obj=export_obj, selected_types=sorted(selected), limits=dict(max_per_type=max_per_type, max_grid_values=max_grid_values), objects=[], unsupported=[], limitations=['Current allocations do not establish application root reachability.', 'Selected geometry types only; other classes remain available through native plaintext decoding.', 'Ring closure, CRS, units, mesh faces and grid/scalar ownership are not inferred.'])
    for allocation in reader.allocations.iter_allocations():
        scanned += 1
        name = allocation['name']
        observed[name] += 1
        if name not in selected or (max_per_type is not None and counts[name] >= max_per_type):
            continue
        counts[name] += 1
        address = allocation['address']
        ident = f's{address.segment}_c{address.cluster}_o{address.offset:x}'
        entry = dict(id=ident, type=name, source_address=asdict(address), paths=[])
        try:
            if allocation['vector']:
                raise MeshError('Vector of geometry owners is unsupported')
            decoded = reader.fields.decode(allocation)
            metadata = directory / (ident + '.native.json')
            dump_json(metadata, decoded)
            entry['paths'].append(metadata.name)
            if name == PREFIX + 'RegularGrid3':
                result = reader.grid(allocation, directory, ident)
            elif name == 'Fs::Grid3ScalarData':
                result = reader.scalar_grid(allocation, directory, ident, max_grid_values)
            else:
                result = reader.points(allocation, directory, ident, export_obj=export_obj)
            paths = entry['paths'] + result.pop('paths')
            entry.update(result, paths=paths)
            entry['status'] = 'PARTIAL_VALUES' if entry.get('values_complete') is False else 'EXPORTED'
            report['objects'].append(entry)
        except (ValueError, KeyError) as exc:
            entry.update(status='UNSUPPORTED', error=str(exc))
            entry['paths'] = sorted((p.name for p in directory.glob(ident + '.*')))
            report['unsupported'].append(entry)
        if max_per_type is not None and all((counts[n] >= max_per_type for n in selected)):
            complete_scan = False
            break
    db.verify_source()
    report.update(source_unchanged=True, allocation_scan_complete=complete_scan, allocations_scanned=scanned, encountered_type_counts=dict(sorted(observed.items())), attempted_by_type=dict(counts), complete_for_selected_types=complete_scan and (not report['unsupported']) and all((o['status'] == 'EXPORTED' for o in report['objects'])) and all((observed[n] == counts[n] for n in selected)))
    for entry in report['objects'] + report['unsupported']:
        entry['hashes'] = {name: digest(directory / name) for name in entry['paths']}
    dump_json(directory / 'manifest.json', report)
    return report

def export_geometry(db, output, types=None, max_per_type=None, max_grid_values=None, *, export_obj=True):
    """Publish a complete manifest atomically, including explicit partial results.

    Unexpected I/O or structural failures leave no destination or staging files.
    A raced destination is preserved by the atomic no-replace publication.
    """
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Destination exists; choose a new directory')
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.fsd-geometry-', dir=destination.parent))
    try:
        payload = staging / 'payload'
        report = _write_geometry(db, payload, types, max_per_type, max_grid_values, export_obj)
        db.verify_source()
        publish_directory(payload, destination)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)

def main(argv=None):
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--types', nargs='+', choices=sorted(SUPPORTED))
    parser.add_argument('--max-per-type', type=int)
    parser.add_argument('--max-grid-values', type=int)
    parser.add_argument('--no-obj', action='store_true', help='retain plaintext coordinates without creating OBJ files')
    args = parser.parse_args(argv)
    try:
        report = export_geometry(NativeDatabase.from_path(args.source), args.output, args.types, args.max_per_type, args.max_grid_values, export_obj=not args.no_obj)
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted; unfinished geometry output was not published.', file=sys.stderr)
        return 130
    print(json.dumps({k: report[k] for k in ('complete_for_selected_types', 'allocation_scan_complete', 'attempted_by_type')}))
    return 0 if report['complete_for_selected_types'] else 2
if __name__ == '__main__':
    raise SystemExit(main())
