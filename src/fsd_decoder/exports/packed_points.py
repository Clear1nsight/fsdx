"""Evidence-gated InterleavedPoint decoding, using a portable FSDX.

The persisted union contains no coordinate-semantic discriminant. This module
retains every record and decodes a candidate Morton model; XYZ export requires
an independently stored PointSet witness to match every quantized coordinate.
No original FSD, proprietary runtime, mesh generation or rendering is used.
"""
from __future__ import annotations
import argparse
import csv
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import struct
import tempfile
import sys
from fsd_decoder.core.diagnostics import attach_context, contextual, failure_record
from fsd_decoder.exports.fsd_export import digest as file_digest, publish_directory
POINT = 'Fs::Spatial::Geom::InterleavedPoint'
OWNER = 'Fs::Spatial::Geom::InterleavedPointSet'
REFERENCE = 'Fs::Spatial::Geom::PointSet'
PROFILE = 'TUTORIAL_MORTON_U32_MAX_0x55555555'
MAX_VALUE = 1431655765
MAX_RECORDS = 100000
MAX_PACKED_ARRAYS = 32
MAX_SCALAR_RECORD_BYTES = 4096
MAX_COPY_PAYLOAD_BYTES = 32 * 1024 * 1024

def _bounded_count(count):
    if type(count) is not int or not 0 <= count <= MAX_RECORDS:
        raise PackedPointError(f'Record count exceeds bounded packed profile (0..{MAX_RECORDS})')
    return count

class PackedPointError(ValueError):
    pass

def unpack_lanes(raw: bytes) -> dict:
    """Return exact stored lanes and candidate integers, including unknown bits."""
    if len(raw) != 16:
        raise PackedPointError('An InterleavedPoint record must contain exactly 16 bytes')
    words = struct.unpack('<4I', raw)
    integers = tuple((sum(((word >> 3 * bit + axis & 1) << 8 * lane + bit for lane, word in enumerate(words) for bit in range(8))) for axis in range(3)))
    high_bytes = tuple((word >> 24 for word in words))
    status = 'UNKNOWN_HIGH_LANE_BITS' if any(high_bytes) else 'OUTSIDE_CORROBORATED_QUANTIZED_RANGE' if any((q > MAX_VALUE for q in integers)) else 'CANDIDATE_MORTON_INTEGERS'
    return dict(raw_hex=raw.hex(), uint32_lanes=words, high_lane_bytes=high_bytes, candidate_quantized_xyz=integers, status=status)

def pack_lanes(integers) -> bytes:
    """Exact inverse of the candidate low-24-bit lane transformation."""
    values = tuple(integers)
    if len(values) != 3 or any((type(q) is not int or not 0 <= q < 2 ** 32 for q in values)):
        raise PackedPointError('Three unsigned 32-bit integers are required')
    words = [sum(((q >> 8 * lane + bit & 1) << 3 * bit + axis for axis, q in enumerate(values) for bit in range(8))) for lane in range(4)]
    return struct.pack('<4I', *words)

def model_xyz(record, minimum, maximum):
    """Evaluate the bounded candidate model; this alone does not prove semantics."""
    if record['status'] != 'CANDIDATE_MORTON_INTEGERS':
        raise PackedPointError('Record has bits or values outside the corroborated model')
    low, high = (tuple(minimum), tuple(maximum))
    if len(low) != 3 or len(high) != 3 or any((not math.isfinite(v) for v in low + high)) or any((a > b for a, b in zip(low, high))):
        raise PackedPointError('Finite three-dimensional ordered bounds are required')
    return tuple((a + (b - a) * q / MAX_VALUE for a, b, q in zip(low, high, record['candidate_quantized_xyz'])))

def _digest(raw):
    return hashlib.sha256(raw).hexdigest()

class PackedPointReader:

    def __init__(self, db):
        self.db = db

    @contextual('packed_field', name='name')
    def _fields(self, allocation, name):
        if allocation is None or allocation['vector'] or (not 0 < allocation['size'] <= MAX_SCALAR_RECORD_BYTES):
            raise PackedPointError('Scalar allocation exceeds bounded packed-profile extent')
        return self.db.fields.decode(allocation)['fields']

    @contextual('packed_field', name='name')
    def _field(self, fields, name):
        matching = [f for f in fields if f['path'].endswith('.' + name)]
        if len(matching) != 1:
            raise PackedPointError('Expected exactly one schema-owned field: ' + name)
        return matching[0]

    def field(self, allocation, name):
        return self._field(self._fields(allocation, name), name)

    def pointer(self, allocation, name):
        return self._pointer(self.field(allocation, name), name)

    def _pointer(self, field, name):
        target = field.get('target')
        if field['kind'] != 'stored_reference' or target is None:
            raise PackedPointError('Expected a resolved nonnull pointer: ' + name)
        target = target['address']
        return self.db.address(target['segment'], target['cluster'], target['offset'])

    def array(self, target, count, *, name=None, size=None):
        _bounded_count(count)
        allocation = self.db.allocation(target.segment, target.cluster, target.offset)
        if allocation is None or not allocation['vector'] or allocation['count'] != count or (allocation['logical_offset'] + allocation['array_header_size'] != target.offset) or (name is not None and allocation['name'] != name) or (size is not None and allocation['element_size'] != size) or (allocation['element_stride'] != allocation['element_size']):
            raise PackedPointError('Pointer is not an exact matching current array payload')
        return allocation

    def coordinate(self, target):
        allocation = self.db.allocation(target.segment, target.cluster, target.offset)
        if allocation is None or allocation['vector'] or allocation['logical_offset'] != target.offset:
            raise PackedPointError('Coordinate target must be a current scalar allocation start')
        layout = self.db.fields.schema.layout(allocation['name'])

        def inherits_coordinate(node):
            return node['name'] == 'Fs::Spatial::Coordinate' or any((inherits_coordinate(base['layout']) for base in node['bases']))
        if not inherits_coordinate(layout):
            raise PackedPointError('Coordinate target has no Coordinate schema base')
        default_hooks = (getattr(self.field, '__func__', None) is _DEFAULT_FIELD
                         and getattr(self.pointer, '__func__', None) is _DEFAULT_POINTER)
        if default_hooks:
            fields = self._fields(allocation, 'm_dimension')
            dimension = self._field(fields, 'm_dimension')['value']
        else:
            dimension = self.field(allocation, 'm_dimension')['value']
        if dimension != 3:
            raise PackedPointError('Packed profile requires exactly three dimensions')
        values = (self._pointer(self._field(fields, 'm_pValues'), 'm_pValues')
                  if default_hooks else self.pointer(allocation, 'm_pValues'))
        self.array(values, dimension, name='double[]', size=8)
        raw = self.db.read(values, dimension * 8)
        xyz = struct.unpack('<3d', raw)
        if not all(map(math.isfinite, xyz)):
            raise PackedPointError('Coordinate witness has nonfinite storage')
        return dict(source_address=asdict(target), values_address=asdict(values), binary64le_hex=raw.hex(), xyz=xyz)

    def context(self, owner):
        if owner is None or owner['name'] != OWNER or owner['vector']:
            raise PackedPointError('Expected an InterleavedPointSet scalar owner')
        count = _bounded_count(self.field(owner, 'm_pointCounter')['value'])
        if not count:
            raise PackedPointError('Packed profile requires a nonempty coordinate witness')
        points = self.pointer(owner, 'm_pPoints')
        allocation = self.array(points, count, name=POINT + '[]', size=16)
        maps = {}
        for name in ('m_pExternalToInternalMap', 'm_pInternalToExternalMap'):
            target = self.pointer(owner, name)
            self.array(target, count, name='4 byte long[]', size=4)
            raw = self.db.read(target, count * 4)
            values = tuple((v[0] for v in struct.iter_unpack('<I', raw)))
            if set(values) != set(range(count)):
                raise PackedPointError('Stored index map is not a complete zero-based permutation')
            maps[name] = dict(source_address=asdict(target), raw_sha256=_digest(raw), values=values)
        inverse = maps['m_pInternalToExternalMap']['values']
        forward = maps['m_pExternalToInternalMap']['values']
        if any((forward[inverse[i]] != i for i in range(count))):
            raise PackedPointError('Stored maps are not inverse permutations')
        minimum = self.coordinate(self.pointer(owner, 'm_minCoord'))
        maximum = self.coordinate(self.pointer(owner, 'm_maxCoord'))
        raw = self.db.read(points, 16 * count)
        return dict(owner_address=asdict(owner['address']), point_count=count, points_address=asdict(points), allocation_address=asdict(allocation['address']), minimum=minimum, maximum=maximum, maps=maps, raw=raw, coordinate_system_address=asdict(self.pointer(owner, 'm_pCoordinateSystem')))

    def verify_witness(self, context, reference):
        """Require all coordinates to re-encode to the exact stored low lane bytes."""
        if reference is None or reference['name'] != REFERENCE or reference['vector']:
            raise PackedPointError('Witness must be an ordinary PointSet scalar')
        count = _bounded_count(context['point_count'])
        reference_crs = asdict(self.pointer(reference, 'm_pCoordinateSystem'))
        if reference_crs != context['coordinate_system_address']:
            raise PackedPointError('PointSet witness uses a different stored coordinate-system identity')
        if self.field(reference, 'm_numPoints')['value'] != count:
            raise PackedPointError('PointSet witness count differs from packed owner')
        points = self.pointer(reference, 'm_ppPointArray')
        self.array(points, count, name='4 byte void*[]', size=4)
        low, high = (context['minimum']['xyz'], context['maximum']['xyz'])
        if any((a >= b for a, b in zip(low, high))):
            raise PackedPointError('Witness verification requires nondegenerate ordered bounds')
        errors = [0.0] * 3
        qmin, qmax = ([2 ** 32] * 3, [0] * 3)
        mismatches, unknown = ([], [])
        sampled = []
        for internal in range(count):
            raw = context['raw'][16 * internal:16 * (internal + 1)]
            decoded = unpack_lanes(raw)
            external = context['maps']['m_pInternalToExternalMap']['values'][internal]
            if decoded['status'] != 'CANDIDATE_MORTON_INTEGERS':
                unknown.append(internal)
                continue
            slot = self.db.address(points.segment, points.cluster, points.offset + 4 * external)
            target = self.db.resolve(slot, width=4, raw=self.db.read(slot, 4))
            if target is None:
                raise PackedPointError('Null coordinate in independent PointSet witness')
            witness = self.coordinate(target)
            xyz = model_xyz(decoded, low, high)
            encoded = tuple((int(math.floor((value - a) / (b - a) * MAX_VALUE + 0.5)) for value, a, b in zip(witness['xyz'], low, high)))
            if encoded != decoded['candidate_quantized_xyz']:
                mismatches.append(internal)
            for axis, q in enumerate(decoded['candidate_quantized_xyz']):
                errors[axis] = max(errors[axis], abs(xyz[axis] - witness['xyz'][axis]))
                qmin[axis], qmax[axis] = (min(qmin[axis], q), max(qmax[axis], q))
            if internal in {0, count // 2, count - 1}:
                sampled.append(dict(internal_index=internal, external_index=external, packed=decoded, model_xyz=xyz, witness=witness))
        bounds_cover = tuple(qmin) == (0, 0, 0) and tuple(qmax) == (MAX_VALUE,) * 3
        verified = not mismatches and (not unknown) and bounds_cover and (count > 0)
        return dict(status='CORROBORATED_ALL_RECORDS' if verified else 'UNVERIFIED_MODEL', profile=PROFILE, reference_owner_address=asdict(reference['address']), coordinate_system_address=reference_crs, stored_coordinate_system_identity_equal=True, checked_records=count - len(unknown), total_records=count, exact_quantized_reencoding_matches=count - len(unknown) - len(mismatches), mismatch_internal_indexes=mismatches, unknown_internal_indexes=unknown, quantized_axis_minima=qmin, quantized_axis_maxima=qmax, axis_bounds_cover_quantization_range=bounds_cover, maximum_absolute_error_xyz=errors, half_quantization_step_xyz=[(b - a) / MAX_VALUE / 2 for a, b in zip(low, high)], samples=sampled)

    @contextual('packed_export', output='output')
    def export(self, owner, reference, output):
        """Atomically publish a complete bundle into a new directory, never replace."""
        destination = Path(output).absolute()
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)
        context = self.context(owner)
        witness = self.verify_witness(context, reference)
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix='.fsd-packed-', dir=destination.parent))
        try:
            report = self._write_export(context, witness, owner, staging)
            for path in staging.iterdir():
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
            descriptor = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            publish_directory(staging, destination)
            return report
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    def _write_export(self, context, witness, owner, destination):
        """Write only into the private staging directory supplied by export()."""
        names = []
        with (destination / 'packed_records.jsonl').open('x') as stream:
            for internal in range(context['point_count']):
                raw = context['raw'][16 * internal:16 * (internal + 1)]
                record = unpack_lanes(raw)
                record.update(internal_index=internal, external_index=context['maps']['m_pInternalToExternalMap']['values'][internal], source_address=dict(context['points_address'], offset=context['points_address']['offset'] + internal * 16))
                stream.write(json.dumps(record) + '\n')
        names.append('packed_records.jsonl')
        if witness['status'] == 'CORROBORATED_ALL_RECORDS':
            with (destination / 'coordinates.csv').open('x', newline='') as stream:
                writer = csv.writer(stream)
                writer.writerow(['internal_index', 'external_index', 'x', 'y', 'z', 'quantized_x', 'quantized_y', 'quantized_z', 'raw_hex', 'segment', 'cluster', 'logical_offset'])
                for internal in range(context['point_count']):
                    record = unpack_lanes(context['raw'][16 * internal:16 * (internal + 1)])
                    xyz = model_xyz(record, context['minimum']['xyz'], context['maximum']['xyz'])
                    writer.writerow([internal, context['maps']['m_pInternalToExternalMap']['values'][internal], *map(repr, xyz), *record['candidate_quantized_xyz'], record['raw_hex'], context['points_address']['segment'], context['points_address']['cluster'], context['points_address']['offset'] + 16 * internal])
            names.append('coordinates.csv')
        copies = []
        copied_payload_bytes = 0
        for allocation in self.db.iter_allocations(name=POINT + '[]'):
            if len(copies) >= MAX_PACKED_ARRAYS:
                raise PackedPointError('Packed allocation count exceeds bounded profile')
            count = _bounded_count(allocation['count'])
            if not allocation['vector'] or allocation['element_size'] != 16 or allocation['element_stride'] != 16:
                raise PackedPointError('Additional packed array has an unsupported extent or stride')
            payload_bytes = count * 16
            copied_payload_bytes += payload_bytes
            if copied_payload_bytes > MAX_COPY_PAYLOAD_BYTES:
                raise PackedPointError('Packed copy payload total exceeds bounded profile')
            target = self.db.address(allocation['segment'], allocation['cluster'], allocation['logical_offset'] + allocation['array_header_size'])
            raw = self.db.read(target, payload_bytes)
            filename = f's{allocation['segment']}_c{allocation['cluster']}_o{allocation['logical_offset']}.raw.bin'
            (destination / filename).write_bytes(raw)
            names.append(filename)
            copies.append(dict(allocation_address=asdict(allocation['address']), payload_address=asdict(target), count=allocation['count'], raw_sha256=_digest(raw), raw_bytes=len(raw), file=filename, array_header_raw_hex=allocation['array_header_hex'], array_header_size=allocation['array_header_size'], equals_owner_payload=raw == context['raw'], selected_by_owner=target == self.pointer(owner, 'm_pPoints')))
        report = {k: v for k, v in context.items() if k != 'raw'}
        report.update(status=witness['status'], publication_status='COMPLETE', resource_limits=dict(max_records=MAX_RECORDS, max_packed_arrays=MAX_PACKED_ARRAYS, max_scalar_record_bytes=MAX_SCALAR_RECORD_BYTES, max_copy_payload_bytes=MAX_COPY_PAYLOAD_BYTES, max_owner_payload_bytes=16 * MAX_RECORDS, max_one_map_payload_bytes=4 * MAX_RECORDS, maximum_context_bulk_bytes=24 * MAX_RECORDS), source_sha256=self.db.sha256, database_id=self.db.database_id, original_fsd_accessed=False, witness=witness, packed_allocations=copies, raw_record_sha256=_digest(context['raw']), unknowns=['Original application algorithm has not been recovered from native machine code.', 'Quantized XYZ are approximate; exact raw records and integer values are retained.', 'CRS, units, overflow variants and other datasets are not inferred.', 'Stored pointer selects the active array; equal other arrays do not establish their lifecycle.'], files={name: dict(bytes=(destination / name).stat().st_size, sha256=file_digest(destination / name)) for name in names})
        (destination / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        return report

# Stable originals also detect overrides patched directly onto the base class.
_DEFAULT_FIELD = PackedPointReader.field
_DEFAULT_POINTER = PackedPointReader.pointer

def _address(text):
    try:
        value = tuple((int(part, 0) for part in text.split(':')))
        if len(value) != 3 or any((v < 0 for v in value)):
            raise ValueError()
        return value
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Expected nonnegative segment:cluster:offset') from exc

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fsdx')
    parser.add_argument('--owner', type=_address, required=True)
    parser.add_argument('--reference-pointset', type=_address, required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    context = dict(phase='open_store', store=args.fsdx, output=args.output,
                   address=dict(zip(('segment', 'cluster', 'offset'), args.owner)))
    try:
        from fsd_decoder.portable.facade import PortableDatabase
        with PortableDatabase(args.fsdx) as db:
            context['phase'] = 'packed_export'
            owner, reference = (db.allocation(*args.owner), db.allocation(*args.reference_pointset))
            if owner is None or reference is None:
                raise PackedPointError('Requested scalar allocation does not exist')
            if tuple((owner[k] for k in ('segment', 'cluster', 'logical_offset'))) != args.owner or tuple((reference[k] for k in ('segment', 'cluster', 'logical_offset'))) != args.reference_pointset:
                raise PackedPointError('Requested address must be an exact allocation start')
            report = PackedPointReader(db).export(owner, reference, args.output)
        print(json.dumps(dict(status=report['status'], point_count=report['point_count'], output=args.output)))
        return 0 if report['status'] == 'CORROBORATED_ALL_RECORDS' else 2
    except Exception as exc:
        detail = failure_record(exc, status='PACKED_POINTS_FAILED', context=context)
        print(json.dumps(detail), file=sys.stderr, flush=True)
        if detail['error_category'] == 'PROGRAMMING_FAILURE':
            raise
        return 1
if __name__ == '__main__':
    raise SystemExit(main())
