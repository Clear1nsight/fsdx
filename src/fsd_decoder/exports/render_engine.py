"""Standard-library-only, source-preserving dataset/frame geometry previews."""
from array import array
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import sys
from fsd_decoder.exports.fsd_render_light import _png_bytes, _publish, _raster, _axis_triad

def _key(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))

def _path(view, owner, key):
    path = Path(owner['paths'][key])
    return path if path.is_absolute() else Path(owner.get('base_directory', view.get('base_directory', '.'))) / path

def _mesh(view, owner):
    values = []
    for key, code, size, countkey in [('vertices_f64le', 'd', 24, 'vertex_count'), ('triangles_u32le', 'I', 12, 'triangle_count')]:
        raw = _path(view, owner, key).read_bytes()
        if hashlib.sha256(raw).hexdigest() != owner['hashes'][key]:
            raise ValueError('Mesh hash mismatch: ' + owner['id'])
        if type(owner[countkey]) is not int or owner[countkey] < 0 or len(raw) != owner[countkey] * size:
            raise ValueError('Mesh count mismatch')
        a = array(code)
        a.frombytes(raw)
        if sys.byteorder != 'little':
            a.byteswap()
        values.append(a)
    vertices, triangles = values
    if len(triangles) and max(triangles) >= len(vertices) // 3:
        raise ValueError('Mesh face index exceeds vertex count')
    if not all((math.isfinite(v) for v in vertices)):
        raise ValueError('Non-finite mesh vertex')
    return (vertices, triangles)

def _sequence(view, owner):
    """One bounded pass, exact decimal/raw verification, source hash on every pass."""
    hasher = hashlib.sha256()
    count = 0
    with _path(view, owner, 'coordinates_jsonl').open('rb') as stream:
        for raw in stream:
            hasher.update(raw)
            record = json.loads(raw)
            if record.get('index') != count:
                raise ValueError('Sequence indices are not consecutive')
            dimension = record['dimension']
            values = record['values']
            if type(dimension) is not int or len(values) != dimension:
                raise ValueError('Coordinate dimension mismatch')
            coordinates = []
            for value in values:
                binary = bytes.fromhex(value['raw_hex'])
                if len(binary) != 8:
                    raise ValueError('Coordinate raw value is not binary64')
                stored = struct.unpack('<d', binary)[0]
                decimal = float(value['decimal'])
                if math.isfinite(stored) and struct.pack('<d', decimal) != binary:
                    raise ValueError('Coordinate decimal differs from source bytes')
                if value.get('finite') is not None and bool(value['finite']) != math.isfinite(stored):
                    raise ValueError('Coordinate finite marker mismatch')
                coordinates.append(stored)
            yield (count, dimension, coordinates)
            count += 1
    if hasher.hexdigest() != owner['hashes']['coordinates_jsonl']:
        raise ValueError('Coordinate sequence hash mismatch: ' + owner['id'])
    if count != owner['point_count']:
        raise ValueError('Coordinate sequence count mismatch')

def _project(coordinates, origin, basis, center, scale, width, height):
    xyz = (coordinates[0], coordinates[1], coordinates[2] if len(coordinates) == 3 else 0.0)
    delta = [xyz[i] - origin[i] for i in range(3)]
    values = [sum((delta[j] * row[j] for j in range(3))) for row in basis]
    return ((values[0] - center[0]) * scale + width / 2, (values[1] - center[1]) * scale + height / 2, values[2] * scale)

def _put(point, depth, rgb, width, height, color):
    x, y, z = point
    x = math.floor(x)
    y = math.floor(y)
    if 0 <= x < width and 0 <= y < height:
        index = y * width + x
        if z >= depth[index]:
            depth[index] = z
            rgb[index * 3:index * 3 + 3] = color
            return 1
    return 0

def _segment(a, b, depth, rgb, width, height, color):
    steps = max(1, math.ceil(max(abs(a[0] - b[0]), abs(a[1] - b[1]))))
    written = 0
    for i in range(steps + 1):
        fraction = i / steps
        written += _put(tuple((a[j] + (b[j] - a[j]) * fraction for j in range(3))), depth, rgb, width, height, color)
    return written

def render_view(view, png_path, report_path, *, width=800, height=600, azimuth=-60.0, elevation=25.0):
    """Render one dataset, native coordinate frame and coordinate dimension.

    Owners have kind triangles/points/lines, id, type, coordinate_system_address,
    paths+hashes and declared counts. Meshes use vertices_f64le/triangles_u32le;
    sequences use coordinates_jsonl. Relative paths use base_directory. A mixed
    dimension sequence is explicitly partitioned by view.frame.dimension; source
    edges crossing a partition boundary are never joined.
    """
    if type(width) is not int or type(height) is not int or (not (128 <= width <= 8192 and 128 <= height <= 8192)):
        raise ValueError('Invalid image dimensions')
    if not math.isfinite(azimuth) or not math.isfinite(elevation) or (not -89.9 <= elevation <= 89.9):
        raise ValueError('Invalid camera')
    png_path = Path(png_path)
    report_path = Path(report_path)
    if png_path.absolute() == report_path.absolute():
        raise ValueError('Output paths must differ')
    for path in (png_path, report_path):
        if os.path.lexists(path):
            raise FileExistsError(str(path))
    source = view['source']
    frame = view['frame']
    dimension = frame['dimension']
    owners = view['owners']
    if dimension not in (2, 3):
        raise ValueError('Only explicitly separated 2D/3D views are supported')
    if not isinstance(source.get('sha256'), str) or len(source['sha256']) != 64 or any((c not in '0123456789abcdef' for c in source['sha256'])):
        raise ValueError('Invalid source digest')
    framekey = _key(frame.get('coordinate_system_address'))
    identifiers = set()
    lower = [math.inf] * 3
    upper = [-math.inf] * 3
    projected_lower = [math.inf] * 2
    projected_upper = [-math.inf] * 2
    az = math.radians(azimuth)
    el = math.radians(elevation)
    basis = ((-math.sin(az), math.cos(az), 0.0), (math.sin(el) * math.cos(az), math.sin(el) * math.sin(az), -math.cos(el)), (math.cos(el) * math.cos(az), math.cos(el) * math.sin(az), math.sin(el))) if dimension == 3 else ((1.0, 0.0, 0.0), (0.0, -1.0, 0.0), (0.0, 0.0, 1.0))

    def bound(values):
        xyz = (values[0], values[1], values[2] if dimension == 3 else 0.0)
        for j, value in enumerate(xyz):
            lower[j] = min(lower[j], value)
            upper[j] = max(upper[j], value)
        for j, row in enumerate(basis[:2]):
            value = sum((xyz[k] * row[k] for k in range(3)))
            projected_lower[j] = min(projected_lower[j], value)
            projected_upper[j] = max(projected_upper[j], value)
    statistics = []
    for owner in owners:
        if owner['id'] in identifiers:
            raise ValueError('Duplicate owner in one view')
        identifiers.add(owner['id'])
        if _key(owner.get('coordinate_system_address')) != framekey:
            raise ValueError('Different native coordinate frames cannot be combined')
        kind = owner['kind']
        stats = {'id': owner['id'], 'type': owner.get('type'), 'kind': kind, 'source_address': owner.get('source_address'), 'coordinate_system_address': owner.get('coordinate_system_address'), 'hashes': owner['hashes'], 'source_points': 0, 'selected_dimension_points': 0, 'excluded_other_dimension_points': 0, 'nonfinite_selected_points': 0, 'submitted_points': 0, 'submitted_segments': 0, 'submitted_triangles': 0}
        if kind == 'triangles':
            if dimension != 3:
                raise ValueError('Native triangle arrays require a 3D view')
            vertices, triangles = _mesh(view, owner)
            for i in range(0, len(vertices), 3):
                bound(vertices[i:i + 3])
            stats.update(source_points=len(vertices) // 3, selected_dimension_points=len(vertices) // 3, declared_triangles=len(triangles) // 3)
        elif kind in ('points', 'lines'):
            for index, dim, values in _sequence(view, owner):
                stats['source_points'] += 1
                if dim != dimension:
                    stats['excluded_other_dimension_points'] += 1
                    continue
                stats['selected_dimension_points'] += 1
                if not all((math.isfinite(v) for v in values)):
                    stats['nonfinite_selected_points'] += 1
                    continue
                bound(values)
        else:
            raise ValueError('Unsupported render owner kind: ' + str(kind))
        statistics.append(stats)
    populated = math.isfinite(lower[0])
    if populated:
        origin = [lower[i] + (upper[i] - lower[i]) / 2 for i in range(3)]
        origin_projection = [sum((origin[k] * basis[j][k] for k in range(3))) for j in range(2)]
        center = [projected_lower[i] + (projected_upper[i] - projected_lower[i]) / 2 - origin_projection[i] for i in range(2)]
        spans = [projected_upper[i] - projected_lower[i] for i in range(2)]
        if not all((math.isfinite(v) for v in spans)):
            raise ValueError('Projected extent overflow')
        scales = [(size - 64) / span for size, span in zip((width, height), spans) if span > 0]
        scale = min(scales) if scales else 1.0
    else:
        origin = [0.0, 0.0, 0.0]
        center = [0.0, 0.0]
        scale = 1.0
    depth = array('d', [-math.inf]) * (width * height)
    rgb = bytearray(b'\xf7\xf7\xf7') * (width * height)
    for owner, stats in zip(owners, statistics):
        if owner['kind'] == 'triangles':
            vertices, triangles = _mesh(view, owner)
            points = array('d')
            for i in range(0, len(vertices), 3):
                points.extend(_project(vertices[i:i + 3], origin, basis, center, scale, width, height))
            degenerate, candidates = _raster(points, triangles, depth, rgb, width, height)
            stats.update(submitted_triangles=len(triangles) // 3, edge_on_or_degenerate_triangles=degenerate)
        else:
            previous = None
            for index, dim, values in _sequence(view, owner):
                if dim != dimension or not all((math.isfinite(v) for v in values)):
                    previous = None
                    continue
                point = _project(values, origin, basis, center, scale, width, height)
                if owner['kind'] == 'points':
                    _put(point, depth, rgb, width, height, b'7iP')
                    stats['submitted_points'] += 1
                else:
                    if previous is not None:
                        _segment(previous, point, depth, rgb, width, height, b'\xb0`(')
                        stats['submitted_segments'] += 1
                    previous = point
    covered = sum((math.isfinite(v) for v in depth))
    _axis_triad(rgb, width, height, basis)
    dataset = view.get('dataset', {})
    note = 'All geometry retains source coordinates; separated or small features may be subpixel or occluded'
    report = {'format': 'fsd-dataset-render-v1', 'source': {k: source.get(k) for k in ('sha256', 'database_id')}, 'dataset': dataset, 'frame': frame, 'status': 'RENDERED', 'owners': statistics, 'owner_count': len(owners), 'complete_for_finite_selected_dimension': True, 'nonfinite_selected_points': sum((s['nonfinite_selected_points'] for s in statistics)), 'image': {'width': width, 'height': height, 'covered_pixels': covered}, 'camera': {'projection': 'orthographic', 'dimension': dimension, 'origin_source_xyz': origin, 'basis_rows': basis, 'projected_center': center, 'pixels_per_source_unit': scale, 'fit_policy': 'All source vertices/points in this explicitly selected dataset/frame/dimension', 'azimuth_degrees': azimuth if dimension == 3 else None, 'elevation_degrees': elevation if dimension == 3 else None}, 'source_bounds': {'min': lower[:dimension], 'max': upper[:dimension]} if populated else None, 'display': {'note': note, 'native_colors_used': False, 'colors': {'triangles': 'blue-grey flat shading', 'points': 'green', 'lines': 'orange'}, 'no_coordinate_transforms': True, 'no_geometry_sampling': True, 'no_added_ring_closure': True, 'two_dimensional_coordinates': 'source XY orthographic projection; no Z value written to source data'}, 'dependencies': {'third_party_packages': []}}
    png = _png_bytes(rgb, width, height, {'Title': str(dataset.get('name', dataset.get('id', 'FSD dataset'))), 'SourceSHA256': source['sha256'], 'CoordinatePolicy': note})
    report['image']['sha256'] = hashlib.sha256(png).hexdigest()
    _publish(png, report, png_path, report_path)
    return report
