"""Portable CPU rendering of FSD mesh exports, using only Python's standard library.

Every source triangle is submitted to an orthographic z-buffer. The one global
camera fits every source vertex. No geometry simplification or fitting heuristic.
"""
from __future__ import annotations
from array import array
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import struct
import sys
import tempfile
import zlib

def _sha(data):
    return hashlib.sha256(data).hexdigest()

def _identity(address):
    return isinstance(address, dict) and isinstance(address.get('database'), str) and bool(address['database']) and all((type(address.get(k)) is int and address[k] >= 0 for k in ('segment', 'cluster', 'offset')))

def _load_manifest(path):
    raw = path.read_bytes()
    manifest = json.loads(raw)
    if manifest.get('complete') is not True or manifest.get('unsupported'):
        raise ValueError('mesh manifest must be complete with no unsupported surfaces')
    source = manifest.get('source')
    if not isinstance(source, dict) or not isinstance(source.get('sha256'), str) or (not re.fullmatch('[0-9a-f]{64}', source['sha256'])):
        raise ValueError('mesh manifest must declare source SHA-256 identity')
    meshes = []
    identifiers = set()
    for entry in manifest['meshes']:
        ident = entry['id']
        address = entry.get('source_address')
        if not isinstance(ident, str) or not ident or ident in identifiers:
            raise ValueError('mesh identifiers must be unique nonempty strings')
        identifiers.add(ident)
        if not _identity(address):
            raise ValueError('invalid logical mesh source address')
        if source.get('database_id') is not None and source['database_id'] != address['database']:
            raise ValueError('mesh source address database differs from manifest source')
        arrays = {}
        for key, code, record_size, count_key in [('vertices_f64le', 'd', 24, 'vertex_count'), ('triangles_u32le', 'I', 12, 'triangle_count')]:
            count = entry[count_key]
            if type(count) is not int or count < 0:
                raise ValueError('mesh counts must be nonnegative integers')
            file = Path(entry['paths'][key])
            file = file if file.is_absolute() else path.parent / file
            data = file.read_bytes()
            if _sha(data) != entry['hashes'][key]:
                raise ValueError(f'exported mesh hash mismatch: {file}')
            if len(data) != record_size * count:
                raise ValueError(f'exported mesh length differs from declared {count_key}')
            values = array(code)
            if values.itemsize != (8 if code == 'd' else 4):
                raise RuntimeError('This Python platform does not provide 64-bit doubles and 32-bit unsigned array integers')
            values.frombytes(data)
            if sys.byteorder != 'little':
                values.byteswap()
            arrays[key] = values
        vertices = arrays['vertices_f64le']
        triangles = arrays['triangles_u32le']
        if not vertices or not all((math.isfinite(v) for v in vertices)):
            raise ValueError('vertices must be nonempty and finite')
        if triangles and max(triangles) >= entry['vertex_count']:
            raise ValueError('triangle index exceeds vertex count')
        meshes.append((entry, vertices, triangles))
    for key, value in [('mesh_count', len(meshes)), ('vertex_count', sum((e['vertex_count'] for e, _, _ in meshes))), ('triangle_count', sum((e['triangle_count'] for e, _, _ in meshes)))]:
        if key in manifest and manifest[key] != value:
            raise ValueError(f'mesh manifest aggregate {key} is inconsistent')
    if not meshes or not sum((len(t) for _, _, t in meshes)):
        raise ValueError('at least one triangle is required')
    return (manifest, meshes, _sha(raw))

def _raster(points, triangles, depth, rgb, width, height):
    """Opaque double-sided flat shading and barycentric depth, all faces visited."""
    degenerate = 0
    covered_candidates = 0
    for n in range(0, len(triangles), 3):
        ai = triangles[n] * 3
        bi = triangles[n + 1] * 3
        ci = triangles[n + 2] * 3
        ax, ay, az = (points[ai], points[ai + 1], points[ai + 2])
        bx, by, bz = (points[bi], points[bi + 1], points[bi + 2])
        cx, cy, cz = (points[ci], points[ci + 1], points[ci + 2])
        denominator = (by - cy) * (ax - cx) + (cx - bx) * (ay - cy)
        if abs(denominator) < 1e-14:
            degenerate += 1
            continue
        xmin = max(0, math.ceil(min(ax, bx, cx) - 0.5))
        xmax = min(width - 1, math.floor(max(ax, bx, cx) - 0.5))
        ymin = max(0, math.ceil(min(ay, by, cy) - 0.5))
        ymax = min(height - 1, math.floor(max(ay, by, cy) - 0.5))
        if xmin > xmax or ymin > ymax:
            continue
        ux, uy, uz = (bx - ax, by - ay, bz - az)
        vx, vy, vz = (cx - ax, cy - ay, cz - az)
        nx, ny, nz = (uy * vz - uz * vy, uz * vx - ux * vz, ux * vy - uy * vx)
        norm = math.sqrt(nx * nx + ny * ny + nz * nz)
        shade = 0.3 + 0.7 * abs((-0.3 * nx - 0.4 * ny + 0.8660254037844386 * nz) / norm)
        color = bytes((int(105 * shade), int(151 * shade), int(173 * shade)))
        inverse = 1.0 / denominator
        wxa = (by - cy) * inverse
        wya = (cx - bx) * inverse
        wxb = (cy - ay) * inverse
        wyb = (ax - cx) * inverse
        for y in range(ymin, ymax + 1):
            dy = y + 0.5 - cy
            dx = xmin + 0.5 - cx
            wa = wxa * dx + wya * dy
            wb = wxb * dx + wyb * dy
            pixel = y * width + xmin
            for _x in range(xmin, xmax + 1):
                wc = 1.0 - wa - wb
                if wa >= -1e-12 and wb >= -1e-12 and (wc >= -1e-12):
                    z = wa * az + wb * bz + wc * cz
                    if z > depth[pixel]:
                        depth[pixel] = z
                        index = pixel * 3
                        rgb[index:index + 3] = color
                wa += wxa
                wb += wxb
                pixel += 1
        covered_candidates += 1
    return (degenerate, covered_candidates)

def _line(rgb, width, height, x0, y0, x1, y1):
    steps = max(abs(x1 - x0), abs(y1 - y0), 1)
    for i in range(steps + 1):
        x = round(x0 + (x1 - x0) * i / steps)
        y = round(y0 + (y1 - y0) * i / steps)
        if 0 <= x < width and 0 <= y < height:
            k = (y * width + x) * 3
            rgb[k:k + 3] = b'\x1e(-'

def _axis_triad(rgb, width, height, basis):
    glyphs = {'X': ['101', '101', '010', '101', '101'], 'Y': ['101', '101', '010', '010', '010'], 'Z': ['111', '001', '010', '100', '111']}
    x0, y0 = (width - 54, height - 50)
    for axis, label in enumerate('XYZ'):
        x1 = round(x0 + 28 * basis[0][axis])
        y1 = round(y0 + 28 * basis[1][axis])
        _line(rgb, width, height, x0, y0, x1, y1)
        for row, line in enumerate(glyphs[label]):
            for col, value in enumerate(line):
                x = x1 + 4 + col
                y = y1 + 3 + row
                if value == '1' and 0 <= x < width and (0 <= y < height):
                    k = (y * width + x) * 3
                    rgb[k:k + 3] = b'\x1e(-'

def _png_bytes(rgb, width, height, text):

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 4294967295)
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        rows.extend(rgb[y * width * 3:(y + 1) * width * 3])
    result = bytearray(b'\x89PNG\r\n\x1a\n')
    result.extend(chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)))
    for key, value in sorted(text.items()):
        result.extend(chunk(b'tEXt', key.encode('latin-1') + b'\x00' + value.encode('latin-1', 'replace')))
    result.extend(chunk(b'IDAT', zlib.compress(rows, 6)))
    result.extend(chunk(b'IEND', b''))
    return bytes(result)

def _publish(png, report, png_path, report_path):
    staged = []
    published = []
    try:
        payloads = (png, (json.dumps(report, indent=2, allow_nan=False) + '\n').encode('utf-8'))
        for target, data in zip((png_path, report_path), payloads):
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.fsd-render-light-', delete=False) as handle:
                staged.append(Path(handle.name))
                handle.write(data)
        for temporary, target in zip(staged, (png_path, report_path)):
            os.link(temporary, target)
            published.append(target)
    except BaseException:
        for path in published:
            path.unlink()
        raise
    finally:
        for path in staged:
            path.unlink(missing_ok=True)

def export_render(mesh_manifest, png_path, render_json, *, width=800, height=600, azimuth=-60.0, elevation=25.0):
    """Verify a complete mesh manifest and write a new PNG plus provenance JSON."""
    if type(width) is not int or type(height) is not int or (not (128 <= width <= 8192 and 128 <= height <= 8192)):
        raise ValueError('image dimensions must be integers between 128 and 8192')
    if not math.isfinite(azimuth) or not math.isfinite(elevation) or (not -89.9 <= elevation <= 89.9):
        raise ValueError('invalid camera angles')
    png_path = Path(png_path)
    report_path = Path(render_json)
    if png_path.suffix.lower() != '.png' or png_path.absolute() == report_path.absolute():
        raise ValueError('distinct PNG and JSON output paths are required')
    for path in (png_path, report_path):
        if os.path.lexists(path):
            raise FileExistsError(str(path))
    manifest, meshes, manifest_hash = _load_manifest(Path(mesh_manifest))
    lower = [math.inf] * 3
    upper = [-math.inf] * 3
    for _, vertices, _ in meshes:
        for i, value in enumerate(vertices):
            axis = i % 3
            if value < lower[axis]:
                lower[axis] = value
            if value > upper[axis]:
                upper[axis] = value
    origin = [lo + (hi - lo) / 2 for lo, hi in zip(lower, upper)]
    az = math.radians(azimuth)
    el = math.radians(elevation)
    right = (-math.sin(az), math.cos(az), 0.0)
    down = (math.sin(el) * math.cos(az), math.sin(el) * math.sin(az), -math.cos(el))
    toward = (math.cos(el) * math.cos(az), math.cos(el) * math.sin(az), math.sin(el))
    basis = (right, down, toward)
    projected = []
    plower = [math.inf] * 2
    pupper = [-math.inf] * 2
    for _, vertices, _ in meshes:
        points = array('d')
        for i in range(0, len(vertices), 3):
            x, y, z = (vertices[i] - origin[0], vertices[i + 1] - origin[1], vertices[i + 2] - origin[2])
            for axis, vector in enumerate(basis):
                value = x * vector[0] + y * vector[1] + z * vector[2]
                if not math.isfinite(value):
                    raise ValueError('projected coordinate overflow')
                points.append(value)
                if axis < 2:
                    if value < plower[axis]:
                        plower[axis] = value
                    if value > pupper[axis]:
                        pupper[axis] = value
        projected.append(points)
    spans = [pupper[i] - plower[i] for i in range(2)]
    if not any((v > 0 for v in spans)) or not all((math.isfinite(v) for v in spans)):
        raise ValueError('mesh has no finite projected extent')
    margin = 32
    available = (width - 2 * margin, height - 2 * margin)
    scale = min((available[i] / spans[i] for i in range(2) if spans[i] > 0))
    center = [(plower[i] + pupper[i]) / 2 for i in range(2)]
    depth = array('d', [-math.inf]) * (width * height)
    rgb = bytearray(b'\xf7\xf7\xf7') * (width * height)
    records = []
    for (entry, vertices, triangles), points in zip(meshes, projected):
        for i in range(0, len(points), 3):
            points[i] = (points[i] - center[0]) * scale + width / 2
            points[i + 1] = (points[i + 1] - center[1]) * scale + height / 2
            points[i + 2] *= scale
        degenerate, pixel_candidates = _raster(points, triangles, depth, rgb, width, height)
        records.append({'id': entry['id'], 'source_address': entry['source_address'], 'coordinate_system_address': entry.get('coordinate_system_address'), 'vertex_count': entry['vertex_count'], 'triangle_count': entry['triangle_count'], 'submitted_triangle_count': len(triangles) // 3, 'vertices_f64le_sha256': entry['hashes']['vertices_f64le'], 'triangles_u32le_sha256': entry['hashes']['triangles_u32le'], 'edge_on_or_degenerate_triangle_count': degenerate, 'triangles_with_pixel_center_in_bounding_box': pixel_candidates})
    covered = sum((math.isfinite(value) for value in depth))
    _axis_triad(rgb, width, height, basis)
    source = dict(manifest['source'])
    note = 'Features may be subpixel due to global separation' if not covered else 'Global source positions retained; some features may be subpixel or occluded'
    png = _png_bytes(rgb, width, height, {'Title': 'Decoded FSD geometry', 'SourceSHA256': source['sha256'], 'CoordinatePolicy': 'Source XYZ; units and CRS unverified; global all-vertex fit', 'DisplayNote': note})
    report = {'format': 'fsd-static-render-v1', 'status': 'RENDERED_DECODED_GEOMETRY', 'source': source, 'mesh_manifest_sha256': manifest_hash, 'image': {'width': width, 'height': height, 'covered_pixels': covered, 'sha256': _sha(png)}, 'camera': {'projection': 'orthographic', 'azimuth_degrees': azimuth, 'elevation_degrees': elevation, 'origin_source_xyz': origin, 'basis_rows_right_down_toward_camera': basis, 'pixels_per_source_unit': scale, 'projected_center': center, 'fit_policy': 'Global bounds of all source vertices, including vertices unreferenced by triangles', 'fit_bounds_source_xyz': {'min': lower, 'max': upper}}, 'source_bounds': {'min': lower, 'max': upper}, 'meshes': records, 'display': {'coordinate_label': 'Source XYZ; units and CRS unverified', 'display_note': note, 'material': 'uniform display-only blue grey', 'shading': 'two-sided flat Lambert from source triangles', 'geometry_simplification': False, 'axis_permutation': False, 'depth': 'per-pixel barycentric z-buffer'}, 'dependencies': {'python': platform.python_version(), 'zlib': zlib.ZLIB_VERSION, 'third_party_packages': []}, 'renderer': 'python-standard-library-cpu'}
    _publish(png, report, png_path, report_path)
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--width', type=int, default=800)
    parser.add_argument('--height', type=int, default=600)
    parser.add_argument('--azimuth', type=float, default=-60)
    parser.add_argument('--elevation', type=float, default=25)
    args = parser.parse_args()
    result = export_render(args.manifest, args.output, args.report or args.output.with_suffix('.json'), width=args.width, height=args.height, azimuth=args.azimuth, elevation=args.elevation)
    print(json.dumps({'output': str(args.output), 'sha256': result['image']['sha256'], 'meshes': len(result['meshes'])}))
if __name__ == '__main__':
    main()
