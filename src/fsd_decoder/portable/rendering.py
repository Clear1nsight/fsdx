"""Dataset previews derived solely from one opened portable encoded store.

Temporary source-exact arrays are private to the output transaction and removed
before publication. Original FSDs and prior export directories are never opened.
"""
from collections import Counter, defaultdict
from dataclasses import asdict, is_dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
from fsd_decoder.exports.extra_geometry import ExtraGeometry
from fsd_decoder.exports.render_engine import render_view
from fsd_decoder.portable.exports import PortableMeshReader

def _address(value):
    return asdict(value) if is_dataclass(value) else dict(value) if value is not None else None

def _digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()

def _json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')

def _catalog(db, progress):
    from fsd_decoder.exports.catalog import build_portable_catalog
    return build_portable_catalog(db, progress=progress)

def _shape_address(db, geometry):
    address = geometry['address']
    if address.get('database', db.database_id) != db.database_id:
        raise ValueError('Geometry belongs to another database')
    return db.address(address['segment'], address['cluster'], address['offset'])

def _write_sequence(extra, geometry, path, progress=None):
    address, allocation, definition = extra.owner(geometry['address'])
    count = extra.uint(address, definition, 'm_numPoints')
    target = extra.pointer(address, definition, 'm_ppPointArray')
    extra.array(target, '4 byte void*[]', count, 4)
    dimensions = Counter()
    count_written = 0
    with path.open('x', encoding='utf-8') as stream:
        for index in range(count):
            slot = extra.db.address(target.segment, target.cluster, target.offset + 4 * index)
            coordinate = extra.coordinate(extra.db.resolve(slot))
            dimensions[coordinate['dimension']] += 1
            stream.write(json.dumps(dict(index=index, **coordinate), allow_nan=False) + '\n')
            count_written += 1
            if progress and count_written % 4096 == 0:
                progress({'phase': 'materialize_geometry', 'geometry_id': geometry['id'], 'checked_points': count_written, 'declared_points': count})
    if count_written != count:
        raise ValueError('Sequence count mismatch')
    return {'point_count': count, 'dimensions': dict(dimensions), 'paths': {'coordinates_jsonl': str(path)}, 'hashes': {'coordinates_jsonl': _digest(path)}}

def _write_mesh(db, reader, geometry, directory, progress=None):
    address = _shape_address(db, geometry)
    layout = reader.surface_members
    nv = reader.uint(address, layout, 'm_numVertex')
    nt = reader.uint(address, layout, 'm_numTri')
    vertices = reader.pointer(address, layout, 'm_ppVertexArray')
    faces = reader.pointer(address, layout, 'm_pTriVertexIndexArray')
    frame = reader.pointer(address, layout, 'm_pCoordinateSystem')
    if _address(frame) != geometry.get('coordinate_system_address'):
        raise ValueError('Catalog and mesh coordinate frames disagree')
    reader.array(vertices, 'pointer', nv)
    reader.array(faces, 'uint32', nt * 3)
    paths = {'vertices_f64le': directory / (geometry['id'] + '.xyz.f64le'), 'triangles_u32le': directory / (geometry['id'] + '.triangles.u32le')}
    checked_vertices = checked_faces = 0
    with paths['vertices_f64le'].open('xb') as stream:
        for index, xyz, raw, point, values in reader.vertices(vertices, nv):
            if index != checked_vertices:
                raise ValueError('Mesh vertices are out of source order')
            stream.write(raw)
            checked_vertices += 1
            if progress and checked_vertices % 4096 == 0:
                progress({'phase': 'materialize_geometry', 'geometry_id': geometry['id'], 'checked_vertices': checked_vertices, 'declared_vertices': nv})
    with paths['triangles_u32le'].open('xb') as stream:
        for start in range(0, nt, 4096):
            count = min(4096, nt - start)
            at = db.address(faces.segment, faces.cluster, faces.offset + start * 12)
            raw = db.read(at, count * 12)
            for triple in struct.iter_unpack('<III', raw):
                if max(triple) >= nv:
                    raise ValueError('Triangle index exceeds vertex count')
                checked_faces += 1
            stream.write(raw)
    if checked_vertices != nv or checked_faces != nt:
        raise ValueError('Mesh array count mismatch')
    return {'vertex_count': checked_vertices, 'triangle_count': checked_faces, 'dimensions': {3: checked_vertices}, 'paths': {key: str(path) for key, path in paths.items()}, 'hashes': {key: _digest(path) for key, path in paths.items()}}

def _datasets(catalog, selected):
    geometries = catalog['geometries']
    result = []
    owned_by_entity = defaultdict(list)
    for geometry in geometries.values():
        for entity_id in set(geometry.get('owner_entity_ids', [])):
            owned_by_entity[entity_id].append(geometry)
    for entity in catalog['entities']:
        owned = owned_by_entity[entity['id']]
        result.append((dict(id=entity['id'], name=entity.get('name'), type=entity.get('type'), group_paths=entity.get('group_paths', []), shape_id=entity.get('shape_id'), shape_address=entity.get('shape_address'), assignment='NAMED_ENTITY'), owned, entity.get('attributes', [])))
    for geometry in geometries.values():
        if not geometry.get('owner_entity_ids'):
            result.append((dict(id='unassigned:' + geometry['id'], name='Unassigned geometry ' + geometry['id'], assignment='UNASSIGNED_ALLOCATED_SHAPE'), [geometry], []))
    if selected is not None:
        wanted = set(selected)
        available = {d['id'] for d, _, _ in result}
        if wanted - available:
            raise ValueError('Unknown dataset IDs: ' + ', '.join(sorted(wanted - available)))
        result = [row for row in result if row[0]['id'] in wanted]
    return result

def render_datasets(db, new_directory, *, dataset_ids=None, width=800, height=600, azimuth=-60, elevation=25, progress=None):
    """Atomically publish portable-store-only dataset/frame PNGs and reports.

    Every allocated Shape remains in catalog.json. Unsupported shapes and missing
    proven image/grid value owners are explicit diagnostics, not fabricated views.
    """
    dataset_ids = tuple(dataset_ids) if dataset_ids is not None else None
    output = Path(new_directory).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.fsdx-renders-', dir=output.parent))
    reserved = False
    extra = None
    source = {'sha256': db.sha256, 'database_id': db.database_id, 'access': 'PORTABLE_STORE_ONLY', 'original_fsd_required': False}
    try:
        catalog = _catalog(db, progress)
        datasets = _datasets(catalog, dataset_ids)
        _json(staging / 'catalog.json', catalog)
        report = {'format': 'FSDX_DATASET_RENDERS', 'format_version': 1, 'source': source, 'catalog_path': 'catalog.json', 'datasets': [], 'diagnostics': [], 'selection': list(dataset_ids) if dataset_ids is not None else None, 'policy': {'coordinate_transforms_applied': False, 'coordinate_frames_separate': True, 'dimensions_separate': True, 'original_fsd_required': False, 'previous_exports_required': False, 'temporary_geometry_published': False}}
        extra = ExtraGeometry(db=db, fields=db.fields, allocation_lookup=lambda a: db.allocation(a.segment, a.cluster, a.offset))
        mesh_reader = None
        for number, (dataset, geometries, attributes) in enumerate(datasets, 1):
            directory = staging / f'dataset_{number:06d}'
            directory.mkdir()
            result = {'dataset': dataset, 'geometry_ids': [g['id'] for g in geometries], 'views': [], 'diagnostics': [], 'containers': [], 'unsupported_geometry_ids': []}
            if progress:
                progress({'phase': 'render_dataset', 'dataset_index': number, 'dataset_count': len(datasets), 'dataset_id': dataset['id']})
            with tempfile.TemporaryDirectory(prefix='.geometry-', dir=staging) as temporary:
                temp = Path(temporary)
                groups = defaultdict(list)
                frames = {}
                for geometry in geometries:
                    gid = geometry['id']
                    category = geometry.get('render_class')
                    cs = geometry.get('coordinate_system_address')
                    try:
                        if str(geometry.get('status', '')).startswith('UNSUPPORTED'):
                            raise ValueError(geometry['status'])
                        if category in ('collection', 'polygon_boundaries'):
                            result['containers'].append({'id': gid, 'child_ids': geometry.get('child_ids', []), 'status': geometry.get('status')})
                            continue
                        if category in ('triangles', 'points', 'lines'):
                            if category == 'triangles':
                                if mesh_reader is None:
                                    mesh_reader = PortableMeshReader(db)
                                details = _write_mesh(db, mesh_reader, geometry, temp, progress)
                            else:
                                shape = extra.shape_metadata(geometry['address'], {'coordinate_system_address': cs})
                                if shape.get('coordinate_system_address') != cs:
                                    raise ValueError('Catalog and sequence coordinate frames disagree')
                                details = _write_sequence(extra, geometry, temp / (gid + '.coordinates.jsonl'), progress)
                            owner = dict(id=gid, type=geometry['type'], kind=category, source_address=geometry['address'], coordinate_system_address=cs, **details)
                            if not details['dimensions']:
                                result['diagnostics'].append({'geometry_id': gid, 'status': 'EMPTY_GEOMETRY', 'error': 'No source coordinate dimensions to render'})
                                continue
                            for dimension, count in details['dimensions'].items():
                                if dimension not in (2, 3):
                                    result['diagnostics'].append({'geometry_id': gid, 'status': 'UNSUPPORTED_COORDINATE_DIMENSION', 'dimension': dimension, 'point_count': count})
                                    continue
                                frame_key = (json.dumps(cs, sort_keys=True) if cs else 'unknown:' + gid, dimension)
                                groups[frame_key].append(owner)
                                frames[frame_key] = {'coordinate_system_address': cs, 'coordinate_system_id': geometry.get('coordinate_system_id'), 'dimension': dimension, 'coordinate_transform_applied': False}
                        elif category in ('image_plane', 'grid2', 'grid3'):
                            if dataset.get('shape_id') != gid:
                                raise ValueError('Entity attribute does not prove value pairing to this non-root image/grid shape')
                            accepted = {'image_plane': {'Fs::ImageData'}, 'grid2': {'Fs::Grid2ScalarData'}, 'grid3': {'Fs::Grid3ScalarData'}}[category]
                            matches = []
                            seen = set()
                            for attribute in attributes:
                                address = attribute.get('value_address')
                                key = json.dumps(address, sort_keys=True)
                                if attribute.get('value_type') in accepted and address and (key not in seen):
                                    matches.append(attribute)
                                    seen.add(key)
                            if not matches:
                                raise ValueError('No exact owning entity attribute proves the required image/grid value object')
                            for index, attribute in enumerate(matches):
                                stem = f'{gid}_value_{index:03d}'
                                context = {'dataset': dataset, 'geometry_id': gid, 'attribute': attribute, 'coordinate_system_address': cs}
                                if category == 'image_plane':
                                    info = extra.render_image(geometry['address'], attribute['value_address'], directory / (stem + '.png'), directory / (stem + '.json'), context=context)
                                    result['views'].append({'kind': 'source_rgba_image', 'geometry_ids': [gid], 'path': f'{directory.name}/{stem}.png', 'report_path': f'{directory.name}/{stem}.json', 'pixel_count': info['pixel_count']})
                                else:
                                    info = extra.render_grid(geometry['address'], attribute['value_address'], directory / stem, context=context)
                                    result['views'].append({'kind': 'stored_grid_scalar_layers', 'geometry_ids': [gid], 'directory': f'{directory.name}/{stem}', 'report': info})
                        else:
                            raise ValueError('No verified adapter for Shape type ' + geometry['type'])
                    except (ValueError, KeyError, IndexError) as exc:
                        result['unsupported_geometry_ids'].append(gid)
                        result['diagnostics'].append({'geometry_id': gid, 'type': geometry.get('type'), 'status': 'UNSUPPORTED', 'error': str(exc)})
                for view_index, (key, owners) in enumerate(groups.items(), 1):
                    stem = f'frame_{view_index:04d}'
                    view = {'source': source, 'dataset': dataset, 'frame': frames[key], 'owners': owners}
                    try:
                        rendered = render_view(view, directory / (stem + '.png'), directory / (stem + '.json'), width=width, height=height, azimuth=azimuth, elevation=elevation)
                        if rendered['nonfinite_selected_points']:
                            result['diagnostics'].append({'geometry_ids': [o['id'] for o in owners], 'status': 'NONFINITE_COORDINATES', 'point_count': rendered['nonfinite_selected_points']})
                        result['views'].append({'kind': 'geometry', 'geometry_ids': [o['id'] for o in owners], 'frame': frames[key], 'path': f'{directory.name}/{stem}.png', 'report_path': f'{directory.name}/{stem}.json', 'covered_pixels': rendered['image']['covered_pixels'], 'submitted_points': sum((o['submitted_points'] for o in rendered['owners'])), 'submitted_segments': sum((o['submitted_segments'] for o in rendered['owners'])), 'submitted_triangles': sum((o['submitted_triangles'] for o in rendered['owners']))})
                    except (ValueError, KeyError, IndexError) as exc:
                        result['unsupported_geometry_ids'].extend((o['id'] for o in owners))
                        result['diagnostics'].append({'geometry_ids': [o['id'] for o in owners], 'status': 'RENDER_FAILED', 'error': str(exc)})
            result['status'] = 'PARTIAL' if result['diagnostics'] else 'RENDERED' if result['views'] else 'NO_RENDERABLE_GEOMETRY'
            _json(directory / 'dataset.json', result)
            report['datasets'].append(result)
            if progress:
                progress({'phase': 'dataset_complete', 'dataset_index': number, 'dataset_count': len(datasets), 'dataset_id': dataset['id'], 'views': len(result['views']), 'diagnostics': len(result['diagnostics'])})
        db.verify_source()
        report.update(dataset_count=len(report['datasets']), view_count=sum((len(r['views']) for r in report['datasets'])), store_verified=False, integrity_scope='QUICK_CHECKED', full_store_verification_performed=False, original_source_reopened=False, complete=bool(catalog.get('complete')) and all((not r['diagnostics'] for r in report['datasets'])))
        report['diagnostics'] = catalog.get('diagnostics', [])
        report['files'] = {str(path.relative_to(staging)): {'sha256': _digest(path), 'bytes': path.stat().st_size} for path in sorted(staging.rglob('*')) if path.is_file()}
        _json(staging / 'manifest.json', report)
        output.mkdir()
        reserved = True
        os.replace(staging, output)
        reserved = False
        return output / 'manifest.json'
    finally:
        if extra is not None:
            extra.close()
        if staging.exists():
            shutil.rmtree(staging)
        if reserved:
            output.rmdir()
