"""Guarded source-independent integration validation of a real portable store.

Original FSD and historical exports are used ONLY to prepare comparison values.
Stage two executes under guards rejecting those inputs and native constructors.
This validator never moves, renames or deletes the original FSD.
"""
from __future__ import annotations
import argparse
import builtins
from contextlib import contextmanager, ExitStack
import csv
from dataclasses import asdict, is_dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
from unittest.mock import patch
HERE = Path(__file__).resolve().parent
DECODER = HERE.parent

def plain(value):
    if is_dataclass(value):
        return plain(asdict(value))
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()

def canonical(value):
    return json.dumps(plain(value), sort_keys=True, separators=(',', ':'), allow_nan=False)

def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(plain(value), stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')

@contextmanager
def source_independence_guard():
    """Deny source/old-export reads and every source-dependent constructor."""
    from fsd_decoder.native.native_database import NativeDatabase
    from fsd_decoder.native.native_allocations import NativeAllocationReader
    from fsd_decoder.schema.native_fields import NativeFields
    from fsd_decoder.schema.schema_members import MemberSchema
    stats = {'file_attempts': [], 'constructor_attempts': [], 'allowed_file_calls': 0}

    def check(file):
        if isinstance(file, int):
            return
        try:
            path = Path(os.fsdecode(file)).absolute()
        except (TypeError, ValueError):
            return
        resolved = path.resolve()
        if any((p.suffix.lower() == '.fsd' or 'FSD_Exports' in p.parts for p in (path, resolved))):
            stats['file_attempts'].append(str(path))
            raise RuntimeError('Forbidden source or historical export access: ' + str(path))
        stats['allowed_file_calls'] += 1
    original_open = builtins.open
    original_io = io.open
    original_bytes = Path.read_bytes
    original_text = Path.read_text

    def guarded_open(file, *args, **kwargs):
        check(file)
        return original_open(file, *args, **kwargs)

    def guarded_io(file, *args, **kwargs):
        check(file)
        return original_io(file, *args, **kwargs)

    def guarded_bytes(path, *args, **kwargs):
        check(path)
        return original_bytes(path, *args, **kwargs)

    def guarded_text(path, *args, **kwargs):
        check(path)
        return original_text(path, *args, **kwargs)

    def forbidden(name):

        def fail(*args, **kwargs):
            stats['constructor_attempts'].append(name)
            raise AssertionError('Source-dependent constructor invoked: ' + name)
        return fail
    with ExitStack() as stack:
        for target, replacement in [('builtins.open', guarded_open), ('io.open', guarded_io)]:
            stack.enter_context(patch(target, replacement))
        stack.enter_context(patch.object(Path, 'read_bytes', guarded_bytes))
        stack.enter_context(patch.object(Path, 'read_text', guarded_text))
        for owner, name in [(NativeDatabase, '__init__'), (NativeDatabase, 'from_path'), (NativeAllocationReader, '__init__'), (NativeFields, '__init__'), (MemberSchema, '__init__')]:
            stack.enter_context(patch.object(owner, name, forbidden(owner.__name__ + '.' + name)))
        yield stats

def prepare_expected(source, bundle, catalog_path):
    from fsd_decoder.native.native_database import NativeDatabase
    from fsd_decoder.native.native_allocations import NativeAllocationReader
    from fsd_decoder.schema.native_fields import NativeFields
    db = NativeDatabase.from_path(source)
    fields = NativeFields(db)
    schema = plain(fields.schema_report())
    roots = plain(db.roots())
    root_targets = {tuple(r['value_target']) for r in roots['roots'] if r.get('value_target')}
    selected = []
    types = set()
    count = 0
    for allocation in NativeAllocationReader(db, fields.types).iter_allocations():
        count += 1
        token = (allocation['segment'], allocation['cluster'], allocation['logical_offset'])
        choose = token in root_targets or allocation['name'] == 'Fs::Spatial::Geom::TriSurface'
        if not allocation['vector'] and allocation['size'] <= 4096 and allocation['name'].startswith('Fs::') and (allocation['name'] not in types) and (len(types) < 12):
            types.add(allocation['name'])
            choose = True
        if choose:
            if allocation['vector']:
                raise ValueError('Regression selection unexpectedly includes a vector')
            selected.append(dict(address=token, value=plain(fields.decode(allocation))))
    mesh_path = Path(bundle) / 'meshes/manifest.json'
    mesh = json.loads(mesh_path.read_text())
    if mesh['source']['sha256'] != db.sha256:
        raise ValueError('Historical mesh source differs')
    for entry in mesh['meshes']:
        for key in ('vertices_f64le', 'triangles_u32le'):
            if sha(mesh_path.parent / entry['paths'][key]) != entry['hashes'][key]:
                raise ValueError('Historical packed array hash differs')
    catalog = json.loads(Path(catalog_path).read_text())
    db.verify_source()
    return dict(source_path=str(Path(source).resolve()), source_sha256=db.sha256, database_id=db.database_id, allocation_count=count, schema=schema, roots=roots, selected=selected, mesh=mesh, catalog=catalog, baseline_files={str(mesh_path.resolve()): sha(mesh_path), str(Path(catalog_path).resolve()): sha(catalog_path)})

def compare_catalog(observed, expected):
    entity_keys = ('id', 'name', 'address', 'type', 'group_paths', 'navigation_item_ids', 'shape_address', 'shape_id', 'attributes')
    geometry_keys = ('id', 'address', 'type', 'coordinate_system_id', 'coordinate_system_address', 'owner_entity_ids', 'child_ids', 'render_class')
    for rows, keys in [('entities', entity_keys), ('geometries', geometry_keys)]:

        def normalize(catalog):
            values = catalog[rows].values() if isinstance(catalog[rows], dict) else catalog[rows]
            return {r['id']: {k: r.get(k) for k in keys} for r in values}
        if canonical(normalize(observed)) != canonical(normalize(expected)):
            observed_rows = normalize(observed)
            expected_rows = normalize(expected)
            changed = [key for key in set(observed_rows) | set(expected_rows) if canonical(observed_rows.get(key)) != canonical(expected_rows.get(key))]
            raise ValueError('Catalog relationships differ: ' + rows + ' ' + str(changed[:10]))
    return dict(entities=len(observed['entities']), geometries=len(observed['geometries']), relationship_projection_matches=True, coverage=observed['coverage'])

def verify_mesh_csv(manifest_path, expected):
    observed = json.loads(Path(manifest_path).read_text())
    old = {m['id']: m for m in expected['meshes']}
    evidence = []
    if not observed['complete'] or set((m['id'] for m in observed['meshes'])) != set(old):
        raise ValueError('Mesh set/coverage differs')
    for mesh in observed['meshes']:
        baseline = old[mesh['id']]
        vertices = hashlib.sha256()
        faces = hashlib.sha256()
        nv = nt = 0
        with (Path(manifest_path).parent / mesh['paths']['vertices']).open(newline='') as stream:
            for row in csv.DictReader(stream):
                if int(row['vertex_index']) != nv:
                    raise ValueError('Vertex order differs')
                raw = struct.pack('<ddd', *(float(row[x]) for x in ('x', 'y', 'z')))
                if raw.hex() != row['xyz_f64le_hex']:
                    raise ValueError('CSV decimal/hex disagreement')
                vertices.update(raw)
                nv += 1
        with (Path(manifest_path).parent / mesh['paths']['triangles']).open(newline='') as stream:
            for row in csv.DictReader(stream):
                if int(row['triangle_index']) != nt:
                    raise ValueError('Triangle order differs')
                faces.update(struct.pack('<III', *(int(row[x]) for x in ('vertex_0', 'vertex_1', 'vertex_2'))))
                nt += 1
        if vertices.hexdigest() != baseline['hashes']['vertices_f64le'] or faces.hexdigest() != baseline['hashes']['triangles_u32le']:
            raise ValueError('CSV reconstructed source arrays differ')
        if (nv, nt) != (baseline['vertex_count'], baseline['triangle_count']):
            raise ValueError('Mesh counts differ')
        evidence.append(dict(id=mesh['id'], vertices=nv, triangles=nt, xyz_sha256=vertices.hexdigest(), triangles_sha256=faces.hexdigest(), csv_decimal_and_hex_exact=True))
    return evidence

def guarded_cli(arguments, report_path):
    from fsd_decoder.cli.output import main as output_main
    with source_independence_guard() as guard:
        status = output_main(arguments)
        if guard['file_attempts'] or guard['constructor_attempts']:
            raise AssertionError('CLI attempted forbidden access')
    save(report_path, dict(status=status, guard=guard, argv=arguments))
    return status

def run(store, source, baseline, catalog_path, output):
    output = Path(output).absolute()
    if output.exists():
        raise FileExistsError(output)
    expected = prepare_expected(source, baseline, catalog_path)
    output.mkdir(parents=True)
    isolated = output / 'isolated'
    isolated.mkdir()
    copied = isolated / 'renamed_snapshot.fsdx'
    shutil.copyfile(store, copied)
    original_store_hash = sha(store)
    if sha(copied) != original_store_hash:
        raise ValueError('Isolated copy differs')
    save(output / 'source_expectations.json', expected)
    from fsd_decoder.portable.facade import PortableDatabase
    from fsd_decoder.portable.exports import export_text, export_mesh_csv
    from fsd_decoder.exports.catalog import build_portable_catalog
    from fsd_decoder.portable.rendering import render_datasets
    with source_independence_guard() as guard:
        with PortableDatabase(copied) as db:
            if db.sha256 != expected['source_sha256']:
                raise ValueError('Portable source identity differs')
            if canonical(db.fields.schema_report()) != canonical(expected['schema']):
                raise ValueError('Compiled schema differs')
            if canonical(db.roots()) != canonical(expected['roots']):
                raise ValueError('Stored roots differ')
            count = sum((1 for a in db.iter_allocations()))
            if count != expected['allocation_count']:
                raise ValueError('Stored allocation count differs')
            for sample in expected['selected']:
                allocation = db.allocation(*sample['address'])
                value = db.fields.decode(allocation)
                if canonical(value) != canonical(sample['value']):
                    raise ValueError('Typed value differs at ' + str(sample['address']))
            text_path = output / 'selected_objects.txt'
            text_report = export_text(db, text_path, allocation_addresses=[s['address'] for s in expected['selected']])
            actual_values = []
            with text_path.open() as stream:
                for line in stream:
                    if line.startswith('VALUE '):
                        actual_values.append(json.loads(line[6:]))
            if canonical(actual_values) != canonical([s['value'] for s in expected['selected']]):
                raise ValueError('Text values differ from source')
            mesh_manifest = export_mesh_csv(db, output / 'mesh_csv')
            mesh_evidence = verify_mesh_csv(mesh_manifest, expected['mesh'])
            catalog = build_portable_catalog(db)
            catalog_evidence = compare_catalog(catalog, expected['catalog'])
            save(output / 'catalog.json', catalog)
            selection = sorted({entity for g in catalog['geometries'].values() if g.get('render_class') in ('triangles', 'image_plane', 'grid2', 'grid3') for entity in g.get('owner_entity_ids', [])})
            render_manifest = render_datasets(db, output / 'rendered_datasets', dataset_ids=selection, width=400, height=300)
            rendering = json.loads(Path(render_manifest).read_text())
            if not rendering['complete']:
                raise ValueError('Selected dataset render incomplete: ' + canonical(rendering))
            verification = db.store.verify(full=True)
            query_stats = dict(db.query_statistics)
        if guard['file_attempts'] or guard['constructor_attempts']:
            raise AssertionError('Stage two attempted forbidden access')
    subprocess_reports = []
    for command in ('info', 'schema', 'verify'):
        result_path = output / ('cli_' + command + '.json')
        guard_path = output / ('cli_' + command + '_guard.json')
        cli = [sys.executable, '-m', 'fsd_decoder.portable.validate_integration', '--guard-cli-report', str(guard_path), '--', str(copied), command, '--output', str(result_path)]
        result = subprocess.run(cli, capture_output=True, text=True, timeout=120)
        (output / ('cli_' + command + '.stdout')).write_text(result.stdout)
        (output / ('cli_' + command + '.stderr')).write_text(result.stderr)
        if result.returncode:
            raise ValueError('Guarded CLI ' + command + ' failed: ' + result.stderr)
        subprocess_reports.append(json.loads(guard_path.read_text()))
    if sha(copied) != original_store_hash:
        raise ValueError('Stage two modified portable copy')
    if sha(source) != expected['source_sha256']:
        raise ValueError('Original FSD changed')
    result = dict(status='PASS', store=str(Path(store).resolve()), isolated_copy=str(copied), store_sha256=original_store_hash, source_sha256=expected['source_sha256'], source_unchanged=True, original_source_access_scope='Validator prepares source expectations before the guard and rechecks source SHA256 after it; stage-two operations inside the guard never reopen the source.', validator_sha256=sha(Path(__file__)), allocation_count=count, selected_values=len(expected['selected']), schema_exact=True, roots_exact=True, guard=guard, text=text_report, meshes=mesh_evidence, catalog=catalog_evidence, rendering=dict(datasets=rendering['dataset_count'], views=rendering['view_count'], complete=rendering['complete'], selection=selection), portable_verification=verification, query_statistics=query_stats, fresh_process_clis=subprocess_reports, limits='Bounded selected text and dataset renders; exhaustive allocation count; all exported triangle meshes. No original FSD moved or deleted.', outputs={str(p.relative_to(output)): dict(bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(output.rglob('*')) if p.is_file() and p != copied})
    save(output / 'validation.json', result)
    print(json.dumps({k: result[k] for k in ('status', 'allocation_count', 'selected_values', 'rendering', 'source_unchanged')}, indent=2))
    return result

def main():
    if '--guard-cli-report' in sys.argv:
        index = sys.argv.index('--guard-cli-report')
        report = sys.argv[index + 1]
        separator = sys.argv.index('--')
        return guarded_cli(sys.argv[separator + 1:], report)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('store', 'source', 'baseline', 'catalog', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    run(args.store, args.source, args.baseline, args.catalog, args.output)
    return 0
if __name__ == '__main__':
    sys.exit(main())
