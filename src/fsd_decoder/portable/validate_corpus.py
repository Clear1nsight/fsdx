"""Validate one FSDX against its source, then exercise an isolated store only.

The source phase performs one exhaustive allocation census, stratified typed
samples, and a complete Entity/Shape catalog. Stage two denies source access and
native constructors. Rendering is deliberately representative, not exhaustive.
Run one fresh process per project to bound retained memory.
"""
from __future__ import annotations
import argparse
from collections import Counter, OrderedDict
from contextlib import contextmanager, ExitStack
import gc
import hashlib
import io
import json
import mmap
import os
import resource
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
from unittest.mock import patch
from urllib.parse import unquote
HERE = Path(__file__).resolve().parent
DECODER = HERE.parent
from fsd_decoder.portable.validate_integration import canonical, plain, save, sha, source_independence_guard, compare_catalog, verify_mesh_csv

def emit(progress, phase, **values):
    if progress:
        progress(dict(phase=phase, **values))

@contextmanager
def corpus_guard(forbidden_paths=()):
    """Extend the integration guard to fd, mmap, SQLite and source aliases.

    This is an instrumented Python execution guard, not an OS security sandbox.
    Direct foreign-function syscalls are outside its scope and are not used by
    the validated reader. Existing source file descriptors are rejected too.
    """
    paths = {Path(p).resolve() for p in forbidden_paths}
    identities = {(p.stat().st_dev, p.stat().st_ino) for p in paths if p.exists()}
    originals = dict(os_open=os.open, mmap=mmap.mmap, sqlite=sqlite3.connect, builtin=__import__('builtins').open, io=io.open)
    calls = {'low_level_attempts': [], 'allowed_low_level_calls': 0}

    def check(value, *, dir_fd=None):
        if isinstance(value, int):
            try:
                value = os.readlink('/proc/self/fd/' + str(value))
            except OSError:
                return
        try:
            raw = os.fsdecode(value)
        except TypeError:
            return
        if raw in (':memory:', ''):
            return
        if raw.startswith('file:'):
            raw = unquote(raw[5:].split('?', 1)[0])
        p = Path(raw)
        if dir_fd is not None and (not p.is_absolute()):
            p = Path(os.readlink('/proc/self/fd/' + str(dir_fd))) / p
        p = p.absolute()
        resolved = p.resolve()
        forbidden = any((q.suffix.lower() == '.fsd' or 'FSD_Exports' in q.parts or q in paths for q in (p, resolved)))
        try:
            st = resolved.stat()
            forbidden = forbidden or (st.st_dev, st.st_ino) in identities
        except OSError:
            pass
        if forbidden:
            calls['low_level_attempts'].append(str(p))
            raise RuntimeError('Forbidden source or baseline access: ' + str(p))
        calls['allowed_low_level_calls'] += 1

    def os_open(path, *args, **kwargs):
        check(path, dir_fd=kwargs.get('dir_fd'))
        return originals['os_open'](path, *args, **kwargs)

    def mapped(fd, *args, **kwargs):
        if fd != -1:
            check(fd)
        return originals['mmap'](fd, *args, **kwargs)

    def connection(database, *args, **kwargs):
        check(database)
        return originals['sqlite'](database, *args, **kwargs)

    def builtin(file, *args, **kwargs):
        check(file)
        return originals['builtin'](file, *args, **kwargs)

    def opened(file, *args, **kwargs):
        check(file)
        return originals['io'](file, *args, **kwargs)
    with ExitStack() as stack:
        stack.enter_context(patch('builtins.open', builtin))
        stack.enter_context(patch('io.open', opened))
        stack.enter_context(patch('os.open', os_open))
        stack.enter_context(patch('mmap.mmap', mapped))
        stack.enter_context(patch('sqlite3.connect', connection))
        base = stack.enter_context(source_independence_guard())
        yield dict(file_guard=base, low_level_guard=calls, scope='Python open/io/os.open, SQLite connect, mmap and native constructors; source inode aliases included')
ALLOCATION_KEYS = ('segment', 'cluster', 'logical_offset', 'native_tag', 'name', 'size', 'count', 'vector', 'element_size', 'element_stride', 'array_header_size', 'array_header_hex', 'terminal_padding_offset', 'terminal_padding_size', 'terminal_padding_hex', 'inter_element_padding_size', 'discriminant_words', 'huge')

def allocation_digest_update(digest, allocation):
    digest.update(canonical([allocation.get(k) for k in ALLOCATION_KEYS]).encode('ascii'))
    digest.update(b'\n')

def element_indices(allocation):
    count = allocation.get('count', 1) if allocation.get('vector') else 1
    return sorted({0, count // 2, count - 1}) if count else []

def sample_stratum(allocation):
    return (allocation['native_tag'], allocation['name'], bool(allocation.get('vector')), bool(allocation.get('array_header_size')), bool(allocation.get('inter_element_padding_size')), bool(allocation.get('terminal_padding_size')), bool(allocation.get('discriminant_words')))

class SourceLookup:
    """Containing-allocation lookup from source page tags, with huge fallback.

    No portable or historical index contributes to the source expectations.
    Only current native allocation tag records are used. Element interpretation
    requires the normalized metadata below, not a retained full allocation list.
    """

    def __init__(self, db, types):
        self.db, self.types = (db, types)
        self.pages = OrderedDict()
        self.huge = {}

    def _records(self, segment, cluster, page):
        token = (segment, cluster, page)
        if token in self.pages:
            self.pages.move_to_end(token)
            return self.pages[token]
        rows = {}
        for kind in (16, 17):
            trace = self.db.tags(segment, cluster, page, self.types, key_kind=kind)
            if trace is None:
                continue
            for raw in trace['records']:
                if raw['name'] == 'free_space_candidate' or not raw['size']:
                    continue
                start = page + raw['page_offset']
                row = dict(raw, segment=segment, cluster=cluster, logical_offset=start, address=self.db.address(segment, cluster, start), huge=kind == 17)
                if start in rows and canonical(rows[start]) != canonical(row):
                    raise ValueError('Conflicting source allocation tags')
                rows[start] = row
        self.pages[token] = rows
        while len(self.pages) > 1024:
            self.pages.popitem(last=False)
        return rows

    def __call__(self, segment, cluster, offset):
        candidates = [a for a in self._records(segment, cluster, offset & ~4095).values() if a['logical_offset'] <= offset < a['logical_offset'] + a['size']]
        if not candidates:
            token = (segment, cluster)
            if token not in self.huge:
                huge = []
                for entry in self.db.iter_metadata(segment, cluster, table=1):
                    if entry['key'] & 31 == 17:
                        page = (entry['key'] >> 5) * 4096
                        huge.extend((a for a in self._records(segment, cluster, page).values() if a['huge']))
                self.huge[token] = huge
            candidates = [a for a in self.huge[token] if a['logical_offset'] <= offset < a['logical_offset'] + a['size']]
        if len(candidates) > 1:
            raise ValueError('Ambiguous source allocation ownership')
        return candidates[0] if candidates else None

def validate_baseline_pin(project_manifest, mesh_path, source_sha256):
    pinned_mesh = project_manifest.get('artifacts', {}).get('meshes/manifest.json', {})
    if project_manifest.get('status') not in ('COMPLETE', 'COMPLETE_VALIDATED_SUPPORTED_LAYOUT') or pinned_mesh.get('sha256') != sha(mesh_path):
        raise ValueError('Mesh baseline manifest differs from completed project artifact pin')
    if project_manifest.get('source', {}).get('sha256') != source_sha256:
        raise ValueError('Completed baseline project belongs to another source')

def prepare_expected(source, baseline, *, progress=None, samples_per_stratum=3):
    from fsd_decoder.native.native_database import NativeDatabase
    from fsd_decoder.native.native_allocations import NativeAllocationReader
    from fsd_decoder.schema.native_fields import NativeFields
    from fsd_decoder.exports.catalog import PortableCatalogReader, build_catalog_from_reader
    emit(progress, 'source_open', source=str(source))
    db = NativeDatabase.from_path(source)
    fields = NativeFields(db)
    schema, roots = (plain(fields.schema_report()), plain(db.roots()))
    lookup = SourceLookup(db, fields.types)
    reader = PortableCatalogReader(db, fields, iter_allocations=lambda: iter(()), allocation_lookup=lookup, source_metadata=dict(path=str(Path(source).resolve()), sha256=db.sha256, bytes=len(db.data), database_id=db.database_id), expected_allocations=0)
    inherits = reader.inherits
    by_name, strata, selected, census_rows = (Counter(), Counter(), [], [])
    digest = hashlib.sha256()
    count = 0
    type_names = {tag: typ['name'] for tag, typ in fields.types.items()}
    relevant_names = {name for name in set(type_names.values()) | set(fields.schema.classes) if inherits(name, 'Fs::Entity') or inherits(name, 'Fs::Spatial::Shape')}
    sample_diagnostics = []
    for a in NativeAllocationReader(db, fields.types).iter_allocations():
        count += 1
        by_name[a['name']] += 1
        allocation_digest_update(digest, a)
        name = a['name'][:-2] if a['name'].endswith('[]') else a['name']
        if name in relevant_names:
            census_rows.append(a)
        stratum = sample_stratum(a)
        if strata[stratum] < samples_per_stratum:
            strata[stratum] += 1
            token = [a['segment'], a['cluster'], a['logical_offset']]
            for index in element_indices(a):
                try:
                    value = plain(fields.decode(a, element_index=index))
                    sample = dict(address=token, element_index=index, value=value)
                except (ValueError, KeyError, IndexError) as exc:
                    sample = dict(address=token, element_index=index, error=dict(type=type(exc).__name__, message=str(exc)))
                    sample_diagnostics.append(dict(address=token, element_index=index, **sample['error']))
                selected.append(sample)
        if count % 100000 == 0:
            emit(progress, 'source_census', allocations=count, typed_samples=len(selected))
    emit(progress, 'source_census_complete', allocations=count, types=len(by_name), typed_samples=len(selected))
    reader.inventory['allocations'] = count
    reader.iter_allocations = lambda: iter(census_rows)
    reader.iter_named_allocations = lambda names: (a for a in census_rows if a['name'] in names)
    reader.allocation_counts_by_name = dict(by_name)
    catalog = build_catalog_from_reader(reader, progress=progress)
    mesh_path = Path(baseline) / 'meshes' / 'manifest.json'
    mesh = json.loads(mesh_path.read_text())
    project_manifest_path = Path(baseline) / 'manifest.json'
    project_manifest = json.loads(project_manifest_path.read_text())
    validate_baseline_pin(project_manifest, mesh_path, db.sha256)
    if mesh['source']['sha256'] != db.sha256 or not mesh.get('complete', True) or mesh.get('unsupported'):
        raise ValueError('Historical mesh baseline is incomplete or from another source')
    source_surfaces = {f's{a['segment']}_c{a['cluster']}_o{a['logical_offset']:x}' for a in census_rows if a['name'] == 'Fs::Spatial::Geom::TriSurface'}
    if source_surfaces != {m['id'] for m in mesh['meshes']}:
        raise ValueError('Mesh baseline does not cover the current surface census')
    baseline_arrays = []
    for entry in mesh['meshes']:
        for key in ('vertices_f64le', 'triangles_u32le'):
            baseline_arrays.append(str((mesh_path.parent / entry['paths'][key]).resolve()))
            if sha(mesh_path.parent / entry['paths'][key]) != entry['hashes'][key]:
                raise ValueError('Historical packed mesh array SHA differs')
    db.verify_source()
    result = dict(source_path=str(Path(source).resolve()), source_sha256=db.sha256, database_id=db.database_id, allocation_count=count, allocation_sha256=digest.hexdigest(), allocations_by_name=dict(by_name), schema=schema, roots=roots, selected=selected, sample_diagnostics=sample_diagnostics, mesh=mesh, catalog=catalog, baseline_array_files=baseline_arrays, baseline_files={str(mesh_path.resolve()): sha(mesh_path), str(project_manifest_path.resolve()): sha(project_manifest_path)}, sample_policy=dict(per_representation_stratum=samples_per_stratum, stratum_fields=['native_tag', 'name', 'vector', 'has_header', 'has_stride_padding', 'has_terminal_padding', 'has_discriminants'], array_elements='first, middle, last', all_observed_types_selected=True))
    del reader, lookup, fields, db, census_rows
    gc.collect()
    return result

def compare_semantics(observed, expected):
    evidence = compare_catalog(observed, expected)
    for gid, geometry in observed['geometries'].items():
        for key in ('status', 'coordinate_system_status'):
            if canonical(geometry.get(key)) != canonical(expected['geometries'][gid].get(key)):
                raise ValueError('Geometry status differs: ' + gid + ' ' + key)
    for key in ('coordinate_systems', 'navigation_groups', 'collection_checks', 'diagnostics', 'unhandled_objects'):
        if canonical(observed.get(key)) != canonical(expected.get(key)):
            raise ValueError('Catalog semantic component differs: ' + key)
    for key in ('entity_allocations', 'shape_allocations', 'unassigned_geometry_ids', 'entities_not_in_navigation'):
        if canonical(observed['coverage'].get(key)) != canonical(expected['coverage'].get(key)):
            raise ValueError('Catalog allocation coverage differs: ' + key)
    evidence['coordinate_frames_and_diagnostics_exact'] = True
    return evidence

def compare_mesh_metadata(observed, expected):
    old = {m['id']: m for m in expected['meshes']}
    if set(old) != {m['id'] for m in observed['meshes']}:
        raise ValueError('Mesh set differs')
    for m in observed['meshes']:
        for key in ('source_address', 'coordinate_system_address', 'vertex_array_address', 'triangle_array_address'):
            if canonical(m.get(key)) != canonical(old[m['id']].get(key)):
                raise ValueError('Mesh ' + key + ' differs: ' + m['id'])

def choose_render_datasets(catalog):
    """One deterministic dataset per declared frame and supported render class.

    Dimension separation is tested by the renderer on every selected dataset.
    Coordinate dimension is recovered by the source shape's stored metadata when
    available; missing dimensions remain explicit, not assumed 3D.
    """
    buckets = {}
    for gid, g in sorted(catalog['geometries'].items()):
        category = g.get('render_class')
        if category not in ('points', 'lines', 'triangles', 'image_plane', 'grid2', 'grid3'):
            continue
        frame = canonical(g.get('coordinate_system_address'))
        dimension = g.get('dimension', 2 if category in ('grid2', 'image_plane') else 3 if category in ('triangles', 'grid3') else 'SOURCE_SEQUENCE_DIMENSIONS')
        owners = sorted(g.get('owner_entity_ids', [])) or ['unassigned:' + gid]
        key = (frame, dimension, category)
        candidate = (owners[0].startswith('unassigned:'), owners[0], gid)
        if key not in buckets or candidate < buckets[key]:
            buckets[key] = candidate
    return (sorted({candidate[1] for candidate in buckets.values()}), [dict(coordinate_system_address=json.loads(frame), dimension=dimension, render_class=category, dataset_id=candidate[1], geometry_id=candidate[2]) for (frame, dimension, category), candidate in sorted(buckets.items(), key=lambda row: repr(row[0]))])

def assert_guard_clean(guard):
    if guard['file_guard']['file_attempts'] or guard['file_guard']['constructor_attempts'] or guard['low_level_guard']['low_level_attempts']:
        raise ValueError('Source-independent operation attempted forbidden access')

def guarded_cli(arguments, report_path, forbidden_paths=()):
    from fsd_decoder.cli.output import main as output_main
    with corpus_guard(forbidden_paths) as guard:
        status = output_main(arguments)
    assert_guard_clean(guard)
    save(report_path, dict(status=status, guard=guard, argv=arguments))
    return status

def run(store, source, baseline, output, *, progress=None, samples_per_stratum=3, width=400, height=300):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    started = time.monotonic()
    validator_hash = sha(Path(__file__))
    expected = prepare_expected(source, baseline, progress=progress, samples_per_stratum=samples_per_stratum)
    save(output / 'source_expectations.json', expected)
    isolated = output / 'isolated'
    isolated.mkdir()
    copied = isolated / 'renamed_snapshot.fsdx'
    emit(progress, 'copy_store', source=str(store), destination=str(copied))
    shutil.copyfile(store, copied)
    original_store_hash = sha(store)
    if sha(copied) != original_store_hash:
        raise ValueError('Isolated store copy differs')
    from fsd_decoder.portable.facade import PortableDatabase
    from fsd_decoder.portable.exports import export_text, export_mesh_csv
    from fsd_decoder.exports.catalog import build_portable_catalog
    from fsd_decoder.portable.rendering import render_datasets
    forbidden = [source, *expected['baseline_files'], *expected['baseline_array_files']]
    with corpus_guard(forbidden) as guard:
        with PortableDatabase(copied) as db:
            emit(progress, 'portable_identity_schema_roots')
            if db.sha256 != expected['source_sha256'] or db.database_id != expected['database_id']:
                raise ValueError('Portable source identity differs')
            if canonical(db.fields.schema_report()) != canonical(expected['schema']):
                raise ValueError('Compiled schema differs')
            if canonical(db.roots()) != canonical(expected['roots']):
                raise ValueError('Stored roots differ')
            count = 0
            digest, by_name = (hashlib.sha256(), Counter())
            for allocation in db.iter_allocations():
                count += 1
                by_name[allocation['name']] += 1
                allocation_digest_update(digest, allocation)
                if count % 100000 == 0:
                    emit(progress, 'portable_census', allocations=count, total=expected['allocation_count'])
            if count != expected['allocation_count'] or dict(by_name) != expected['allocations_by_name'] or digest.hexdigest() != expected['allocation_sha256']:
                raise ValueError('Portable allocation metadata census differs')
            emit(progress, 'typed_samples', samples=len(expected['selected']))
            for sample in expected['selected']:
                allocation = db.allocation(*sample['address'])
                if allocation is None or allocation['logical_offset'] != sample['address'][2]:
                    raise ValueError('Typed sample allocation identity differs')
                try:
                    value = plain(db.fields.decode(allocation, element_index=sample['element_index']))
                    actual = dict(value=value)
                except (ValueError, KeyError, IndexError) as exc:
                    actual = dict(error=dict(type=type(exc).__name__, message=str(exc)))
                expected_result = {k: sample[k] for k in ('value', 'error') if k in sample}
                if canonical(actual) != canonical(expected_result):
                    raise ValueError('Typed value differs at ' + str(sample['address']) + ' element ' + str(sample['element_index']))
            text_samples = []
            seen = set()
            for sample in expected['selected']:
                key = tuple(sample['address'])
                allocation = db.allocation(*key)
                if key not in seen and (not allocation.get('vector')) and ('value' in sample):
                    seen.add(key)
                    text_samples.append(sample)
            text_report = export_text(db, output / 'selected_objects.txt', allocation_addresses=[s['address'] for s in text_samples])
            with (output / 'selected_objects.txt').open() as stream:
                values = [json.loads(line[6:]) for line in stream if line.startswith('VALUE ')]
            if canonical(values) != canonical([s['value'] for s in text_samples]):
                raise ValueError('Plaintext output differs from source typed values')
            emit(progress, 'mesh_csv', surfaces=len(expected['mesh']['meshes']))
            mesh_manifest = export_mesh_csv(db, output / 'mesh_csv', progress=progress)
            compare_mesh_metadata(json.loads(Path(mesh_manifest).read_text()), expected['mesh'])
            mesh_evidence = verify_mesh_csv(mesh_manifest, expected['mesh'])
            emit(progress, 'portable_catalog')
            catalog = build_portable_catalog(db, progress=progress)
            catalog_evidence = compare_semantics(catalog, expected['catalog'])
            save(output / 'catalog.json', catalog)
            selection, render_strata = choose_render_datasets(catalog)
            emit(progress, 'representative_renders', datasets=len(selection), strata=len(render_strata))
            render_path = render_datasets(db, output / 'rendered_datasets', dataset_ids=selection, width=width, height=height, progress=progress)
            rendering = json.loads(Path(render_path).read_text())
            emit(progress, 'portable_full_verification')
            verification = db.store.verify(full=True)
            query_stats = dict(db.query_statistics)
            store_counts = dict(db.store.manifest.get('counts', {}))
            largest_document = db.store.connection.execute('SELECT d.kind,d.name,b.raw_length FROM documents d JOIN blobs b ON b.sha256=d.blob_sha256 ORDER BY b.raw_length DESC LIMIT 1').fetchone()
            document_size = dict(largest_document) if largest_document is not None else None
    assert_guard_clean(guard)
    cli_reports = []
    for command in ('info', 'schema'):
        emit(progress, 'fresh_process_cli', command=command)
        result_path, guard_path = (output / ('cli_' + command + '.json'), output / ('cli_' + command + '_guard.json'))
        cli = [sys.executable, '-m', 'fsd_decoder.portable.validate_corpus', '--guard-cli-report', str(guard_path), '--forbidden-source', str(source), '--', str(copied), command, '--output', str(result_path)]
        result = subprocess.run(cli, capture_output=True, text=True, timeout=1800)
        (output / ('cli_' + command + '.stdout')).write_text(result.stdout)
        (output / ('cli_' + command + '.stderr')).write_text(result.stderr)
        if result.returncode:
            raise ValueError('Guarded CLI ' + command + ' failed: ' + result.stderr)
        cli_reports.append(json.loads(guard_path.read_text()))
    if sha(copied) != original_store_hash or sha(store) != original_store_hash:
        raise ValueError('Stage two modified a portable store')
    if sha(source) != expected['source_sha256']:
        raise ValueError('Original FSD changed')
    diagnostics = [dict(scope='catalog', **d) for d in catalog.get('diagnostics', [])]
    diagnostics += [dict(scope='unsupported_shape', **d) for d in catalog.get('unhandled_objects', [])]
    diagnostics += [dict(scope='render', dataset_id=r['dataset']['id'], **d) for r in rendering['datasets'] for d in r['diagnostics']]
    diagnostics += [dict(scope='typed_sample', **d) for d in expected['sample_diagnostics']]
    if sha(Path(__file__)) != validator_hash:
        raise ValueError('Validator code changed during validation')
    report = dict(status='PASS', data_verification='PASS', semantic_status='WITH_GAPS' if diagnostics or catalog.get('unhandled_objects') else 'COMPLETE_FOR_CURRENT_ADAPTERS', diagnostics=diagnostics, elapsed_seconds=round(time.monotonic() - started, 3), store=str(Path(store).resolve()), isolated_copy=str(copied), store_sha256=original_store_hash, source_sha256=expected['source_sha256'], source_unchanged=True, allocation_count=count, allocation_sha256=digest.hexdigest(), allocations_by_name=dict(by_name), selected_values=len(expected['selected']), sample_policy=expected['sample_policy'], schema_exact=True, roots_exact=True, guard=guard, text=text_report, meshes=mesh_evidence, catalog=catalog_evidence, rendering=dict(datasets=rendering['dataset_count'], views=rendering['view_count'], complete=rendering['complete'], selection=selection, strata=render_strata, coverage='Representative dataset per declared coordinate frame and render class; selected sequences split by actual dimensions. All geometries retained in catalog.'), portable_verification=verification, store_counts=store_counts, largest_stored_document=document_size, peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, query_statistics=query_stats, fresh_process_clis=cli_reports, validator_sha256=validator_hash, original_source_access_scope='Source expectations and pre/post hashes outside guard only; stage two and fresh CLI processes use renamed isolated FSDX copy.', limits=['Typed samples are stratified and bounded; not an exhaustive semantic decode of all primitive values.', 'All current allocations and every exported triangle mesh are compared.', 'Native source catalog and portable catalog share semantic field/relationship rules; this tests preservation, not independent truth of unknown format semantics.', 'Uninterpreted shapes and render failures remain explicit diagnostics; no source files archived or deleted.'])
    save(output / 'validation.json', report)
    emit(progress, 'complete', status=report['status'], semantic_status=report['semantic_status'], allocations=count, meshes=len(mesh_evidence), elapsed_seconds=report['elapsed_seconds'])
    return report

def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if '--guard-cli-report' in args:
        index = args.index('--guard-cli-report')
        source_index = args.index('--forbidden-source')
        return guarded_cli(args[args.index('--') + 1:], args[index + 1], [args[source_index + 1]])
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('store', 'source', 'baseline', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--samples-per-stratum', type=int, default=3)
    parser.add_argument('--width', type=int, default=400)
    parser.add_argument('--height', type=int, default=300)
    ns = parser.parse_args(args)
    if ns.samples_per_stratum < 1:
        parser.error('samples-per-stratum must be positive')
    try:
        report = run(ns.store, ns.source, ns.baseline, ns.output, samples_per_stratum=ns.samples_per_stratum, width=ns.width, height=ns.height, progress=lambda value: print(json.dumps(value, default=str), flush=True))
    except Exception as exc:
        print(json.dumps(dict(status='FAIL', error=type(exc).__name__, message=str(exc))), file=sys.stderr, flush=True)
        return 1
    return 0 if report['status'] == 'PASS' else 1
if __name__ == '__main__':
    sys.exit(main())
