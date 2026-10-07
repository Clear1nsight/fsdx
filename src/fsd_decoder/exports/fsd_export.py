"""Export an FSD into file information, schema, reusable meshes and a static PNG.

The destination must be a new directory. This Linux CLI builds the complete
bundle in a temporary sibling and publishes it using renameat2(NO_REPLACE).
Native decoding, mesh export and portable PNG rendering use Python's standard
library. No external graphics application or scientific package is required.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from fsd_decoder.core.diagnostics import InputValidationError, ResourceLimitError, UnsupportedLayoutError, contextual, failure_record

def publish_directory(source, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise OSError(errno.ENOSYS, 'Atomic directory publication requires Linux renameat2')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

@contextual('bundle_export', source='source', destination='output')
def export_bundle(source, destination, *, max_input_bytes=1000000000, progress=None, export_obj=True):
    from fsd_decoder.native.native_database import NativeDatabase
    from fsd_decoder.exports.fsd_file_info import export_file_info
    from fsd_decoder.exports.fsd_schema import export_schema
    from fsd_decoder.exports.fsd_mesh import export_meshes
    from fsd_decoder.exports.fsd_render_light import export_render
    source, destination = (Path(source).resolve(), Path(destination).absolute())
    if destination.exists() or destination.is_symlink():
        raise InputValidationError('Destination exists; choose a new directory')
    if type(max_input_bytes) is not int or max_input_bytes <= 0 or not source.is_file():
        raise InputValidationError('Invalid source or input size limit')
    if source.stat().st_size > max_input_bytes:
        raise ResourceLimitError('Invalid source or input size limit')
    with source.open('rb') as f:
        data = f.read(max_input_bytes + 1)
    if len(data) > max_input_bytes:
        raise ResourceLimitError('Source grew beyond input size limit')
    db = NativeDatabase(data)
    db.source_path = source
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.fsd-bundle-', dir=destination.parent))
    try:

        def update(phase):
            if progress:
                progress(phase)
        update('Exporting file information')
        export_file_info(db, staging / 'file_information.json')
        update('Exporting schema')
        schema_path = export_schema(db, staging / 'schema.json')
        schema_report = json.loads(Path(schema_path).read_text())
        if schema_report.get('status', '').startswith(('INCOMPLETE', 'UNSUPPORTED')):
            raise UnsupportedLayoutError('Schema export has unsupported layouts')
        update('Exporting native meshes')
        mesh_manifest = export_meshes(db, staging / 'meshes', export_obj=export_obj)
        mesh_report = json.loads(Path(mesh_manifest).read_text())
        if not mesh_report.get('complete'):
            raise UnsupportedLayoutError('Mesh export has unsupported surfaces; bundle was not published')
        update('Rendering all exported meshes')
        export_render(mesh_manifest, staging / 'scene.png', staging / 'render.json')
        db.verify_source()
        files = []
        for path in sorted(staging.rglob('*')):
            if path.is_file():
                files.append(dict(path=path.relative_to(staging).as_posix(), bytes=path.stat().st_size, sha256=digest(path)))
        manifest = dict(format='fsd-export-bundle', format_version=1, source=str(source), source_sha256=db.sha256, source_unchanged=True, export_obj=export_obj, geometry=dict(meshes=len(mesh_report.get('meshes', [])), vertices=sum((m['vertex_count'] for m in mesh_report.get('meshes', []))), triangles=sum((m['triangle_count'] for m in mesh_report.get('meshes', [])))), outputs=dict(file_information='file_information.json', schema='schema.json', meshes='meshes', static_render='scene.png', render_information='render.json'), files=files, status='COMPLETE_SUPPORTED_LAYOUT')
        with (staging / 'manifest.json').open('x') as f:
            json.dump(manifest, f, indent=2)
            f.write('\n')
        db.verify_source()
        publish_directory(staging, destination)
        return dict(source_sha256=db.sha256, output=str(destination), files=len(files) + 1, status=manifest['status'])
    finally:
        if staging.exists():
            shutil.rmtree(staging)

def main(argv=None):
    from fsd_decoder.cli.dump import install_termination_handler
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('-o', '--output', required=True, type=Path, help='new bundle directory')
    p.add_argument('--max-input-bytes', type=int, default=1000000000)
    p.add_argument('--no-obj', action='store_true', help='export plaintext mesh CSV arrays without OBJ files')
    a = p.parse_args(argv)
    install_termination_handler()
    context = dict(phase='bundle_export', source=str(a.source), output=str(a.output))
    def progress(phase):
        context['phase'] = phase
        print(phase, file=sys.stderr, flush=True)
    try:
        report = export_bundle(a.source, a.output, max_input_bytes=a.max_input_bytes, export_obj=not a.no_obj, progress=progress)
    except Exception as e:
        detail = failure_record(e, status='BUNDLE_FAILED', context=context)
        print(json.dumps(detail), file=sys.stderr, flush=True)
        if detail['error_category'] == 'PROGRAMMING_FAILURE':
            raise
        return 1
    except KeyboardInterrupt:
        print('Interrupted; unfinished bundle was not published.', file=sys.stderr)
        return 130
    print(json.dumps(report, sort_keys=True))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
