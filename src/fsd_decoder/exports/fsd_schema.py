"""Export a reusable JSON schema from the current native FSD directory.

The result includes classes, inherited and embedded members, aliases, enum
literals, unions, native tags and logical-to-physical schema extent provenance.
The source is read-only and existing output files are never overwritten.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from fsd_decoder.native.native_database import NativeDatabase
from fsd_decoder.schema.native_fields import NativeFields
FORMAT_VERSION = 1

def build_schema_report(database):
    fields = NativeFields(database)
    schema = fields.schema_report()
    types = {str(k): v for k, v in sorted(fields.schema.type_cache.items())}
    classes = schema['classes']
    declarations = sum((len(c.get('declarations', [])) for c in classes.values()))
    roots = database.roots()
    return dict(format='fsd-native-schema', format_version=FORMAT_VERSION, source=dict(sha256=database.sha256, bytes=len(database.data), database_id=database.database_id), addressing=dict(units='bytes', schema_segment=0, schema_cluster=0, descriptor_offsets='logical offsets in the schema cluster', runtime_instance_layout_offsets='relative to the object or base subobject'), status='COMPLETE_SCHEMA_LAYOUTS' if schema['schema_complete'] else 'INCOMPLETE_SCHEMA_LAYOUTS', counts=dict(classes=len(classes), direct_instance_members=sum((len(c['members']) for c in classes.values())), declared_types=len(types), non_instance_declarations=declarations, native_type_bindings=len(schema['native_type_bindings']), roots=len(roots['roots'])), roots=[dict(name=r['name'], type_name=r['type_name'], value_target=r['value_target'], type_target=r['type_target']) for r in roots['roots']], schema=schema, types=types, limitations=['Class layouts describe stored fields; object identity and membership come from current native allocation tags.', 'Unions expose all declared members; omitted active selectors do not establish a single active member.', 'Bootstrap compact records preserve layout/type information where embedded application member names do not exist.'])

def export_schema(source, output, max_input_bytes=1000000000):
    snapshot = isinstance(source, NativeDatabase)
    database = source if snapshot else None
    source = database.source_path if snapshot else Path(source).resolve()
    output = Path(output).absolute()
    if type(max_input_bytes) is not int or max_input_bytes <= 0:
        raise ValueError('Invalid input byte limit')
    if output.exists() or output.is_symlink():
        raise ValueError('Output exists; choose another path')
    if not snapshot:
        if not source.is_file() or source.stat().st_size > max_input_bytes:
            raise ValueError('Source missing or exceeds size limit')
        with source.open('rb') as f:
            data = f.read(max_input_bytes + 1)
        if len(data) > max_input_bytes:
            raise ValueError('Source grew beyond size limit')
        database = NativeDatabase(data)
    elif len(database.data) > max_input_bytes:
        raise ValueError('Source exceeds size limit')
    report = build_schema_report(database)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n', dir=output.parent, prefix='.fsd-schema-', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, ensure_ascii=True, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if source is not None:
            h = hashlib.sha256()
            with source.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    h.update(chunk)
            if h.hexdigest() != database.sha256:
                raise ValueError('Source changed; schema was not published')
        else:
            database.verify_source()
        os.link(temporary, output)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
    if snapshot:
        return output
    return dict(status=report['status'], **report['counts'], source_sha256=database.sha256, source_unchanged=True, output=str(output), output_bytes=output.stat().st_size)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path)
    parser.add_argument('--max-input-bytes', type=int, default=1000000000)
    args = parser.parse_args()
    try:
        result = export_schema(args.source, args.output, args.max_input_bytes)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'fsd_schema: {exc}\n')
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'COMPLETE_SCHEMA_LAYOUTS' else 3
if __name__ == '__main__':
    raise SystemExit(main())
