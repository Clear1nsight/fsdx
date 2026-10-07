"""Recover application native types from directory-mapped complete schema bytes."""
import hashlib
from fsd_decoder.schema.probe_types import extended_dictionary
from fsd_decoder.schema.bootstrap_sizes import compile_dynamic_bindings
from fsd_decoder.native.native_directory import parse_database_directory
from fsd_decoder.schema.object_records import infer_schema, version_layout, Schema, ObjectRecoveryError

def recover_directory_types(data, directory=None, *, allow_partial_representations=False):
    if directory is None:
        directory = parse_database_directory(data)
    initial = infer_schema(data)
    anchors = [e for e in directory['effective_extents'] if e['logical_start'] == 0 and e['physical_start'] == initial.origin and (e['component'] == 0)]
    if len(anchors) != 1:
        raise ValueError('Schema cluster not uniquely anchored')
    anchor = anchors[0]
    identity = (anchor['segment'], anchor['cluster'])
    extents = sorted((e for e in directory['effective_extents'] if (e['segment'], e['cluster']) == identity), key=lambda e: e['logical_start'])

    def physical(low, size=1):
        hits = [e for e in extents if e['logical_start'] <= low and low + size <= e['logical_start'] + e['length']]
        if len(hits) != 1:
            raise ValueError('Schema record crosses an extent boundary')
        e = hits[0]
        return e['physical_start'] + low - e['logical_start']
    parts = []
    cursor = 0
    for e in extents:
        if e['component'] or e['logical_start'] != cursor:
            raise ValueError('Unsupported fragmented schema allocation')
        parts.append(data[e['physical_start']:e['physical_start'] + e['length']])
        cursor += e['length']
    logical = b''.join(parts)
    schema = infer_schema(logical)
    if schema.origin != 0:
        raise ValueError('Reconstructed schema origin differs')
    from fsd_decoder.native.native_database import NativeDatabase
    version = version_layout(schema)
    dictionary = extended_dictionary(logical, database=NativeDatabase(data, directory), schema_identity=identity)
    sizes = {}
    rejected = []
    compiled = compile_dynamic_bindings(dictionary)
    if compiled['errors'] and (not allow_partial_representations):
        raise ValueError('Unsupported compact class representation')
    from fsd_decoder.native.native_tags import BOOTSTRAP_TYPES
    if any((b['native_tag'] in BOOTSTRAP_TYPES for b in dictionary if b['binding_active'] and b['native_tag'])):
        raise ValueError('Application native tag collides with bootstrap type')
    by_id = {r['binding']['dictionary_id']: r for r in compiled['entries']}
    for binding in dictionary:
        if not binding['native_tag'] or not binding['binding_active']:
            continue
        if binding['dictionary_id'] not in by_id:
            rejected.append(dict(binding=binding, reason='UNCOMPILED_REPRESENTATION', allocation_size=None, discriminant_grammar=None))
            continue
        try:
            c = schema.named_descriptor(binding['name'], 'class')
        except ObjectRecoveryError as e:
            calc = by_id[binding['dictionary_id']]
            sizes[binding['native_tag']] = dict(name=binding['name'], size=calc['size'], binding=binding, needs_discriminants=calc['needs_discriminants'], representation_flags=calc['flags'], schema_size_unavailable=str(e), size_evidence=calc['size_evidence'], schema_segment=identity[0], schema_cluster=identity[1])
            rejected.append(dict(binding=binding, reason=str(e), compact_bytecode_size_recovered=calc['size']))
            continue
        tag = binding['native_tag']
        if tag in sizes:
            raise ValueError('Duplicate native type binding')
        calc = by_id[binding['dictionary_id']]
        if calc['size'] != c['size_bytes']:
            raise ValueError('Schema class size and compact representation disagree')
        mapped = {k: physical(v) for k, v in c.items() if k.endswith('_offset')}
        sizes[tag] = dict(name=binding['name'], size=c['size_bytes'], binding=binding, needs_discriminants=calc['needs_discriminants'], representation_flags=calc['flags'], compact_size_crosscheck=True, schema_logical=c, schema_physical=mapped, schema_segment=identity[0], schema_cluster=identity[1], schema_size_field=mapped['value_offset'], name_reference_offset=mapped['name_reference_offset'], name_offset=mapped['name_offset'])
    return (sizes, dict(schema_segment=identity[0], schema_cluster=identity[1], schema_bytes=len(logical), schema_sha256=hashlib.sha256(logical).hexdigest(), extents=extents, rejected=rejected, dictionary_candidates=len(dictionary), representation_complete=not compiled['errors'], representation_errors=compiled['errors']))
