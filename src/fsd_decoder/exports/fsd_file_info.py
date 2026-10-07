"""Compact, source-linked FILE INFORMATION output for native FSD decoding.

This output describes the source and committed storage catalogue. It does not
claim to enumerate application objects, identify every geometry, or determine
the FracSIS application version from a filename or ObjectStore runtime version.
"""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
from fsd_decoder.native.native_database import NativeDatabase
FORMAT = 'fsd-file-information'
CONTRACT_VERSION = 1

def _address(database_id, value):
    if value is None:
        return None
    segment, cluster, offset = value
    return dict(database=database_id, segment=segment, cluster=cluster, offset=offset)

def _utc(value):
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None

def _application_version(db, roots, native_fields=None):
    candidates = [root for root in roots['roots'] if root['type_name'] == 'Fs::Version']
    if not candidates:
        return dict(status='NO_DECLARED_VERSION_ROOT', value=None)
    if len(candidates) != 1:
        return dict(status='AMBIGUOUS_VERSION_ROOT', value=None)
    root = candidates[0]
    try:
        from fsd_decoder.schema.native_fields import NativeFields
        fields = native_fields if native_fields is not None else NativeFields(db, allow_partial_representations=True)
        if fields.database is not db:
            raise ValueError('Version schema belongs to a different database snapshot')

        def allocation_at(address):
            segment, cluster, offset = address
            page = offset & ~4095
            matches = []
            for kind in (16, 17):
                trace = db.tags(segment, cluster, page, fields.types, key_kind=kind)
                if trace is not None:
                    matches.extend((record for record in trace['records'] if page + record['page_offset'] == offset))
            if len(matches) != 1:
                raise ValueError('Version target lacks a unique current native allocation')
            return {**matches[0], 'segment': segment, 'cluster': cluster, 'logical_offset': offset}
        target = root['value_target']
        if target is None:
            raise ValueError('Version root has a null value')
        allocation = allocation_at(target)
        if allocation['name'] != 'Fs::Version' or allocation['count'] != 1 or allocation['vector']:
            raise ValueError('Version root does not reference an exact Fs::Version allocation')
        decoded = fields.decode(allocation)
        members = [field for field in decoded.get('fields', []) if field.get('path') == 'Fs::Version.m_versionString._strRep']
        if len(members) != 1 or members[0].get('pointee_type', {}).get('name') != '1 byte char':
            raise ValueError('Version member lacks the declared character pointer schema')
        member = members[0]
        pointer = member.get('target')
        if not pointer or pointer.get('status') != 'CURRENT_NATIVE_PRM':
            raise ValueError('Version character pointer lacks current PRM resolution')
        address = pointer['address']
        char_address = (address['segment'], address['cluster'], address['offset'])
        chars = allocation_at(char_address)
        if chars['native_tag'] != 1 or not chars['vector'] or chars.get('element_size') != 1 or (chars.get('array_header_size', 0) != 0):
            raise ValueError('Version text is not a native character array')
        if not 1 <= chars['count'] <= 4096:
            raise ValueError('Version character allocation exceeds bounded text size')
        raw = db.read_at(*char_address, chars['count'])
        end = raw.find(b'\x00')
        if end < 0:
            raise ValueError('Version character allocation has no terminating NUL')
        value = raw[:end].decode('utf-8', errors='strict')
        return dict(status='NATIVE_ROOT_SCHEMA_AND_CHAR_ALLOCATION', value=value, root_name=root['name'], version_address=_address(db.database_id, target), schema_member_path=member['path'], member_source_address=member['source_address'], character_array_address=address, character_count=chars['count'], character_array_raw_hex=raw.hex(), native_tag=chars['native_tag'], allocation_tag_raw_hex=chars['tag_bytes'], character_source_spans=[dict(physical_start=span.physical_start, length=span.length) for span in db.spans(db.address(*char_address), len(raw))])
    except (ValueError, KeyError) as exc:
        return dict(status='UNSUPPORTED_VERSION_INTERPRETATION', value=None, root_name=root['name'], version_address=_address(db.database_id, root['value_target']), reason=str(exc))

def build_file_info(db, native_fields=None):
    """Return deterministic JSON-safe metadata from an existing NativeDatabase.

    No metadata scan or object enumeration is performed. The caller may reuse
    this same database snapshot for schema, mesh, and rendering outputs.
    """
    db.verify_source()
    directory = db.directory
    roots = db.roots()
    application_version = _application_version(db, roots, native_fields)
    segments = []
    extents_by_owner = {}
    for extent in directory['effective_extents']:
        extents_by_owner.setdefault((extent['segment'], extent['cluster']), []).append(extent)
    for sid, segment in sorted(directory['segments'].items(), key=lambda item: int(item[0])):
        sid = int(sid)
        clusters = []
        for cluster in db.iter_clusters(segment=sid):
            cid = cluster['cluster']
            tables = []
            for index, table in enumerate(cluster['metadata_tables']):
                if table is None:
                    tables.append(dict(index=index, present=False))
                    continue
                tables.append(dict(index=index, present=True, purpose='page_free_space' if index == 0 else 'allocation_tags_and_pointer_maps', directory_depth=table['kinds'][0], directory_shift=table['kinds'][1], extent_count=len(table['extents']), allocated_bytes=sum((e['sector_count'] * 512 for e in table['extents'])), global_overflow_enabled=bool(table.get('table_flag', 0))))
            extents = []
            for extent in extents_by_owner.get((sid, cid), []):
                extents.append({key: extent[key] for key in ('logical_start', 'physical_start', 'length', 'component', 'provenance')})
            clusters.append(dict(cluster=cid, flags=cluster['flags'], native_timestamp_raw=cluster['timestamp'], allocated_logical_bytes=cluster['allocated_bytes'], stored_used_bytes=cluster['used_bytes'], stored_used_within_allocation=0 <= cluster['used_bytes'] <= cluster['allocated_bytes'], data_extent_count=len(extents), data_extents=extents, metadata_tables=tables))
        segment_info = dict(segment=sid, flags=segment['flags'], native_timestamp_raw=segment['timestamp'], clusters=clusters)
        for key in ('mode', 'native_normalized_mode', 'owner', 'comment', 'pair'):
            if key in segment:
                segment_info[key] = segment[key]
        segments.append(segment_info)
    exported_roots = []
    for root in roots['roots']:
        address = _address(db.database_id, root['address'])
        spans = [dict(logical_start=span.logical_start, physical_start=span.physical_start, length=span.length) for span in db.spans(db.address(*root['address']), 24)]
        exported_roots.append(dict(index=root['index'], name=root['name'], declared_type=root['type_name'], record_address=address, value_address=_address(db.database_id, root['value_target']), typespec_address=_address(db.database_id, root['type_target']), name_raw_hex=root['name_raw_hex'], record_raw_hex=root['record_raw_hex'], record_source_spans=spans))
    clusters = [cluster for segment in segments for cluster in segment['clusters']]
    selected = directory['selected_outer_segment']
    streams = [dict(outer_segment=stream['outer_segment'], sequence=stream['sequence'], selected=stream['outer_segment'] == selected, payload_bytes=stream['payload_bytes'], source_spans=stream['source_spans']) for stream in directory['directory_streams']]
    header = directory['header']
    report = dict(format=FORMAT, contract_version=CONTRACT_VERSION, source=dict(name=db.source_path.name if db.source_path else None, path=str(db.source_path) if db.source_path else None, size_bytes=len(db.data), sha256=db.sha256, database_id=db.database_id, native_database_id_words=list(header['dbid'])), native_format=dict(magic_hex=header['magic_hex'], file_type=header['file_type'], consistency_condition=header['condition'], consistency_condition_name='consistent' if header['condition'] == 1 else 'unassigned', native_header_timestamp_raw=header['timestamp'], native_header_timestamp_as_unix_utc=_utc(header['timestamp']), directory_snapshot_version=directory['snapshot']['version'], client_database_header_version=roots['version'], root_pointer_width_bytes=8, application_version=application_version['value'], application_version_status=application_version['status'], application_version_evidence=application_version, application_version_root=next((root['value_address'] for root in exported_roots if root['declared_type'] == 'Fs::Version'), None)), directory=dict(selected_outer_segment=selected, selection_rule='lower_of_two_consecutive_sequences', streams=streams, replayed_event_count=directory['event_count'], consumed_payload_bytes=directory['consumed_payload_bytes'], byte_accounting=directory['byte_accounting'], consumed_source_spans=directory['consumed_source_spans']), storage_summary=dict(segment_count=len(segments), cluster_count=len(clusters), data_extent_count=len(directory['effective_extents']), allocated_logical_bytes=sum((c['allocated_logical_bytes'] for c in clusters)), stored_used_bytes=sum((c['stored_used_bytes'] for c in clusters)), stored_used_outside_allocation_count=sum((not c['stored_used_within_allocation'] for c in clusters)), present_metadata_table_count=sum((t['present'] for c in clusters for t in c['metadata_tables']))), roots=exported_roots, segments=segments, spatial_context=dict(coordinate_reference_system=None, coordinate_units=None, axis_order=None, status='UNKNOWN_NOT_DECODED_FROM_ACTIVE_COORDINATE_MANAGER'), coverage=dict(header_decoded=True, selected_directory_fully_consumed=bool(directory['complete']), root_count=roots['root_count'], root_count_resolved=len(exported_roots), current_extent_map=True, filewide_carving_used=False, full_object_enumeration_performed=False, full_geometry_enumeration_performed=False, application_version_root_decoded=application_version['value'] is not None, source_unchanged=True), limitations=['Stored used-byte counters are native fields, not a count of reachable objects or a promise of file-space reclamation.', 'Allocated logical bytes exclude metadata and historical bytes; subtracting them from file size does not yield free space.', 'The timestamp UTC field is a Unix-epoch interpretation of the native value, not a filesystem creation-date claim.', 'File type and schema/header format versions do not identify the FracSIS application release or ObjectStore producer release.', 'Declared void-pointer root types are preserved without assigning an inferred application type.', 'Application version is decoded only through its exact native root, schema member, PRM, and bounded character allocation.', 'Full object/schema, geometry, coordinate systems, units, materials, and rendered views belong to their separate outputs.', 'External database/storage components and enabled global overflow metadata are unsupported by the current facade.'])
    db.verify_source()
    return report

def export_file_info(db, output):
    """Write one new UTF-8 file exclusively; never replace an existing output."""
    output = Path(output)
    report = build_file_info(db)
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, ensure_ascii=True, indent=2, allow_nan=False)
        stream.write('\n')
    return output

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    db = NativeDatabase.from_path(arguments.source)
    output = export_file_info(db, arguments.output)
    print(output.resolve())
if __name__ == '__main__':
    main()
