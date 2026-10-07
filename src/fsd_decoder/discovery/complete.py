"""Complete indexed allocation/reference accounting with bounded typed pages.

The FSDX allocation and pointer tables are the inventory. Reusing their exact
identities avoids a second copy of millions of coordinate and interval objects.
Element ranges are accounted for; typed interpretation is reported separately.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import gzip
import os
from pathlib import Path
import tempfile
import time

from fsd_decoder.discovery.datasets import DiscoverySession, _character, _object, session_operation
from fsd_decoder.discovery.relationship_discovery import RelationshipError
from fsd_decoder.portable.format import MAX_BLOB_BYTES

COMPLETE_VERSION = 2


def export_all_objects(db, output, *, progress=None):
    """Publish a complete JSON-lines object stream, optionally gzip compressed.

    The summary is last, after integrity verification. Failure/interruption
    removes this operation's private staging file and publishes no partial run.
    """
    from fsd_decoder.core.provenance import runtime_identity
    from fsd_decoder.core.json_io import dump_json
    output = Path(output).absolute()
    if os.path.lexists(output):
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    session = DiscoverySession(db)
    with session_operation(session):
        status_counts, classification_counts = Counter(), Counter()
        started = time.monotonic()
        descriptor, name = tempfile.mkstemp(prefix='.discovery-', dir=output.parent)
        stage = Path(name)
        os.close(descriptor)
        try:
            opener = gzip.open if output.suffix == '.gz' else open
            options = dict(encoding='utf-8')
            if opener is gzip.open:
                options['compresslevel'] = 1
            with opener(stage, 'wt', **options) as stream:
                def emit(value):
                    dump_json(value, stream, ensure_ascii=True, allow_nan=False)
                    stream.write('\n')
                emit(dict(record='header', format='FSD_DISCOVERY_OBJECT_STREAM', version=1,
                    source=dict(db.source_info), runtime_identity=runtime_identity(),
                    type_census=session.census, allocations_counted=session.total,
                    policy='ALL_CLASS_ELEMENTS; NATIVE_OR_UNKNOWN_ARRAYS_AS_PAYLOAD_RECORDS',
                    application_semantics_complete=False))
                for obj in session.iter_objects(progress=progress):
                    emit(dict(record='object', object=obj))
                    status_counts[obj['status']] += 1
                    classification_counts[obj['classification']] += 1
                summary = dict(record='summary', status='COMPLETE', enumeration_complete=True,
                    objects_inspected=sum(status_counts.values()), status_counts=dict(status_counts),
                    classification_counts=dict(classification_counts),
                    elapsed_seconds=time.monotonic()-started, application_semantics_complete=False,
                    original_source_required=False)
                emit(summary)
            with stage.open('rb') as stream:
                os.fsync(stream.fileno())
            os.link(stage, output)
            return dict(summary, output=str(output))
        finally:
            stage.unlink(missing_ok=True)


def _member_views(slots, displacement):
    views = []
    for slot in slots:
        if slot['kind'] != 'pointer' and not (
                slot['kind'] == 'class' and (slot['type_name'] or '').startswith(
                    ('os_soft_pointer32<', 'os_hard_pointer32<',
                     'os_soft_pointer64<', 'os_hard_pointer64<'))):
            continue
        delta = displacement - slot['offset']
        if delta < 0:
            continue
        indices = []
        for array in slot['arrays']:
            stride = array.get('stride')
            if type(stride) is not int or stride <= 0:
                delta = -1
                break
            index, delta = divmod(delta, stride)
            if index >= array['count']:
                delta = -1
                break
            indices.append(index)
        if delta == 0:
            views.append(dict(path=slot['path'], array_indices=indices,
                conditional_union=slot['conditional_union'],
                evidence='DECLARED_SLOT_POSITION; ACTIVE_UNION_NOT_INFERRED'))
    return views


def build_complete_discovery(db, *, progress=None, session=None,
                             collection_options: Mapping | None = None):
    """Account for every allocation, stored element range and recorded binding.

    SQL streams the source indexes and aggregates reference shapes. Only the
    established Entity family is expanded into typed object pages here. Other
    objects remain discoverable through source-derived type selectors and exact
    allocation/element addresses; none is silently dropped or called a dataset.
    """
    started = time.monotonic()
    session = session or DiscoverySession(db)
    with session_operation(session):
        if session.db is not db:
            raise RelationshipError('Discovery session belongs to another store')
        census = session.census
        declarations = {row['type']: row for row in census}
        conn = db.store.connection
        coverage = []
        represented_elements = represented_allocations = 0
        # A template group is a set selected by name_id/template_id, not a contiguous
        # id interval: intervening allocation ids must never be claimed as members.
        for name, template_id, native_tag, raw, count, elements, size, vectors, minimum, maximum in conn.execute('''
            SELECT n.name,a.template_id,a.native_tag,
              CASE WHEN length(CAST(t.metadata AS BLOB))<=? THEN t.metadata END,
              count(*),sum(a.element_count),sum(a.size),sum(a.vector),min(a.id),max(a.id)
            FROM allocations a JOIN names n ON n.id=a.name_id
            JOIN allocation_templates t ON t.id=a.template_id
            GROUP BY a.name_id,a.template_id,a.native_tag''', (MAX_BLOB_BYTES,)):
            from fsd_decoder.portable.format import decode_json
            template = decode_json(raw) if raw is not None else None
            declaration = declarations[name]
            coverage.append(dict(type=name, template_id=template_id,
                native_tag=native_tag,
                allocations=count, stored_elements=elements, bytes=size, vectors=vectors,
                minimum_allocation_id=minimum, maximum_allocation_id=maximum,
                selector=dict(table='allocations', name=name, template_id=template_id, native_tag=native_tag),
                element_identity='a{allocation_id}:e{0..element_count-1}',
                template=template,
                status='INDEXED_SCHEMA_ELEMENTS' if template is not None and
                       db.fields.schema_admission(dict(template, native_tag=native_tag, name=name))['admitted'] else
                       'INDEXED_NATIVE_OR_UNKNOWN_ELEMENTS',
                typed_values_individually_inspected=False))
            represented_allocations += count
            represented_elements += elements
        actual = conn.execute('SELECT count(*),coalesce(sum(element_count),0) FROM allocations').fetchone()
        if (represented_allocations, represented_elements) != tuple(actual):
            raise RelationshipError('Complete discovery allocation/element accounting mismatch')

        if progress:
            progress(dict(phase='discovery_accounting', allocations=represented_allocations,
                          stored_elements=represented_elements, finished=True))
        relations = []
        pointer_counts = Counter()
        # Exact predecessor probes use the existing allocation address index. A
        # predecessor is accepted only when the full source slot / target is inside.
        # Targets in unallocated gaps never attach to the nearest preceding object.
        query = '''WITH mapped AS (
          SELECT p.*,
            (SELECT a.id FROM allocations a WHERE a.segment=p.segment AND a.cluster=p.cluster
             AND a.logical_offset<=p.logical_offset ORDER BY a.logical_offset DESC LIMIT 1) AS sid,
            (SELECT a.id FROM allocations a WHERE a.segment=p.target_segment AND a.cluster=p.target_cluster
             AND a.logical_offset<=p.target_offset ORDER BY a.logical_offset DESC LIMIT 1) AS tid
          FROM pointers p)
          SELECT sn.name,tn.name,p.status,
            CASE WHEN s.id IS NULL THEN NULL ELSE
              CASE WHEN s.vector=1 AND json_extract(st.metadata,'$.element_stride')>0
              THEN (p.logical_offset-s.logical_offset-coalesce(json_extract(st.metadata,'$.array_header_size'),0))
                % json_extract(st.metadata,'$.element_stride')
              ELSE p.logical_offset-s.logical_offset END END AS slot_displacement,
            p.width,count(*)
          FROM mapped p
          LEFT JOIN allocations s ON s.id=p.sid
            AND p.logical_offset+p.width<=s.logical_offset+s.size
          LEFT JOIN allocations t ON t.id=p.tid AND p.target_offset<t.logical_offset+t.size
          LEFT JOIN names sn ON sn.id=s.name_id LEFT JOIN names tn ON tn.id=t.name_id
          LEFT JOIN allocation_templates st ON st.id=s.template_id
          GROUP BY sn.name,tn.name,p.status,slot_displacement,p.width
          ORDER BY sn.name,slot_displacement,tn.name,p.status,p.width'''
        for source_type, target_type, status, displacement, width, count in conn.execute(query):
            declaration = declarations.get(source_type, {})
            views = _member_views(declaration.get('slots', ()), displacement) if displacement is not None else []
            relations.append(dict(source_type=source_type, target_type=target_type,
                status=status, slot_displacement=displacement, width=width, bindings=count,
                declaration_views=views, meaning='CURRENT_RECORDED_REFERENCE; OWNERSHIP_NOT_INFERRED'))
            pointer_counts[status] += count
            if len(relations) > 100000:
                raise RelationshipError('Reference shape report exceeds 100000 groups')
        expected_pointers = conn.execute('SELECT count(*) FROM pointers').fetchone()[0]
        if sum(pointer_counts.values()) != expected_pointers:
            raise RelationshipError('Complete discovery binding accounting mismatch')
        if progress:
            progress(dict(phase='discovery_references', pointer_bindings=expected_pointers,
                          reference_shapes=len(relations), finished=True))

        metadata = dict(project_name='Not established', creation_date='Not established',
                        header_timestamp_raw=db.header.get('timestamp'))
        metadata_evidence = []
        roots = db.roots().get('roots', [])
        if len(roots) > 1000:
            raise RelationshipError('Root metadata inspection exceeds 1000 roots')
        for root in roots:
            location = root.get('value_target')
            if not location:
                continue
            allocation = db.allocation(*location)
            if allocation is None:
                continue
            declaration = declarations.get(allocation['name'], {})
            # Root labels alone are not values. Inspect relevant declared fields.
            if not declaration.get('schema_class') or not any(
                    any('.' + member + '.' in slot['path'] or slot['path'].endswith('.' + member)
                        for member in ('m_versionString', 'm_projectName', 'm_createTime', 'm_creationDate'))
                    for slot in declaration['slots']):
                continue
            delta = location[2] - allocation['logical_offset'] - allocation.get('array_header_size', 0)
            stride = allocation.get('element_stride', allocation['size'])
            if delta < 0 or not stride or delta % stride:
                continue
            obj = _object(db, session.reader, allocation, delta // stride, declaration,
                          max_element_bytes=65536, max_text_bytes=65536, max_references=128)
            for field in obj.get('text_fields', []):
                for member, key in (('m_versionString', 'fracsis_version'), ('m_projectName', 'project_name')):
                    if ('.' + member + '.') in field['path'] and field['status'] == 'TERMINATED' and field['text']:
                        metadata_evidence.append(dict(root=root['name'], object_id=obj['id'], field=field, role=key))
                        if key not in metadata or metadata[key] == 'Not established':
                            metadata[key] = field['text']
                        elif metadata[key] != field['text']:
                            metadata[key] = 'Conflicting source values; see metadata evidence'
        metadata.setdefault('fracsis_version', 'Not recovered')
        if progress:
            progress(dict(phase='file_information', information=metadata))
        entities, name_candidates = [], []
        for declaration in census:
            if not declaration.get('entity_family') and not declaration.get('source_entity_candidate'):
                continue
            cursor = None
            while True:
                page = session.page(type_name=declaration['type'], cursor=cursor, max_objects=128,
                                    progress=progress,
                                    include_collections=False)
                destination = entities if declaration.get('entity_family') else name_candidates
                destination.extend(page['objects'])
                if len(entities) + len(name_candidates) > 100000:
                    raise RelationshipError('Entity report exceeds 100000 objects; use typed pagination')
                if progress:
                    # Compact UI evidence, never a second object inventory or
                    # promotion to confirmed application meaning. Full records
                    # and source text remain in the discovery document.
                    rows = []
                    for obj in page['objects']:
                        names = obj.get('name_fields', [])
                        rows.append(dict(id=obj['id'], type=obj['type'][:256],
                            names=[dict(text=field['text'][:256], status=field['status'])
                                   for field in names[:4]],
                            names_truncated=len(names) > 4 or any(len(f['text']) > 256 for f in names[:4]),
                            classification='ESTABLISHED_ENTITY' if declaration.get('entity_family') else 'SOURCE_ENTITY_NAME_CANDIDATE',
                            creation_time_fields=obj.get('creation_time_fields', []),
                            status=obj['status'], address=obj['address']))
                    progress(dict(phase='dataset_discovery_rows', datasets=rows,
                                  entities_discovered=len(entities), name_candidates=len(name_candidates)))
                cursor = page['inspection']['next_cursor']
                # Object summaries are retained by the report; their full decoded
                # field trees and allocation metadata are not. Release each page's
                # working set before inspecting the next one or membership phase.
                session.reader.decode.cache_clear()
                session.reader.allocation.cache_clear()
                if cursor is None:
                    break
        candidates = []
        for declaration in census:
            if declaration.get('entity_family'):
                continue
            reasons = []
            slots = declaration['slots']
            if any(_character(slot['pointee_type']) and not slot['conditional_union'] for slot in slots):
                reasons.append('SOURCE_SCHEMA_TEXT_REFERENCE')
            if any(slot['pointee_type'] and not _character(slot['pointee_type'])
                   and not slot['conditional_union'] for slot in slots):
                reasons.append('SOURCE_SCHEMA_NON_TEXT_REFERENCE')
            if not declaration['schema_class']:
                reasons.append('NATIVE_OR_UNKNOWN_STORAGE_RETAINED')
            candidates.append(dict(type=declaration['type'], allocations=declaration['allocations'],
                elements=declaration['elements'], reasons=reasons,
                classification='UNCONFIRMED_OBJECT_FAMILY',
                access=dict(command='discover --type', type_name=declaration['type']),
                application_role='UNESTABLISHED'))
        if progress:
            for start in range(0, len(candidates), 128):
                progress(dict(phase='dataset_discovery_rows', datasets=[dict(
                    id='family:' + row['type'], type=row['type'][:256], names=[],
                    classification='UNCONFIRMED_OBJECT_FAMILY', status='ROLE_UNESTABLISHED',
                    allocations=row['allocations'], elements=row['elements'])
                    for row in candidates[start:start + 128]],
                    candidate_families=min(start + 128, len(candidates))))
        result = dict(format='FSD_DATASET_DISCOVERY', version=COMPLETE_VERSION, source=dict(db.source_info),
            policy='COMPLETE_SOURCE_INDEX_AND_SCHEMA_ACCOUNTING; NO_INSTANCE_NAME_ALLOWLIST',
            type_census=census, census_complete=True, allocations_counted=represented_allocations,
            objects=entities, dataset_candidate_types=candidates, allocation_groups=coverage,
            dataset_name_candidates=name_candidates, file_metadata=metadata,
            file_metadata_evidence=metadata_evidence,
            reference_shapes=relations,
            accounting=dict(complete=True, allocations=represented_allocations,
                stored_elements=represented_elements, pointer_bindings=expected_pointers,
                pointer_status_counts=dict(pointer_counts),
                source_bindings_without_allocation=sum(row['bindings'] for row in relations if row['source_type'] is None),
                resolved_targets_without_allocation=sum(row['bindings'] for row in relations
                    if row['status']=='RESOLVED' and row['target_type'] is None),
                allocation_index='allocations JOIN names JOIN allocation_templates',
                reference_index='pointers; exact slot and target addresses retained',
                representation='EXACT_INDEXED_ALLOCATION_AND_ELEMENT_SETS; NOT_EXPANDED_VALUE_JSON'),
            inspection=dict(objects_inspected=len(entities) + len(name_candidates), enumeration_complete=True,
                enumeration_scope='COMPLETE_ALLOCATION_AND_ELEMENT_INDEX_ACCOUNTING',
                typed_values_complete=False, reference_views_complete=True,
                reference_scope='EVERY_RECORDED_BINDING; IMPLICIT_NULL_SLOTS_REQUIRE_TYPED_INSPECTION',
                next_cursor=None),
            original_source_required=False, application_semantics_complete=False,
            elapsed_seconds=time.monotonic()-started,
            limitations=['Indexed element accounting is separate from individual typed inspection.',
                'Object families outside Entity remain unconfirmed; no arbitrary names or ownership are assigned.',
                'Conditional union slots are declarations, not established active relationships.',
                'Original physical history remains in the archival FSD.'])
        # Describe optional access without executing a global census or claiming
        # its coverage. Range evidence and actual value pages have separate APIs.
        result['payload_census_access'] = dict(status='NOT_RUN_BY_DEFAULT',
            module='fsd_decoder.discovery.payload_census',
            api='discover_payload_census_batch', format='FSD_PAYLOAD_CENSUS',
            checkpoint_required=True, execution='EXPLICIT_BOUNDED_RESUMABLE_BATCHES',
            retained_evidence=dict(api='iter_payload_census',
                selectors=dict(kind=['allocations', 'plans', 'raw_ranges', 'unindexed_ranges', 'value_ranges',
                    'binding_ranges', 'incoming', 'incoming_views',
                    'incoming_allocations', 'declarations', 'unrecorded_views'],
                    after_id='EXCLUSIVE_RETAINED_ROW_ID', limit='BOUNDED_ROW_COUNT'),
                scope='RETAINED_CHECKPOINT_EXECUTION'),
            actual_value_pages=dict(module='fsd_decoder.portable.text_pages',
                api='export_text_page', resume_api='export_text_pages',
                read_api='read_text_pages', format='FSDX_RESUMABLE_TEXT_PAGES',
                evidence='ACTUAL_TYPED_VALUES_AND_EXPLICIT_RAW_BYTE_PAGES',
                portable_store_required=True, original_fsd_required=False),
            evidence_facets=dict(incoming_scope='EXACT_ADDRESSED_ELEMENTS_BASE_AND_BYTE_VIEWS',
                first_element_reference_establishes_allocation_remainder=False,
                raw_bytes='DISJOINT_INDEXED_ALLOCATION_BYTE_RANGES',
                retained_logical_bytes='INDEXED_ALLOCATION_BYTES_AND_DISJOINT_RAW_UNINDEXED_CHUNK_RANGES',
                unindexed_ranges_establish_missing_objects=False,
                physical_history_included=False,
                values='RETAINED_VALUE_RANGE_CLASSIFICATION',
                primitive_block_checks='SEPARATE_FROM_INDIVIDUAL_VALUE_INTERPRETATION',
                actual_interpretation='RETAINED_INTERPRETATION_COUNTS_AND_ACTUAL_VALUE_PAGES',
                raw_logical_coverage_is_semantic_coverage=False),
            ownership='UNKNOWN', application_semantics_complete=False)
        from .roles import build_role_inventory
        result['dataset_roles'] = build_role_inventory(db, result)
        result['dataset_roles']['payload_census_access_reference'] = 'payload_census_access'
        from .membership import discover_membership, reconcile_entities
        result['collection_evidence'] = discover_membership(session, progress=progress,
            **(collection_options or {}))
        result['dataset_roles']['collection_evidence_reference'] = 'collection_evidence'
        result['entity_reconciliation'] = reconcile_entities(result, result['collection_evidence'])
        session.finish()
        if progress:
            progress(dict(phase='dataset_discovery_summary', entities_discovered=len(entities),
                name_candidates=len(name_candidates),
                candidate_families=len(candidates), enumeration_complete=True,
                application_semantics_complete=False))
        return result
