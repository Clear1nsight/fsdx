"""Bounded, source-independent plaintext views of explicitly selected Entities.

Field labels and allocation element ranges are source evidence. Neither the
selection nor a reference assigns geometry ownership, CRS, units or an active
union arm. The final summary reconciles emitted records against selected ranges;
it never promotes byte/index accounting into complete application semantics.
"""
from __future__ import annotations

from collections import Counter, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, is_dataclass
import os
from pathlib import Path
import re
import tempfile
from typing import TextIO

from fsd_decoder.core.json_io import dump_json
from fsd_decoder.core.interpretation import interpretation_facets
from fsd_decoder.core.provenance import runtime_identity
from fsd_decoder.core.diagnostics import require_source_failure
from fsd_decoder.discovery.datasets import DiscoverySession, session_operation, _slots
from fsd_decoder.discovery.payload_links import iter_payload_links, inspect_payload_reference, inspect_current_storage_reference, _kind
from fsd_decoder.discovery.collections import inspect_collection
from fsd_decoder.discovery.hash_sets import collection_type_context
from fsd_decoder.discovery.payload_links import _location, _selector, _traversal, _current_storage_pointer_gaps
from fsd_decoder.discovery.relationship_discovery import inspect_element
from fsd_decoder.exports.catalog import CatalogError
from fsd_decoder.portable.exports import ExportError, _digest, _json_default, _source


def _limit(value: int, name: str, ceiling: int) -> int:
    if type(value) is not int or not 1 <= value <= ceiling:
        raise ExportError(f'{name} must be an integer from 1 to {ceiling}')
    return value


def _address(db, value) -> dict:
    if is_dataclass(value):
        value = asdict(value)
    if not isinstance(value, Mapping):
        try:
            value = dict(zip(('segment', 'cluster', 'offset'), value, strict=True))
        except (TypeError, ValueError):
            raise ExportError('Selection requires segment, cluster and offset') from None
    if value.get('database', db.database_id) != db.database_id:
        raise ExportError('Selection belongs to another database')
    if any(type(value.get(k)) is not int or value[k] < 0 for k in ('segment', 'cluster', 'offset')):
        raise ExportError('Selection address components must be nonnegative integers')
    return dict(database=db.database_id, **{k: value[k] for k in ('segment', 'cluster', 'offset')})


def _element(db, address: Mapping) -> tuple[dict, int]:
    allocation = db.allocation(address['segment'], address['cluster'], address['offset'])
    if allocation is None:
        raise ExportError('Selection is outside a current allocation')
    relative = address['offset'] - allocation['logical_offset'] - allocation.get('array_header_size', 0)
    stride = allocation.get('element_stride', allocation.get('element_size', allocation['size']))
    if relative < 0 or stride <= 0 or relative % stride:
        raise ExportError('Selection is not an exact current element start')
    index = relative // stride
    if index >= allocation.get('count', 1):
        raise ExportError('Selection exceeds the current element count')
    return allocation, index


def _emit(stream: TextIO, record: str, value: Mapping) -> None:
    stream.write(record.upper() + ' ')
    dump_json(value, stream, default=_json_default, ensure_ascii=True,
              allow_nan=False, separators=(',', ':'))
    stream.write('\n')


def _incoming_link(link: Mapping) -> dict:
    """Retain occurrence identity separately from the emitted target range."""
    keys = ('source_address', 'slot_address', 'field_path', 'source_type',
            'parent_allocation_id', 'parent_element_index', 'collection_address',
            'collection_member_slot_index', 'member_evidence', 'declared_pointee',
            'declaration_scope', 'binding_status', 'binding_evidence', 'raw_hex',
            'stored_word', 'target_address', 'target_view', 'target_type_status',
            'status', 'traversal', 'depth', 'path', 'payload_selector', 'target_role')
    return {key: link[key] for key in keys if key in link}


def _continuation_reason(counts, reason: str, local=None) -> dict:
    """Aggregate finite outcomes, never source paths or target identities."""
    counts['continuation_' + reason] += 1
    if local is not None:
        local[reason] += 1
    return dict(reason=reason)


def _reference_continuation_scope(requested: bool, counts=None) -> dict:
    result = dict(requested=requested,
        status=('REQUESTED' if counts is None else 'ATTEMPTED') if requested else 'NOT_ATTEMPTED',
        scope='STORED_REFERENCE_OCCURRENCES_IN_EXPORTED_PAYLOAD_RECORDS',
        collection_policy='INDEPENDENT_VERIFIED_MEMBERSHIP_ADAPTER',
        collection_member_occurrence_scope='ADAPTER_RETURNED_MEMBER_ROWS; OTHER_SLOT_STATES_RETAINED_IN_ADAPTER_EVIDENCE',
        completion_policy='EXISTING_FLAGS_RETAIN_CONFIGURED_ENUMERATION_MEANINGS',
        reason_count_policy='DECISION_OCCURRENCES; NOT_A_SOURCE_OR_TARGET_POPULATION',
        exact_range_deduplication_scope='ONE_SELECTED_ENTITY_QUEUE',
        overlapping_ranges_globally_deduplicated=False)
    if counts is not None:
        result.update(payload_reference_occurrences=counts['payload_reference_occurrences'],
            collection_member_occurrences=counts['collection_member_occurrences'],
            outcome_counts={key.removeprefix('continuation_'): value
                for key, value in counts.items() if key.startswith('continuation_')},
            processed_exact_ranges=counts['payload_ranges'],
            repeated_exact_range_suppressions=counts['duplicate_payload_ranges'],
            bounded_reference_occurrences=counts['reference_follow_bounds'],
            unattempted_reference_occurrences=counts['continuation_NOT_ATTEMPTED'],
            unexported_selected_records=counts['omitted_records'],
            untyped_exported_records=counts['untyped_records'],
            unverified_collection_populations=counts['unverified_collection_populations'],
            residual_reference_population='UNEXPORTED_OR_UNTYPED_RECORDS_AND_UNVERIFIED_ADAPTERS_NOT_COUNTED')
    return result


def _decode(db, allocation: Mapping, index: int, maximum: int, *, raw_fallback: bool = False) -> dict:
    """Admit one bounded element and a bounded source-declared field population."""
    size = allocation.get('element_size', allocation['size']) if allocation.get('vector') else allocation['size']
    if size > maximum:
        return dict(status='ELEMENT_SIZE_BOUND', element_size=size, max_element_bytes=maximum)
    base = allocation['name'].removesuffix('[]')
    if db.fields.schema_admission(allocation)['admitted']:
        slots = _slots(db.fields.schema, base)
        leaves = 0
        for slot in slots:
            count = 1
            for array in slot['arrays']:
                count *= array['count']
            leaves += count
        if leaves > 4096:
            return dict(status='SCHEMA_INSPECTION_BOUND', declared_leaves=leaves, max_leaves=4096)
    try:
        return db.fields.decode(allocation, element_index=index)
    except Exception as exc:
        if not raw_fallback:
            raise
        require_source_failure(exc, dict(phase='current_storage_value',
            name=allocation['name'], element_index=index))
        offset = (allocation['logical_offset'] + allocation.get('array_header_size', 0) +
            index * allocation.get('element_stride', allocation['size']))
        return inspect_element(db, allocation['segment'], allocation['cluster'], offset,
            max_element_bytes=maximum, include_scalars=True)


def _selection(db, session, addresses, type_name):
    if addresses is not None:
        for address in addresses:
            address = _address(db, address)
            allocation, index = _element(db, address)
            if not db.fields.schema_admission(allocation)['admitted'] or not session.reader.inherits(allocation['name'].removesuffix('[]'), 'Fs::Entity'):
                raise ExportError('Selected element does not derive from source-declared Fs::Entity')
            yield address, allocation, index
        return
    declaration = next((row for row in session.census if row['type'] == type_name), None)
    if declaration is None or not declaration.get('entity_family'):
        raise ExportError('Selected exact allocation type is not a current source-declared Entity type')
    for allocation in db.iter_allocations(name=type_name):
        for index in range(allocation.get('count', 1)):
            offset = (allocation['logical_offset'] + allocation.get('array_header_size', 0)
                      + index * allocation.get('element_stride', allocation['size']))
            yield _address(db, (allocation['segment'], allocation['cluster'], offset)), allocation, index


def _affiliation(entity, affiliation=None):
    """Preserve legacy Entity fields; root output carries occurrence provenance."""
    return {'entity_address': entity} if affiliation is None else dict(affiliation)


def _queue_collection_members(db, session, stream, entity, link, pending, queued,
                             counts, *, processed_ranges, max_nodes, max_links, max_depth,
                             max_collection_nodes, max_collection_members,
                             max_collection_slots, affiliation=None, follow_affiliated_entities=False):
    selector = link['payload_selector']
    address = selector['canonical_address']
    available = dict(nodes=min(max_nodes-counts['nodes_inspected'],
                              max_collection_nodes-counts['collection_nodes']),
                     members=max_collection_members-counts['collection_member_evidence'],
                     slots=max_collection_slots-counts['collection_slots'])
    if min(available.values()) <= 0 or link.get('depth', 1) >= max_depth:
        counts['unverified_collection_populations'] += 1
        counts['unresolved'] += 1
        _emit(stream, 'collection', dict(**_affiliation(entity, affiliation), address=address,
            field_path=link.get('field_path'), status='COLLECTION_RESOURCE_BOUND',
            incoming_link=_incoming_link(link), export_continuation=_continuation_reason(counts,
                'DEPTH_BOUND' if link.get('depth', 1) >= max_depth else 'COLLECTION_RESOURCE_BOUND'),
            declared_count=None, omitted_members=None, configuration_remaining=available,
            membership_complete=False, ownership='NOT_INFERRED'))
        return False
    context = None
    base = selector['type'].removesuffix('[]')
    if session.reader.inherits(base, 'os_set') and '::<os_Collection<' in (link.get('field_path') or ''):
        try:
            context = collection_type_context(session.reader, address,
                link['source_address'], link['field_path'])
        except CatalogError as exc:
            counts['unverified_collection_populations'] += 1
            counts['unresolved'] += 1
            _emit(stream, 'collection', dict(**_affiliation(entity, affiliation), address=address,
                status='SOURCE_COLLECTION_CONTEXT_UNCONFIRMED', error=str(exc),
                incoming_link=_incoming_link(link), export_continuation=_continuation_reason(counts,
                    'SOURCE_COLLECTION_CONTEXT_UNCONFIRMED'),
                membership_complete=False, ownership='NOT_INFERRED'))
            return False
    result = inspect_collection(session.reader, address, max_nodes=available['nodes'],
        max_members=available['members'], max_slots=available['slots'], type_context=context)
    counts['collections_inspected'] += 1
    counts['collection_nodes'] += len(result['nodes'])
    counts['nodes_inspected'] += len(result['nodes'])
    evidence = sum(len(result.get(key, ())) for key in
                   ('members', 'slot_references', 'incompatible_self_references'))
    counts['collection_member_evidence'] += evidence
    slots = result.get('scanned_slots', sum(n.get('pointer_capacity', 0) for n in result['nodes']))
    counts['collection_slots'] += slots
    counts['collection_member_occurrences'] += len(result.get('members', ()))
    verified = (result['status'] == 'VERIFIED_CARDINALITY' and result.get('equal')
                and result['declared_count'] == result['observed_count'])
    _emit(stream, 'collection', dict(**_affiliation(entity, affiliation), source_address=link.get('source_address'),
        field_path=link.get('field_path'), evidence=result,
        incoming_link=_incoming_link(link), export_continuation=_continuation_reason(counts,
            'ADAPTER_VERIFIED' if verified else 'ADAPTER_UNVERIFIED'),
        accepted_for_record_export=verified, ownership='NOT_INFERRED'))
    declared = result.get('declared_count')
    if type(declared) is int:
        counts['collection_declared_members'] += declared
    if not verified:
        counts['unverified_collection_populations'] += 1
        counts['unresolved'] += 1
        counts['collection_unverified_observed_members'] += len(result.get('members', ()))
        if type(declared) is int:
            counts['collection_omitted_members'] += declared
        return False
    counts['collection_verified_members'] += result['observed_count']
    complete = True
    for member in result['members']:
        target = member.get('address')
        if target is None:
            counts['collection_null_members'] += 1
            _emit(stream, 'member', dict(**_affiliation(entity, affiliation), collection_address=address,
                evidence=member, status='VERIFIED_NULL_MEMBER_SLOT',
                export_continuation=_continuation_reason(counts, 'NULL_ENDPOINT'), ownership='NOT_INFERRED'))
            continue
        declared_type = dict(kind='class', name=context['element_type']) if context else None
        allocation, view = _location(db, target, declared_type)
        if allocation is None or 'canonical_address' not in view:
            counts['collection_omitted_members'] += 1
            counts['unresolved'] += 1
            complete = False
            _emit(stream, 'member', dict(**_affiliation(entity, affiliation), collection_address=address,
                evidence=member, target_view=view, status='MEMBER_ELEMENT_UNCONFIRMED',
                export_continuation=_continuation_reason(counts, 'MEMBER_ELEMENT_UNCONFIRMED'),
                ownership='NOT_INFERRED'))
            continue
        child_selector = _selector(allocation, view)
        child_selector.update(stored_elements=1, extent_semantics='ONE_VERIFIED_COLLECTION_MEMBER_ELEMENT')
        child = dict(record='link', **_affiliation(entity, affiliation), collection_address=address,
            source_address=member.get('source_address'), field_path=link.get('field_path'),
            slot_address=member.get('source_address'),
            parent_allocation_id=selector['allocation_id'],
            parent_element_index=selector['element_start_index'],
            collection_member_slot_index=member.get('slot_index'),
            target_address=target, target_view=view, payload_selector=child_selector,
            traversal=_traversal(session, allocation, declared_type), declared_pointee=declared_type,
            status='VERIFIED_COLLECTION_MEMBER_CURRENT_ELEMENT', depth=link.get('depth', 1) + 1,
            path=link.get('path', []), member_evidence=member, ownership='NOT_INFERRED')
        if follow_affiliated_entities and child['traversal'] == 'OTHER_ENTITY':
            child['traversal'] = 'SOURCE_ROOT_AFFILIATED_ENTITY_RECORD'
            child['target_role'] = 'SOURCE_ROOT_AFFILIATED_ENTITY_RECORD'
        key = (child_selector['allocation_id'], child_selector['element_start_index'], 1)
        reason = ('REPEATED_EXACT_RANGE' if key in queued or key in processed_ranges else
                  'NODE_BOUND' if counts['nodes_inspected'] >= max_nodes else
                  'LINK_BOUND' if counts['link_records'] >= max_links else 'QUEUED_RANGE')
        child['export_continuation'] = _continuation_reason(counts, reason)
        _emit(stream, 'member', child)
        if reason == 'REPEATED_EXACT_RANGE':
            counts['duplicate_payload_ranges'] += 1
            continue
        if counts['nodes_inspected'] >= max_nodes or counts['link_records'] >= max_links:
            counts['collection_omitted_members'] += 1
            counts['declared_records'] += 1
            counts['omitted_records'] += 1
            complete = False
            continue
        counts['nodes_inspected'] += 1
        counts['link_records'] += 1
        queued.add(key)
        pending.append(child)
    return complete


def _write_payloads(db, session, stream, entity, pending, counts, *, max_records,
                    max_nodes, max_links, max_depth, max_element_bytes,
                    follow_reference_payloads, max_collection_nodes,
                    max_collection_members, max_collection_slots,
                    window_key=None, window_result=None, affiliation=None, follow_affiliated_entities=False,
                    current_storage_graph=False, graph_gaps=None):
    """Drain a budgeted queue; no reference is admitted without indexed evidence."""
    payloads = set()
    queued = {(r['payload_selector']['allocation_id'], r['payload_selector']['element_start_index'],
               r['payload_selector']['stored_elements']) for r in pending}
    follow_complete = True
    while pending:
        link = pending.popleft()
        selector = link['payload_selector']
        target = _address(db, selector['allocation_address'])
        allocation = db.allocation(target['segment'], target['cluster'], target['offset'])
        first, total = selector['element_start_index'], selector['stored_elements']
        if (allocation is None or allocation['logical_offset'] != target['offset']
                or allocation.get('store_allocation_id') != selector['allocation_id']
                or type(first) is not int or type(total) is not int or first < 0 or total < 0
                or first + total > allocation.get('count', 1)):
            raise ExportError('Payload selector disagrees with current allocation index')
        key = (selector['allocation_id'], first, total)
        queued.discard(key)
        if key in payloads:
            counts['duplicate_payload_ranges'] += 1
            _continuation_reason(counts, 'REPEATED_EXACT_RANGE')
            continue
        payloads.add(key)
        counts['payload_ranges'] += 1
        counts['declared_records'] += total
        collection = link.get('traversal') == 'COLLECTION_MEMBERSHIP_REQUIRES_ADAPTER'
        if collection:
            verified = _queue_collection_members(db, session, stream, entity, link, pending, queued,
                counts, processed_ranges=payloads, max_nodes=max_nodes, max_links=max_links, max_depth=max_depth,
                max_collection_nodes=max_collection_nodes, max_collection_members=max_collection_members,
                max_collection_slots=max_collection_slots, affiliation=affiliation,
                follow_affiliated_entities=follow_affiliated_entities)
            follow_complete = follow_complete and verified
        if link.get('traversal') == 'OTHER_ENTITY' and not follow_affiliated_entities:
            counts['excluded_records'] += total
            _emit(stream, 'payload', dict(**_affiliation(entity, affiliation), selector=selector,
                status='TERMINAL_APPLICATION_LINK', exported_records=0,
                incoming_link=_incoming_link(link), export_continuation=_continuation_reason(counts,
                    'OTHER_ENTITY_REQUIRES_EXPLICIT_SELECTION'),
                excluded_records=total, omitted_records=0,
                selection_policy='REQUIRES_SEPARATE_EXPLICIT_SELECTION_OR_COLLECTION_ADAPTER'))
            follow_complete = False
            if key == window_key and window_result is not None:
                window_result.update(exported=0,omitted=0,excluded=total)
            continue
        written = 0
        untyped = 0
        outcomes = Counter()
        reference_occurrences = 0
        for index in range(first, first + total):
            if counts['records'] == max_records:
                break
            decoded = _decode(db, allocation, index, max_element_bytes, raw_fallback=current_storage_graph)
            facets = interpretation_facets(decoded)
            offset = (target['offset'] + allocation.get('array_header_size', 0)
                      + index * allocation.get('element_stride', allocation['size']))
            record_address = dict(target, offset=offset)
            if graph_gaps is not None:
                gaps = _current_storage_pointer_gaps(decoded)
                graph_gaps.update(gaps)
                if gaps:
                    _emit(stream, 'diagnostic', dict(**_affiliation(entity, affiliation),
                        status='CURRENT_STORAGE_GRAPH_POINTER_CLASSIFICATION_GAP',
                        current_storage_graph_gaps=gaps, payload_selector=selector,
                        element_index=index, raw_selector=decoded.get('raw_selector') or dict(
                            address=record_address, size=allocation.get('element_size', allocation['size'])
                            if allocation.get('vector') else allocation['size']),
                        incoming_link=_incoming_link(link)))
            if not facets['typed_fields_complete']:
                counts['unresolved'] += 1
                counts['untyped_records'] += 1
                untyped += 1
                _continuation_reason(counts, 'UNTYPED_RECORD', outcomes)
            _emit(stream, 'record', dict(**_affiliation(entity, affiliation),
                source_address=link.get('source_address'), field_path=link.get('field_path'),
                incoming_link=_incoming_link(link),
                address=record_address, type=allocation['name'],
                allocation_id=selector['allocation_id'], element_index=index,
                value=decoded, interpretation=facets))
            counts['records'] += 1
            written += 1
            if collection:
                continue
            references = ([decoded] if decoded.get('kind') == 'stored_reference' else
                          (field for field in decoded.get('fields', ())
                           if field.get('kind') == 'stored_reference'))
            for reference in references:
                counts['payload_reference_occurrences'] += 1
                reference_occurrences += 1
                if not follow_reference_payloads:
                    if graph_gaps is not None:
                        graph_gaps['REFERENCE_FOLLOW_NOT_ATTEMPTED'] += 1
                    _continuation_reason(counts, 'NOT_ATTEMPTED', outcomes)
                    continue
                if counts['link_records'] >= max_links or link.get('depth', 1) >= max_depth:
                    if graph_gaps is not None:
                        graph_gaps['LINK_BOUND' if counts['link_records'] >= max_links else 'DEPTH_BOUND'] += 1
                    counts['reference_follow_bounds'] += 1
                    _continuation_reason(counts,
                        'LINK_BOUND' if counts['link_records'] >= max_links else 'DEPTH_BOUND', outcomes)
                    follow_complete = False
                    continue
                declared = None
                if decoded.get('kind') == 'stored_reference':
                    parent = _kind(link.get('declared_pointee'))
                    declared = parent.get('element') if parent and parent.get('kind') == 'pointer' else None
                child = inspect_payload_reference(session, reference, declared)
                if current_storage_graph and not child.get('payload_selector') and child.get('status') != 'NULL_SOURCE_FIELD':
                    source_status = child['status']
                    child = inspect_current_storage_reference(session, reference, max_element_bytes=max_element_bytes)
                    child['source_relationship_status'] = source_status
                child.update(**_affiliation(entity, affiliation), source_address=record_address,
                    depth=link.get('depth', 1) + 1,
                    path=link.get('path', []) + ([reference['path']] if reference.get('path') else []),
                    parent_allocation_id=selector['allocation_id'], parent_element_index=index)
                # Native pointer elements have an index, not an invented member label.
                if not child.get('field_path'):
                    child['field_path'] = link.get('field_path')
                if follow_affiliated_entities and child.get('traversal') == 'OTHER_ENTITY':
                    child['traversal'] = 'SOURCE_ROOT_AFFILIATED_ENTITY_RECORD'
                    child['target_role'] = 'SOURCE_ROOT_AFFILIATED_ENTITY_RECORD'
                child_selector = child.get('payload_selector')
                child_key = ((child_selector['allocation_id'], child_selector['element_start_index'],
                              child_selector['stored_elements']) if child_selector else None)
                reason = ('NULL_ENDPOINT' if child.get('status') == 'NULL_SOURCE_FIELD' else
                          child.get('status', 'UNRESOLVED_REFERENCE') if child_selector is None else
                          'REPEATED_EXACT_RANGE' if child_key in payloads or child_key in queued else
                          'NODE_BOUND' if counts['nodes_inspected'] >= max_nodes else 'QUEUED_RANGE')
                child['export_continuation'] = _continuation_reason(counts, reason, outcomes)
                _emit(stream, 'link', child)
                counts['links'] += 1
                counts['link_records'] += 1
                if child.get('status') not in ('SOURCE_DECLARED_FIELD_TARGET', 'CURRENT_COMPACT_POINTER_TARGET', 'NULL_SOURCE_FIELD'):
                    counts['unresolved'] += 1
                if not child_selector:
                    if graph_gaps is not None and child.get('status') != 'NULL_SOURCE_FIELD':
                        graph_gaps[child.get('status', 'UNRESOLVED_REFERENCE')] += 1
                    continue
                if child_key in payloads or child_key in queued:
                    counts['duplicate_payload_ranges'] += 1
                    continue
                if counts['nodes_inspected'] >= max_nodes:
                    if graph_gaps is not None:
                        graph_gaps['NODE_BOUND'] += 1
                    counts['reference_follow_bounds'] += 1
                    follow_complete = False
                    _emit(stream, 'diagnostic', dict(status='NODE_BOUND', **_affiliation(entity, affiliation),
                        payload_selector=child_selector, declared_records=child_selector['stored_elements']))
                    # The blocked range still participates in record reconciliation.
                    counts['declared_records'] += child_selector['stored_elements']
                    counts['omitted_records'] += child_selector['stored_elements']
                    payloads.add(child_key)
                    continue
                counts['nodes_inspected'] += 1
                queued.add(child_key)
                pending.append(child)
        omitted = total - written
        if key == window_key and window_result is not None:
            window_result.update(exported=written,omitted=omitted,excluded=0)
        counts['omitted_records'] += omitted
        if omitted:
            if graph_gaps is not None:
                graph_gaps['RECORD_BOUND'] += 1
            # A verified member selector represents one occurrence. Container
            # ranges, excluded Entity links and repeated ranges are separate.
            if link.get('status') == 'VERIFIED_COLLECTION_MEMBER_CURRENT_ELEMENT':
                counts['collection_omitted_members'] += 1
            _continuation_reason(counts, 'RECORD_BOUND', outcomes)
        _emit(stream, 'payload', dict(**_affiliation(entity, affiliation), selector=selector,
            incoming_link=_incoming_link(link), export_continuation=dict(
                reference_follow_requested=follow_reference_payloads,
                reference_scope='COLLECTION_MEMBERSHIP_ADAPTER' if collection else
                    'EXPORTED_PAYLOAD_RECORD_STORED_REFERENCES',
                status='ADAPTER_ATTEMPTED' if collection else
                    'ATTEMPTED' if follow_reference_payloads else 'NOT_ATTEMPTED',
                observed_reference_occurrences=reference_occurrences, outcome_counts=dict(outcomes),
                uninspected_selected_records=omitted,
                untyped_exported_records=untyped,
                uninspected_reference_occurrences=None if omitted or untyped else 0),
            exported_records=written, omitted_records=omitted, excluded_records=0,
            status='RECORD_LIMIT' if omitted else 'EXPORTED_RANGE',
            range_reconciled=written + omitted == total,
            field_length_verified=False, ownership='NOT_INFERRED'))
    return follow_complete


def _dataset_export_counts():
    return Counter(entities=0, links=0, payload_ranges=0, records=0,
                     declared_records=0, omitted_records=0, unresolved=0,
                     excluded_records=0, nodes_inspected=0, link_records=0,
                     reference_follow_bounds=0, duplicate_selections=0, duplicate_payload_ranges=0,
                     collections_inspected=0, collection_nodes=0, collection_member_evidence=0,
                     collection_slots=0, collection_declared_members=0, collection_verified_members=0,
                     collection_omitted_members=0, collection_null_members=0,
                     collection_unverified_observed_members=0, unverified_collection_populations=0,
                     untyped_entities=0, untyped_records=0)


def write_dataset_text(db, stream: TextIO, *, entity_addresses: Iterable | None = None,
                       entity_type: str | None = None, max_entities: int = 10000,
                       max_records: int = 100000, max_nodes: int = 128,
                       max_depth: int = 4, max_links: int = 1024,
                       max_element_bytes: int = 65536,
                       follow_reference_payloads: bool = True,
                       max_collection_nodes: int = 1000, max_collection_members: int = 10000,
                       max_collection_slots: int = 100000,
                       progress: Callable[[dict], None] | None = None) -> dict:
    """Write tagged JSON plaintext, then verify/reconcile the bounded operation.

    Exactly one selector is required. Type names match the stored allocation
    label exactly, including ``[]``. Address selectors identify exact class
    elements, including elements inside vectors. Record/node/link budgets apply
    explicitly; ranges omitted by a budget retain their declared count. The
    session census/cache and at most max_entities address keys remain in memory,
    with one decoded element and max_links deduplication keys per Entity. These
    admission bounds are not a measured process RSS guarantee.
    """
    if (entity_addresses is None) == (entity_type is None):
        raise ExportError('Exactly one of entity_addresses or entity_type is required')
    if entity_type is not None and (not isinstance(entity_type, str) or not entity_type):
        raise ExportError('entity_type must be a nonempty exact source type label')
    if type(follow_reference_payloads) is not bool:
        raise ExportError('follow_reference_payloads must be a boolean')
    _limit(max_entities, 'max_entities', 100000)
    _limit(max_records, 'max_records', 10000000)
    _limit(max_nodes, 'max_nodes', 10000)
    if type(max_depth) is not int or not 0 <= max_depth <= 64:
        raise ExportError('max_depth must be an integer from 0 to 64')
    _limit(max_links, 'max_links', 100000)
    _limit(max_element_bytes, 'max_element_bytes', 1048576)
    _limit(max_collection_nodes, 'max_collection_nodes', 10000)
    _limit(max_collection_members, 'max_collection_members', 100000)
    _limit(max_collection_slots, 'max_collection_slots', 1000000)
    session = DiscoverySession(db)
    with session_operation(session):
        counts = _dataset_export_counts()
        bounds = dict(max_entities=max_entities, max_records=max_records, max_nodes=max_nodes,
                      max_depth=max_depth, max_links=max_links, max_element_bytes=max_element_bytes,
                      max_schema_leaves=4096, follow_reference_payloads=follow_reference_payloads,
                      max_collection_nodes=max_collection_nodes, max_collection_members=max_collection_members,
                      max_collection_slots=max_collection_slots,
                      budget_scope='WHOLE_EXPORT; NODES_INCLUDE_SOURCE_TRAVERSAL_AND_FOLLOW_TARGET_ADMISSIONS')
        expected = (next((row['elements'] for row in session.census if row['type'] == entity_type), 0)
                    if entity_type is not None else None)
        pins = runtime_identity()
        _emit(stream, 'header', dict(format='FSD_ENTITY_DATASET_TEXT', version=1,
            source=_source(db), runtime_identity=pins,
            reference_continuation_scope=_reference_continuation_scope(follow_reference_payloads),
            selection=dict(entity_type=entity_type, mode='EXACT_ENTITY_TYPE' if entity_type else 'EXACT_ENTITY_ADDRESSES'),
            bounds=bounds, application_semantics_complete=False,
            payload_count_policy='REMAINING_ALLOCATION_ELEMENTS; FIELD_LENGTH_NOT_INFERRED',
            interpretation='SOURCE_FIELD_LABELS; OWNERSHIP_CRS_UNITS_AND_ACTIVE_UNIONS_NOT_INFERRED'))
        seen = set()
        selection_truncated = False
        links_complete = True
        entity_field_paths_complete = True
        try:
            for address, allocation, index in _selection(db, session, entity_addresses, entity_type):
                token = (address['segment'], address['cluster'], address['offset'])
                # Count every supplied item against the selection bound, even duplicates.
                if counts['entities'] + counts['duplicate_selections'] == max_entities:
                    selection_truncated = True
                    break
                if token in seen:
                    counts['duplicate_selections'] += 1
                    continue
                seen.add(token)
                counts['entities'] += 1
                value = _decode(db, allocation, index, max_element_bytes)
                facets = interpretation_facets(value)
                if not facets['typed_fields_complete']:
                    counts['unresolved'] += 1
                    counts['untyped_entities'] += 1
                _emit(stream, 'entity', dict(address=address, type=allocation['name'], element_index=index,
                    allocation_id=allocation.get('store_allocation_id'), value=value, interpretation=facets))
                pending = deque()
                if counts['nodes_inspected'] >= max_nodes or counts['link_records'] >= max_links:
                    links_complete = False
                    entity_field_paths_complete = False
                    counts['unresolved'] += 1
                    _emit(stream, 'diagnostic', dict(status='SOURCE_TRAVERSAL_BOUND', entity_address=address,
                        export_continuation=_continuation_reason(counts, 'SOURCE_TRAVERSAL_BOUND'),
                        uninspected_entity_fields=True))
                    continue
                link_summary_seen = False
                for link in iter_payload_links(session, address, max_nodes=max_nodes-counts['nodes_inspected'],
                        max_depth=max_depth, max_links=max_links-counts['link_records'], max_element_bytes=max_element_bytes):
                    kind = link['record']
                    if kind == 'diagnostic' or (kind == 'link' and not link.get('payload_selector')):
                        reason = 'NULL_ENDPOINT' if link.get('status') == 'NULL_SOURCE_FIELD' else link.get(
                            'status', 'UNRESOLVED_REFERENCE')
                        link = dict(link, export_continuation=dict(
                            _continuation_reason(counts, reason), scope='ENTITY_DECLARED_FIELD_TRAVERSAL'))
                    _emit(stream, 'payload_link_' + kind if kind in ('header', 'summary') else kind, link)
                    if kind == 'summary':
                        link_summary_seen = True
                        links_complete = links_complete and link.get('complete', False)
                        entity_field_paths_complete = entity_field_paths_complete and link.get('complete', False)
                        counts['nodes_inspected'] += link['nodes_inspected']
                        counts['link_records'] += link['records']
                    elif kind == 'diagnostic':
                        counts['unresolved'] += 1
                    elif kind == 'link':
                        counts['links'] += 1
                        if link.get('status') not in ('SOURCE_DECLARED_FIELD_TARGET', 'NULL_SOURCE_FIELD'):
                            counts['unresolved'] += 1
                    selector = link.get('payload_selector')
                    if selector:
                        pending.append(link)
                if not link_summary_seen:
                    raise ExportError('Payload-link stream ended without a reconciliation summary')
                followed = _write_payloads(db, session, stream, address, pending, counts,
                    max_records=max_records, max_nodes=max_nodes, max_links=max_links, max_depth=max_depth,
                    max_element_bytes=max_element_bytes, follow_reference_payloads=follow_reference_payloads,
                    max_collection_nodes=max_collection_nodes, max_collection_members=max_collection_members,
                    max_collection_slots=max_collection_slots)
                links_complete = links_complete and followed
                if progress:
                    progress(dict(phase='dataset_text', **counts))
            session.finish()
            if runtime_identity() != pins:
                raise ExportError('Runtime changed during dataset text export')
            complete = not (selection_truncated or counts['omitted_records'] or counts['excluded_records'] or counts['unresolved']) and links_complete
            summary = dict(counts, status='COMPLETE' if complete else 'INCOMPLETE',
                reference_continuation_scope=_reference_continuation_scope(follow_reference_payloads, counts),
                source=_source(db), bounds=bounds, selection_truncated=selection_truncated,
                selected_type_declared_entities=expected,
                entity_selection_complete=not selection_truncated,
                selected_entity_field_paths_complete=entity_field_paths_complete and not selection_truncated,
                payload_traversal_complete=links_complete,
                payload_record_enumeration_complete=not (counts['omitted_records'] or counts['excluded_records']
                    or counts['collection_omitted_members'] or counts['unverified_collection_populations']),
                typed_values_complete=not (counts['untyped_entities'] or counts['untyped_records']),
                record_ranges_reconciled=counts['records'] + counts['omitted_records'] + counts['excluded_records'] == counts['declared_records'],
                integrity_scope='SQLITE_QUICK_AND_FOREIGN_KEYS; ACCESSED_BLOBS',
                full_store_verification_performed=False, original_source_required=False,
                application_semantics_complete=False)
            if expected is not None and not selection_truncated and counts['entities'] != expected:
                raise ExportError('Entity selection differs from the current type census')
            _emit(stream, 'summary', summary)
            return summary
        finally:
            session.close()


def export_dataset_text(db, new_path: str | Path, **options) -> dict:
    """Sync private staging and atomically publish without replacing any path."""
    return _publish_text(db, new_path, write_dataset_text, options)


def _publish_text(db, new_path, writer, options):
    output = Path(new_path).absolute()
    if os.path.lexists(output):
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                dir=output.parent, prefix='.fsdx-dataset-', delete=False) as stream:
            stage = Path(stream.name)
            summary = writer(db, stream, **options)
            stream.flush()
            os.fsync(stream.fileno())
        digest = _digest(stage)
        size = stage.stat().st_size
        os.link(stage, output)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return dict(summary, output=str(output), output_sha256=digest, output_bytes=size)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)


class ProjectionError(ExportError):
    """The requested source path was not proved; full reachability is unknown."""

    def __init__(self, message: str, proof: Mapping):
        super().__init__(message)
        self.proof = dict(proof)


class _ByteWriter:
    def __init__(self, stream: TextIO, maximum: int, *, operation: str = 'Projection'):
        self.stream, self.maximum, self.bytes_written = stream, maximum, 0
        self.operation = operation

    def write(self, text: str) -> int:
        size = len(text.encode('utf-8'))
        if self.bytes_written + size > self.maximum:
            raise ExportError(self.operation + ' output exceeds configured byte budget')
        result = self.stream.write(text)
        self.bytes_written += size
        return result


def _projection_counts():
    return Counter(entities=0, links=0, payload_ranges=0, records=0,
        declared_records=0, omitted_records=0, unresolved=0, excluded_records=0,
        nodes_inspected=0, link_records=0, reference_follow_bounds=0,
        duplicate_selections=0, duplicate_payload_ranges=0,
        collections_inspected=0, collection_nodes=0, collection_member_evidence=0,
        collection_slots=0, collection_declared_members=0, collection_verified_members=0,
        collection_omitted_members=0, collection_null_members=0,
        collection_unverified_observed_members=0, unverified_collection_populations=0,
        untyped_entities=0, untyped_records=0)


def _prove_projection_record(session, entity, requested, counts, bounds):
    """Bounded exact source-field/member proof; unrelated data is not exported."""
    db = session.db
    requested_allocation, requested_index = _element(db, requested)
    root_allocation, _ = _element(db, entity)
    if not session.reader.inherits(root_allocation['name'].removesuffix('[]'), 'Fs::Entity'):
        raise ExportError('Projection root does not derive from source-declared Fs::Entity')
    if entity == requested:
        return dict(record_address=requested, path=[], depth=0,
                    proof='EXACT_ROOT_ENTITY_ELEMENT', root_scope_complete=False)
    if session.reader.inherits(requested_allocation['name'].removesuffix('[]'), 'Fs::Entity'):
        raise ExportError('Projection cannot silently select a different Entity')
    pending = deque([(entity, [], 0, None)])
    admitted = {tuple(entity[k] for k in ('segment', 'cluster', 'offset'))}
    visited = set()
    seen_collections = set()
    unknown = Counter()
    declaration_by_type = {row['type']: row for row in session.census}

    def match(link, path, depth):
        selector = link.get('payload_selector')
        if not selector or link.get('traversal') == 'OTHER_ENTITY':
            return None
        if (selector['allocation_id'] == requested_allocation['store_allocation_id']
                and selector['element_start_index'] <= requested_index <
                    selector['element_start_index'] + selector['stored_elements']):
            return dict(record_address=requested, path=path, depth=depth,
                proof='SOURCE_FIELD_OR_VERIFIED_MEMBER_AND_CURRENT_ELEMENT_VIEW',
                array_extent_policy='INDEXED_ALLOCATION_RANGE; FIELD_LENGTH_AND_OWNERSHIP_UNESTABLISHED',
                root_scope_complete=False)
        return None

    def enqueue(address, path, depth, inherited=None):
        key = tuple(address[k] for k in ('segment', 'cluster', 'offset'))
        if key in admitted:
            return
        if depth >= bounds['max_depth'] or len(admitted) >= bounds['max_nodes']:
            unknown['node_or_depth_admission_bound'] += 1
            return
        admitted.add(key)
        pending.append((address, path, depth, inherited))

    def accept(link, path, depth):
        result = match(link, path, depth)
        if result:
            return result
        selector = link.get('payload_selector')
        if not selector or link.get('traversal') == 'OTHER_ENTITY':
            return None
        if link.get('traversal') == 'COLLECTION_MEMBERSHIP_REQUIRES_ADAPTER':
            address = selector['canonical_address']
            context = None
            if session.reader.inherits(selector['type'].removesuffix('[]'), 'os_set') and '::<os_Collection<' in (link.get('field_path') or ''):
                try:
                    context = collection_type_context(session.reader, address,
                        link['source_address'], link['field_path'])
                except CatalogError:
                    unknown['collection_context_unconfirmed'] += 1
                    return None
            key = (*tuple(address[k] for k in ('segment', 'cluster', 'offset')),
                   context.get('element_type') if context else None)
            if key in seen_collections:
                return None
            seen_collections.add(key)
            remaining = dict(nodes=min(bounds['max_nodes']-counts['nodes_inspected'],
                                       bounds['max_collection_nodes']-counts['collection_nodes']),
                members=bounds['max_collection_members']-counts['collection_member_evidence'],
                slots=bounds['max_collection_slots']-counts['collection_slots'])
            if min(remaining.values()) <= 0:
                unknown['collection_resource_bound'] += 1
                return None
            membership = inspect_collection(session.reader, address, max_nodes=remaining['nodes'],
                max_members=remaining['members'], max_slots=remaining['slots'], type_context=context)
            counts['collections_inspected'] += 1
            counts['collection_nodes'] += len(membership['nodes'])
            counts['nodes_inspected'] += len(membership['nodes'])
            counts['collection_slots'] += membership.get('scanned_slots', 0)
            counts['collection_member_evidence'] += sum(len(membership.get(k, ())) for k in
                ('members', 'slot_references', 'incompatible_self_references'))
            if type(membership.get('declared_count')) is int:
                counts['collection_declared_members'] += membership['declared_count']
            if (membership['status'] != 'VERIFIED_CARDINALITY' or not membership.get('equal')
                    or membership['declared_count'] != membership['observed_count']):
                unknown['collection_membership_unverified'] += 1
                return None
            counts['collection_verified_members'] += membership['observed_count']
            deferred = []
            for member in membership['members']:
                if member.get('address') is None:
                    continue
                expected = dict(kind='class', name=context['element_type']) if context else None
                allocation, view = _location(db, member['address'], expected)
                if allocation is None or 'canonical_address' not in view:
                    unknown['collection_member_element_unconfirmed'] += 1
                    continue
                child_selector = _selector(allocation, view)
                child_selector.update(stored_elements=1,
                    extent_semantics='ONE_VERIFIED_COLLECTION_MEMBER_ELEMENT')
                child = dict(record='member', status='VERIFIED_COLLECTION_MEMBER_CURRENT_ELEMENT',
                    source_address=member.get('source_address'), target_address=member['address'],
                    payload_selector=child_selector, traversal=_traversal(session, allocation, expected),
                    collection_address=address, member_evidence=member,
                    collection_status=membership['status'], declared_count=membership['declared_count'],
                    observed_count=membership['observed_count'], type_context=context,
                    ownership='NOT_INFERRED')
                member_path = path + [child]
                found = match(child, member_path, depth + 1)
                if found:
                    return found
                if child['traversal'] != 'OTHER_ENTITY':
                    deferred.append((view['canonical_address'], member_path, depth + 1, None))
            for args in deferred:
                enqueue(*args)
            return None
        if selector.get('vector'):
            declared = _kind(link.get('declared_pointee'))
            if selector['native_tag'] in (8, 14) and declared and declared.get('kind') == 'pointer':
                # Slots are admitted one at a time; no entire array is decoded.
                first, stop = selector['element_start_index'], selector['element_start_index'] + selector['stored_elements']
                for index in range(first, stop):
                    if len(admitted) >= bounds['max_nodes']:
                        unknown['array_element_admission_bound'] += stop-index
                        break
                    address = dict(selector['canonical_address'], offset=
                        selector['allocation_address']['offset'] + selector.get('array_header_size', 0)
                        + index * selector['element_stride'])
                    enqueue(address, path, depth, declared['element'])
            return None
        target_allocation = db.allocation(selector['canonical_address']['segment'],
            selector['canonical_address']['cluster'], selector['canonical_address']['offset'])
        if target_allocation is not None and db.fields.schema_admission(target_allocation)['admitted']:
            enqueue(selector['canonical_address'], path, depth)
        return None

    while pending:
        if counts['nodes_inspected'] >= bounds['max_nodes'] or counts['link_records'] >= bounds['max_links']:
            unknown['source_traversal_resource_bound'] += len(pending)
            break
        address, path, depth, inherited = pending.popleft()
        key = tuple(address[k] for k in ('segment', 'cluster', 'offset'))
        if key in visited:
            continue
        visited.add(key)
        allocation, index = _element(db, address)
        counts['nodes_inspected'] += 1
        try:
            value = _decode(db, allocation, index, bounds['max_element_bytes'])
        except Exception as exc:
            require_source_failure(exc, dict(phase='projection_source_proof', address=address))
            unknown['source_record_decode_unresolved'] += 1
            continue
        declarations = declaration_by_type[allocation['name']].get('slots', ())
        slots = {slot['path']: slot for slot in declarations}
        refs = ([value] if value.get('kind') == 'stored_reference' else
                (field for field in value.get('fields', ()) if field.get('kind') == 'stored_reference'))
        for reference in refs:
            if counts['link_records'] >= bounds['max_links']:
                unknown['source_link_resource_bound'] += 1
                break
            if value.get('kind') != 'stored_reference':
                symbolic = re.sub(r'\[\d+\]', '[]', reference.get('path', ''))
                slot = slots.get(symbolic)
                if slot is None or slot.get('conditional_union'):
                    unknown['source_declaration_or_union_unconfirmed'] += 1
                    continue
            link = inspect_payload_reference(session, reference, inherited)
            link.update(source_record_address=address, source_address=address, depth=depth + 1)
            counts['link_records'] += 1
            if link['status'] != 'SOURCE_DECLARED_FIELD_TARGET':
                if link['status'] != 'NULL_SOURCE_FIELD':
                    unknown[link['status']] += 1
                continue
            proof = accept(link, path + [link], depth + 1)
            if proof:
                proof['search_usage'] = dict(counts)
                proof['unselected_unknown_edges'] = dict(unknown)
                return proof
        session.check_identity()
    raise ProjectionError('Requested record source path is unproved within the configured scope',
        dict(record_address=requested, entity_address=entity, search_usage=dict(counts),
             unknown_edges=dict(unknown), root_scope_complete=False, reachable=None))


def write_payload_projection(db, stream: TextIO, *, entity_address, record_address,
        field_path: str | None = None, element_start: int = 0, element_count: int = 3,
        max_records: int = 128, max_nodes: int = 128, max_links: int = 256,
        max_depth: int = 8, max_element_bytes: int = 65536,
        max_collection_nodes: int = 1000, max_collection_members: int = 10000,
        max_collection_slots: int = 100000, follow_reference_payloads: bool = True,
        max_output_bytes: int = 8388608, progress: Callable[[dict], None] | None = None) -> dict:
    """Project one source-proved exact record or unconditional field window.

    Successful projected enumeration is separate from interpretation and from
    the unenumerated Entity's full scope. Window extents are indexed allocation
    evidence; they do not establish field length, member roles or ownership.
    A byte-budget failure aborts atomic publication rather than publishing a
    silently truncated JSON record. Stream callers retain their own partial
    writes on failure and should use export_payload_projection for publication.
    """
    for name, value, ceiling in (('element_count', element_count, 10000000),
        ('max_records',max_records,10000000), ('max_nodes',max_nodes,10000),
        ('max_links',max_links,100000), ('max_element_bytes',max_element_bytes,1048576),
        ('max_collection_nodes',max_collection_nodes,10000),
        ('max_collection_members',max_collection_members,100000),
        ('max_collection_slots',max_collection_slots,1000000),
        ('max_output_bytes',max_output_bytes,1073741824)):
        _limit(value, name, ceiling)
    if type(element_start) is not int or element_start < 0:
        raise ExportError('element_start must be a nonnegative integer')
    if type(max_depth) is not int or not 0 <= max_depth <= 64:
        raise ExportError('max_depth must be an integer from 0 to 64')
    if type(follow_reference_payloads) is not bool:
        raise ExportError('follow_reference_payloads must be a boolean')
    if field_path is not None and (not isinstance(field_path,str) or not 1 <= len(field_path) <= 4096):
        raise ExportError('field_path must contain 1 to 4096 characters')
    entity, record = _address(db, entity_address), _address(db, record_address)
    allocation, index = _element(db, record)
    session = DiscoverySession(db)
    with session_operation(session):
        pins = runtime_identity()
        counts = _projection_counts()
        bounds = dict(max_records=max_records,max_nodes=max_nodes,max_links=max_links,max_depth=max_depth,
            max_element_bytes=max_element_bytes,max_collection_nodes=max_collection_nodes,
            max_collection_members=max_collection_members,max_collection_slots=max_collection_slots,
            max_output_bytes=max_output_bytes,follow_reference_payloads=follow_reference_payloads,
            max_schema_leaves=4096,budget_scope='WHOLE_PROOF_AND_PROJECTION')
        bounded = _ByteWriter(stream, max_output_bytes)
        try:
            proof = _prove_projection_record(session, entity, record, counts, bounds)
            if counts['nodes_inspected'] >= max_nodes:
                raise ProjectionError('Projection source record exceeds source-node budget',proof)
            counts['nodes_inspected'] += 1
            value = _decode(db, allocation, index, max_element_bytes)
            if field_path is not None:
                if proof['depth'] + 1 > max_depth:
                    raise ProjectionError('Projection source field exceeds depth budget',proof)
                slots = _slots(db.fields.schema, allocation['name'].removesuffix('[]'))
                symbolic = re.sub(r'\[\d+\]', '[]', field_path)
                declared = [slot for slot in slots if slot['path'] == symbolic]
                if len(declared) != 1 or declared[0].get('conditional_union'):
                    raise ExportError('Projection field is absent, ambiguous or a conditional union declaration')
                selected = [field for field in value.get('fields', ()) if field.get('path') == field_path]
                if len(selected) != 1 or selected[0].get('kind') != 'stored_reference':
                    raise ExportError('Projection requires one active source-declared stored-reference field')
                if counts['link_records'] >= max_links:
                    raise ProjectionError('Projection field verification exceeds source-link budget',proof)
                link = inspect_payload_reference(session, selected[0])
                counts['link_records'] += 1
                if link.get('payload_selector'):
                    target = link['payload_selector']['canonical_address']
                    target_allocation = db.allocation(target['segment'],target['cluster'],target['offset'])
                    link['traversal'] = _traversal(session,target_allocation,link.get('declared_pointee'))
                if link['status'] != 'SOURCE_DECLARED_FIELD_TARGET' or link.get('traversal') == 'OTHER_ENTITY':
                    raise ProjectionError('Projection field target is unconfirmed or another Entity',
                                          dict(proof,field_link=link))
                link.update(source_address=record, depth=proof['depth'] + 1,
                    path=[edge.get('field_path') for edge in proof['path'] if edge.get('field_path')] + [field_path])
            else:
                if session.reader.inherits(allocation['name'].removesuffix('[]'),'Fs::Entity') and (
                        element_start != 0 or element_count != 1):
                    raise ExportError('An exact Entity record projection requires start zero and count one')
                _, view = _location(db, record)
                link = dict(record='link', source_address=record, field_path=None,
                    payload_selector=_selector(allocation,view), traversal='EXACT_PROJECTED_RECORD',
                    status='SOURCE_PROVED_CURRENT_RECORD_WINDOW', depth=proof['depth'], path=[])
            selector = dict(link['payload_selector'])
            available = selector['stored_elements']
            if element_start + element_count > available:
                raise ExportError('Requested projection window exceeds the indexed allocation range')
            selector.update(element_start_index=selector['element_start_index'] + element_start,
                stored_elements=element_count,
                extent_semantics='INDEXED_ALLOCATION_WINDOW; FIELD_LENGTH_AND_OWNERSHIP_UNESTABLISHED')
            selector['window_start_address'] = dict(selector['allocation_address'],offset=
                selector['allocation_address']['offset'] + selector.get('array_header_size',0)
                + selector['element_start_index'] * selector['element_stride'])
            link = dict(link,payload_selector=selector)
            _emit(bounded,'header',dict(format='FSD_LINKED_RECORD_FIELD_PROJECTION',version=1,
                source=_source(db),runtime_identity=pins,bounds=bounds,
                reference_continuation_scope=_reference_continuation_scope(follow_reference_payloads),
                selection=dict(entity_address=entity,record_address=record,field_path=field_path,
                    element_start=element_start,element_count=element_count),proof=proof,
                projected_scope='EXACT_SELECTED_WINDOW_AND_VERIFIED_REFERENCE_PAYLOADS',
                root_full_scope_enumerated=False,application_semantics_complete=False,
                interpretation='STORED_VALUES; CRS_UNITS_OWNERSHIP_AND_ACTIVE_UNIONS_UNESTABLISHED'))
            _emit(bounded,'projection_source',dict(address=record,type=allocation['name'],
                value=value,interpretation=interpretation_facets(value),selected_field_link=link))
            window_result = {}
            window_key = (selector['allocation_id'],selector['element_start_index'],element_count)
            complete = _write_payloads(db,session,bounded,entity,deque([link]),counts,
                max_records=max_records,max_nodes=max_nodes,max_links=max_links,max_depth=max_depth,
                max_element_bytes=max_element_bytes,follow_reference_payloads=follow_reference_payloads,
                max_collection_nodes=max_collection_nodes,max_collection_members=max_collection_members,
                max_collection_slots=max_collection_slots,window_key=window_key,window_result=window_result)
            session.finish()
            if runtime_identity() != pins:
                raise ExportError('Runtime changed during payload projection')
            enumeration_complete = complete and not (counts['omitted_records'] or counts['excluded_records']
                or counts['collection_omitted_members'] or counts['unverified_collection_populations'])
            summary = dict(counts,status='COMPLETE' if enumeration_complete else 'INCOMPLETE',
                reference_continuation_scope=_reference_continuation_scope(follow_reference_payloads, counts),
                source=_source(db),bounds=bounds,root_entities_proved=1,selected_window_elements=element_count,
                selected_window_elements_emitted=window_result.get('exported',0),
                selected_window_elements_omitted=window_result.get('omitted',element_count),
                selected_window_elements_excluded=window_result.get('excluded',0),
                source_range_elements=available,unselected_source_elements=available-element_count,
                unselected_prefix_elements=element_start,
                unselected_suffix_elements=available-element_start-element_count,
                projected_enumeration_complete=enumeration_complete,
                root_full_scope_enumerated=False,application_semantics_complete=False,
                typed_values_complete=counts['untyped_records']==0,
                record_ranges_reconciled=counts['records']+counts['omitted_records']+counts['excluded_records']==counts['declared_records'],
                original_source_required=False,full_store_verification_performed=False,
                integrity_scope='SQLITE_QUICK_AND_FOREIGN_KEYS; ACCESSED_BLOBS',
                field_length_verified=False,ownership='NOT_INFERRED')
            _emit(bounded,'summary',summary)
            if progress:
                progress(dict(phase='payload_projection',**counts))
            return dict(summary,output_bytes_written=bounded.bytes_written)
        finally:
            session.close()


def export_payload_projection(db,new_path: str | Path,**options) -> dict:
    """Atomically publish a proved bounded projection without replacement."""
    return _publish_text(db,new_path,write_payload_projection,options)


def write_root_payload_text(db, stream: TextIO, *, root_index: int,
        max_records: int = 128, max_nodes: int = 128, max_depth: int = 4,
        max_links: int = 1024, max_element_bytes: int = 65536,
        max_output_bytes: int = 8388608, follow_reference_payloads: bool = True,
        follow_affiliated_entities: bool = True, current_storage_graph: bool = True,
        max_collection_nodes: int = 1000, max_collection_members: int = 10000,
        max_collection_slots: int = 100000, progress=None) -> dict:
    """Emit one retained root and bounded actual affiliated payload values.

    Exact allocation-remainder selectors retain unknown field lengths. Record
    and output bounds prevent a root link from implying a whole large-array
    export; omitted/excluded counts remain visible. Unadmitted exact root values
    remain independently decoded native/raw evidence, with no declared walk.
    """
    from fsd_decoder.discovery.root_relationships import iter_root_payload_links
    if type(follow_reference_payloads) is not bool:
        raise ExportError('follow_reference_payloads must be a boolean')
    if type(follow_affiliated_entities) is not bool:
        raise ExportError('follow_affiliated_entities must be a boolean')
    if type(current_storage_graph) is not bool:
        raise ExportError('current_storage_graph must be a boolean')
    _limit(max_records, 'max_records', 10000000)
    _limit(max_nodes, 'max_nodes', 10000)
    _limit(max_links, 'max_links', 100000)
    _limit(max_element_bytes, 'max_element_bytes', 1048576)
    _limit(max_output_bytes, 'max_output_bytes', 268435456)
    _limit(max_collection_nodes, 'max_collection_nodes', 10000)
    _limit(max_collection_members, 'max_collection_members', 100000)
    _limit(max_collection_slots, 'max_collection_slots', 1000000)
    if type(max_depth) is not int or not 0 <= max_depth <= 64:
        raise ExportError('max_depth must be an integer from 0 to 64')
    session = DiscoverySession(db)
    with session_operation(session):
        sink = _ByteWriter(stream, max_output_bytes, operation='Root payload')
        counts = _dataset_export_counts()
        counts.pop('entities', None)
        counts.pop('untyped_entities', None)
        counts['untyped_roots'] = 0
        bounds = dict(max_records=max_records, max_nodes=max_nodes, max_depth=max_depth,
            max_links=max_links, max_element_bytes=max_element_bytes, max_output_bytes=max_output_bytes,
            max_schema_leaves=4096, follow_reference_payloads=follow_reference_payloads,
            follow_affiliated_entities=follow_affiliated_entities, current_storage_graph=current_storage_graph,
            max_collection_nodes=max_collection_nodes, max_collection_members=max_collection_members,
            max_collection_slots=max_collection_slots,
            budget_scope='ONE_ROOT; SOURCE_WALK_AND_PAYLOAD_QUEUE_SHARE_LIMITS')
        pins = runtime_identity()
        _emit(sink, 'header', dict(format='FSD_SOURCE_ROOT_PAYLOAD_TEXT', version=1,
            source=_source(db), runtime_identity=pins, selection=dict(root_index=root_index), bounds=bounds,
            reference_continuation_scope=_reference_continuation_scope(follow_reference_payloads),
            payload_count_policy='INDEXED_ALLOCATION_REMAINDER; FIELD_LENGTH_NOT_ESTABLISHED',
            interpretation='SOURCE_ROOT_STRUCTURAL_AFFILIATION; OWNERSHIP_CRS_UNITS_AND_CLASS_IDENTITY_NOT_INFERRED',
            application_semantics_complete=False))
        pending = deque()
        root = None
        link_summary = None
        root_value_complete = False
        try:
            for link in iter_root_payload_links(session, root_index, max_nodes=max_nodes,
                    max_depth=max_depth, max_links=max_links, max_element_bytes=max_element_bytes,
                    follow_affiliated_entities=follow_affiliated_entities, current_storage_graph=current_storage_graph):
                kind = link['record']
                if kind == 'header':
                    root = link['root']
                    seed = root.get('seed')
                    value = None
                    facets = None
                    if seed is not None:
                        allocation = db.allocation(seed['address']['segment'], seed['address']['cluster'],
                            seed['address']['offset'])
                        if allocation is None or allocation.get('store_allocation_id') != seed['allocation_id']:
                            raise ExportError('Root seed disagrees with current allocation index')
                        value = _decode(db, allocation, seed['element_index'], max_element_bytes, raw_fallback=True)
                        facets = interpretation_facets(value)
                        root_value_complete = facets['typed_fields_complete']
                        if not root_value_complete:
                            counts['unresolved'] += 1
                            counts['untyped_roots'] += 1
                    _emit(sink, 'root', dict(root=root, value=value, interpretation=facets,
                        decoded_scope='ONE_CURRENT_ROOT_VALUE_ELEMENT' if value is not None else 'UNAVAILABLE',
                        source_field_traversal_admitted=root['source_fields_admitted'],
                        current_storage_graph=current_storage_graph))
                    continue
                _emit(sink, 'payload_link_summary' if kind == 'summary' else kind, link)
                if kind == 'summary':
                    link_summary = link
                    counts['nodes_inspected'] += link['nodes_inspected']
                    counts['link_records'] += link['records']
                elif kind == 'diagnostic':
                    counts['unresolved'] += 1
                elif kind == 'link':
                    counts['links'] += 1
                    if link.get('status') not in ('SOURCE_DECLARED_FIELD_TARGET', 'CURRENT_COMPACT_POINTER_TARGET', 'NULL_SOURCE_FIELD'):
                        counts['unresolved'] += 1
                if link.get('payload_selector'):
                    pending.append(link)
            if root is None or link_summary is None:
                raise ExportError('Root-link stream ended without reconciliation')
            root_seed = root.get('seed')
            # An unadmitted exact root still has one bounded native/raw element
            # above; it does not authorize following references into new targets.
            affiliation = dict(root_index=root_index, root_address=root_seed['address'] if root_seed else None,
                root_origin=root, affiliation='SOURCE_ROOT_STRUCTURAL_PATH')
            graph_gaps = Counter(link_summary.get('current_storage_graph_gap_counts', {}))
            graph_gaps.update(limit.upper()+'_BOUND' for limit in link_summary.get('bounded', ()))
            followed = _write_payloads(db, session, sink, affiliation['root_address'], pending, counts,
                max_records=max_records, max_nodes=max_nodes, max_links=max_links, max_depth=max_depth,
                max_element_bytes=max_element_bytes, follow_reference_payloads=follow_reference_payloads,
                max_collection_nodes=max_collection_nodes, max_collection_members=max_collection_members,
                max_collection_slots=max_collection_slots, affiliation=affiliation,
                follow_affiliated_entities=follow_affiliated_entities, current_storage_graph=current_storage_graph,
                graph_gaps=graph_gaps if current_storage_graph else None)
            session.finish()
            if runtime_identity() != pins:
                raise ExportError('Runtime changed during root plaintext export')
            root_walk_admitted = root['traversal_admitted'] or (current_storage_graph and root['current_storage_admitted'])
            complete = bool(root_walk_admitted and root_value_complete and
                link_summary.get('complete') and followed and not (counts['omitted_records'] or
                counts['excluded_records'] or counts['unresolved']))
            summary = dict(counts, status='COMPLETE' if complete else 'INCOMPLETE', source=_source(db), bounds=bounds,
                root_index=root_index, root_seed_admitted=root_walk_admitted,
                root_source_fields_admitted=root['source_fields_admitted'],
                root_value_typed_complete=root_value_complete,
                selected_root_field_paths_complete=bool(root['source_fields_admitted'] and link_summary.get('complete')),
                current_storage_graph_complete=bool(current_storage_graph and root_walk_admitted and
                    link_summary.get('current_storage_inspected_graph_complete') and followed and not graph_gaps and
                    not (counts['omitted_records'] or counts['excluded_records'] or
                        counts['collection_omitted_members'] or counts['unverified_collection_populations'])),
                current_storage_graph_gap_counts=dict(graph_gaps),
                payload_traversal_complete=bool(link_summary.get('complete') and followed),
                payload_record_enumeration_complete=not (counts['omitted_records'] or counts['excluded_records']
                    or counts['collection_omitted_members'] or counts['unverified_collection_populations']),
                typed_values_complete=root_value_complete and not counts['untyped_records'],
                record_ranges_reconciled=counts['records'] + counts['omitted_records'] + counts['excluded_records'] == counts['declared_records'],
                root_occurrences=1, ownership_established=False, application_semantics_complete=False,
                original_source_required=False, full_store_verification_performed=False,
                integrity_scope='SQLITE_QUICK_AND_FOREIGN_KEYS; ACCESSED_BLOBS',
                reference_continuation_scope=_reference_continuation_scope(follow_reference_payloads, counts))
            _emit(sink, 'summary', summary)
            if progress:
                progress(dict(phase='root_payload_text', root_index=root_index, **counts))
            return summary
        finally:
            session.close()


def export_root_payload_text(db, new_path: str | Path, *, root_index: int, **options) -> dict:
    """Atomically publish one new bounded root-affiliated plaintext file."""
    return _publish_text(db, new_path, write_root_payload_text, dict(root_index=root_index, **options))
