"""Policy-selected direct collection contexts from exact source/storage evidence.

Uses existing compiled source slots and captured-PRM link validation. Existing
list/array adapters retain unknown element T; V1/V2 selection and set rules stay
explicit. Source/storage concordance does not witness source-class identity.
"""
from __future__ import annotations
from collections.abc import Mapping
import re

from fsd_decoder.core.diagnostics import InputValidationError
from fsd_decoder.discovery.datasets import DiscoverySession, _slots
from fsd_decoder.discovery.payload_links import inspect_payload_reference, _location
from fsd_decoder.exports.catalog import CatalogReader
from fsd_decoder.discovery.roles import supported_collection_family

LEGACY_REFERRER_POLICY = 'TEMPLATE_NAV_V1'
DIRECT_LIST_REFERRER_POLICY = 'TEMPLATE_NAV_AND_DIRECT_LISTS_V2'
DIRECT_COLLECTION_REFERRER_POLICY = 'TEMPLATE_NAV_AND_DECLARED_LISTS_EXACT_ARRAY_V3'
DEFAULT_REFERRER_POLICY = DIRECT_COLLECTION_REFERRER_POLICY
ACCEPTED_REFERRER_POLICIES = (LEGACY_REFERRER_POLICY, DIRECT_LIST_REFERRER_POLICY, DIRECT_COLLECTION_REFERRER_POLICY)

def validate_referrer_policy(policy: str) -> str:
    if type(policy) is not str or policy not in ACCEPTED_REFERRER_POLICIES:
        raise InputValidationError('Unknown collection referrer policy')
    return policy

def _known(kind):
    while kind and kind.get('kind') in ('alias', 'qualified'):
        if kind.get('unknown_qualifier_flags'):
            return None
        kind = kind.get('underlying')
    return kind

def direct_list_slot(reader: CatalogReader, slot: Mapping) -> bool:
    kind = _known(slot.get('pointee_type'))
    return bool(slot.get('kind') == 'pointer' and not slot.get('conditional_union')
        and kind and kind.get('kind') == 'class' and kind.get('name') == 'os_list'
        and 'os_list' in reader.fields.schema.classes)

def direct_collection_candidate(reader: CatalogReader, slot: Mapping) -> bool:
    """Source-family declaration visibility, including unadmitted qualifiers."""
    if slot.get('kind') != 'pointer':
        return False
    kind = slot.get('pointee_type')
    for _ in range(64):
        if not kind or kind.get('kind') not in ('alias', 'qualified'):
            break
        kind = kind.get('underlying')
    return bool(kind and kind.get('kind') == 'class'
                and supported_collection_family(reader, kind.get('name', '')))


def direct_collection_slot(reader: CatalogReader, slot: Mapping,
                           referrer_policy: str = DEFAULT_REFERRER_POLICY) -> bool:
    validate_referrer_policy(referrer_policy)
    if referrer_policy == LEGACY_REFERRER_POLICY:
        return False
    if referrer_policy == DIRECT_LIST_REFERRER_POLICY:
        return direct_list_slot(reader, slot)
    kind = _known(slot.get('pointee_type'))
    if (slot.get('kind') != 'pointer' or slot.get('conditional_union') or not kind
            or kind.get('kind') != 'class' or kind.get('name') not in reader.fields.schema.classes
            or not supported_collection_family(reader, kind['name'])):
        return False
    return ((reader.inherits(kind['name'], 'os_list')
             and not any(reader.inherits(kind['name'], anchor) for anchor in ('os_set', 'os_array')))
            or kind['name'] == 'os_array')


def direct_collection_exclusion_reason(reader: CatalogReader, slot: Mapping,
                                      referrer_policy: str) -> str:
    if slot.get('conditional_union'):
        return 'ACTIVE_UNION_ARM_NOT_ESTABLISHED'
    if referrer_policy != DIRECT_COLLECTION_REFERRER_POLICY:
        return 'POINTER_FAMILY_HAS_NO_SUPPORTED_TEMPLATE_CONTEXT'
    kind = _known(slot.get('pointee_type'))
    if kind is None:
        return 'SOURCE_POINTEE_QUALIFIERS_UNESTABLISHED'
    name = kind.get('name', '')
    if reader.inherits(name, 'os_set'):
        return 'DIRECT_SET_ELEMENT_TYPE_UNESTABLISHED'
    if reader.inherits(name, 'os_array') and name != 'os_array':
        return 'ARRAY_SUBCLASS_NATIVE_DISPATCH_UNESTABLISHED'
    return 'COLLECTION_SOURCE_FAMILY_DISPATCH_UNESTABLISHED'


def _slot_offset(slot, path):
    indices = [int(index) for index in re.findall(r'\[(\d+)\]', path)]
    arrays = slot.get('arrays', ())
    if len(indices) != len(arrays):
        return None
    offset = slot['offset']
    for index, array in zip(indices, arrays):
        count, stride = array.get('count'), array.get('stride')
        if (type(count) is not int or type(stride) is not int or count < 1
                or stride < 1 or index >= count):
            return None
        offset += index * stride
    return offset

def direct_list_context(session: DiscoverySession, address: Mapping | None, referrer: Mapping,
                        field_path: str) -> dict:
    """Preserve the V2 exact-os_list source context contract."""
    return _direct_context(session, address, referrer, field_path, DIRECT_LIST_REFERRER_POLICY)


def direct_collection_context(session: DiscoverySession, address: Mapping | None,
                              referrer: Mapping, field_path: str,
                              referrer_policy: str = DEFAULT_REFERRER_POLICY) -> dict:
    """Validate a policy-selected source field without inferring element T."""
    validate_referrer_policy(referrer_policy)
    return _direct_context(session, address, referrer, field_path, referrer_policy)


def _direct_context(session, address, referrer, field_path, referrer_policy):
    """Validate the exact current source field and policy-supported receiver, no T."""
    db, reader = session.db, session.reader
    result = dict(referrer_address=dict(referrer), field_path=field_path,
        address=dict(address) if address is not None else None,
        element_type_status=('UNESTABLISHED_DIRECT_LIST_SOURCE' if referrer_policy == DIRECT_LIST_REFERRER_POLICY
                             else 'UNESTABLISHED_DIRECT_COLLECTION_SOURCE'),
        type_filter_applied=False, ownership='NOT_INFERRED',
        evidence=('COMPILED_SOURCE_FIELD_RAW_BYTES_CAPTURED_PRM_EXACT_LIST_RECEIVER' if referrer_policy == DIRECT_LIST_REFERRER_POLICY
                  else 'COMPILED_SOURCE_FIELD_RAW_BYTES_CAPTURED_PRM_EXACT_COLLECTION_RECEIVER'))
    def stop(status):
        return dict(result, status=status)
    if not isinstance(field_path, str) or not 1 <= len(field_path) <= 4096:
        raise InputValidationError('Collection field path must contain 1 to 4096 characters')
    if referrer.get('database') != db.database_id:
        return stop('FOREIGN_SOURCE_DATABASE')
    allocation = db.allocation(referrer['segment'], referrer['cluster'], referrer['offset'])
    if allocation is None:
        return stop('NO_CURRENT_SOURCE_ALLOCATION')
    admission = reader.fields.schema_admission(allocation)
    result['source_schema_admission'] = admission
    if not admission['admitted']:
        return stop('SOURCE_SCHEMA_STORAGE_UNESTABLISHED')
    allocation, view = _location(db, referrer)
    if not allocation or view.get('status') != 'EXACT_ELEMENT_START':
        return stop('REFERRER_NOT_EXACT_ELEMENT_START')
    if allocation['element_size'] > 65536:
        return stop('REFERRER_ELEMENT_SIZE_BOUND')
    owner = admission['schema_name']
    if owner not in reader.fields.schema.classes:
        return stop('SOURCE_SCHEMA_UNAVAILABLE')
    symbolic = re.sub(r'\[\d+\]', '[]', field_path)
    # Independent fresh source-schema flattening, not caller-supplied slot hints.
    slots = [slot for slot in _slots(reader.fields.schema, owner) if slot['path'] == symbolic]
    if len(slots) != 1:
        return stop('SOURCE_SLOT_MISSING_OR_AMBIGUOUS')
    slot = slots[0]
    result['source_declaration'] = slot
    if slot.get('conditional_union'):
        return stop('ACTIVE_UNION_ARM_NOT_ESTABLISHED')
    if not direct_collection_slot(reader, slot, referrer_policy):
        return stop('DIRECT_LIST_SOURCE_DECLARATION_UNSUPPORTED' if referrer_policy == DIRECT_LIST_REFERRER_POLICY
                    else 'DIRECT_COLLECTION_SOURCE_DECLARATION_UNSUPPORTED')
    expected_offset = _slot_offset(slot, field_path)
    if expected_offset is None:
        return stop('SOURCE_ARRAY_SELECTOR_UNSUPPORTED')
    value = reader.value(referrer)
    if value.get('unsupported_reasons'):
        return stop('REFERRER_TYPED_LAYOUT_UNSUPPORTED')
    fields = [field for field in value.get('fields', ()) if field.get('path') == field_path]
    if len(fields) != 1 or fields[0].get('kind') != 'stored_reference':
        return stop('CURRENT_SOURCE_FIELD_MISSING_OR_AMBIGUOUS')
    field = fields[0]
    width = field.get('size')
    expected_source = dict(referrer, offset=referrer['offset'] + expected_offset)
    if (field.get('record_relative_offset') != expected_offset
            or field.get('source_address') != expected_source
            or field.get('schema_type_descriptor') != slot.get('descriptor_offset')
            or type(width) is not int or width not in (4, 8)):
        return stop('CURRENT_SOURCE_FIELD_DECLARATION_MISMATCH')
    if expected_offset + width > allocation['element_size']:
        return stop('SOURCE_SLOT_CROSSES_ELEMENT')
    raw = db.read(db.address(expected_source['segment'], expected_source['cluster'],
        expected_source['offset']), width)
    if field.get('raw_hex') != raw.hex():
        return stop('SOURCE_SLOT_RAW_MISMATCH')
    binding = db.store.connection.execute('SELECT width,raw,status,target_segment,target_cluster,target_offset FROM pointers WHERE segment=? AND cluster=? AND logical_offset=?',
        (expected_source['segment'], expected_source['cluster'], expected_source['offset'])).fetchone()
    if binding is None:
        return stop('MISSING_CAPTURED_BINDING')
    if binding[0] != width:
        return stop('CAPTURED_SOURCE_WIDTH_MISMATCH')
    current = field.get('target')
    current = current.get('address', current) if isinstance(current, Mapping) else None
    if current != address:
        return stop('CURRENT_SOURCE_TARGET_MISMATCH')
    if binding[1] != raw:
        return stop('SOURCE_SLOT_RAW_MISMATCH')
    if binding[2] == 'NULL':
        return stop('NULL_SOURCE_FIELD')
    if binding[2] != 'RESOLVED':
        return stop('BINDING_NOT_RESOLVED')
    if current is None:
        return stop('UNRESOLVED_SOURCE_FIELD')
    if current.get('database') != db.database_id:
        return stop('FOREIGN_DATABASE')
    if tuple(current.get(k) for k in ('segment', 'cluster', 'offset')) != tuple(binding[3:]):
        return stop('CAPTURED_TARGET_MISMATCH')
    target_allocation = db.allocation(current['segment'], current['cluster'], current['offset'])
    if target_allocation is None:
        return stop('NO_CURRENT_ALLOCATION')
    target_admission = reader.fields.schema_admission(target_allocation)
    result['target_schema_admission'] = target_admission
    if not target_admission['admitted']:
        return stop('TARGET_SCHEMA_STORAGE_UNESTABLISHED')
    link = inspect_payload_reference(session, field, slot['pointee_type'])
    result['source_link'] = link
    if link['status'] != 'SOURCE_DECLARED_FIELD_TARGET':
        return stop(link['status'])
    target_view = link['target_view']
    if target_view.get('element_displacement') != 0:
        # Structural base-view evidence is retained. These policies do
        # not canonicalize a base receiver into a different adapter address.
        return stop('DIRECT_LIST_BASE_VIEW_UNSUPPORTED' if referrer_policy == DIRECT_LIST_REFERRER_POLICY
                    else 'DIRECT_COLLECTION_BASE_VIEW_UNSUPPORTED')
    selector = link['payload_selector']
    target_name = target_admission['schema_name']
    declared = _known(slot['pointee_type'])
    if referrer_policy == DIRECT_LIST_REFERRER_POLICY:
        if target_name != 'os_list':
            return stop('DIRECT_LIST_RECEIVER_LAYOUT_UNSUPPORTED')
        size = reader.fields.schema.layout('os_list').get('size')
        if (type(size) is not int or size < 1 or declared.get('size') != size
                or selector['element_size'] != size or selector['element_stride'] < size):
            return stop('DIRECT_LIST_RECEIVER_LAYOUT_UNSUPPORTED')
    else:
        is_list = reader.inherits(target_name, 'os_list') and not any(
            reader.inherits(target_name, anchor) for anchor in ('os_set', 'os_array'))
        if not is_list and target_name != 'os_array':
            return stop('DIRECT_COLLECTION_RECEIVER_DISPATCH_UNSUPPORTED')
        declared_size = reader.fields.schema.layout(declared['name']).get('size')
        size = reader.fields.schema.layout(target_name).get('size')
        if (type(size) is not int or size < 1 or declared.get('size') != declared_size
                or selector['element_size'] != size or selector['element_stride'] < size
                or (target_name == 'os_array' and size != 32)):
            return stop('DIRECT_COLLECTION_RECEIVER_LAYOUT_UNSUPPORTED')
        result['adapter_family'] = 'LIST' if is_list else 'ARRAY'
    result['collection_address'] = dict(address)
    result['target_selector'] = selector
    return stop('DIRECT_LIST_CONTEXT_CONFIRMED' if referrer_policy == DIRECT_LIST_REFERRER_POLICY
                else 'DIRECT_COLLECTION_CONTEXT_CONFIRMED')

