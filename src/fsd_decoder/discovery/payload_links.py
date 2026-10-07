"""Bounded Entity-to-payload paths justified by current source declarations.

A path is a sequence of stored source fields, not application ownership. Native
allocation ranges remain distinct from field lengths and geological meaning.
Collections are terminal storage links; their members require their adapter.
"""
from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterator, Mapping
from dataclasses import asdict
import re

from fsd_decoder.core.provenance import runtime_identity
from fsd_decoder.core.diagnostics import require_source_failure
from .datasets import DiscoverySession, _character, _limit, _typed, session_operation
from .source_declarations import declared_pointee
from .relationship_discovery import RelationshipError, _target_view, inspect_element

VERSION = 1
ACCEPTED_LINK_STATUS = 'SOURCE_DECLARED_FIELD_TARGET'


def _current_storage_pointer_gaps(value: Mapping) -> list[str]:
    """Separate pointer classification from full source/value interpretation.

    Compact runtime words, ordinals and explicit filler remain nonedges even
    when source ABI admission fails. Opaque bytes and unselected unions cannot
    establish that all current pointers have been enumerated.
    """
    gaps = set()
    if not _typed(value.get('status')):
        gaps.add('CURRENT_NODE_POINTER_CLASSIFICATION_UNESTABLISHED')
    if value.get('uninterpreted_regions') or value.get('padding_raw_hex'):
        gaps.add('CURRENT_STORAGE_REGION_POINTER_CLASSIFICATION_UNESTABLISHED')
    # inspect_element projects primitive records to references without copying
    # their scalar kind. Its empty list proves no pointers for a typed scalar.
    for field in value.get('fields', value.get('references', [value])):
        kind = field.get('kind')
        if kind in ('union', 'union_storage') or field.get('declared_views'):
            gaps.add('CONDITIONAL_UNION_ACTIVE_MEMBER_UNKNOWN')
        elif kind == 'layout_bytes':
            opcode = field.get('opcode', '').removeprefix('0x')
            if opcode not in ('08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '34'):
                gaps.add('CURRENT_STORAGE_REGION_POINTER_CLASSIFICATION_UNESTABLISHED')
        elif kind not in ('stored_reference', 'primitive', 'enum', 'bitfield',
                'integer', 'floating', 'floating_storage', 'character', 'character_bytes',
                'ordinal_storage', 'alignment_byte', 'runtime_code_word', 'bitfield_storage'):
            gaps.add('CURRENT_FIELD_POINTER_CLASSIFICATION_UNESTABLISHED')
    return sorted(gaps)


def _address(db, value: Mapping) -> dict:
    if not isinstance(value, Mapping):
        raise RelationshipError('Payload address must be a mapping')
    parts = [value.get(k) for k in ('segment', 'cluster', 'offset')]
    if any(type(p) is not int or p < 0 for p in parts):
        raise RelationshipError('Payload address requires nonnegative integer coordinates')
    database = value.get('database', db.database_id)
    return dict(database=database, segment=parts[0], cluster=parts[1], offset=parts[2])


def _kind(kind):
    while kind and kind.get('kind') in ('qualified', 'alias'):
        if kind.get('unknown_qualifier_flags'):
            return None
        kind = kind.get('underlying')
    return kind


def _declared_pointee(session, field, slot):
    if field.get('pointee_type') is not None:
        return field['pointee_type']
    # Existing pointees and class-only consumers need no primitive registry.
    return declared_pointee(session.db.fields.schema,
        getattr(session.db.fields, 'types', {}), field, slot)


def _location(db, address: Mapping, declared=None) -> tuple[dict | None, dict]:
    """Canonicalize only exact element starts or the declared exact base view."""
    if address['database'] != db.database_id:
        return None, dict(status='FOREIGN_DATABASE')
    allocation = db.allocation(address['segment'], address['cluster'], address['offset'])
    if allocation is None:
        return None, dict(status='NO_CURRENT_ALLOCATION')
    if allocation['name'] == 'inline_char_bytes' and _character(declared):
        if address['offset'] >= allocation['logical_offset'] + allocation.get('count', 0):
            return allocation, dict(status='ALLOCATION_PADDING')
        canonical = dict(address, offset=allocation['logical_offset'])
        return allocation, dict(status='EXACT_INLINE_CHARACTER_BYTE', canonical_address=canonical,
            element_index=0, character_byte_displacement=address['offset']-allocation['logical_offset'],
            matching_schema_base_types=[])
    header = allocation.get('array_header_size', 0)
    stride = allocation.get('element_stride', allocation.get('element_size', allocation['size']))
    size = allocation.get('element_size', allocation['size'])
    relative = address['offset'] - allocation['logical_offset'] - header
    if type(stride) is not int or stride <= 0 or relative < 0:
        return allocation, dict(status='HEADER_OR_UNKNOWN_STRIDE')
    index, within = divmod(relative, stride)
    count = allocation.get('count', 1)
    if index >= count or within >= size:
        return allocation, dict(status='ALLOCATION_PADDING')
    view = _target_view(db, allocation, address['offset'])
    pointee = _kind(declared)
    name = pointee.get('name') if pointee else None
    if within and (not name or name not in view['matching_schema_base_types']):
        return allocation, dict(view, status='INTERIOR_WITHOUT_DECLARED_BASE_VIEW')
    canonical = asdict(db.address(address['segment'], address['cluster'],
        allocation['logical_offset'] + header + index * stride))
    return allocation, dict(view, status='EXACT_DECLARED_BASE_SUBOBJECT' if within else
        'EXACT_ELEMENT_START', canonical_address=canonical, element_index=index)


def _compatible(db, allocation, declared, view) -> str:
    kind = _kind(declared)
    if kind is None:
        return 'POINTEE_TYPE_UNESTABLISHED'
    # Source _Void_type_ descriptors are unsized, type-erased pointees. Their
    # declared pointer still supplies address evidence, never a target type.
    if kind.get('kind') == 'void':
        return 'TYPE_ERASED_SOURCE_POINTER'
    name = allocation['name'].removesuffix('[]')
    if kind.get('kind') in ('class', 'union'):
        if not db.fields.schema_admission(allocation)['admitted']:
            return 'POINTEE_TYPE_UNESTABLISHED'
        return 'DECLARED_TYPE_MATCH' if kind.get('name') in view.get(
            'matching_schema_base_types', ()) else 'POINTEE_TYPE_MISMATCH'
    if kind.get('kind') == 'primitive':
        if kind.get('name') == 'void':
            return 'TYPE_ERASED_SOURCE_POINTER'
        if kind.get('name') == name or (_character(kind) and
                (allocation.get('native_tag') == 1 or name == 'inline_char_bytes')):
            return 'DECLARED_TYPE_MATCH'
        ieee = {'float': ('4 byte ieees float',4), 'double': ('8 byte ieeed double',8)}
        if name in ieee and (kind.get('name'),kind.get('size')) == ieee[name] and allocation.get(
                'native_tag') == (5 if name=='float' else 6):
            return 'DECLARED_IEEE_PRIMITIVE_ALIAS_MATCH'
        if (kind.get('name') in ieee and (name,allocation.get('element_size')) == ieee[kind['name']]
                and allocation.get('native_tag') == (19 if kind['name']=='float' else 21)):
            return 'DECLARED_IEEE_PRIMITIVE_ALIAS_MATCH'
        return 'POINTEE_TYPE_MISMATCH'
    # Pointer-to-pointer payloads have independently identified native pointer
    # storage. A schema name/word alone cannot select any pointee union view.
    if kind.get('kind') == 'pointer' and allocation.get('native_tag') in (8, 14):
        tag = allocation['native_tag']
        native = getattr(db.fields, 'types', {}).get(tag, {})
        declared_size = kind.get('size')
        native_size = native.get('size')
        element_size = allocation.get('element_size')
        view['pointer_storage_compatibility'] = dict(declared_pointer_size=declared_size,
            native_tag=tag, native_pointer_size=native_size,
            allocation_element_size=element_size,
            allocation_element_stride=allocation.get('element_stride'))
        if (type(declared_size) is not int or declared_size not in (4, 8) or
                type(native_size) is not int or native_size != (4 if tag == 8 else 8) or
                type(element_size) is not int or element_size != native_size):
            return 'POINTEE_TYPE_UNESTABLISHED'
        return 'DECLARED_POINTER_STORAGE_MATCH' if declared_size == native_size else 'POINTEE_TYPE_MISMATCH'
    return 'POINTEE_TYPE_UNESTABLISHED'


def _selector(allocation, view) -> dict:
    index = view['element_index']
    inline_char = allocation['name'] == 'inline_char_bytes'
    return dict(allocation_id=allocation['store_allocation_id'],
        allocation_address=dict(view['canonical_address'], offset=allocation['logical_offset']),
        canonical_address=view['canonical_address'], type=allocation['name'],
        native_tag=allocation['native_tag'], vector=allocation.get('vector', False),
        element_start_index=index, stored_elements=1 if inline_char else allocation.get('count', 1) - index,
        allocation_element_count=allocation.get('count', 1),
        element_size=allocation.get('element_size', allocation['size']),
        element_stride=allocation.get('element_stride', allocation.get('element_size', allocation['size'])),
        array_header_size=allocation.get('array_header_size', 0), allocation_bytes=allocation['size'],
        extent_semantics='INDEXED_ALLOCATION_REMAINDER; FIELD_LENGTH_NOT_ESTABLISHED')


def _traversal(session, allocation, declared) -> str:
    base = allocation['name'].removesuffix('[]')
    is_class = session.db.fields.schema_admission(allocation)['admitted']
    if _character(declared):
        return 'TEXT_STORAGE'
    if is_class and any(session.reader.inherits(base, b)
            for b in ('os_collection', 'os_list', 'os_set', 'os_array')):
        return 'COLLECTION_MEMBERSHIP_REQUIRES_ADAPTER'
    if is_class and session.reader.inherits(base, 'Fs::Entity'):
        return 'OTHER_ENTITY'
    if allocation.get('vector'):
        return 'ARRAY_ALLOCATION'
    return 'SOURCE_DECLARED_STRUCTURAL_RECORD' if is_class else 'NATIVE_OR_UNKNOWN_STORAGE'


def inspect_payload_reference(session: DiscoverySession, reference: Mapping,
                              declared_pointee: Mapping | None = None) -> dict:
    """Validate a typed pointer-array element against its captured source slot.

    The caller supplies the pointee declaration inherited from its accepted
    source-field pointer-to-pointer link. This helper does not infer pointees
    from runtime names, native words, project labels or an active union view.
    The exact PRM row must agree with the decoder's source bytes and target.
    """
    with session_operation(session):
        return _inspect_reference(session, reference, declared_pointee)


def _inspect_reference(session, reference, declared_pointee=None, *, source_declared=True):
    """Shared captured-row/current target proof; declaration admission is explicit."""
    with session_operation(session):
        db = session.db
        if not isinstance(reference, Mapping) or reference.get('kind') != 'stored_reference':
            raise RelationshipError('Payload reference requires a decoded stored_reference')
        declared_pointee = declared_pointee or reference.get('pointee_type')
        slot = _address(db, reference.get('source_address'))
        result = dict(record='link', source_address=slot, slot_address=slot,
            field_path=reference.get('path'), declared_pointee=declared_pointee,
            raw_hex=reference.get('raw_hex'), stored_word=reference.get('stored_word'),
            payload_selector=None, ownership='NOT_INFERRED', geological_meaning='UNESTABLISHED',
            declaration_scope='INHERITED_SOURCE_FIELD_POINTEE; NO_UNION_SELECTION')
        if slot['database'] != db.database_id:
            return dict(result, status='FOREIGN_SOURCE_DATABASE')
        source_allocation = db.allocation(slot['segment'], slot['cluster'], slot['offset'])
        if source_allocation is None:
            return dict(result, status='NO_CURRENT_SOURCE_ALLOCATION')
        source_admission = db.fields.schema_admission(source_allocation)
        if source_declared and source_admission['schema_name'] is not None and not source_admission['admitted']:
            return dict(result, status='SOURCE_DECLARATION_UNESTABLISHED', schema_admission=source_admission)
        if source_declared and declared_pointee is None and isinstance(reference.get('path'), str):
            symbolic = re.sub(r'\[\d+\]', '[]', reference['path'])
            declaration = next((r for r in session.census if r['type']==source_allocation['name']), None)
            source_slot = next((s for s in declaration.get('slots', ()) if s['path']==symbolic
                and not s.get('conditional_union')), None) if declaration else None
            if source_slot:
                declared_pointee = _declared_pointee(session, reference, source_slot)
                result['declared_pointee'] = declared_pointee
        row = db.store.connection.execute('''SELECT status,target_segment,target_cluster,target_offset,
            width,raw FROM pointers WHERE segment=? AND cluster=? AND logical_offset=?''',
            (slot['segment'], slot['cluster'], slot['offset'])).fetchone()
        if row is None:
            status = 'NULL_SOURCE_FIELD' if reference.get('stored_word') == 0 and db.store.manifest.get(
                'pointer_resolution_complete') else 'MISSING_CAPTURED_BINDING'
            return dict(result, status=status, binding_status='NULL' if status=='NULL_SOURCE_FIELD' else 'MISSING')
        binding, segment, cluster, offset, width, raw = tuple(row)
        result['binding_status'] = binding
        result['binding_evidence'] = 'EXPLICIT_CAPTURED_PRM_BINDING'
        if not source_declared and width != reference.get('size', reference.get('element_size')):
            return dict(result, status='SOURCE_SLOT_WIDTH_MISMATCH')
        if slot['offset'] + width > source_allocation['logical_offset'] + source_allocation['size']:
            return dict(result, status='SOURCE_SLOT_CROSSES_ALLOCATION')
        if reference.get('raw_hex') != raw.hex():
            return dict(result, status='SOURCE_SLOT_RAW_MISMATCH')
        if binding == 'NULL':
            return dict(result, status='NULL_SOURCE_FIELD')
        if binding != 'RESOLVED':
            return dict(result, status='BINDING_NOT_RESOLVED')
        address = reference.get('target')
        address = address.get('address', address) if isinstance(address, Mapping) else None
        if address is None:
            return dict(result, status='UNRESOLVED_SOURCE_FIELD')
        address = _address(db, address)
        result['target_address'] = address
        if address['database'] != db.database_id:
            return dict(result, status='FOREIGN_DATABASE')
        if (address['segment'], address['cluster'], address['offset']) != (segment, cluster, offset):
            return dict(result, status='CAPTURED_TARGET_MISMATCH')
        allocation, view = _location(db, address, declared_pointee)
        result['target_view'] = view
        if 'canonical_address' not in view:
            return dict(result, status=view['status'])
        compatibility = (_compatible(db, allocation, declared_pointee, view) if source_declared else
            'CURRENT_STORAGE_ONLY; SOURCE_POINTEE_UNESTABLISHED')
        result['target_type_status'] = compatibility
        if compatibility in ('POINTEE_TYPE_MISMATCH', 'POINTEE_TYPE_UNESTABLISHED'):
            return dict(result, status=compatibility)
        result['payload_selector'] = _selector(allocation, view)
        result['traversal'] = _traversal(session, allocation, declared_pointee)
        return dict(result, status=ACCEPTED_LINK_STATUS if source_declared else 'CURRENT_COMPACT_POINTER_TARGET')


def inspect_current_storage_reference(session: DiscoverySession, reference: Mapping, *,
        max_element_bytes: int = 65536) -> dict:
    """Verify actual native pointer storage, without a source-pointee claim.

    Re-decode the containing current element through the public interpreter.
    Only its semantic compact pointer fields or exact native pointer elements
    can supply edges. Runtime words, filler and unselected unions cannot.
    """
    with session_operation(session):
        _limit(max_element_bytes, 'max_element_bytes', 1048576)
        db = session.db
        slot = _address(db, reference.get('source_address'))
        evidence = dict(record='link', source_address=slot, slot_address=slot,
            payload_selector=None, ownership='NOT_INFERRED', association_witnessed=False,
            declaration_scope='CURRENT_STORAGE_GRAPH; SOURCE_CLASS_AND_POINTEE_UNESTABLISHED')
        if slot['database'] != db.database_id:
            return dict(evidence, status='FOREIGN_SOURCE_DATABASE')
        allocation = db.allocation(slot['segment'], slot['cluster'], slot['offset'])
        if allocation is None:
            return dict(evidence, status='NO_CURRENT_SOURCE_ALLOCATION')
        stride = allocation.get('element_stride', allocation.get('element_size', allocation['size']))
        size = allocation.get('element_size', allocation['size'])
        relative = slot['offset'] - allocation['logical_offset'] - allocation.get('array_header_size', 0)
        if type(stride) is not int or stride <= 0 or relative < 0:
            return dict(evidence, status='SOURCE_ELEMENT_UNESTABLISHED')
        index, within = divmod(relative, stride)
        if index >= allocation.get('count', 1) or within >= size:
            return dict(evidence, status='SOURCE_ELEMENT_UNESTABLISHED')
        read_size = size if allocation.get('vector') else allocation['size']
        if read_size > max_element_bytes:
            return dict(evidence, status='SOURCE_ELEMENT_SIZE_BOUND', element_size=read_size)
        # Unknown captured bindings are terminal before any interpreter resolver
        # can confuse resolve(None) with a semantic null pointer.
        captured_row = db.store.connection.execute('''SELECT status,width,raw FROM pointers
            WHERE segment=? AND cluster=? AND logical_offset=?''',
            (slot['segment'], slot['cluster'], slot['offset'])).fetchone()
        reference_raw = reference.get('raw_hex')
        if captured_row is not None and captured_row['status'] not in ('RESOLVED', 'NULL'):
            if not isinstance(reference_raw, str) or reference_raw != captured_row['raw'].hex():
                return dict(evidence, status='SOURCE_SLOT_RAW_MISMATCH')
            return dict(evidence, status='BINDING_NOT_RESOLVED', binding_status=captured_row['status'],
                binding_evidence='EXPLICIT_CAPTURED_PRM_BINDING', raw_hex=reference_raw)
        try:
            decoded = db.fields.decode(allocation, element_index=index)
        except Exception as exc:
            require_source_failure(exc, dict(phase='root-current-storage-reference', address=slot, element_index=index))
            return dict(evidence, status='CURRENT_SOURCE_ELEMENT_DECODE_UNRESOLVED',
                error=str(exc), source_element_index=index,
                raw_selector=dict(address=dict(slot, offset=slot['offset'] - within), size=read_size))
        admitted = db.fields.schema_admission(allocation)['admitted']
        matches = []
        for field in decoded.get('fields', [decoded]):
            if field.get('kind') != 'stored_reference':
                continue
            field_slot = field.get('source_address')
            field_offset = field.get('record_relative_offset', 0)
            if field_slot is None:
                field_slot = dict(slot, offset=allocation['logical_offset'] +
                    allocation.get('array_header_size', 0) + index * stride + field_offset)
            if _address(db, field_slot) != slot:
                continue
            if field.get('raw_hex') != reference.get('raw_hex'):
                continue
            native = getattr(db.fields, 'types', {}).get(allocation['native_tag'], {})
            builtin = allocation['native_tag'] in (8, 14) and native.get('size') == size == (
                4 if allocation['native_tag'] == 8 else 8)
            opcode = field.get('opcode')
            opcode = opcode.removeprefix('0x') if isinstance(opcode, str) else opcode
            if opcode in ('17', '18', '35', '36'):
                width = 4 if opcode in ('17', '35') else 8
                if field.get('size') != width:
                    continue
                basis = 'CURRENT_COMPACT_SEMANTIC_POINTER_OPCODE'
            elif builtin:
                width = size
                basis = 'CURRENT_NATIVE_POINTER_ELEMENT'
            elif admitted and field.get('size') in (4, 8):
                width = field['size']
                basis = 'CORROBORATED_SOURCE_COMPACT_POINTER_STORAGE_INTERVAL'
            else:
                continue
            raw = field.get('value_raw_hex', field.get('raw_hex'))
            if not isinstance(raw, str) or len(raw) != width * 2 or within + width > size:
                continue
            if db.read(db.address(slot['segment'], slot['cluster'], slot['offset']), width).hex() != raw:
                continue
            machine_path = (field.get('path') if opcode else None) or f'@byte+{within}:pointer{width * 8}'
            normalized = dict(field, source_address=slot, raw_hex=raw, size=width,
                path=machine_path, pointee_type=None)
            matches.append((normalized, basis))
        if len(matches) != 1:
            return dict(evidence, status='CURRENT_SEMANTIC_POINTER_UNESTABLISHED',
                matching_current_fields=len(matches))
        normalized, basis = matches[0]
        result = _inspect_reference(session, normalized, source_declared=False)
        result.update(declaration_scope=evidence['declaration_scope'], association_witnessed=False,
            semantic_pointer_evidence=basis, field_path_kind='CURRENT_STORAGE_INTERVAL',
            declared_pointee=None, source_element_index=index,
            source_element_address=dict(slot, offset=slot['offset'] - within))
        if result.get('payload_selector'):
            target = result['payload_selector']['canonical_address']
            destination = db.allocation(target['segment'], target['cluster'], target['offset'])
            typ = getattr(db.fields, 'types', {}).get(destination['native_tag'], {})
            if (result['traversal'] == 'NATIVE_OR_UNKNOWN_STORAGE' and not destination.get('vector')
                    and ('trace' in typ or destination['native_tag'] in (8, 14))):
                result['traversal'] = 'CURRENT_NATIVE_STRUCTURAL_RECORD'
        return result


def iter_payload_links(session: DiscoverySession, entity_address: Mapping, *,
                       max_nodes: int = 128, max_depth: int = 4,
                       max_links: int = 1024, max_element_bytes: int = 65536) -> Iterator[dict]:
    """Stream bounded declared field paths for one exact established Entity.

    Consumers must exhaust the iterator to receive its verified final summary.
    Arrays, other Entities and collections are terminal; scalar structural
    records can be followed within the explicit work budgets. Every accepted
    link carries a payload selector, including scalar structural records.
    """
    with session_operation(session):
        _limit(max_nodes, 'max_nodes', 10000)
        _limit(max_links, 'max_links', 100000)
        _limit(max_element_bytes, 'max_element_bytes', 1048576)
        if type(max_depth) is not int or not 0 <= max_depth <= 64:
            raise RelationshipError('max_depth must be an integer from 0 to 64')
        db = session.db
        address = _address(db, entity_address)
        allocation, start = _location(db, address, dict(kind='class', name='Fs::Entity'))
        if allocation is None or not db.fields.schema_admission(allocation)['admitted'] or 'canonical_address' not in start or not session.reader.inherits(
                allocation['name'].removesuffix('[]'), 'Fs::Entity'):
            raise RelationshipError('Payload selection requires an exact current Entity element or Entity base view')
        entity = dict(address=start['canonical_address'], supplied_address=address,
            type=allocation['name'], allocation_id=allocation['store_allocation_id'],
            element_index=start['element_index'])
        yield from _iter_declared_payload_links(session, entity, max_nodes=max_nodes,
            max_depth=max_depth, max_links=max_links, max_element_bytes=max_element_bytes)


def _iter_declared_payload_links(session: DiscoverySession, entity: Mapping, *,
        max_nodes: int, max_depth: int, max_links: int, max_element_bytes: int,
        root_origin: Mapping | None = None, follow_affiliated_entities: bool = False,
        current_storage_graph: bool = False) -> Iterator[dict]:
    """Share the bounded walk; the admitted public stream owns its lifecycle."""
    db = session.db
    start = dict(canonical_address=entity['address'])
    context = ({'entity': entity} if root_origin is None else {'root': root_origin, 'seed': entity})
    affiliation = ({'entity_address': entity['address']} if root_origin is None else
        {'root_index': root_origin['index'], 'root_address': entity['address'],
         'root_origin': root_origin, 'affiliation': 'SOURCE_ROOT_STRUCTURAL_PATH'})
    diagnostic_context = {} if root_origin is None else affiliation
    configuration = dict(max_nodes=max_nodes, max_depth=max_depth, max_links=max_links,
        max_element_bytes=max_element_bytes, max_schema_leaves=4096)
    if root_origin is not None:
        configuration['follow_affiliated_entities'] = follow_affiliated_entities
        configuration['current_storage_graph'] = current_storage_graph
    pins = runtime_identity()
    declarations = {r['type']: r for r in session.census}
    pending = deque([(start['canonical_address'], 0, [])]) if max_depth else deque()
    seen = {tuple(start['canonical_address'][k] for k in ('segment', 'cluster', 'offset'))}
    counts, bounded = Counter(), set() if max_depth else {'depth'}
    nodes = records = declared_slots = 0
    interpretation_counts = Counter()
    graph_gaps = Counter()
    session.check_identity()
    yield dict(record='header', format='FSD_ENTITY_PAYLOAD_LINK_STREAM' if root_origin is None else 'FSD_SOURCE_ROOT_PAYLOAD_LINK_STREAM', version=VERSION,
        source=dict(db.source_info), **context, runtime_identity=pins,
        configuration=configuration, policy='SOURCE_DECLARED_FIELD_PATHS; OWNERSHIP_NOT_INFERRED')
    while pending and records < max_links:
        current, depth, path = pending.popleft()
        nodes += 1
        current_allocation = db.allocation(current['segment'], current['cluster'], current['offset'])
        declaration = declarations[current_allocation['name']]
        leaf_count = 0
        for slot in declaration.get('slots', ()):
            multiplicity = 1
            for array in slot.get('arrays', ()):
                multiplicity *= array['count']
            leaf_count += multiplicity
        source_admitted = db.fields.schema_admission(current_allocation)['admitted']
        if (declaration.get('diagnostics') or leaf_count > 4096) and not (current_storage_graph and not source_admitted):
            if current_storage_graph:
                graph_gaps['SCHEMA_INSPECTION_BOUND'] += 1
            records += 1
            counts['SCHEMA_INSPECTION_BOUND'] += 1
            yield dict(record='diagnostic', **diagnostic_context, address=current, status='SCHEMA_INSPECTION_BOUND',
                schema_leaves=leaf_count, declaration_diagnostics=declaration.get('diagnostics', []))
            continue
        inspected = inspect_element(db, current['segment'], current['cluster'], current['offset'],
            max_element_bytes=max_element_bytes)
        facets = inspected.get('interpretation', {})
        pointer_gaps = _current_storage_pointer_gaps(inspected) if current_storage_graph else []
        graph_gaps.update(pointer_gaps)
        for key, value in facets.items():
            if key.endswith('_count') and type(value) is int:
                interpretation_counts[key] += value
        if facets and not facets.get('typed_fields_complete'):
            if records == max_links:
                bounded.add('links')
                break
            records += 1
            counts['NODE_INTERPRETATION_UNRESOLVED'] += 1
            yield dict(record='diagnostic', **diagnostic_context, address=current, status='NODE_INTERPRETATION_UNRESOLVED',
                path=path, interpretation=facets,
                **({'current_storage_graph_gaps': pointer_gaps,
                    'raw_selector': dict(address=current, size=current_allocation.get('element_size', current_allocation['size']))}
                   if current_storage_graph else {}),
                raw_hex=inspected.get('raw_hex', inspected.get('record_hex')),
                tag_discriminants=inspected.get('tag_discriminants', []),
                discriminant_status=inspected.get('discriminant_status'))
        slots = {s['path']: s for s in declaration.get('slots', ())}
        if current_storage_graph and not source_admitted:
            slots = {}
        conditional = [s for s in slots.values() if s.get('conditional_union')]
        if current_storage_graph and conditional:
            graph_gaps['CONDITIONAL_UNION_ACTIVE_MEMBER_UNKNOWN'] += 1
        for slot in conditional:
            if records == max_links:
                bounded.add('links')
                break
            records += 1
            counts['CONDITIONAL_UNION_ACTIVE_MEMBER_UNKNOWN'] += 1
            yield dict(record='diagnostic', **diagnostic_context, address=current, field_path=slot['path'],
                status='CONDITIONAL_UNION_ACTIVE_MEMBER_UNKNOWN', path=path,
                declared_kind=slot['kind'], active_member=None)
        if not _typed(inspected['status']):
            if records == max_links:
                bounded.add('links')
                break
            records += 1
            counts[inspected['status']] += 1
            yield dict(record='diagnostic', **diagnostic_context, address=current, status=inspected['status'],
                unsupported_reasons=inspected.get('unsupported_reasons', []),
                error=inspected.get('error'), path=path, interpretation=facets,
                raw_hex=inspected.get('raw_hex', inspected.get('record_hex')))
        for field in inspected.get('references', ()):
            if records == max_links:
                bounded.add('links')
                break
            declared_slots += 1
            symbolic = re.sub(r'\[\d+\]', '[]', field.get('path') or '')
            slot = slots.get(symbolic)
            declared_pointee = _declared_pointee(session, field, slot) if slot else None
            link = dict(record='link', **affiliation, source_address=current,
                source_type=current_allocation['name'], field_path=field.get('path'),
                slot_address=field['source_address'], depth=depth + 1, path=path + ([field['path']] if field.get('path') else []),
                stored_word=field.get('stored_word'), raw_hex=field.get('raw_hex'),
                binding_status=field.get('binding_status'),
                binding_evidence=field.get('binding_evidence'),
                declared_pointee=declared_pointee, payload_selector=None,
                ownership='NOT_INFERRED', geological_meaning='UNESTABLISHED')
            if current_storage_graph:
                verified = (_inspect_reference(session, field, declared_pointee) if slot and
                    not slot.get('conditional_union') and source_admitted else None)
                if verified is None or (not verified.get('payload_selector') and
                        verified.get('status') not in ('NULL_SOURCE_FIELD',)):
                    native = inspect_current_storage_reference(session, field,
                        max_element_bytes=max_element_bytes)
                    if verified is not None:
                        native['source_relationship_status'] = verified['status']
                    verified = native
                link.update(verified)
                link.update(affiliation, source_address=current, source_type=current_allocation['name'],
                    depth=depth + 1, path=path + ([verified['field_path']] if verified.get('field_path') else []))
                status = verified['status']
                if verified.get('payload_selector'):
                    view = verified['target_view']
                    traversal = verified['traversal']
            else:
                target = field.get('target')
                target = target.get('address', target) if isinstance(target, Mapping) else None
                if not slot or slot.get('conditional_union'):
                    status = 'SOURCE_DECLARATION_UNESTABLISHED'
                elif field.get('binding_status') == 'NULL':
                    status = 'NULL_SOURCE_FIELD'
                elif not target:
                    status = 'UNRESOLVED_SOURCE_FIELD'
                else:
                    target = _address(db, target)
                    link['target_address'] = target
                    destination, view = _location(db, target, declared_pointee)
                    link['target_view'] = view
                    if 'canonical_address' not in view:
                        status = view['status']
                    else:
                        compatibility = _compatible(db, destination, declared_pointee, view)
                        link['target_type_status'] = compatibility
                        if compatibility in ('POINTEE_TYPE_MISMATCH', 'POINTEE_TYPE_UNESTABLISHED'):
                            status = compatibility
                        elif field.get('binding_status') != 'RESOLVED':
                            status = 'BINDING_NOT_RESOLVED'
                        else:
                            status = ACCEPTED_LINK_STATUS
                            link['payload_selector'] = _selector(destination, view)
                            traversal = _traversal(session, destination, declared_pointee)
            if link.get('payload_selector'):
                affiliated_entity = traversal == 'OTHER_ENTITY' and follow_affiliated_entities
                if affiliated_entity:
                    link['target_role'] = 'SOURCE_ROOT_AFFILIATED_ENTITY_RECORD'
                structural = traversal in ('SOURCE_DECLARED_STRUCTURAL_RECORD', 'CURRENT_NATIVE_STRUCTURAL_RECORD')
                if not structural and not affiliated_entity:
                    link['traversal'] = traversal
                else:
                    canonical = view['canonical_address']
                    key = tuple(canonical[k] for k in ('segment', 'cluster', 'offset'))
                    if key in seen:
                        link['traversal'] = 'ALREADY_VISITED'
                    elif depth + 1 >= max_depth:
                        bounded.add('depth')
                        link['traversal'] = 'DEPTH_BOUND'
                    elif len(seen) >= max_nodes:
                        bounded.add('nodes')
                        link['traversal'] = 'NODE_BOUND'
                    else:
                        seen.add(key)
                        pending.append((canonical, depth + 1, link['path']))
                        link['traversal'] = 'SOURCE_ROOT_AFFILIATED_ENTITY_RECORD' if affiliated_entity else traversal
            link['status'] = status
            if current_storage_graph and not link.get('payload_selector') and status != 'NULL_SOURCE_FIELD':
                graph_gaps[status] += 1
                link['current_storage_graph_gap'] = status
            counts[status] += 1
            records += 1
            yield link
        session.check_identity()
    if pending:
        bounded.add('links')
    session.check_identity()
    if runtime_identity() != pins:
        raise RelationshipError('Runtime changed during payload-link inspection')
    yield dict(record='summary', **context,
        **({} if root_origin is None else {'root_seed_admitted': True,
            'source_fields_admitted': root_origin['source_fields_admitted'],
            'pending_frontier': [dict(address=at, depth=at_depth, path=at_path,
                payload_selector=_selector(db.allocation(at['segment'], at['cluster'], at['offset']),
                    _location(db, at, None)[1])) for at, at_depth, at_path in pending]}),
        configuration=configuration,
        nodes_inspected=nodes, records=records, source_fields_inspected=declared_slots,
        interpretation_counts=dict(interpretation_counts),
        status_counts=dict(counts), bounded=sorted(bounded), traversal_complete=not bounded,
        complete=not bounded,
        **({'current_storage_inspected_graph_complete': not bounded and not graph_gaps,
            'current_storage_graph_gap_counts': dict(graph_gaps),
            'current_storage_graph_scope': 'INSPECTED_NODE_POINTERS; SELECTED_TERMINAL_PAYLOADS_REQUIRE_EXPORT_EXPANSION'}
           if current_storage_graph else {}),
        integrity_mode='SESSION_IDENTITY_CHECK; SESSION_FINISH_REQUIRED_FOR_QUICK_CHECK',
        enumeration_scope=('ONE_ENTITY_DECLARED_FIELD_PATHS; ARRAYS_AND_COLLECTIONS_TERMINAL'
            if root_origin is None else 'ONE_SOURCE_ROOT_DECLARED_FIELD_PATHS; ARRAYS_AND_COLLECTIONS_TERMINAL'),
        geological_semantics_complete=False, ownership_established=False,
        original_source_required=False,
        limitations=['Native allocation ranges are not established field lengths.',
            'Array elements and collection members are not recursively traversed.',
            'Conditional union fields never supply active links.',
            'Verified field paths do not assign ownership, units, CRS or geological roles.'])


def inspect_payload_links(db, entity_address: Mapping, *, session: DiscoverySession | None = None,
                          max_nodes: int = 128, max_depth: int = 4,
                          max_links: int = 1024, max_element_bytes: int = 65536) -> dict:
    """Materialize one small budgeted stream without expanding any payload."""
    owned = session is None
    session = session or DiscoverySession(db)
    with session_operation(session):
        if session.db is not db:
            raise RelationshipError('Payload session belongs to another store')
        links, diagnostics = [], []
        for record in iter_payload_links(session, entity_address, max_nodes=max_nodes,
                max_depth=max_depth, max_links=max_links, max_element_bytes=max_element_bytes):
            if record['record'] == 'header':
                result = dict(record)
                result.pop('record')
                result['format'] = 'FSD_ENTITY_PAYLOAD_LINKS'
            elif record['record'] == 'summary':
                result['summary'] = record
            else:
                (links if record['record'] == 'link' else diagnostics).append(record)
        if owned:
            session.finish()
        return dict(result, links=links, diagnostics=diagnostics)
