"""Bounded retained SOURCE_ROOT affiliation, without application ownership.

Native root slots are eight-byte provenance fields. They are distinct from
application member declarations, compact RDs and compiled class descriptors.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence

from fsd_decoder.core.provenance import runtime_identity
from .datasets import DiscoverySession, _limit, session_operation
from .payload_links import (_address, _compatible, _iter_declared_payload_links,
                            _location, _selector, _traversal)
from .relationship_discovery import RelationshipError

MAX_ROOT_RECORDS = 10000
MAX_ROOT_NAME_BYTES = 4096


def _root_address(db, value):
    if isinstance(value, Mapping):
        return _address(db, value)
    if isinstance(value, (list, tuple)) and len(value) == 3:
        return _address(db, dict(zip(('segment', 'cluster', 'offset'), value)))
    raise RelationshipError('Retained root address requires exact coordinates')


def _hex(value, size=None, maximum=MAX_ROOT_NAME_BYTES):
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2:
        return None
    if size is not None and len(value) != size * 2:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _root_binding(db, source, raw, retained_target):
    evidence = dict(source_address=source, width=8, raw_hex=raw.hex(),
        retained_target=retained_target, evidence='CAPTURED_NATIVE_ROOT_SLOT_PRM')
    if source['database'] != db.database_id:
        return dict(evidence, status='FOREIGN_SOURCE_DATABASE', verified=False)
    current_raw = db.read(db.address(source['segment'], source['cluster'], source['offset']), 8)
    if current_raw != raw:
        return dict(evidence, status='SOURCE_SLOT_RAW_MISMATCH', verified=False)
    row = db.store.connection.execute('''SELECT status,target_segment,target_cluster,target_offset,
        width,raw FROM pointers WHERE segment=? AND cluster=? AND logical_offset=?''',
        (source['segment'], source['cluster'], source['offset'])).fetchone()
    if row is None:
        null = (raw == bytes(8) and retained_target is None and
                db.store.manifest.get('pointer_resolution_complete') is True)
        return dict(evidence, status='NULL' if null else 'MISSING_CAPTURED_BINDING', verified=null)
    status, segment, cluster, offset, width, captured = tuple(row)
    evidence['binding_status'] = status
    if width != 8:
        return dict(evidence, status='SOURCE_SLOT_WIDTH_MISMATCH', verified=False)
    if captured != raw:
        return dict(evidence, status='SOURCE_SLOT_RAW_MISMATCH', verified=False)
    if status != 'RESOLVED':
        return dict(evidence, status=status if retained_target is None else
            'CAPTURED_TARGET_MISMATCH', verified=retained_target is None)
    if retained_target is None:
        return dict(evidence, status='CAPTURED_TARGET_MISMATCH', verified=False)
    target = _root_address(db, retained_target)
    evidence['target_address'] = target
    if target['database'] != db.database_id:
        return dict(evidence, status='FOREIGN_DATABASE', verified=False)
    if (target['segment'], target['cluster'], target['offset']) != (segment, cluster, offset):
        return dict(evidence, status='CAPTURED_TARGET_MISMATCH', verified=False)
    return dict(evidence, status='RESOLVED', verified=True)


def _root_string(db, location, raw_hex, text):
    raw = _hex(raw_hex)
    if raw is None or b'\0' in raw:
        return 'ROOT_NAME_EVIDENCE_UNAVAILABLE'
    if location is None:
        return 'ROOT_NAME_ADDRESS_UNRESOLVED'
    address = _root_address(db, location)
    if address['database'] != db.database_id:
        return 'FOREIGN_DATABASE'
    actual = db.read(db.address(address['segment'], address['cluster'], address['offset']), len(raw) + 1)
    if actual != raw + b'\0' or text != raw.decode('utf-8', errors='backslashreplace'):
        return 'ROOT_NAME_RAW_MISMATCH'
    return 'VERIFIED'


def inspect_source_root(session: DiscoverySession, root_index: int) -> dict:
    """Admit one retained occurrence; unknown values remain explicit evidence.

    A root index is an occurrence selector, never a dataset/class/CRS identity.
    Metadata-only legacy roots receive no invented raw or pointer evidence.
    """
    with session_operation(session):
        if type(root_index) is not int or not 0 <= root_index < MAX_ROOT_RECORDS:
            raise RelationshipError('root_index must be an integer from 0 to 9999')
        db = session.db
        session.check_identity()
        report = db.roots()
        records = report.get('roots', ())
        if not isinstance(records, Sequence) or len(records) > MAX_ROOT_RECORDS:
            raise RelationshipError('Retained root inventory exceeds bounded root policy')
        matches = [record for record in records if isinstance(record, Mapping) and
                   type(record.get('index')) is int and record['index'] == root_index]
        if len(matches) != 1:
            raise RelationshipError('Root index must select exactly one retained root occurrence')
        record = matches[0]
        result = dict(index=root_index, name=record.get('name'), declared_type=record.get('type_name'),
            record_address=record.get('address'), record_raw_hex=record.get('record_raw_hex'),
            name_address=record.get('name_address'), name_raw_hex=record.get('name_raw_hex'),
            value_pointer_raw_hex=record.get('value_pointer_raw_hex'), value_target=record.get('value_target'),
            type_pointer_raw_hex=record.get('type_pointer_raw_hex'), type_target=record.get('type_target'),
            type_name_address=record.get('type_name_address'), type_name_raw_hex=record.get('type_name_raw_hex'),
            root_slot_width=8, ownership='NOT_INFERRED', class_identity='NOT_WITNESSED',
            geological_meaning='UNESTABLISHED', crs='UNESTABLISHED', units='UNESTABLISHED',
            affiliation='SOURCE_ROOT_STRUCTURAL_PATH', association_witnessed=False,
            declared_root_type_compatible=False, root_type_status='DECLARED_TYPE_UNESTABLISHED',
            seed=None, root_value_selector=None,
            traversal_admitted=False, source_fields_admitted=False, current_storage_admitted=False,
            binding_evidence=[])

        def finish(status):
            session.check_identity()
            return dict(result, status=status)

        raw = _hex(record.get('record_raw_hex'), size=24, maximum=24)
        if report.get('version') != 2 or raw is None:
            return finish('ROOT_RECORD_EVIDENCE_UNAVAILABLE')
        source = _root_address(db, record.get('address'))
        if source['database'] != db.database_id:
            return finish('FOREIGN_SOURCE_DATABASE')
        current = db.read(db.address(source['segment'], source['cluster'], source['offset']), 24)
        if current != raw:
            return finish('ROOT_RECORD_RAW_MISMATCH')
        value_raw = _hex(record.get('value_pointer_raw_hex'), size=8, maximum=8)
        type_raw = _hex(record.get('type_pointer_raw_hex'), size=8, maximum=8)
        if value_raw != raw[8:16] or type_raw != raw[16:24]:
            return finish('ROOT_SLOT_METADATA_RAW_MISMATCH')
        for displacement, word, target in ((0, raw[:8], record.get('name_address')),
                (8, value_raw, record.get('value_target')),
                (16, type_raw, record.get('type_target'))):
            binding = _root_binding(db, dict(source, offset=source['offset'] + displacement), word, target)
            result['binding_evidence'].append(binding)
            if not binding['verified']:
                return finish(binding['status'])
        name_status = _root_string(db, record.get('name_address'), record.get('name_raw_hex'), record.get('name'))
        if name_status != 'VERIFIED':
            return finish(name_status)
        value_binding = result['binding_evidence'][1]
        if value_binding['status'] != 'RESOLVED':
            return finish('NULL_SOURCE_ROOT_VALUE' if value_binding['status'] == 'NULL' else 'UNRESOLVED_SOURCE_ROOT_VALUE')
        target = value_binding['target_address']
        # Establish the retained type-name chain separately. Only corroborated
        # source-class names can authorize a nonzero base view. Missing/type-erased
        # declarations never suppress an independently exact current VALUE target.
        declared = None
        type_binding = result['binding_evidence'][2]
        result['root_type_status'] = 'ROOT_TYPE_UNRESOLVED'
        if type_binding['status'] == 'RESOLVED':
            type_source = type_binding['target_address']
            type_word = db.read(db.address(type_source['segment'], type_source['cluster'], type_source['offset']), 8)
            name_binding = _root_binding(db, type_source, type_word, record.get('type_name_address'))
            result['binding_evidence'].append(name_binding)
            if name_binding['verified'] and name_binding['status'] == 'RESOLVED':
                type_status = _root_string(db, record.get('type_name_address'),
                    record.get('type_name_raw_hex'), record.get('type_name'))
                if type_status == 'VERIFIED':
                    result['root_type_status'] = 'DECLARED_TYPE_UNESTABLISHED'
                    if record.get('type_name') in db.fields.schema.classes:
                        declared = dict(kind='class', name=record['type_name'])
                        result['root_type_status'] = 'SOURCE_ROOT_CLASS_DECLARATION_RETAINED'
                else:
                    result['root_type_status'] = 'ROOT_TYPE_NAME_EVIDENCE_UNESTABLISHED'
            else:
                result['root_type_status'] = 'ROOT_TYPE_NAME_BINDING_UNESTABLISHED'
        allocation, view = _location(db, target, declared)
        result['target_view'] = view
        result['supplied_address'] = target
        if allocation is None or 'canonical_address' not in view:
            return finish(view['status'])
        result['seed'] = dict(address=view['canonical_address'], supplied_address=target,
            type=allocation['name'], allocation_id=allocation['store_allocation_id'],
            element_index=view['element_index'])
        result['root_value_selector'] = _selector(allocation, view)
        admission = db.fields.schema_admission(allocation)
        result['schema_admission'] = admission
        result['source_fields_admitted'] = admission['admitted']
        native = getattr(db.fields, 'types', {}).get(allocation['native_tag'], {})
        result['current_storage_admitted'] = bool(native)
        if not admission['admitted']:
            result['declaration_scope'] = 'CURRENT_NATIVE_STORAGE; SOURCE_CLASS_FIELDS_UNESTABLISHED'
            return finish('ROOT_CURRENT_NATIVE_OR_UNKNOWN_STORAGE_VIEW')
        compatibility = _compatible(db, allocation, declared, view) if declared else 'DECLARED_TYPE_UNESTABLISHED'
        result['target_type_status'] = compatibility
        result['declared_root_type_compatible'] = compatibility == 'DECLARED_TYPE_MATCH'
        result['traversal'] = _traversal(session, allocation,
            declared or dict(kind='class', name=admission['schema_name']))
        result['traversal_admitted'] = True
        if result['declared_root_type_compatible']:
            return finish('SOURCE_ROOT_DECLARED_CURRENT_VALUE')
        # Actual admitted source fields supply their own declarations. This grants
        # bounded structural inspection without borrowing root type/identity roles.
        result['declaration_scope'] = 'INDEPENDENT_CURRENT_ALLOCATION_SOURCE_LAYOUT; ROOT_TYPE_UNESTABLISHED'
        return finish('CONFLICTING_ROOT_DECLARATION_CURRENT_ALLOCATION_VIEW' if declared else
            'TYPE_ERASED_CURRENT_ALLOCATION_VIEW')


def iter_root_payload_links(session: DiscoverySession, root_index: int, *,
        max_nodes: int = 128, max_depth: int = 4, max_links: int = 1024,
        max_element_bytes: int = 65536,
        follow_affiliated_entities: bool = True, current_storage_graph: bool = True) -> Iterator[dict]:
    """Retain root evidence and stream admitted declared structural paths."""
    with session_operation(session):
        if type(follow_affiliated_entities) is not bool:
            raise RelationshipError('follow_affiliated_entities must be a boolean')
        if type(current_storage_graph) is not bool:
            raise RelationshipError('current_storage_graph must be a boolean')
        _limit(max_nodes, 'max_nodes', 10000)
        _limit(max_links, 'max_links', 100000)
        _limit(max_element_bytes, 'max_element_bytes', 1048576)
        if type(max_depth) is not int or not 0 <= max_depth <= 64:
            raise RelationshipError('max_depth must be an integer from 0 to 64')
        root = inspect_source_root(session, root_index)
        if root['traversal_admitted'] or (current_storage_graph and root['current_storage_admitted']):
            # An Entity root is affiliated structurally. Its name is never promoted
            # into Entity identity/ownership; downstream Entity links stay terminal.
            yield from _iter_declared_payload_links(session, root['seed'], root_origin=root,
                max_nodes=max_nodes, max_depth=max_depth, max_links=max_links,
                max_element_bytes=max_element_bytes, follow_affiliated_entities=follow_affiliated_entities,
                current_storage_graph=current_storage_graph)
            return
        pins = runtime_identity()
        bounds = dict(max_nodes=max_nodes, max_depth=max_depth, max_links=max_links,
            max_element_bytes=max_element_bytes, max_schema_leaves=4096,
            follow_affiliated_entities=follow_affiliated_entities, current_storage_graph=current_storage_graph)
        yield dict(record='header', format='FSD_SOURCE_ROOT_PAYLOAD_LINK_STREAM', version=1,
            source=dict(session.db.source_info), runtime_identity=pins, root=root,
            seed=root.get('seed'), configuration=bounds,
            policy='SOURCE_ROOT_DECLARED_FIELD_PATHS; OWNERSHIP_NOT_INFERRED')
        yield dict(record='diagnostic', root=root, status=root['status'], path=[])
        session.check_identity()
        if runtime_identity() != pins:
            raise RelationshipError('Runtime changed during root-link inspection')
        yield dict(record='summary', root=root, seed=root.get('seed'), configuration=bounds,
            root_seed_admitted=False, nodes_inspected=0, records=1, source_fields_inspected=0,
            status_counts={root['status']: 1}, bounded=[], traversal_complete=False, complete=False,
            ownership_established=False, geological_semantics_complete=False,
            original_source_required=False,
            integrity_mode='SESSION_IDENTITY_CHECK; SESSION_FINISH_REQUIRED_FOR_QUICK_CHECK')


def inspect_root_payload_links(db, root_index: int, *, session: DiscoverySession | None = None,
        max_nodes: int = 128, max_depth: int = 4, max_links: int = 1024,
        max_element_bytes: int = 65536, follow_affiliated_entities: bool = True,
        current_storage_graph: bool = True) -> dict:
    """Materialize one bounded root occurrence without expanding payloads."""
    owned = session is None
    session = session or DiscoverySession(db)
    with session_operation(session):
        if session.db is not db:
            raise RelationshipError('Root payload session belongs to another store')
        links, diagnostics = [], []
        for record in iter_root_payload_links(session, root_index, max_nodes=max_nodes,
                max_depth=max_depth, max_links=max_links, max_element_bytes=max_element_bytes,
                follow_affiliated_entities=follow_affiliated_entities, current_storage_graph=current_storage_graph):
            kind = record['record']
            if kind == 'header':
                result = dict(record)
                result.pop('record')
                result['format'] = 'FSD_SOURCE_ROOT_PAYLOAD_LINKS'
            elif kind == 'summary':
                result['summary'] = record
            else:
                (links if kind == 'link' else diagnostics).append(record)
        if owned:
            session.finish()
        return dict(result, links=links, diagnostics=diagnostics)
