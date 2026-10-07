"""Compact source-type/template roles; generic candidates are not datasets."""
from collections import Counter
from collections.abc import Mapping

from .datasets import _character
from .relationship_discovery import RelationshipError
from fsd_decoder.exports.catalog import PortableCatalogReader


def supported_collection_family(reader: PortableCatalogReader, name: str) -> bool:
    """Recognize supported storage families from source schema inheritance.

    This role does not verify an instance layout, membership or cardinality.
    Generic os_collection ancestry alone supplies no supported adapter family.
    """
    return any(reader.inherits(name.removesuffix('[]'), anchor)
               for anchor in ('os_list', 'os_set', 'os_array'))


def storage_role(declaration: Mapping, *, vector: bool = False) -> str:
    if declaration.get('entity_family'):
        return 'ESTABLISHED_ENTITY_FAMILY'
    if declaration.get('collection_family'):
        return 'COLLECTION_STORAGE'
    if vector and not declaration['schema_class']:
        return 'ARRAY_PAYLOAD_STORAGE'
    return 'STRUCTURAL_RECORD' if declaration['schema_class'] else 'UNKNOWN_STORAGE'


def build_role_inventory(db, report: Mapping) -> dict:
    """Group every allocation, preserving uncertainty and exact access selectors.

    Type-level edges are investigation signals, never object ownership or proof
    of collection membership. Cardinality fields are declarations, not counts of
    arbitrary references. No project labels control grouping or selection.
    """
    source = report.get('source', {})
    if (report.get('version') != 2 or source.get('sha256') != db.sha256
            or source.get('database_id') != db.database_id
            or report.get('accounting', {}).get('complete') is not True):
        raise RelationshipError('Dataset role inventory requires matching complete discovery')
    census = {row['type']: dict(row) for row in report['type_census']}
    reader = PortableCatalogReader(db, db.fields, iter_allocations=lambda: iter(()),
        allocation_lookup=db.allocation, source_metadata=db.source_info, expected_allocations=0)
    for row in census.values():
        if row['schema_class'] and not row['diagnostics']:
            row['collection_family'] = supported_collection_family(reader, row['type'])
    incoming, outgoing, entity_links, array_links = Counter(), Counter(), Counter(), Counter()
    connections = []
    for relation in report['reference_shapes']:
        source_type, target_type = relation['source_type'], relation['target_type']
        count = relation['bindings']
        outgoing[source_type] += count
        incoming[target_type] += count
        if relation['status'] != 'RESOLVED' or target_type is None:
            continue
        if census.get(source_type, {}).get('entity_family'):
            entity_links[target_type] += count
        paths = {view['path'] for view in relation['declaration_views'] if not view['conditional_union']}
        if any(slot['path'] in paths and slot['pointee_type'] and not _character(slot['pointee_type'])
               for slot in census.get(source_type, {}).get('slots', ())):
            target = census[target_type]
            if not target['schema_class'] and target_type.endswith('[]'):
                array_links[source_type] += count
        connections.append(dict(source_type=source_type, target_type=target_type,
            bindings=count, slot_displacement=relation['slot_displacement'],
            declaration_views=relation['declaration_views']))

    roots = []
    root_types = set()
    root_records = db.roots().get('roots', [])
    if len(root_records) > 10000:
        raise RelationshipError('Dataset role root inventory exceeds 10000 records')
    for record in root_records:
        target = record.get('value_target', record.get('target'))
        if isinstance(target, Mapping):
            address = [target.get(key) for key in ('segment', 'cluster', 'offset')]
        else:
            address = target
        valid = (isinstance(address, (list, tuple)) and len(address) == 3
                 and all(type(value) is int and value >= 0 for value in address))
        allocation = db.allocation(*address) if valid else None
        kind = allocation['name'] if allocation is not None else None
        if kind is not None:
            root_types.add(kind)
        roots.append(dict(name=record.get('name'), address=address, type=kind,
            allocation_id=allocation.get('store_allocation_id') if allocation else None,
            status='CURRENT_ALLOCATION' if allocation else 'NO_CURRENT_ALLOCATION',
            meaning='SOURCE_ROOT_LABEL; DATASET_ROLE_NOT_ASSUMED'))

    groups = []
    for group in report['allocation_groups']:
        declaration = census[group['type']]
        role = storage_role(declaration, vector=group['vectors'] == group['allocations'])
        text = any(slot['pointee_type'] and not slot['conditional_union']
                   and _character(slot['pointee_type']) for slot in declaration['slots'])
        signals = []
        if text:
            signals.append('DECLARED_TEXT_REFERENCE')
        if array_links[group['type']]:
            signals.append('DECLARED_REFERENCE_TO_NATIVE_ARRAY_TYPE')
        if entity_links[group['type']]:
            signals.append('TARGET_OF_ENTITY_TYPE_REFERENCE')
        if group['type'] in root_types:
            signals.append('TYPE_CONTAINS_SOURCE_ROOT_TARGET')
        collection = role == 'COLLECTION_STORAGE'
        groups.append(dict(type=group['type'], template_id=group['template_id'],
            role=role, allocations=group['allocations'], stored_elements=group['stored_elements'],
            bytes=group['bytes'], selector=group['selector'], investigation_signals=signals,
            review_priority='ESTABLISHED_ENTITY' if role == 'ESTABLISHED_ENTITY_FAMILY'
                else 'NAMED_STRUCTURAL_RECORD' if role == 'STRUCTURAL_RECORD' and text
                and array_links[group['type']] else 'SOURCE_ROOT_OR_ENTITY_LINK'
                if group['type'] in root_types or entity_links[group['type']] else 'STORAGE_ONLY',
            reference_type_totals=dict(incoming=incoming[group['type']], outgoing=outgoing[group['type']]),
            reference_scope='TYPE_AGGREGATED; NOT_TEMPLATE_MEMBERSHIP_OR_INSTANCE_OWNERSHIP',
            cardinality=dict(declared_fields=[slot['path'] for slot in declaration['slots']
                if collection and slot['path'].endswith('.card')],
                status='NOT_CHECKED_BY_TYPE_GROUPING' if collection else 'NOT_APPLICABLE',
                arbitrary_reference_count_is_membership=False),
            application_role='ESTABLISHED_ENTITY_ANCHOR' if declaration.get('entity_family') else 'UNCONFIRMED'))
    allocations = sum(group['allocations'] for group in groups)
    elements = sum(group['stored_elements'] for group in groups)
    if (allocations != report['accounting']['allocations']
            or elements != report['accounting']['stored_elements']):
        raise RelationshipError('Dataset role groups do not cover complete accounting')
    role_counts = Counter()
    for group in groups:
        role_counts[group['role']] += group['allocations']
    entities = [dict(id=obj['id'], type=obj['type'], address=obj['address'],
        name_fields=obj.get('name_fields', []), status=obj['status']) for obj in report['objects']]
    return dict(format='FSD_DATASET_ROLE_INVENTORY', version=1, source=dict(source),
        groups=groups, established_entities=entities, roots=roots, type_connections=connections,
        accounting=dict(complete=True, allocations=allocations, stored_elements=elements,
            groups=len(groups), allocation_counts_by_role=dict(role_counts)),
        new_confirmed_dataset_roles=0, application_semantics_complete=False,
        limitations=['Structural storage roles do not establish geological dataset meaning.',
            'Type-level reference totals are repeated across templates; do not sum them as separate bindings.',
            'Collection membership/cardinality needs its verified instance adapter.',
            'Generic DATASET_CANDIDATE labels remain legacy investigation hints, not this dataset inventory.'])
