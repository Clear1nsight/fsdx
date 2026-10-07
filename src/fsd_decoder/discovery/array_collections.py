"""Bounded os_array membership from independently checked native accessors.

The retained o6_coll1.dll array vtable selects packed-list indexed retrieval:
index < list_entries maps to alist + 4 * index. lower_bound is retained without
assigning it storage semantics. Free-storage references are never members.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from fsd_decoder.exports.catalog import addrkey, target
from fsd_decoder.exports.fsd_mesh import members

if TYPE_CHECKING:
    from fsd_decoder.exports.catalog import CatalogReader
    from .collection_progress import CollectionProgress


def inspect_array(reader: CatalogReader, address: Mapping, root: Mapping, *,
                  max_nodes: int, max_members: int, max_slots: int) -> dict:
    """Inspect only the observed 32-byte array / 4-byte wrapper representation.

The caller validates budgets and the exact root element. Source declarations
must match offsets used by the independently inspected native accessors, not
merely counts convenient for a proposed window. Subclass dispatch is unknown.
"""
    kind = root.get('class_name', root['type_name']).removesuffix('[]')
    result = dict(address=dict(address), representation=root['type_name'],
        declared_count=None, observed_count=0, equal=False, status='UNCONFIRMED',
        complete=False, membership_complete=False, members=[],
        nodes=[dict(address=dict(address), type=kind)], diagnostics=[],
        ownership='NOT_INFERRED', order='INDEXED_ARRAY_SLOT_ORDER',
        evidence='SOURCE_SCHEMA_AND_NATIVE_INDEXED_RETRIEVAL_ACCESSOR',
        controls={}, control_fields={}, storage=None, storage_slots=[],
        scanned_slots=0, active_window=None,
        lower_bound_semantics='UNESTABLISHED; NOT_USED_BY_NATIVE_INDEXED_RETRIEVAL',
        native_rule=dict(representation='os_array', root_size=32, slot_width=4,
            cardinality_rva='0x2d710', indexed_retrieval_rva='0x2c7b0',
            position_slot_rva='0x2c0b0', array_vtable_rva='0x5fdc4'))

    def stop(status: str, reason: str) -> dict:
        result['status'] = status
        result['diagnostics'].append(reason)
        return result

    if kind != 'os_array':
        return stop('UNSUPPORTED_REPRESENTATION', 'Array subclass native dispatch is unestablished')
    if root.get('unsupported_reasons'):
        return stop('UNSUPPORTED_LAYOUT', 'Array root has unsupported typed declarations')
    layout = reader.fields.schema.layout(kind)
    declarations = members(layout)
    if layout['size'] != 32:
        return stop('UNSUPPORTED_LAYOUT', 'Array size differs from independently checked native accessors')
    for name, offset in (('list_entries', 8), ('list_size', 12), ('alist', 16),
                         ('tail', 20), ('lower_bound', 28)):
        declaration = declarations.get(name)
        if declaration is None or declaration[0] != offset or declaration[1]['size'] != 4:
            return stop('UNSUPPORTED_LAYOUT', 'Array declaration differs from native accessor: ' + name)
        fields = [f for f in root.get('fields', ()) if f.get('path', '').endswith('.' + name)]
        if (len(fields) != 1 or fields[0].get('record_relative_offset') != offset
                or fields[0].get('size') != 4):
            return stop('UNSUPPORTED_LAYOUT', 'Array field missing or inconsistent: ' + name)
        result['control_fields'][name] = dict(fields[0])
    for name in ('list_entries', 'list_size', 'lower_bound'):
        field = result['control_fields'][name]
        number = field.get('value')
        if field.get('kind') != 'primitive' or type(number) is not int or not 0 <= number <= 0xffffffff:
            return stop('CARDINALITY_UNRESOLVED', 'Array control is not a four-byte unsigned integer: ' + name)
        result['controls'][name] = number
    entries, capacity = (result['controls'][n] for n in ('list_entries', 'list_size'))
    result['declared_count'] = entries
    if entries > capacity:
        return stop('CARDINALITY_MISMATCH', 'Array entries exceed storage capacity')
    pointers = {}
    for name in ('alist', 'tail'):
        field = result['control_fields'][name]
        if field.get('kind') != 'stored_reference':
            return stop('UNSUPPORTED_LAYOUT', 'Array storage control lacks typed reference: ' + name)
        p = target(field)
        if p is None and field.get('target_status') != 'NULL':
            return stop('UNRESOLVED_REFERENCE', 'Array storage control is unresolved: ' + name)
        if p and p.get('database') != reader.db.database_id:
            return stop('FOREIGN_DATABASE', 'Array storage control belongs to another database')
        pointers[name] = p
    start, tail = pointers['alist'], pointers['tail']
    result['active_window'] = dict(start_index=0, stop_index=entries,
        rule='NATIVE_INDEXED_RETRIEVAL; NOT_LOWER_BOUND_PLUS_COUNT')
    if capacity == 0:
        if start is not None or tail is not None:
            return stop('UNSUPPORTED_LAYOUT', 'Zero-capacity array retains storage or tail reference')
        result.update(status='VERIFIED_CARDINALITY', complete=True,
            membership_complete=True, equal=True)
        return result
    if start is None:
        return stop('UNSUPPORTED_LAYOUT', 'Nonzero-capacity array has no storage reference')
    allocation = reader.allocation(*addrkey(start))
    payload_start = allocation['logical_offset'] + allocation['array_header_size']
    result['storage'] = dict(address=start, allocation_address=dict(database=reader.db.database_id,
        segment=allocation['segment'], cluster=allocation['cluster'], offset=allocation['logical_offset']),
        type=allocation['name'], native_count=allocation['count'],
        element_size=allocation['element_size'], element_stride=allocation['element_stride'])
    if start['offset'] != payload_start:
        return stop('INTERIOR_NODE', 'Array storage does not point to its exact payload start')
    if (allocation['name'] != 'os_coll_ptr[]' or not allocation['vector']
            or allocation['count'] != capacity or allocation['element_size'] != 4
            or allocation['element_stride'] != 4):
        return stop('UNSUPPORTED_LAYOUT', 'Array storage disagrees with declared native pointer capacity')
    wrapper = members(reader.fields.schema.layout('os_coll_ptr'))
    slot = wrapper.get('_ptr')
    if (slot is None or slot[0] != 0 or slot[1]['size'] != 4
            or slot[1].get('kind') != 'class' or slot[1].get('name') != 'os_soft_pointer32<void>'):
        return stop('UNSUPPORTED_LAYOUT', 'Array pointer wrapper lacks observed four-byte slot declaration')
    expected_tail = dict(start, offset=start['offset'] + (entries - 1) * 4) if entries else None
    if tail != expected_tail:
        return stop('CARDINALITY_MISMATCH', 'Array tail disagrees with indexed retrieval endpoint')
    if max_nodes < 2 or entries > max_members or capacity > max_slots:
        return stop('RESOURCE_BOUND', 'Array storage exceeds node, member or slot scan budget')
    result['nodes'].append(dict(address=start, type=allocation['name'],
        pointer_capacity=capacity, bookkeeping_fields=['inactive_storage', 'index_info']))
    # Member records share a collection-owned snapshot, isolated from the input
    # and the independently mutable result/root-node address dictionaries.
    member_node_address = dict(address)
    for index in range(capacity):
        value = reader.fields.decode(allocation, index)
        fields = [f for f in value.get('fields', ()) if f.get('path', '').endswith('._ptr')]
        if (value.get('unsupported_reasons') or len(fields) != 1
                or fields[0].get('kind') != 'stored_reference'
                or fields[0].get('record_relative_offset') != 0 or fields[0].get('size') != 4):
            return stop('UNSUPPORTED_LAYOUT', 'Array storage slot lacks exact typed pointer wrapper')
        field = fields[0]
        p = target(field)
        result['storage_slots'].append(dict(slot_index=index, source_address=field.get('source_address'),
            address=p, raw_hex=field.get('raw_hex'), target_status=field.get('target_status'),
            role='ACTIVE_INDEXED_SLOT' if index < entries else 'INACTIVE_STORAGE; MEANING_UNESTABLISHED'))
        result['scanned_slots'] += 1
        if index >= entries:
            continue
        if p and p.get('database') != reader.db.database_id:
            return stop('FOREIGN_DATABASE', 'Active array member belongs to another database')
        if p is None and field.get('target_status') != 'NULL':
            return stop('UNRESOLVED_REFERENCE', 'Active array member is unresolved')
        member_allocation = reader.allocation(*addrkey(p)) if p else None
        result['members'].append(dict(node_address=member_node_address, slot_index=index,
            source_address=field.get('source_address'), address=p,
            target_type=member_allocation['name'] if member_allocation else None,
            target_status='CURRENT_ALLOCATION' if member_allocation else 'NULL',
            meaning='COLLECTION_MEMBER_SLOT; OWNERSHIP_NOT_INFERRED'))
        result['observed_count'] += 1
    result.update(status='VERIFIED_CARDINALITY', complete=True, membership_complete=True, equal=True)
    return result


def advance_array(reader: CatalogReader, progress: CollectionProgress) -> None:
    """Advance exact native array storage without revisiting committed slots."""
    from .collection_progress import scalar, pointer, read_declared
    state = progress.state
    address = state['address']
    kind = state['root_kind']
    if state['phase']=='ARRAY_START':
        if kind!='os_array':
            progress.stop('UNSUPPORTED_REPRESENTATION','Array subclass native dispatch is unestablished');return
        layout = reader.fields.schema.layout(kind)
        declarations = members(layout)
        if layout['size']!=32 or any(name not in declarations or declarations[name][0]!=offset
                or declarations[name][1]['size']!=4 for name,offset in
                (('list_entries',8),('list_size',12),('alist',16),('tail',20),('lower_bound',28))):
            progress.stop('UNSUPPORTED_LAYOUT','Array declaration differs from native accessors');return
        controls = {name:scalar(reader,progress,address,kind,name) for name in ('list_entries','list_size','lower_bound')}
        if any(value>0xffffffff for value in controls.values()):
            progress.stop('CARDINALITY_UNRESOLVED','Array controls exceed unsigned four-byte range');return
        entries,capacity = controls['list_entries'],controls['list_size']
        state.update(controls=controls,declared_count=entries)
        if entries>capacity:
            progress.stop('CARDINALITY_MISMATCH','Array entries exceed storage capacity');return
        _,start = pointer(reader,progress,address,kind,'alist')
        _,tail = pointer(reader,progress,address,kind,'tail')
        if any(p and p.get('database')!=reader.db.database_id for p in (start,tail)):
            progress.stop('FOREIGN_DATABASE','Array storage control belongs to another database');return
        state['active_window'] = dict(start_index=0,stop_index=entries,
            rule='NATIVE_INDEXED_RETRIEVAL; NOT_LOWER_BOUND_PLUS_COUNT')
        state['lower_bound_semantics']='UNESTABLISHED; NOT_USED_BY_NATIVE_INDEXED_RETRIEVAL'
        if not capacity:
            if start or tail:
                progress.stop('UNSUPPORTED_LAYOUT','Zero-capacity array retains storage or tail reference');return
            progress.close();return
        if start is None:
            progress.stop('UNSUPPORTED_LAYOUT','Nonzero-capacity array has no storage reference');return
        allocation = reader.allocation(*addrkey(start))
        if start['offset']!=allocation['logical_offset']+allocation['array_header_size']:
            progress.stop('INTERIOR_NODE','Array storage is not at exact payload start');return
        if (allocation['name']!='os_coll_ptr[]' or not allocation['vector'] or allocation['count']!=capacity
                or allocation['element_size']!=4 or allocation['element_stride']!=4):
            progress.stop('UNSUPPORTED_LAYOUT','Array storage disagrees with native pointer capacity');return
        slot = members(reader.fields.schema.layout('os_coll_ptr')).get('_ptr')
        if (not slot or slot[0]!=0 or slot[1]['size']!=4 or slot[1].get('kind')!='class'
                or slot[1].get('name')!='os_soft_pointer32<void>'):
            progress.stop('UNSUPPORTED_LAYOUT','Array wrapper lacks observed four-byte pointer');return
        expected = dict(start,offset=start['offset']+(entries-1)*4) if entries else None
        if tail!=expected:
            progress.stop('CARDINALITY_MISMATCH','Array tail disagrees with indexed retrieval endpoint');return
        state.update(storage_address=start,cursor=0,phase='ARRAY_STORAGE')
    if state['phase']=='ARRAY_STORAGE':
        if not progress.admits(nodes=1):return
        start=state['storage_address']
        progress.record('nodes',dict(address=start,type='os_coll_ptr[]',pointer_capacity=state['controls']['list_size']),node=start,nodes=1)
        state['phase']='ARRAY_SLOTS'
    start=state['storage_address']
    allocation=reader.allocation(*addrkey(start))
    entries,capacity=state['controls']['list_entries'],state['controls']['list_size']
    while state['cursor']<capacity:
        index=state['cursor'];active=index<entries
        if not progress.admits(slots=1,storage_evidence_slots=1,members=int(active)):return
        slot_address=dict(start,offset=start['offset']+index*4)
        fields=read_declared(reader,progress,slot_address,'os_coll_ptr','_ptr',retain_unresolved=True,control=False)
        if (len(fields)!=1 or fields[0].get('kind')!='stored_reference'
                or fields[0].get('record_relative_offset')!=0 or fields[0].get('size')!=4):
            progress.stop('UNSUPPORTED_LAYOUT','Array slot lacks exact typed wrapper');return
        field=fields[0];p=target(field)
        progress.record('storage_slots',dict(slot_index=index,source_address=field.get('source_address'),
            address=p,raw_hex=field.get('raw_hex'),target_status=field.get('target_status'),
            role='ACTIVE_INDEXED_SLOT' if active else 'INACTIVE_STORAGE; MEANING_UNESTABLISHED'),
            node=start,index=index,slots=1,storage_evidence_slots=1)
        state['cursor']+=1
        if not active:continue
        if p and p.get('database')!=reader.db.database_id:
            progress.stop('FOREIGN_DATABASE','Active array member belongs to another database');return
        if p is None and field.get('target_status')!='NULL':
            progress.stop('UNRESOLVED_REFERENCE','Active array member is unresolved');return
        member=reader.allocation(*addrkey(p)) if p else None
        progress.record('members',dict(node_address=address,slot_index=index,source_address=field.get('source_address'),
            address=p,target_type=member['name'] if member else None,target_status='CURRENT_ALLOCATION' if member else 'NULL',
            meaning='COLLECTION_MEMBER_SLOT; OWNERSHIP_NOT_INFERRED'),node=start,index=index,members=1)
        state['observed_count']+=1
    progress.close()
