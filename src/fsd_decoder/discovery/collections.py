"""Bounded membership evidence for observed source-declared lists and sets.

Bookkeeping references are never members. Unknown representations, interior
block addresses and incomplete chains remain explicit, rather than becoming a
shorter apparently valid collection. Membership does not establish ownership.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping
import re
from typing import TYPE_CHECKING

from fsd_decoder.core.diagnostics import InputValidationError, require_source_failure
from fsd_decoder.exports.catalog import PortableCatalogReader, addrkey, target
from fsd_decoder.exports.fsd_mesh import members

if TYPE_CHECKING:
    from fsd_decoder.exports.catalog import CatalogReader
    from fsd_decoder.portable.facade import PortableDatabase
    from .collection_progress import CollectionProgress


def inspect_collection(reader: CatalogReader, address: Mapping, *, max_nodes: int = 1000,
                       max_members: int = 10000, max_slots: int = 100000,
                       type_context: Mapping | None = None) -> dict:
    """Inspect one collection, retaining exact slots and uncertainty.

    List inspection uses source offsets/counts, local cardinalities and typed
    PRM references. Set inspection has a separate schema/count-gated adapter.
    Cross-block order and undocumented flag bits are not assigned semantics.
    """
    for name, value, maximum in (('max_nodes', max_nodes, 10000), ('max_members', max_members, 100000),
                                  ('max_slots', max_slots, 1000000)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise InputValidationError(f'{name} must be between 1 and {maximum}')
    result = dict(address=dict(address), representation=None, declared_count=None,
        observed_count=0, equal=False, status='UNCONFIRMED', complete=False,
        members=[], nodes=[], diagnostics=[], scanned_slots=0, ownership='NOT_INFERRED',
        order='SLOT_ORDER_WITHIN_NODE_ONLY; CROSS_BLOCK_ORDER_UNESTABLISHED',
        evidence='SOURCE_SCHEMA_LOCAL_CARDINALITIES_AND_TYPED_REFERENCE_SLOTS')

    def stop(status, reason):
        result['status'] = status
        result['diagnostics'].append(reason)
        return result

    pending = deque([dict(address)])
    seen = set()
    try:
        while pending:
            current = pending.popleft()
            key = addrkey(current)
            if key in seen:
                continue
            if len(seen) >= max_nodes:
                return stop('RESOURCE_BOUND', 'Collection node budget reached')
            if current.get('database') != reader.db.database_id:
                return stop('FOREIGN_DATABASE', 'Collection reference belongs to another database')
            allocation = reader.allocation(*key)
            if allocation['element_size'] > 65536:
                return stop('RESOURCE_BOUND', 'Collection element exceeds 65536 bytes')
            delta = current['offset'] - allocation['logical_offset'] - allocation['array_header_size']
            stride = allocation['element_stride']
            if stride <= 0 or delta < 0 or delta % stride or delta // stride >= allocation['count']:
                return stop('INTERIOR_NODE', 'Collection node is not an exact current element start')
            # The allocation's compiled declaration is available before value
            # expansion. Reserve the whole pointer capacity, including inactive
            # and chain slots that this adapter must inspect, for each node.
            allocated_kind = allocation['name'].removesuffix('[]')
            if (reader.inherits(allocated_kind, 'os_list')
                    or reader.inherits(allocated_kind, 'os_chained_list_block')):
                declared_array = members(reader.fields.schema.layout(allocated_kind)).get('pointers')
                if declared_array is not None:
                    array_type = declared_array[1]
                    capacity = array_type.get('count')
                    if (array_type.get('kind') == 'array' and type(capacity) is int
                            and 1 <= capacity <= 10000
                            and result['scanned_slots'] + capacity > max_slots):
                        return stop('RESOURCE_BOUND', 'List pointer-slot scan budget reached before node expansion')
            value = reader.value(current)
            kind = value.get('class_name', value['type_name']).removesuffix('[]')
            root = not seen
            seen.add(key)
            if root:
                result['representation'] = value['type_name']
                if reader.inherits(kind, 'os_set'):
                    from .hash_sets import inspect_hash_set
                    return inspect_hash_set(reader, address, value, max_nodes=max_nodes,
                        max_members=max_members, max_slots=max_slots, type_context=type_context)
                if type_context is not None:
                    return stop('UNSUPPORTED_CONTEXT', 'Typed referrer context currently supports hash sets only')
                if reader.inherits(kind, 'os_array'):
                    from .array_collections import inspect_array
                    return inspect_array(reader, address, value, max_nodes=max_nodes,
                        max_members=max_members, max_slots=max_slots)
                if not reader.inherits(kind, 'os_list'):
                    return stop('UNSUPPORTED_REPRESENTATION', 'No verified membership adapter for ' + kind)
            elif not reader.inherits(kind, 'os_chained_list_block'):
                return stop('UNSUPPORTED_CHAIN_TARGET', 'Chain target is not a declared list block')
            if value.get('unsupported_reasons'):
                return stop('UNSUPPORTED_LAYOUT', 'Node has unsupported typed declarations')
            layout = members(reader.fields.schema.layout(kind))
            if 'pointers' not in layout or '_local_card' not in layout:
                return stop('UNSUPPORTED_LAYOUT', 'Missing declared pointer array or local cardinality')
            at, array = layout['pointers']
            if array.get('kind') != 'array' or type(array.get('count')) is not int or not 1 <= array['count'] <= 10000:
                return stop('UNSUPPORTED_LAYOUT', 'Pointer array capacity is unknown or exceeds bounds')
            element = array['element']
            while element.get('kind') == 'alias':
                element = element['underlying']
            if element.get('kind') != 'class':
                return stop('UNSUPPORTED_LAYOUT', 'Pointer wrapper is not a declared class')
            wrapper = members(reader.fields.schema.layout(element['name']))
            if '_ptr' not in wrapper:
                return stop('UNSUPPORTED_LAYOUT', 'Pointer wrapper lacks declared _ptr member')
            pointer_at, pointer_type = wrapper['_ptr']
            fields = value.get('fields', [])

            def scalar(name):
                offset, declaration = layout[name]
                matches = [f for f in fields if f.get('path', '').endswith('.' + name)
                    and f.get('record_relative_offset') == offset and f.get('size') == declaration['size']]
                return matches[0].get('value') if len(matches) == 1 else None

            local = scalar('_local_card')
            capacity = array['count']
            if type(local) is not int or not 0 <= local <= capacity:
                return stop('LOCAL_CARDINALITY_UNRESOLVED', 'Invalid or missing local cardinality')
            if root:
                if 'card' not in layout:
                    return stop('CARDINALITY_UNRESOLVED', 'Missing declared total cardinality')
                result['declared_count'] = scalar('card')
                if type(result['declared_count']) is not int or result['declared_count'] < 0:
                    return stop('CARDINALITY_UNRESOLVED', 'Invalid total cardinality')
            slots = {}
            for field in fields:
                match = re.search(r'\.pointers\[(\d+)\]\._ptr$', field.get('path', ''))
                if match:
                    if result['scanned_slots'] >= max_slots:
                        return stop('RESOURCE_BOUND', 'List pointer-slot scan budget reached')
                    result['scanned_slots'] += 1
                    index = int(match[1])
                    if (index in slots or index >= capacity or field.get('kind') != 'stored_reference'
                            or field.get('record_relative_offset') != at + index * element['size'] + pointer_at
                            or field.get('size') != pointer_type['size']):
                        return stop('UNSUPPORTED_LAYOUT', 'Ambiguous or inconsistent pointer array slots')
                    slots[index] = field
            if len(slots) != capacity:
                return stop('UNSUPPORTED_LAYOUT', 'Typed pointer array is incomplete')
            result['nodes'].append(dict(address=current, type=kind, local_cardinality=local,
                pointer_capacity=capacity, bookkeeping_fields=['index_info'] if root else ['prev']))
            if len(result['members']) + local > max_members:
                return stop('RESOURCE_BOUND', 'Collection member budget reached')
            forward = None
            for index in range(capacity):
                field = slots[index]
                p = target(field)
                if p and p.get('database') != reader.db.database_id:
                    return stop('FOREIGN_DATABASE', 'Member or chain reference belongs to another database')
                if p is None and field.get('target_status') != 'NULL':
                    return stop('UNRESOLVED_REFERENCE', 'A pointer-array slot is unresolved')
                if index < local:
                    allocation = reader.allocation(*addrkey(p)) if p else None
                    result['members'].append(dict(node_address=current, slot_index=index,
                        source_address=field.get('source_address'), address=p,
                        target_type=allocation['name'] if allocation else None,
                        target_status='CURRENT_ALLOCATION' if allocation else 'NULL',
                        meaning='COLLECTION_MEMBER_SLOT; OWNERSHIP_NOT_INFERRED'))
                    result['observed_count'] += 1
                elif p:
                    if index != capacity - 1:
                        return stop('INACTIVE_SLOT_REFERENCE', 'Nonterminal inactive slot has a reference')
                    if addrkey(p) != addrkey(address):
                        block = reader.allocation(*addrkey(p))
                        if not reader.inherits(block['name'].removesuffix('[]'), 'os_chained_list_block'):
                            return stop('UNSUPPORTED_CHAIN_TARGET', 'Terminal chain slot is not a list block')
                        forward = p
            if not root:
                if 'prev' not in layout:
                    return stop('UNSUPPORTED_LAYOUT', 'Block lacks declared backlink')
                prev_at, prev_type = layout['prev']
                while prev_type.get('kind') == 'alias':
                    prev_type = prev_type['underlying']
                if prev_type.get('kind') != 'class':
                    return stop('UNSUPPORTED_LAYOUT', 'Block backlink wrapper is not a class')
                prev_wrapper = members(reader.fields.schema.layout(prev_type['name']))
                if '_ptr' not in prev_wrapper:
                    return stop('UNSUPPORTED_LAYOUT', 'Block backlink wrapper lacks _ptr')
                prev_pointer_at, prev_pointer_type = prev_wrapper['_ptr']
                prev = [f for f in fields if f.get('path', '').endswith('.prev._ptr')]
                if (len(prev) != 1 or prev[0].get('kind') != 'stored_reference'
                        or prev[0].get('record_relative_offset') != prev_at + prev_pointer_at
                        or prev[0].get('size') != prev_pointer_type['size']):
                    return stop('UNSUPPORTED_LAYOUT', 'Missing or ambiguous block backlink')
                p = target(prev[0])
                if p:
                    if p.get('database') != reader.db.database_id:
                        return stop('FOREIGN_DATABASE', 'Block backlink belongs to another database')
                    if addrkey(p) != addrkey(address):
                        pending.append(p)
                elif prev[0].get('target_status') != 'NULL':
                    return stop('UNRESOLVED_REFERENCE', 'Block backlink is unresolved')
            # Preserve the catalog's historical breadth-first field order:
            # backlinks precede the terminal forward slot in block layouts.
            if forward is not None:
                pending.append(forward)
        result['complete'] = True
        result['equal'] = result['declared_count'] == result['observed_count']
        result['status'] = 'VERIFIED_CARDINALITY' if result['equal'] else 'CARDINALITY_MISMATCH'
        return result
    except Exception as exc:
        require_source_failure(exc, dict(phase='collection_membership', address=dict(address)))
        return stop('TYPED_DECODE_UNRESOLVED', type(exc).__name__ + ': ' + str(exc))


def inspect_portable_collection(db: PortableDatabase, address: Mapping, *, max_nodes: int = 1000,
                                max_members: int = 10000, max_slots: int = 100000,
                                referrer: Mapping | None = None, field_path: str | None = None) -> dict:
    """Source-independent single-collection inspection with bounded reader caches."""
    reader = PortableCatalogReader(db, db.fields, iter_allocations=lambda: iter(()),
        allocation_lookup=db.allocation, source_metadata=db.source_info, expected_allocations=0)
    if (referrer is None) != (field_path is None):
        raise InputValidationError('Collection referrer and field path must be provided together')
    context = None
    if referrer is not None:
        from .hash_sets import collection_type_context
        context = collection_type_context(reader, address, referrer, field_path)
    return inspect_collection(reader, address, max_nodes=max_nodes, max_members=max_members,
        max_slots=max_slots, type_context=context)


def advance_collection(reader: CatalogReader, progress: CollectionProgress, *, max_nodes: int, max_members: int, max_slots: int) -> dict:
    """Advance a disk-backed prefix; the caller guards and commits its transaction.

    Limits admit this step, not the cumulative collection. A yielded prefix is
    PARTIAL until the adapter closes traversal and its existing count gates.
    """
    from .collection_progress import exact_element, supported_layout
    progress.begin(max_nodes=max_nodes,max_members=max_members,max_slots=max_slots)
    state=progress.state
    if state['terminal']:return progress.save()
    try:
        if state['phase']=='ROOT':
            if not progress.admits(nodes=1):return progress.save()
            allocation=exact_element(reader,state['address'])
            if allocation['element_size']>65536:
                state['resource_exclusion']=dict(reason='SINGLE_ELEMENT_RAW_SIZE',limit=65536,
                    allocation_address=dict(state['address'],offset=allocation['logical_offset']),
                    element_address=state['address'],element_bytes=allocation['element_size'],
                    raw_selector=dict(start=state['address']['offset'],stop=state['address']['offset']+allocation['element_size']))
                progress.stop('RESOURCE_BOUND','Collection element exceeds independently bounded raw decode size')
                return progress.save()
            kind=allocation['name'].removesuffix('[]')
            supported_layout(reader,kind)
            state.update(root_kind=kind,representation=allocation['name'])
            progress.record('nodes',dict(address=state['address'],type=kind),nodes=1)
            if reader.inherits(kind,'os_set'):
                state.update(adapter='HASH_SET',phase='HASH_START')
            elif state['type_context'] is not None:
                progress.stop('UNSUPPORTED_CONTEXT','Typed referrer context currently supports hash sets only')
            elif reader.inherits(kind,'os_array'):
                state.update(adapter='ARRAY',phase='ARRAY_START')
            elif reader.inherits(kind,'os_list'):
                state.update(adapter='LIST',phase='LIST_NODE')
                progress.enqueue(state['address'])
            else:
                progress.stop('UNSUPPORTED_REPRESENTATION','No verified membership adapter for '+kind)
        if not state['terminal']:
            if state['adapter']=='LIST':
                advance_list(reader,progress)
            elif state['adapter']=='ARRAY':
                from .array_collections import advance_array
                advance_array(reader,progress)
            elif state['adapter']=='HASH_SET':
                from .hash_sets import advance_hash_set
                advance_hash_set(reader,progress)
    except Exception as exc:
        require_source_failure(exc,dict(phase='collection_prefix',address=state['address']))
        progress.stop('TYPED_DECODE_UNRESOLVED',type(exc).__name__+': '+str(exc))
    return progress.save()


def advance_list(reader: CatalogReader, progress: CollectionProgress) -> None:
    """Source-declared list traversal with a node/slot cursor and on-disk BFS."""
    from .collection_progress import exact_element, supported_layout, scalar, pointer, read_declared
    state=progress.state
    while not state['terminal']:
        current=state.get('current_node')
        if current is None:
            next_node=progress.next_node()
            if next_node is None:
                progress.close();return
            position,address=next_node
            root=addrkey(address)==addrkey(state['address'])
            if not root and not progress.admits(nodes=1):return
            allocation=exact_element(reader,address)
            if allocation['element_size']>65536:
                state['resource_exclusion']=dict(reason='SINGLE_ELEMENT_RAW_SIZE',limit=65536,
                    element_address=address,element_bytes=allocation['element_size'],
                    raw_selector=dict(start=address['offset'],stop=address['offset']+allocation['element_size']))
                progress.stop('RESOURCE_BOUND','List node exceeds raw element bound');return
            kind=allocation['name'].removesuffix('[]')
            if not root and not reader.inherits(kind,'os_chained_list_block'):
                progress.stop('UNSUPPORTED_CHAIN_TARGET','Chain target is not a declared list block');return
            layout=members(supported_layout(reader,kind))
            if 'pointers' not in layout or '_local_card' not in layout:
                progress.stop('UNSUPPORTED_LAYOUT','Missing declared pointer array or local cardinality');return
            at,array=layout['pointers']
            if array.get('kind')!='array' or type(array.get('count')) is not int or not 1<=array['count']<=10000:
                progress.stop('UNSUPPORTED_LAYOUT','Pointer capacity is outside observed declaration bound');return
            element=array['element']
            while element.get('kind')=='alias':element=element['underlying']
            if element.get('kind')!='class' or '_ptr' not in members(reader.fields.schema.layout(element['name'])):
                progress.stop('UNSUPPORTED_LAYOUT','Pointer wrapper lacks declared _ptr');return
            local=scalar(reader,progress,address,kind,'_local_card')
            if local>array['count']:
                progress.stop('LOCAL_CARDINALITY_UNRESOLVED','Local cardinality exceeds pointer capacity');return
            if root:
                if 'card' not in layout:
                    progress.stop('CARDINALITY_UNRESOLVED','Missing declared total cardinality');return
                state['declared_count']=scalar(reader,progress,address,kind,'card')
            prev=None
            if not root:
                if 'prev' not in layout:
                    progress.stop('UNSUPPORTED_LAYOUT','Block lacks declared backlink');return
                _,prev=pointer(reader,progress,address,kind,'prev',wrapper=True)
                if prev and prev.get('database')!=reader.db.database_id:
                    progress.stop('FOREIGN_DATABASE','Block backlink belongs to another database');return
                progress.record('nodes',dict(address=address,type=kind,local_cardinality=local,
                    pointer_capacity=array['count'],bookkeeping_fields=['prev']),node=address,nodes=1)
            else:
                progress.record('node_controls',dict(address=address,local_cardinality=local,
                    pointer_capacity=array['count'],bookkeeping_fields=['index_info']),node=address)
            current=dict(address=address,position=position,kind=kind,local=local,
                capacity=array['count'],index=0,prev=prev,forward=None)
            state.update(current_node=current,phase='LIST_SLOTS',cursor=dict(node_address=address,next_slot=0))
        address=current['address'];index=current['index'];active=index<current['local']
        if index<current['capacity']:
            if not progress.admits(slots=1,storage_evidence_slots=1,members=int(active)):return
            fields=read_declared(reader,progress,address,current['kind'],'pointers',index=index,retain_unresolved=True)
            if len(fields)!=1 or fields[0].get('kind')!='stored_reference' or not fields[0].get('path','').endswith('._ptr'):
                progress.stop('UNSUPPORTED_LAYOUT','List slot lacks exact typed pointer wrapper');return
            field=fields[0];p=target(field)
            progress.record('storage_slots',dict(slot_index=index,source_address=field.get('source_address'),
                address=p,raw_hex=field.get('raw_hex'),target_status=field.get('target_status'),
                role='ACTIVE_MEMBER_SLOT' if active else 'TERMINAL_CHAIN_OR_INACTIVE' if index==current['capacity']-1 else 'INACTIVE_STORAGE'),
                node=address,index=index,slots=1,storage_evidence_slots=1)
            current['index']+=1;state['cursor']['next_slot']=current['index']
            if p and p.get('database')!=reader.db.database_id:
                progress.stop('FOREIGN_DATABASE','Member or chain reference belongs to another database');return
            if p is None and field.get('target_status')!='NULL':
                progress.stop('UNRESOLVED_REFERENCE','A pointer-array slot is unresolved');return
            if active:
                allocation=reader.allocation(*addrkey(p)) if p else None
                progress.record('members',dict(node_address=address,slot_index=index,
                    source_address=field.get('source_address'),address=p,target_type=allocation['name'] if allocation else None,
                    target_status='CURRENT_ALLOCATION' if allocation else 'NULL',
                    meaning='COLLECTION_MEMBER_SLOT; OWNERSHIP_NOT_INFERRED'),node=address,index=index,members=1)
                state['observed_count']+=1
            elif p:
                if index!=current['capacity']-1:
                    progress.stop('INACTIVE_SLOT_REFERENCE','Nonterminal inactive slot has a reference');return
                if addrkey(p)!=addrkey(state['address']):
                    block=reader.allocation(*addrkey(p))
                    if not reader.inherits(block['name'].removesuffix('[]'),'os_chained_list_block'):
                        progress.stop('UNSUPPORTED_CHAIN_TARGET','Terminal chain slot is not a list block');return
                    current['forward']=p
            continue
        for p in (current['prev'],current['forward']):
            if p and addrkey(p)!=addrkey(state['address']):progress.enqueue(p)
        progress.close_node(current['position'])
        state.update(current_node=None,phase='LIST_NODE',cursor=None)
