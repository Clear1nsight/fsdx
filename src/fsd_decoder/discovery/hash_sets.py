"""Evidence-gated pointer-key hash sets with optional source-typed context."""
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING
import re

from fsd_decoder.exports.catalog import CatalogError, addrkey, target
from fsd_decoder.exports.fsd_mesh import members
from fsd_decoder.core.diagnostics import InputValidationError

if TYPE_CHECKING:
    from fsd_decoder.exports.catalog import CatalogReader
    from .collection_progress import CollectionProgress


def _unaliased(declaration: Mapping) -> Mapping:
    for _ in range(64):
        if declaration.get('kind') != 'alias':
            return declaration
        declaration = declaration['underlying']
    raise CatalogError('Hash declaration alias depth exceeds 64')


def hash_receiver(reader: CatalogReader, address: Mapping, kind: str) -> dict | None:
    """Match the pinned native hash receiver to one source-declared base view.

    o6_coll1.dll slot_first/slot_null compare a resolved slot with their
    _RH_dynhash receiver, not the physical _RH_HashTable. The native receiver
    controls occur at +20/+24/+28. No receiver is inferred from type compatibility.
    """
    if kind != 'os_set':
        # A derived source layout cannot establish that virtual dispatch uses
        # the pinned os_set implementation rather than an unknown override.
        return None
    root = reader.fields.schema.layout(kind)
    if root.get('size') != 40:
        return None
    candidates = []
    def visit(layout, offset, depth):
        if depth > 64:
            raise CatalogError('Hash receiver base declaration exceeds depth bound')
        if layout.get('name') == '_RH_dynhash':
            candidates.append((layout, offset))
        for base in layout.get('bases', ()):
            visit(base['layout'], offset + base['offset'], depth + 1)
    visit(root, 0, 0)
    if len(candidates) != 1:
        return None
    layout, offset = candidates[0]
    if offset != 0:
        # The reviewed os_set vtable install and inherited receiver share +0.
        # A shifted base is a different ABI even when its local fields match.
        return None
    fields = members(layout)
    for name, expected in (('flags',20), ('cnt_idx',24), ('index_sp',28)):
        declaration = fields.get(name)
        if not declaration or declaration[0] != expected or declaration[1].get('size') != 4:
            return None
    pointer = _unaliased(fields['index_sp'][1])
    if pointer.get('kind') != 'class':
        return None
    inner = members(reader.fields.schema.layout(pointer['name'])).get('_ptr')
    if not inner or inner[0] != 0 or inner[1].get('size') != 4:
        return None
    return dict(address=dict(address,offset=address['offset']+offset),base_offset=offset,
        declared_base='_RH_dynhash',evidence='PINNED_NATIVE_DISPATCH_AND_SOURCE_BASE_LAYOUT',
        controls=dict(flags=dict(offset=20,width=4),cnt_idx=dict(offset=24,width=4),
                      index_sp=dict(offset=28,width=4)),
        pointer_wrapper=dict(type=pointer['name'],offset=0,width=4),
        dll_sha256='c53c4111a5a8137cb5a3254617016763680e2b77a3a28144992083e24bf70471',
        slot_first_rva='0x395c0',slot_null_rva='0x39790',cardinality_rva='0x31500')


def _native_counter_layout(reader: CatalogReader, kind: str) -> bool:
    """The selected native cardinality reads the table's +4 counter."""
    fields=members(reader.fields.schema.layout(kind))
    return all(name in fields and fields[name][0]==offset and fields[name][1].get('size')==width
        for name,offset,width in (('_level',0,2),('_n_deleted',2,2),('_n_entries',4,4),
            ('_n_keys',8,4),('_n_slots',12,4),('_contents',16,4),('bitmap',20,4)))


def _simple_table_supported(controls, counts, bitmap, receiver, type_context):
    """Admit only the already matched single-table pointer-slot branch.

    Reviewed os_set first/next select resolved nonnull, nonreceiver slots and
    never consult _n_deleted. Nonzero counters are admitted narrowly for the
    source-typed 0xe001 branch after receiver/table/wrapper layout validation.
    The counter is not interpreted as a required number of self sentinels.
    """
    if bitmap is not None or counts['_level'] != 0:
        return False
    return counts['_n_deleted'] == 0 or (controls['flags'] == 0xe001
        and receiver is not None and type_context is not None)


def _deleted_counter_evidence(counts):
    if counts['_n_deleted'] == 0:
        return {}
    return dict(native_pointer_iteration=dict(
        predicate='RESOLVED_NONNULL_NON_COLLECTION_RECEIVER; SOURCE_TYPE_COMPATIBILITY_REQUIRED',
        captured_binding_assumption='ZERO_WORD_WITH_NONNULL_BINDING_REMAINS_UNCONFIRMED',
        deleted_counter_meaning='RETAINED_SOURCE_COUNTER; TOMBSTONE_COUNT_NOT_INFERRED',
        dll_sha256='c53c4111a5a8137cb5a3254617016763680e2b77a3a28144992083e24bf70471',
        first_occupied_slot_rva='0x2e920',next_occupied_slot_rva='0x2ea30',slot_occupied_rva='0x394f0'))


def _null_binding_conflict(controls, counts, field):
    return (controls['flags'] == 0xe001 and counts['_n_deleted'] != 0
        and int.from_bytes(bytes.fromhex(field['raw_hex']),'little') == 0
        and target(field) is not None)


def _null_binding_evidence(node, index, field):
    return dict(node_address=node,slot_index=index,source_address=field['source_address'],
        address=target(field),raw_hex=field['raw_hex'],target_status=field.get('target_status'),
        captured_binding=field.get('target'),
        meaning='ZERO_STORED_WORD_WITH_NONNULL_CAPTURED_BINDING; NATIVE_OCCUPANCY_UNCONFIRMED')


def _slot_role(q, address, receiver, *, typed, type_compatible):
    """Classify one resolved slot after source-typed compatibility is observed."""
    sentinel = receiver is not None and addrkey(q) == addrkey(receiver['address'])
    if receiver is None and addrkey(q) == addrkey(address):
        return None, False
    if sentinel:
        output = 'incompatible_self_references' if typed and not type_compatible else 'slot_references'
    else:
        output = 'members' if type_compatible else 'slot_references'
    return output, sentinel


def _field(reader: CatalogReader, value: Mapping, name: str, *, wrapper: bool = False) -> Mapping:
    """Require one typed field at its source-declared offset and width."""
    kind = value.get('class_name', value['type_name']).removesuffix('[]')
    declaration = members(reader.fields.schema.layout(kind))
    if name not in declaration:
        raise CatalogError('Hash layout lacks declared ' + name)
    offset, typ = declaration[name]
    suffix = '.' + name
    if wrapper:
        typ = _unaliased(typ)
        if typ.get('kind') != 'class':
            raise CatalogError('Hash pointer wrapper is not a class')
        fields = members(reader.fields.schema.layout(typ['name']))
        if '_ptr' not in fields:
            raise CatalogError('Hash pointer wrapper lacks _ptr')
        inner, typ = fields['_ptr']
        offset += inner
        suffix += '._ptr'
    matches = [f for f in value.get('fields', ()) if f.get('path', '').endswith(suffix)
        and f.get('record_relative_offset') == offset and f.get('size') == typ['size']]
    if len(matches) != 1:
        raise CatalogError('Hash field missing, ambiguous or inconsistent: ' + name)
    return matches[0]


def collection_type_context(reader: CatalogReader, address: Mapping, referrer: Mapping,
                            field_path: str) -> dict:
    """Derive T from an actual compiled os_Collection<T*> reference field.

    An arbitrary expected-type string or dataset-name hint is never accepted.
    The caller identifies an exact current referrer element and decoded field.
    """
    if not isinstance(field_path, str) or not 1 <= len(field_path) <= 4096:
        raise InputValidationError('Collection field path must contain 1 to 4096 characters')
    if referrer.get('database') != reader.db.database_id:
        raise CatalogError('Collection referrer belongs to another database')
    allocation = reader.allocation(*addrkey(referrer))
    if allocation['element_size'] > 65536:
        raise CatalogError('Collection referrer element exceeds 65536 bytes')
    value = reader.value(referrer)
    if value.get('unsupported_reasons'):
        raise CatalogError('Collection referrer has unsupported typed declarations')
    selected = [field for field in value.get('fields', ()) if field.get('path') == field_path]
    if len(selected) != 1 or selected[0].get('kind') != 'stored_reference' or target(selected[0]) != dict(address):
        raise CatalogError('Collection context is not the exact current reference to this collection')
    templates = re.findall(r'::<(os_Collection<([^<>]+)\*>)>', field_path)
    if len(templates) != 1 or not field_path.endswith('::<os_outofline_collection>._coll'):
        raise CatalogError('Collection context lacks supported pointer-template declaration')
    template, element = templates[0]
    element = element.strip()
    if (element not in reader.fields.schema.classes
            or not reader.inherits(template, 'os_outofline_collection')):
        raise CatalogError('Collection element/template is not established by compiled source schema')
    return dict(referrer_address=dict(referrer), field_path=field_path,
        template_type=template, element_type=element,
        evidence='SOURCE_GENERIC_TEMPLATE_AND_CURRENT_REFERENCE; OWNERSHIP_NOT_INFERRED')


def inspect_hash_set(reader: CatalogReader, address: Mapping, root: Mapping, *,
                     max_nodes: int, max_members: int, max_slots: int,
                     type_context: Mapping | None = None) -> dict:
    """Verify counts in observed single-table or source-typed indexed sets.

    Flags select two observed storage modes, without interpreting individual
    bits. Generic indexed inspection retains unconfirmed reference evidence.
    Contextual inspection requires declared T* views, local key-count agreement
    and the selected stored total; incompatible self-references remain separate.
    """
    if type_context is not None:
        if not isinstance(type_context, Mapping) or not {'referrer_address', 'field_path'} <= type_context.keys():
            raise InputValidationError('Hash type context requires a source referrer and field path')
        type_context = collection_type_context(reader, address, type_context['referrer_address'],
            type_context['field_path'])
    result = dict(address=dict(address), representation=root['type_name'],
        declared_count=None, observed_count=0, equal=False, status='UNCONFIRMED',
        complete=False, members=[], nodes=[dict(address=dict(address), type=root['type_name'])],
        diagnostics=[], ownership='NOT_INFERRED', order='UNORDERED_SET',
        evidence='SOURCE_SCHEMA_HASH_DIRECTORY_TABLE_COUNTERS_AND_TYPED_SLOTS',
        controls={}, directory_slots=[], hash_tables=[], slot_references=[],
        scanned_slots=0, membership_complete=False,
        cardinality_source='UNESTABLISHED')
    result['type_context'] = dict(type_context) if type_context is not None else None
    result['incompatible_self_references'] = []
    result['self_sentinel_receiver'] = hash_receiver(reader,address,root.get('class_name',root['type_name']).removesuffix('[]'))

    def stop(status, reason):
        result['status'] = status
        result['diagnostics'].append(reason)
        return result

    if root.get('unsupported_reasons'):
        return stop('UNSUPPORTED_LAYOUT', 'Hash root has unsupported typed declarations')

    def scalar(value, name):
        field = _field(reader, value, name)
        number = field.get('value')
        if field.get('kind') not in ('primitive', 'enum') or type(number) is not int or number < 0:
            raise CatalogError('Hash counter is not a nonnegative typed integer: ' + name)
        return number

    def pointer(value, name, *, wrapper=False):
        field = _field(reader, value, name, wrapper=wrapper)
        if field.get('kind') != 'stored_reference':
            raise CatalogError('Hash pointer field lacks typed reference: ' + name)
        p = target(field)
        if p is None and field.get('target_status') != 'NULL':
            raise CatalogError('Hash pointer is unresolved: ' + name)
        if p and p.get('database') != reader.db.database_id:
            raise CatalogError('Hash reference belongs to another database')
        return p

    def payload(p):
        if p is None:
            raise CatalogError('Hash payload pointer is null')
        if p.get('database') != reader.db.database_id:
            raise CatalogError('Hash payload belongs to another database')
        allocation = reader.allocation(*addrkey(p))
        if p['offset'] != allocation['logical_offset'] + allocation['array_header_size']:
            raise CatalogError('Hash payload is not at its exact current payload start')
        return allocation

    controls = {name:scalar(root, name) for name in
        ('flags', 'n_HashTables', 'depth', 'n_slots', 'slot_size', 'key_size', 'cnt_idx')}
    result['controls'] = controls
    flags = controls['flags']
    if flags not in (0xe001, 0xe401):
        return stop('UNSUPPORTED_REPRESENTATION', 'Hash flag combination has no verified storage adapter')
    if result['self_sentinel_receiver'] is None:
        return stop('UNSUPPORTED_LAYOUT','Hash representation lacks matched native receiver/control/pointer layout')
    simple = flags == 0xe001
    if simple and (controls['n_HashTables'] != 1 or controls['depth'] != 0):
        return stop('UNSUPPORTED_REPRESENTATION', 'Single-table mode has unexpected directory shape')
    if controls['slot_size'] != 4 or controls['key_size'] != 4:
        return stop('UNSUPPORTED_REPRESENTATION', 'Hash slot/key widths differ from observed pointer-key mode')
    directory = pointer(root, 'index_sp', wrapper=True)
    allocation = payload(directory)
    if (not allocation['vector'] or allocation['count'] != controls['n_HashTables']
            or allocation['element_size'] != 4 or allocation['element_stride'] != 4):
        return stop('UNSUPPORTED_LAYOUT', 'Hash directory allocation disagrees with stored controls')
    if allocation['count'] > max_slots or max_nodes < 2:
        return stop('RESOURCE_BOUND', 'Hash directory exceeds slot or node budget')
    result['nodes'].append(dict(address=directory, type=allocation['name']))
    tables = {}
    for index in range(allocation['count']):
        value = reader.fields.decode(allocation, index)
        if value.get('kind') != 'stored_reference':
            return stop('UNSUPPORTED_LAYOUT', 'Directory element is not a typed pointer')
        p = target(value)
        if p is None and value.get('target_status') != 'NULL':
            return stop('UNRESOLVED_REFERENCE', 'Hash directory slot is unresolved')
        result['directory_slots'].append(dict(index=index, source_address=value['source_address'],
            address=p, raw_hex=value['raw_hex']))
        if p:
            if p.get('database') != reader.db.database_id:
                return stop('FOREIGN_DATABASE', 'Hash directory belongs to another database')
            if addrkey(p) not in tables:
                if len(tables) + 2 >= max_nodes:
                    return stop('RESOURCE_BOUND', 'Hash table node budget reached')
                tables[addrkey(p)] = p
    result['scanned_slots'] = allocation['count']
    if not tables:
        if not simple or controls['cnt_idx'] != 0xffffffff:
            return stop('CARDINALITY_UNRESOLVED', 'Null hash directory has unestablished count selection')
        result.update(status='EMPTY_DIRECTORY', complete=True, membership_complete=True,
            cardinality_source='NO_TABLE_COUNTER_STORED; ALL_DIRECTORY_SLOTS_NULL')
        return result
    if simple and controls['cnt_idx'] != 0:
        return stop('CARDINALITY_UNRESOLVED', 'Single-table cardinality selector is not the observed zero')
    member_addresses = set()
    typed = type_context is not None
    selected_counter = None
    if typed and not simple:
        selector = controls['cnt_idx']
        if selector >= len(result['directory_slots']):
            return stop('CARDINALITY_UNRESOLVED', 'Indexed count selector is outside directory')
        selected_counter = result['directory_slots'][selector]['address']
        if selected_counter is None:
            return stop('CARDINALITY_UNRESOLVED', 'Indexed count selector references null')
    for p in tables.values():
        table_allocation = reader.allocation(*addrkey(p))
        if table_allocation['element_size'] > 65536:
            return stop('RESOURCE_BOUND', 'Hash table element exceeds 65536 bytes')
        delta = p['offset'] - table_allocation['logical_offset'] - table_allocation['array_header_size']
        stride = table_allocation['element_stride']
        if stride <= 0 or delta < 0 or delta % stride or delta // stride >= table_allocation['count']:
            return stop('INTERIOR_NODE', 'Hash table reference is not an exact current element')
        value = reader.value(p)
        kind = value.get('class_name', value['type_name']).removesuffix('[]')
        if not reader.inherits(kind, '_RH_HashTable') or value.get('unsupported_reasons'):
            return stop('UNSUPPORTED_LAYOUT', 'Hash table lacks supported declared fields')
        if not _native_counter_layout(reader,kind):
            return stop('UNSUPPORTED_LAYOUT','Hash table differs from native selected-counter layout')
        counts = {name:scalar(value, name) for name in
            ('_n_entries','_n_keys','_n_deleted','_n_slots','_level')}
        contents = pointer(value, '_contents')
        bitmap = pointer(value, 'bitmap')
        slots = payload(contents)
        if (not slots['vector'] or not reader.inherits(slots['name'].removesuffix('[]'), '_RH_dynhash_slot')
                or slots['count'] != counts['_n_slots'] or slots['element_size'] != controls['slot_size']
                or slots['element_stride'] != slots['element_size'] or counts['_n_slots'] != controls['n_slots']):
            return stop('UNSUPPORTED_LAYOUT', 'Hash slot allocation disagrees with declared table/slot shape')
        if result['scanned_slots'] + slots['count'] > max_slots:
            return stop('RESOURCE_BOUND', 'Hash slot scan budget reached')
        if simple and not _simple_table_supported(controls,counts,bitmap,result['self_sentinel_receiver'],type_context):
            return stop('SLOT_MEMBERSHIP_UNCONFIRMED', 'Single-table occupancy or deletion representation is unestablished')
        result['nodes'].append(dict(address=p, type=value['type_name']))
        table = dict(address=p, counters=counts, contents_address=contents, bitmap_address=bitmap,
            bitmap_semantics='UNESTABLISHED', nonnull_reference_slots=0,
            **(_deleted_counter_evidence(counts) if simple else {}))
        result['hash_tables'].append(table)
        if typed and not simple and addrkey(p) == addrkey(selected_counter):
            result['declared_count'] = counts['_n_entries']
            result['cardinality_source'] = 'SOURCE_SELECTED_TABLE_N_ENTRIES_AND_EACH_TABLE_N_KEYS'
        if simple:
            result['declared_count'] = counts['_n_entries']
            result['cardinality_source'] = 'SOURCE_TABLE_N_ENTRIES_AND_N_KEYS'
            if counts['_n_entries'] != counts['_n_keys'] or counts['_n_keys'] > slots['count']:
                return stop('CARDINALITY_MISMATCH', 'Single-table entry/key counters disagree')
            if counts['_n_keys'] > max_members:
                return stop('RESOURCE_BOUND', 'Hash membership exceeds member budget')
        for index in range(slots['count']):
            element = reader.fields.decode(slots, index)
            field = _field(reader, element, 'val', wrapper=True)
            if field.get('kind') != 'stored_reference':
                return stop('UNSUPPORTED_LAYOUT', 'Hash slot value is not a typed pointer')
            q = target(field)
            result['scanned_slots'] += 1
            if simple and _null_binding_conflict(controls,counts,field):
                if sum(len(result[key]) for key in ('members','slot_references','incompatible_self_references')) >= max_members:
                    return stop('RESOURCE_BOUND','Hash reference evidence budget reached')
                result['slot_references'].append(_null_binding_evidence(p,index,field))
                return stop('SLOT_MEMBERSHIP_UNCONFIRMED','Zero stored word has a nonnull captured binding; native occupancy is unconfirmed')
            if q is None:
                if field.get('target_status') != 'NULL':
                    return stop('UNRESOLVED_REFERENCE', 'Hash slot pointer is unresolved')
                continue
            if q.get('database') != reader.db.database_id:
                return stop('FOREIGN_DATABASE', 'Hash slot reference belongs to another database')
            referenced = reader.allocation(*addrkey(q))
            table['nonnull_reference_slots'] += 1
            compatible = simple
            if typed:
                from .relationship_discovery import _target_view
                view = _target_view(reader.db, referenced, q['offset'])
                compatible = type_context['element_type'] in view.get('matching_schema_base_types', ())
            output_name, sentinel = _slot_role(q,address,result['self_sentinel_receiver'],
                typed=typed,type_compatible=compatible)
            if output_name is None:
                return stop('SLOT_MEMBERSHIP_UNCONFIRMED','Self slot lacks a matched source-declared native receiver')
            if typed and not compatible and not sentinel:
                return stop('MEMBER_TYPE_MISMATCH', 'Indexed slot has an incompatible non-self target')
            type_compatible = compatible
            compatible = compatible and not sentinel
            output = result[output_name]
            if sum(len(result[key]) for key in ('members','slot_references','incompatible_self_references')) >= max_members:
                return stop('RESOURCE_BOUND', 'Hash reference evidence budget reached')
            output.append(dict(node_address=p, slot_index=index, source_address=field['source_address'],
                address=q, raw_hex=field['raw_hex'], target_type=referenced['name'],
                target_status='CURRENT_ALLOCATION', meaning='NATIVE_HASH_RECEIVER_SELF_SENTINEL; NOT_COLLECTION_MEMBER; DELETION_STATE_NOT_INFERRED'
                if sentinel else 'COLLECTION_MEMBER_SLOT; OWNERSHIP_NOT_INFERRED'
                if compatible else 'TYPE_INCOMPATIBLE_SELF_REFERENCE; DELETION_SEMANTICS_UNCONFIRMED'
                if typed else 'HASH_SLOT_REFERENCE; MEMBERSHIP_NOT_ESTABLISHED',
                **(dict(sentinel_receiver_address=result['self_sentinel_receiver']['address'],
                        source_type_compatible=type_compatible if typed else None) if sentinel else {})))
            if compatible:
                result['observed_count'] += 1
                if addrkey(q) in member_addresses:
                    return stop('DUPLICATE_SET_REFERENCE', 'Pointer-key set contains duplicate target addresses')
                member_addresses.add(addrkey(q))
                table['compatible_member_slots'] = table.get('compatible_member_slots', 0) + 1
        if typed and table.get('compatible_member_slots', 0) != counts['_n_keys']:
            return stop('CARDINALITY_MISMATCH', 'Typed slot count disagrees with local stored key count')
    result['complete'] = True
    if not simple and not typed:
        return stop('SLOT_MEMBERSHIP_UNCONFIRMED',
            'Indexed routing, self-reference/deletion slots and count selector require independent interpretation')
    result['equal'] = result['declared_count'] == result['observed_count']
    result['membership_complete'] = result['equal']
    result['status'] = 'VERIFIED_CARDINALITY' if result['equal'] else 'CARDINALITY_MISMATCH'
    return result


def advance_hash_set(reader: CatalogReader, progress: CollectionProgress) -> None:
    """Resume directory/table slots with on-disk alias and member uniqueness."""
    from .collection_progress import exact_element, supported_layout, scalar, pointer, read_declared
    state=progress.state;address=state['address'];kind=state['root_kind']
    # Source-declared receiver identity is recomputed even for an existing slot
    # cursor; externally altered cached metadata cannot admit a sentinel member.
    state['self_sentinel_receiver']=hash_receiver(reader,address,kind)
    if state['phase']!='HASH_START' and state['self_sentinel_receiver'] is None:
        progress.stop('UNSUPPORTED_LAYOUT','Hash representation lacks matched native receiver/control/pointer layout');return
    if state['phase']=='HASH_START':
        context=state['type_context']
        if context is not None:
            state['type_context']=collection_type_context(reader,address,context['referrer_address'],context['field_path'])
        controls={name:scalar(reader,progress,address,kind,name) for name in
            ('flags','n_HashTables','depth','n_slots','slot_size','key_size','cnt_idx')}
        state['controls']=controls;flags=controls['flags']
        if flags not in (0xe001,0xe401):
            progress.stop('UNSUPPORTED_REPRESENTATION','Hash flag combination has no verified storage adapter');return
        if state['self_sentinel_receiver'] is None:
            progress.stop('UNSUPPORTED_LAYOUT','Hash representation lacks matched native receiver/control/pointer layout');return
        simple=flags==0xe001;state['simple']=simple
        if simple and (controls['n_HashTables']!=1 or controls['depth']!=0):
            progress.stop('UNSUPPORTED_REPRESENTATION','Single-table mode has unexpected directory shape');return
        if controls['slot_size']!=4 or controls['key_size']!=4:
            progress.stop('UNSUPPORTED_REPRESENTATION','Hash slot/key widths differ from observed pointer-key mode');return
        index_decl=members(reader.fields.schema.layout(kind)).get('index_sp')
        if not index_decl or _unaliased(index_decl[1]).get('kind')!='class':
            progress.stop('UNSUPPORTED_LAYOUT','Hash directory lacks declared pointer wrapper');return
        _,directory=pointer(reader,progress,address,kind,'index_sp',wrapper=True)
        if directory is None:
            progress.stop('TYPED_DECODE_UNRESOLVED','Hash directory pointer is null');return
        if directory.get('database')!=reader.db.database_id:
            progress.stop('FOREIGN_DATABASE','Hash directory belongs to another database');return
        allocation=reader.allocation(*addrkey(directory))
        if directory['offset']!=allocation['logical_offset']+allocation['array_header_size']:
            progress.stop('INTERIOR_NODE','Hash directory is not at exact payload start');return
        if (not allocation['vector'] or allocation['count']!=controls['n_HashTables']
                or allocation['element_size']!=4 or allocation['element_stride']!=4):
            progress.stop('UNSUPPORTED_LAYOUT','Hash directory disagrees with stored controls');return
        state.update(directory_address=directory,cursor=0,selected_counter=None,phase='HASH_DIRECTORY_NODE')
    if state['phase']=='HASH_DIRECTORY_NODE':
        if not progress.admits(nodes=1):return
        directory=state['directory_address'];allocation=reader.allocation(*addrkey(directory))
        progress.record('nodes',dict(address=directory,type=allocation['name']),node=directory,nodes=1)
        state['phase']='HASH_DIRECTORY'
    if state['phase']=='HASH_DIRECTORY':
        directory=state['directory_address'];allocation=reader.allocation(*addrkey(directory))
        while state['cursor']<allocation['count']:
            if not progress.admits(slots=1):return
            index=state['cursor'];field=reader.fields.decode(allocation,index)
            if field.get('kind')!='stored_reference':
                progress.stop('UNSUPPORTED_LAYOUT','Directory element is not a typed pointer');return
            p=target(field)
            if p is None and field.get('target_status')!='NULL':
                progress.stop('UNRESOLVED_REFERENCE','Hash directory slot is unresolved');return
            if p and p.get('database')!=reader.db.database_id:
                progress.stop('FOREIGN_DATABASE','Hash directory belongs to another database');return
            progress.record('directory_slots',dict(index=index,source_address=field['source_address'],
                address=p,raw_hex=field['raw_hex']),node=directory,index=index,slots=1)
            state['cursor']+=1
            if p:progress.enqueue(p)
            if index==state['controls']['cnt_idx']:state['selected_counter']=p
        if progress.next_node() is None:
            if not state['simple'] or state['controls']['cnt_idx']!=0xffffffff:
                progress.stop('CARDINALITY_UNRESOLVED','Null hash directory has unestablished count selection');return
            state.update(membership_complete=True,equal=False,
                cardinality_source='NO_TABLE_COUNTER_STORED; ALL_DIRECTORY_SLOTS_NULL')
            progress.stop('EMPTY_DIRECTORY',complete=True);return
        if state['simple'] and state['controls']['cnt_idx']!=0:
            progress.stop('CARDINALITY_UNRESOLVED','Single-table cardinality selector is not the observed zero');return
        if state['type_context'] is not None and not state['simple'] and state['selected_counter'] is None:
            progress.stop('CARDINALITY_UNRESOLVED','Indexed count selector is outside directory or references null');return
        state.update(phase='HASH_TABLE',cursor=None,current_table=None)
    typed=state['type_context'] is not None
    while not state['terminal']:
        current=state.get('current_table')
        if current is None:
            next_node=progress.next_node()
            if next_node is None:
                if not state['simple'] and not typed:
                    progress.stop('SLOT_MEMBERSHIP_UNCONFIRMED','Indexed routing/self-reference/deletion slots require source context',complete=True)
                else:progress.close()
                return
            if not progress.admits(nodes=1):return
            position,p=next_node;table_allocation=exact_element(reader,p)
            if table_allocation['element_size']>65536:
                state['resource_exclusion']=dict(reason='SINGLE_ELEMENT_RAW_SIZE',limit=65536,
                    element_address=p,element_bytes=table_allocation['element_size'],
                    raw_selector=dict(start=p['offset'],stop=p['offset']+table_allocation['element_size']))
                progress.stop('RESOURCE_BOUND','Hash table element exceeds raw bound');return
            table_kind=table_allocation['name'].removesuffix('[]')
            if not reader.inherits(table_kind,'_RH_HashTable'):
                progress.stop('UNSUPPORTED_LAYOUT','Hash table lacks supported declared fields');return
            supported_layout(reader,table_kind)
            if not _native_counter_layout(reader,table_kind):
                progress.stop('UNSUPPORTED_LAYOUT','Hash table differs from native selected-counter layout');return
            counts={name:scalar(reader,progress,p,table_kind,name) for name in
                ('_n_entries','_n_keys','_n_deleted','_n_slots','_level')}
            _,contents=pointer(reader,progress,p,table_kind,'_contents')
            _,bitmap=pointer(reader,progress,p,table_kind,'bitmap')
            if contents is None:
                progress.stop('TYPED_DECODE_UNRESOLVED','Hash contents pointer is null');return
            if contents.get('database')!=reader.db.database_id or bitmap and bitmap.get('database')!=reader.db.database_id:
                progress.stop('FOREIGN_DATABASE','Hash payload belongs to another database');return
            slots=reader.allocation(*addrkey(contents))
            if contents['offset']!=slots['logical_offset']+slots['array_header_size']:
                progress.stop('INTERIOR_NODE','Hash contents is not at exact payload start');return
            if (not slots['vector'] or not reader.inherits(slots['name'].removesuffix('[]'),'_RH_dynhash_slot')
                    or slots['count']!=counts['_n_slots'] or slots['element_size']!=state['controls']['slot_size']
                    or slots['element_stride']!=slots['element_size'] or counts['_n_slots']!=state['controls']['n_slots']):
                progress.stop('UNSUPPORTED_LAYOUT','Hash slots disagree with declared table shape');return
            slot_decl=members(reader.fields.schema.layout(slots['name'].removesuffix('[]'))).get('val')
            if not slot_decl or _unaliased(slot_decl[1]).get('kind')!='class':
                progress.stop('UNSUPPORTED_LAYOUT','Hash slot lacks declared pointer wrapper');return
            wrapper=members(reader.fields.schema.layout(_unaliased(slot_decl[1])['name']))
            if '_ptr' not in wrapper:
                progress.stop('UNSUPPORTED_LAYOUT','Hash slot wrapper lacks declared _ptr');return
            if state['simple'] and not _simple_table_supported(state['controls'],counts,bitmap,
                    state['self_sentinel_receiver'],state['type_context']):
                progress.stop('SLOT_MEMBERSHIP_UNCONFIRMED','Single-table occupancy or deletion representation is unestablished');return
            if state['simple']:
                state.update(declared_count=counts['_n_entries'],cardinality_source='SOURCE_TABLE_N_ENTRIES_AND_N_KEYS')
                if counts['_n_entries']!=counts['_n_keys'] or counts['_n_keys']>slots['count']:
                    progress.stop('CARDINALITY_MISMATCH','Single-table entry/key counters disagree');return
            elif typed and addrkey(p)==addrkey(state['selected_counter']):
                state.update(declared_count=counts['_n_entries'],cardinality_source='SOURCE_SELECTED_TABLE_N_ENTRIES_AND_EACH_TABLE_N_KEYS')
            progress.record('nodes',dict(address=p,type=table_kind),node=p,nodes=1)
            current=dict(address=p,position=position,kind=table_kind,counts=counts,contents=contents,
                bitmap=bitmap,index=0,compatible=0,nonnull=0)
            state.update(current_table=current,phase='HASH_SLOTS',cursor=dict(table_address=p,next_slot=0))
        p=current['address'];slots=reader.allocation(*addrkey(current['contents']))
        while current['index']<slots['count']:
            # A nonnull slot may require one reference record; admission reserves
            # that maximum before its decode, without retrying committed slots.
            if not progress.admits(slots=1,storage_evidence_slots=1,members=1):return
            index=current['index'];slot_address=dict(current['contents'],offset=current['contents']['offset']+index*slots['element_stride'])
            fields=read_declared(reader,progress,slot_address,slots['name'].removesuffix('[]'),'val',retain_unresolved=True,control=False)
            if len(fields)!=1 or not fields[0].get('path','').endswith('.val._ptr'):
                progress.stop('UNSUPPORTED_LAYOUT','Hash slot is not a unique declared pointer');return
            field=fields[0]
            if field.get('kind')!='stored_reference':
                progress.stop('UNSUPPORTED_LAYOUT','Hash slot value is not a typed pointer');return
            q=target(field)
            progress.record('storage_slots',dict(slot_index=index,source_address=field.get('source_address'),
                address=q,raw_hex=field.get('raw_hex'),target_status=field.get('target_status'),
                role='HASH_SLOT; OCCUPANCY_REQUIRES_EXISTING_ADAPTER_GATES'),node=p,index=index,slots=1,storage_evidence_slots=1)
            current['index']+=1;state['cursor']['next_slot']=current['index']
            if state['simple'] and _null_binding_conflict(state['controls'],current['counts'],field):
                progress.record('slot_references',_null_binding_evidence(p,index,field),node=p,index=index,members=1)
                progress.stop('SLOT_MEMBERSHIP_UNCONFIRMED','Zero stored word has a nonnull captured binding; native occupancy is unconfirmed');return
            if q is None:
                if field.get('target_status')!='NULL':
                    progress.stop('UNRESOLVED_REFERENCE','Hash slot pointer is unresolved');return
                continue
            if q.get('database')!=reader.db.database_id:
                progress.stop('FOREIGN_DATABASE','Hash slot belongs to another database');return
            referenced=reader.allocation(*addrkey(q));current['nonnull']+=1
            compatible=state['simple']
            if typed:
                from .relationship_discovery import _target_view
                view=_target_view(reader.db,referenced,q['offset'])
                compatible=state['type_context']['element_type'] in view.get('matching_schema_base_types',())
            output,sentinel=_slot_role(q,address,state['self_sentinel_receiver'],
                typed=typed,type_compatible=compatible)
            if output is None:
                progress.stop('SLOT_MEMBERSHIP_UNCONFIRMED','Self slot lacks a matched source-declared native receiver');return
            if typed and not compatible and not sentinel:
                progress.stop('MEMBER_TYPE_MISMATCH','Indexed slot has an incompatible non-self target');return
            type_compatible=compatible
            compatible=compatible and not sentinel
            progress.record(output,dict(node_address=p,slot_index=index,source_address=field['source_address'],
                address=q,raw_hex=field['raw_hex'],target_type=referenced['name'],target_status='CURRENT_ALLOCATION',
                meaning='NATIVE_HASH_RECEIVER_SELF_SENTINEL; NOT_COLLECTION_MEMBER; DELETION_STATE_NOT_INFERRED' if sentinel else
                    'COLLECTION_MEMBER_SLOT; OWNERSHIP_NOT_INFERRED' if compatible else
                    'TYPE_INCOMPATIBLE_SELF_REFERENCE; DELETION_SEMANTICS_UNCONFIRMED' if typed else
                    'HASH_SLOT_REFERENCE; MEMBERSHIP_NOT_ESTABLISHED',
                **(dict(sentinel_receiver_address=state['self_sentinel_receiver']['address'],
                        source_type_compatible=type_compatible if typed else None) if sentinel else {})),node=p,index=index,members=1)
            if compatible:
                state['observed_count']+=1;current['compatible']+=1
                if not progress.member_key(q):
                    progress.stop('DUPLICATE_SET_REFERENCE','Pointer-key set contains duplicate targets');return
        progress.record('hash_tables',dict(address=p,counters=current['counts'],contents_address=current['contents'],
            bitmap_address=current['bitmap'],bitmap_semantics='UNESTABLISHED',nonnull_reference_slots=current['nonnull'],
            compatible_member_slots=current['compatible'],
            **(_deleted_counter_evidence(current['counts']) if state['simple'] else {})),node=p)
        if typed and current['compatible']!=current['counts']['_n_keys']:
            progress.stop('CARDINALITY_MISMATCH','Typed slots disagree with local stored key count');return
        progress.close_node(current['position'])
        state.update(current_table=None,phase='HASH_TABLE',cursor=None)
