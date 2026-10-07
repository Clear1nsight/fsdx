"""Disk-backed collection prefixes and narrow source-declared field reads.

The caller owns the transaction and source/runtime guard. This module never
commits. Completed slot records are not materialized again to resume a task.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import json
import re
import sqlite3

from fsd_decoder.core.diagnostics import InputValidationError
from fsd_decoder.exports.catalog import CatalogError, addrkey, target, _admitted_layout
from fsd_decoder.exports.fsd_mesh import members
from fsd_decoder.schema.decode_members import MemberDecoder
from fsd_decoder.schema.expansion_admission import (ExpansionLimits, ExpansionMetadataError, schema_cost, admit_cost, DEFAULT_MAX_DECODED_LEAVES, DEFAULT_MAX_EXPANSION_WORK)


COSTS = ('members', 'slots', 'nodes', 'storage_evidence_slots')
STATES = ('PENDING', 'CONTINUING', 'PROCESSED', 'BLOCKED_RESOURCE_BOUND')


def validate_progress_state(state) -> None:
    phases={'ROOT','ARRAY_START','ARRAY_STORAGE','ARRAY_SLOTS','LIST_NODE','LIST_SLOTS',
            'HASH_START','HASH_DIRECTORY_NODE','HASH_DIRECTORY','HASH_TABLE','HASH_SLOTS'}
    required={'version','address','type_context','adapter','phase','representation','declared_count',
        'observed_count','equal','complete','membership_complete','status','diagnostics','resource_usage',
        'record_counts','sequence','controls','cursor','queue_position','terminal','control_reads','control_bytes','steps'}
    if (not isinstance(state,dict) or not required<=state.keys() or type(state['version']) is not int or state['version']!=1
            or not isinstance(state['address'],dict) or not isinstance(state['controls'],dict)
            or type(state['phase']) is not str or state['phase'] not in phases or not isinstance(state['status'],str)
            or not isinstance(state['diagnostics'],list) or not isinstance(state['record_counts'],dict)
            or not isinstance(state['resource_usage'],dict) or set(state['resource_usage'])!=set(COSTS)
            or state['adapter'] not in (None,'LIST','ARRAY','HASH_SET')
            or any(type(state[key]) is not bool for key in ('equal','complete','membership_complete','terminal'))
            or any(type(state[key]) is not int or state[key]<0 for key in
                ('observed_count','sequence','queue_position','control_reads','control_bytes','steps'))
            or state['declared_count'] is not None and (type(state['declared_count']) is not int or state['declared_count']<0)
            or any(type(value) is not int or value<0 for data in (state['record_counts'],state['resource_usage']) for value in data.values())
            or not state['terminal'] and (state['complete'] or state['equal'] or state['membership_complete'] or state['status']!='PARTIAL')):
        raise InputValidationError('Invalid collection progress state shape/counters')
    if state['phase'] in ('ARRAY_SLOTS','HASH_DIRECTORY') and (type(state['cursor']) is not int or state['cursor']<0):
        raise InputValidationError('Invalid collection progress slot cursor')
    if state['phase'] in ('LIST_SLOTS','HASH_SLOTS'):
        current=state.get('current_node') if state['phase']=='LIST_SLOTS' else state.get('current_table')
        if (not isinstance(current,dict) or not isinstance(state['cursor'],dict)
                or any(key not in current for key in ('address','position','kind','index'))
                or type(current['index']) is not int or current['index']<0
                or state['cursor'].get('next_slot')!=current['index']):
            raise InputValidationError('Invalid collection progress current-node cursor')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def create_progress_tables(connection: sqlite3.Connection) -> None:
    """Create the empty progress schema without committing caller-owned work."""
    statements = '''
        CREATE TABLE collection_progress(task_id INTEGER PRIMARY KEY,state TEXT NOT NULL);
        CREATE TABLE collection_records(task_id INTEGER NOT NULL,sequence INTEGER NOT NULL,
            kind TEXT NOT NULL,node_key TEXT NOT NULL,slot_index INTEGER NOT NULL,
            evidence TEXT NOT NULL,members INTEGER NOT NULL,slots INTEGER NOT NULL,
            nodes INTEGER NOT NULL,storage_evidence_slots INTEGER NOT NULL,
            PRIMARY KEY(task_id,sequence),UNIQUE(task_id,kind,node_key,slot_index));
        CREATE TABLE collection_queue(task_id INTEGER NOT NULL,position INTEGER NOT NULL,
            address TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'PENDING',
            PRIMARY KEY(task_id,position),UNIQUE(task_id,address));
        CREATE INDEX collection_queue_pending ON collection_queue(task_id,state,position);
        CREATE TABLE collection_member_keys(task_id INTEGER NOT NULL,address TEXT NOT NULL,
            PRIMARY KEY(task_id,address));
    '''
    # executescript commits an existing transaction before running its SQL.
    # Individual DDL statements participate in the caller's transaction.
    for statement in statements.split(';'):
        if statement.strip():
            connection.execute(statement)


class CollectionProgress:
    """One task's bounded metadata, indexed queues and append-only evidence."""
    def __init__(self, connection: sqlite3.Connection, task_id: int, address: Mapping,
                 context: Mapping | None = None):
        self.connection, self.task_id = connection, task_id
        row = connection.execute('SELECT state FROM collection_progress WHERE task_id=?', (task_id,)).fetchone()
        if row:
            self.state = json.loads(row[0])
            validate_progress_state(self.state)
            if self.state['address'] != dict(address) or self.state['type_context'] != context:
                raise InputValidationError('Collection progress address/context differs from queued task')
        else:
            self.state = dict(version=1,address=dict(address),type_context=dict(context) if context else None,
                adapter=None,phase='ROOT',representation=None,declared_count=None,observed_count=0,
                equal=False,complete=False,membership_complete=False,status='PARTIAL',diagnostics=[],
                resource_usage={name:0 for name in COSTS},record_counts={},sequence=0,
                controls={},cursor=None,queue_position=0,terminal=False,
                control_reads=0,control_bytes=0,steps=0,ownership='NOT_INFERRED')
        self.usage = {name:0 for name in COSTS}
        self.reads = self.bytes = 0
        self.limits = {}

    def begin(self, *, max_members: int, max_slots: int, max_nodes: int) -> None:
        for name,value,ceiling in (('members',max_members,100000),('slots',max_slots,1000000),
                                   ('nodes',max_nodes,10000)):
            if type(value) is not int or not 0 <= value <= ceiling:
                raise InputValidationError(f'Collection step {name} must be between zero and {ceiling}')
        self.limits = dict(members=max_members,slots=max_slots,nodes=max_nodes,
                           storage_evidence_slots=max_slots)
        self.state['steps']+=1

    def admits(self, **costs) -> bool:
        return all(self.usage[name]+cost <= self.limits[name] for name,cost in costs.items())

    def record(self, kind: str, evidence: Mapping, *, node=None, index=-1, **costs) -> None:
        if not self.admits(**costs):
            raise InputValidationError('Collection prefix attempted to exceed its admitted step')
        values = {name:costs.get(name,0) for name in COSTS}
        self.state['sequence'] += 1
        self.connection.execute('INSERT INTO collection_records VALUES (?,?,?,?,?,?,?,?,?,?)',
            (self.task_id,self.state['sequence'],kind,encoded(node or self.state['address']),index,
             encoded(evidence),*(values[name] for name in COSTS)))
        self.state['record_counts'][kind] = self.state['record_counts'].get(kind,0)+1
        for name,cost in values.items():
            self.usage[name] += cost
            self.state['resource_usage'][name] += cost

    def enqueue(self, address: Mapping) -> None:
        self.state['queue_position'] += 1
        inserted = self.connection.execute('INSERT OR IGNORE INTO collection_queue(task_id,position,address) VALUES (?,?,?)',
            (self.task_id,self.state['queue_position'],encoded(dict(address)))).rowcount
        if not inserted:
            self.state['queue_position'] -= 1

    def next_node(self):
        row = self.connection.execute("SELECT position,address FROM collection_queue WHERE task_id=? AND state='PENDING' ORDER BY position LIMIT 1",(self.task_id,)).fetchone()
        return (row[0],json.loads(row[1])) if row else None

    def close_node(self, position: int) -> None:
        self.connection.execute("UPDATE collection_queue SET state='DONE' WHERE task_id=? AND position=?",(self.task_id,position))

    def member_key(self, address: Mapping) -> bool:
        return bool(self.connection.execute('INSERT OR IGNORE INTO collection_member_keys VALUES (?,?)',
            (self.task_id,encoded(dict(address)))).rowcount)

    def stop(self, status: str, reason: str | None = None, *, complete=False) -> None:
        self.state.update(status=status,terminal=True,complete=complete)
        if reason:
            self.state['diagnostics'].append(reason)

    def close(self, *, cardinality=True) -> None:
        state = self.state
        equal = state['declared_count'] == state['observed_count'] if cardinality else False
        state.update(equal=equal,membership_complete=equal)
        self.stop('VERIFIED_CARDINALITY' if equal else 'CARDINALITY_MISMATCH', complete=True)

    def save(self) -> dict:
        self.state['control_reads'] += self.reads
        self.state['control_bytes'] += self.bytes
        validate_progress_state(self.state)
        self.connection.execute('INSERT OR REPLACE INTO collection_progress VALUES (?,?)',
                                (self.task_id,encoded(self.state)))
        return dict(self.summary(),step_usage=dict(self.usage),
                    step_control_reads=self.reads,step_control_bytes=self.bytes)

    def summary(self) -> dict:
        state = self.state
        summary={key:state[key] for key in ('address','representation','declared_count','observed_count',
            'equal','complete','membership_complete','status','diagnostics','ownership','adapter',
            'phase','cursor','controls','type_context','resource_usage','record_counts','sequence',
            'terminal','control_reads','control_bytes','steps')}
        summary.update({key:state[key] for key in ('active_window','lower_bound_semantics',
            'cardinality_source','resource_exclusion','self_sentinel_receiver') if key in state})
        return summary


def exact_element(reader, address):
    if address.get('database') != reader.db.database_id:
        raise CatalogError('Collection reference belongs to another database')
    allocation = reader.allocation(*addrkey(address))
    delta = address['offset']-allocation['logical_offset']-allocation['array_header_size']
    stride = allocation['element_stride']
    if stride <= 0 or delta < 0 or delta % stride or delta//stride >= allocation['count']:
        raise CatalogError('Collection node is not an exact current element start')
    return allocation


def supported_layout(reader, kind):
    if kind not in reader.fields.schema.classes or reader.fields._layout_problems(kind):
        raise CatalogError('Collection node lacks supported compiled declarations')
    return reader.fields.schema.layout(kind)


def read_declared(reader, progress: CollectionProgress, address: Mapping, kind: str,
                  name: str, *, index: int | None = None, retain_unresolved=False, control=True) -> list[dict]:
    """Use the existing compiled leaf decoder over one declared field/window."""
    allocation = exact_element(reader, address)
    layout = _admitted_layout(reader, allocation, kind)
    supported_layout(reader, kind)
    declaration = members(layout).get(name)
    if declaration is None:
        raise CatalogError('Collection declaration lacks '+name)
    offset,typ = declaration
    path_length = len(kind) + 1 + len(name)
    if index is not None:
        if typ.get('kind') != 'array' or not 0 <= index < typ['count']:
            raise CatalogError('Collection slot is outside its declared array')
        typ = typ['element'];offset += index*typ['size'];path_length += 2 + len(str(index))
    size = typ.get('size')
    if type(size) is not int or not 1 <= size <= 65536 or offset < 0 or offset+size > min(layout['size'], allocation['element_size']):
        raise CatalogError('Collection declaration exceeds current element')
    source = dict(address,offset=address['offset']+offset)
    limits = reader.fields.expansion_limits
    try:
        cost = schema_cost(reader.fields.decoder.layout, typ=typ, limits=limits,
                           max_depth=reader.fields.decoder.max_depth, max_array_elements=1, path_length=path_length)
    except ExpansionMetadataError as exc:
        raise CatalogError(str(exc)) from exc
    admit_cost(cost, limits, context=dict(address=source, type=kind),
               raw_selector=dict(address=source, size=size))
    path = kind + '.' + name + (f'[{index}]' if index is not None else '')
    raw = reader.db.read_at(source['segment'],source['cluster'],source['offset'],size)
    unresolved=set()
    def resolver(relative,width,word):
        if retain_unresolved:
            row=reader.db.store.connection.execute('''SELECT width,raw,status FROM pointers
                WHERE segment=? AND cluster=? AND logical_offset=?''',
                (source['segment'],source['cluster'],source['offset']+relative)).fetchone()
            if row is not None and row['status']=='UNRESOLVED':
                if row['width']!=width or row['raw']!=word.to_bytes(width,'little'):
                    raise CatalogError('Retained unresolved pointer differs from snapshot bytes')
                unresolved.add(relative)
                return None
        return reader.fields._resolve(reader.db.address(source['segment'],source['cluster'],
            source['offset']+relative),width,word)
    decoder = MemberDecoder(raw,reader.fields.schema,resolver,max_array_elements=1, max_decoded_leaves=limits.max_decoded_leaves, max_expansion_work=limits.max_expansion_work)
    decoder.layouts = reader.fields.decoder.layouts
    fields = decoder.leaf(typ,0,path,0,0)
    for field in fields:
        relative = field.pop('source_offset')
        field['source_address'] = dict(source,offset=source['offset']+relative)
        field['record_relative_offset'] = offset+relative
        if relative in unresolved:
            field['target_status']='UNRESOLVED'
        if field.get('status') in ('UNKNOWN_SIZE','ARRAY_LIMIT','UNSUPPORTED_FLOAT_FORMAT','UNSUPPORTED_TYPE'):
            raise CatalogError('Collection field lacks supported typed declaration')
    if index is None and control:
        progress.reads += 1;progress.bytes += size
    return fields


def scalar(reader, progress, address, kind, name):
    fields = read_declared(reader,progress,address,kind,name)
    if len(fields)!=1 or fields[0].get('kind') not in ('primitive','enum'):
        raise CatalogError('Collection scalar is not a unique typed integer: '+name)
    value = fields[0].get('value')
    if type(value) is not int or value < 0:
        raise CatalogError('Collection scalar is not a nonnegative integer: '+name)
    return value


def pointer(reader, progress, address, kind, name, *, index=None, wrapper=False):
    fields = read_declared(reader,progress,address,kind,name,index=index)
    selected = [field for field in fields if field.get('kind')=='stored_reference']
    suffix='.'+name+('._ptr' if wrapper else '')
    if len(selected)!=1 or len(fields)!=1 or not selected[0].get('path','').endswith(suffix):
        raise CatalogError('Collection pointer is not a unique typed reference: '+name)
    field = selected[0]
    p = target(field)
    if p is None and field.get('target_status')!='NULL':
        raise CatalogError('Collection pointer is unresolved: '+name)
    return field,p


def scalar_progress_counts(connection):
    """Fresh-admission scalar reconciliation; no historical evidence JSON parse."""
    return connection.execute('''SELECT task_id,count(*),coalesce(sum(members),0),
        coalesce(sum(slots),0),coalesce(sum(nodes),0),coalesce(sum(storage_evidence_slots),0)
        FROM collection_records GROUP BY task_id''')
