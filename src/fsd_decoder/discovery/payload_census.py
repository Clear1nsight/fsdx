"""Compact resumable payload ranges and source-declared incoming evidence.

All indexed allocations/elements are the population. Primitive block checks,
individual interpretation, exact incoming elements and ownership are separate.
Immutable FSDX supplies bytes and original PRM rows; this derivative never copies
their raw payloads or creates a JSON record for every stored value.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from fsd_decoder.core.diagnostics import InputValidationError, UnsupportedLayoutError, require_source_failure
from fsd_decoder.core.interpretation import interpretation_facets
from fsd_decoder.core.provenance import runtime_identity
from fsd_decoder.portable.format import decode_json, MAX_BLOB_BYTES
from .complete import _member_views
from .datasets import DiscoverySession, _limit, session_operation
from .decoding_coverage import expansion_admission, _primitive_fast
from .membership import _checkpoint_path, _store_digest, _json
from .payload_links import _declared_pointee, _location, _compatible

VERSION = 3
_VALIDATED_READERS = OrderedDict()
_KINDS = {'allocations', 'plans', 'raw_ranges', 'unindexed_ranges', 'value_ranges', 'binding_ranges', 'unrecorded_views', 'incoming', 'incoming_views', 'incoming_allocations', 'declarations'}
_SCHEMA = '''
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE allocations(id INTEGER PRIMARY KEY,raw_done INTEGER NOT NULL,value_done INTEGER NOT NULL,
  stored_elements INTEGER NOT NULL,bytes INTEGER NOT NULL,complete INTEGER NOT NULL);
CREATE TABLE declarations(id INTEGER PRIMARY KEY,type TEXT,path TEXT,evidence TEXT NOT NULL,UNIQUE(type,path));
CREATE TABLE plans(id INTEGER PRIMARY KEY,type TEXT UNIQUE,status TEXT,unconditional INTEGER,conditional INTEGER,error TEXT);
CREATE TABLE raw_ranges(id INTEGER PRIMARY KEY,allocation_id INTEGER,first INTEGER,last INTEGER,status TEXT,detail TEXT);
CREATE INDEX raw_allocation ON raw_ranges(allocation_id,first);
CREATE TABLE unindexed_ranges(id INTEGER PRIMARY KEY,segment INTEGER,cluster INTEGER,chunk_start INTEGER,
 chunk_length INTEGER,first INTEGER,last INTEGER,status TEXT);
CREATE INDEX unindexed_address ON unindexed_ranges(segment,cluster,chunk_start,first);
CREATE TABLE value_ranges(id INTEGER PRIMARY KEY,allocation_id INTEGER,first INTEGER,last INTEGER,status TEXT,detail TEXT,
 records_decoded INTEGER NOT NULL);
CREATE INDEX value_allocation ON value_ranges(allocation_id,first);
CREATE TABLE binding_ranges(id INTEGER PRIMARY KEY,source_id INTEGER,slot_id INTEGER,first INTEGER,last INTEGER,
 status TEXT,count INTEGER,detail TEXT,prm_first_segment INTEGER,prm_first_cluster INTEGER,prm_first_offset INTEGER,
 prm_last_segment INTEGER,prm_last_cluster INTEGER,prm_last_offset INTEGER,
 unconditional_matches INTEGER,conditional_matches INTEGER,target_status TEXT);
CREATE INDEX binding_source ON binding_ranges(source_id,slot_id,status,last);
CREATE TABLE unrecorded_views(id INTEGER PRIMARY KEY,allocation_id INTEGER,slot_id INTEGER,displacement INTEGER,
 first INTEGER,last INTEGER,status TEXT);
CREATE INDEX unrecorded_slot ON unrecorded_views(allocation_id,slot_id,displacement,status,last);
CREATE TABLE incoming(id INTEGER PRIMARY KEY,allocation_id INTEGER,first INTEGER,last INTEGER,status TEXT);
CREATE INDEX incoming_allocation ON incoming(allocation_id,status,first);
CREATE TABLE incoming_views(id INTEGER PRIMARY KEY,allocation_id INTEGER,first INTEGER,last INTEGER,axis TEXT,
 byte_displacement INTEGER,view TEXT,status TEXT,bindings INTEGER);
CREATE INDEX incoming_views_target ON incoming_views(allocation_id,axis,byte_displacement,view,status,first);
CREATE TABLE incoming_allocations(id INTEGER PRIMARY KEY,allocation_id INTEGER,status TEXT,bindings INTEGER,
 UNIQUE(allocation_id,status));
'''


def _population(db):
    allocations, elements, size = db.store.connection.execute(
        'SELECT count(*),coalesce(sum(element_count),0),coalesce(sum(size),0) FROM allocations').fetchone()
    bindings = db.store.connection.execute('SELECT count(*) FROM pointers').fetchone()[0]
    chunks,retained=db.store.connection.execute('SELECT count(*),coalesce(sum(length),0) FROM chunks').fetchone()
    for table,start,length in (('allocations','logical_offset','size'),('chunks','logical_start','length')):
        overlapping=db.store.connection.execute(f'''SELECT count(*) FROM (SELECT {start} start,
            max({start}+{length}) OVER (PARTITION BY segment,cluster ORDER BY {start}
                ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) previous_end FROM {table})
            WHERE start<previous_end''').fetchone()[0]
        if overlapping:
            raise InputValidationError('Overlapping source '+table+' cannot establish disjoint logical byte coverage')
    return dict(allocations=allocations, stored_elements=elements, allocation_bytes=size,
        recorded_bindings=bindings,retained_logical_bytes=retained,retained_chunks=chunks)


def _pointer_slots(schema, name):
    """Lazy symbolic declarations; no native array elements are expanded."""
    def walk(kind, offset, path, arrays=(), conditional=False, depth=0):
        if depth > 64:
            raise UnsupportedLayoutError('Source pointer declaration nesting exceeds 64')
        tag = kind['kind']
        if tag in ('alias','qualified'):
            if kind.get('unknown_qualifier_flags'):
                raise UnsupportedLayoutError('Source pointer cardinality has unknown qualifiers')
            yield from walk(kind['underlying'],offset,path,arrays,conditional,depth+1)
        elif tag == 'array':
            yield from walk(kind['element'],offset,path+'[]',
                (*arrays,dict(count=kind['count'],stride=kind['element'].get('size'))),conditional,depth+1)
        elif tag == 'pointer' or tag == 'class' and kind.get('name','').startswith(
                ('os_soft_pointer32<','os_hard_pointer32<','os_soft_pointer64<','os_hard_pointer64<')):
            yield dict(path=path,offset=offset,kind=tag,type_name=kind.get('name'),size=kind.get('size'),
                descriptor_offset=kind.get('descriptor_offset'),arrays=arrays,conditional_union=conditional,
                pointee_type=kind.get('element') if tag=='pointer' else None)
        elif tag in ('class','union'):
            layout = schema.layout(kind['name'])
            union=tag=='union' or layout.get('class_kind_bits')==2
            if layout.get('unresolved'):
                raise UnsupportedLayoutError('Source layout contains unresolved declarations')
            for base in layout.get('bases',()):
                yield from walk(base['type'],offset+base['offset'],path+'::<'+base['type']['name']+'>',
                    arrays,conditional,depth+1)
            for member in layout.get('members',()):
                yield from walk(member['type'],offset+member['offset'],path+'.'+member['name'],
                    arrays,conditional or union,depth+1)
        elif tag not in ('primitive','enum'):
            raise UnsupportedLayoutError('Source declaration cardinality is unestablished: '+tag)
    layout = schema.layout(name)
    yield from walk(dict(kind='union' if layout.get('class_kind_bits')==2 else 'class',name=name),0,name)


def _plans(session):
    result = {}
    for row in session.census:
        slots, error = [], None
        if row['schema_class']:
            try:
                for slot in _pointer_slots(session.db.fields.schema,row['type'].removesuffix('[]')):
                    if len(slots)==100000:
                        raise UnsupportedLayoutError('Source symbolic pointer declaration policy exceeds 100000')
                    slots.append(slot)
            except Exception as exc:
                require_source_failure(exc,dict(phase='payload_slot_plan',name=row['type']))
                error = str(exc)
        counts = Counter()
        for slot in slots:
            amount = 1
            for array in slot['arrays']:
                amount *= array['count']
            counts['conditional' if slot['conditional_union'] else 'unconditional'] += amount
        result[row['type']] = dict(slots=slots,counts=dict(counts),error=error,
            admitted_native_tags=sorted({g['native_tag'] for g in row.get('native_tag_groups', ())
                                        if g['schema_admission']['admitted']}),
            status='SOURCE_SLOT_CARDINALITY_UNESTABLISHED' if error else
                'SOURCE_SCHEMA_DECLARATIONS' if row['schema_class'] else 'NO_SOURCE_CLASS_DECLARATIONS')
    return result


def _allocation_plan(plans, allocation, fields):
    plan = plans[allocation['name']]
    admission = fields.schema_admission(allocation)
    if admission['admitted']:
        return plan
    return dict(plan, slots=[], counts={}, error='SOURCE_CLASS_ADMISSION_UNESTABLISHED'
                if admission['schema_name'] is not None else None,
                status=admission['status'])


def _allocation(db, identifier):
    row = db.store.connection.execute(db.store._allocation_query()+' WHERE a.id=?',(identifier,)).fetchone()
    if row is None:
        raise InputValidationError('Payload cursor allocation is absent from source')
    return db.store._allocation_record(row)


def _range(connection, table, aid, first, last, status, detail):
    encoded = _json(detail)
    decoded = (1 if detail.get('decoded_record_units')=='ONE_INLINE_CHARACTER_BLOCK' else last-first
        if detail.get('decoded_record_units') else 0)
    old = connection.execute(f'''SELECT id,last,status,detail FROM {table}
        WHERE allocation_id=? ORDER BY first DESC LIMIT 1''',(aid,)).fetchone()
    if old and old[1]==first and old[2:]==(status,encoded):
        connection.execute(f'UPDATE {table} SET last=? WHERE id=?',(last,old[0]))
        if table=='value_ranges':
            connection.execute('UPDATE value_ranges SET records_decoded=records_decoded+? WHERE id=?',(decoded,old[0]))
    else:
        if table=='value_ranges':
            connection.execute('INSERT INTO value_ranges(allocation_id,first,last,status,detail,records_decoded) VALUES(?,?,?,?,?,?)',
                (aid,first,last,status,encoded,decoded))
        else:
            connection.execute(f'INSERT INTO {table}(allocation_id,first,last,status,detail) VALUES(?,?,?,?,?)',
                (aid,first,last,status,encoded))


def _incoming(connection, aid, index, status):
    rows = list(connection.execute('''SELECT id,first,last FROM incoming WHERE allocation_id=?
        AND status=? AND first<=? AND last>=?''',(aid,status,index+1,index)))
    first, last = index,index+1
    for identifier,lo,hi in rows:
        first,last = min(first,lo),max(last,hi)
        connection.execute('DELETE FROM incoming WHERE id=?',(identifier,))
    connection.execute('INSERT INTO incoming(allocation_id,first,last,status) VALUES(?,?,?,?)',
        (aid,first,last,status))


def _incoming_view(connection,aid,index,displacement,view,status):
    axis='INLINE_CHARACTER_BYTE' if view=='EXACT_INLINE_CHARACTER_BYTE' else 'ELEMENT'
    if axis=='INLINE_CHARACTER_BYTE':index,displacement=displacement,0
    rows=list(connection.execute('''SELECT id,first,last,bindings FROM incoming_views WHERE allocation_id=?
        AND axis=? AND byte_displacement=? AND view=? AND status=? AND first<=? AND last>=?''',
        (aid,axis,displacement,view,status,index+1,index)))
    first,last,bindings=index,index+1,1
    for identifier,lo,hi,count in rows:
        first,last,bindings=min(first,lo),max(last,hi),bindings+count
        connection.execute('DELETE FROM incoming_views WHERE id=?',(identifier,))
    connection.execute('INSERT INTO incoming_views(allocation_id,first,last,axis,byte_displacement,view,status,bindings) VALUES(?,?,?,?,?,?,?,?)',
        (aid,first,last,axis,displacement,view,status,bindings))


def _unrecorded_fields(session,connection,a,index,value,slots):
    """Bounded decoded unconditional declarations only; raw bits remain in FSDX."""
    stack=[value];checked=0
    origin=a['logical_offset']+a.get('array_header_size',0)+index*a.get('element_stride',a['size'])
    while stack:
        node=stack.pop()
        if isinstance(node,list):stack.extend(node);continue
        if not isinstance(node,Mapping) or node.get('kind')=='union':continue
        if node.get('kind')=='stored_reference' and isinstance(node.get('source_address'),Mapping):
            address=node['source_address']
            displacement=address['offset']-origin
            matches=_member_views(slots,displacement)
            candidates=[s for s in slots if not s['conditional_union'] and any(v['path']==s['path'] for v in matches)]
            if len(candidates)==1 and not session.db.store.connection.execute(
                    'SELECT 1 FROM pointers WHERE segment=? AND cluster=? AND logical_offset=?',
                    (address['segment'],address['cluster'],address['offset'])).fetchone():
                slot=candidates[0]
                if node.get('size')==slot.get('size') and node.get('stored_word') is not None:
                    status=('IMPLICIT_NULL_SOURCE_FIELD' if node['stored_word']==0 and session.db.store.manifest.get('pointer_resolution_complete')
                        else 'MISSING_CAPTURED_BINDING' if node['stored_word'] else 'UNRECORDED_REFERENCE_NOT_PROVED_NULL')
                    sid=connection.execute('SELECT id FROM declarations WHERE type=? AND path=?',(a['name'],slot['path'])).fetchone()[0]
                    old=connection.execute('''SELECT id,last FROM unrecorded_views WHERE allocation_id=? AND slot_id=?
                        AND displacement=? AND status=? ORDER BY last DESC LIMIT 1''',(a['store_allocation_id'],sid,displacement,status)).fetchone()
                    if old and old[1]==index:
                        connection.execute('UPDATE unrecorded_views SET last=? WHERE id=?',(index+1,old[0]))
                    else:
                        connection.execute('INSERT INTO unrecorded_views(allocation_id,slot_id,displacement,first,last,status) VALUES(?,?,?,?,?,?)',
                            (a['store_allocation_id'],sid,displacement,index,index+1,status))
                    checked+=1
        stack.extend(child for key,child in node.items() if key not in ('pointee_type','schema_declarations'))
    return checked


def _state(connection):
    row = connection.execute("SELECT value FROM metadata WHERE key='state'").fetchone()
    state = json.loads(row[0]) if row else None
    if not isinstance(state,dict) or state.get('version')!=VERSION or state.get('format')!='FSD_PAYLOAD_CENSUS':
        raise InputValidationError('Invalid payload census checkpoint state')
    try:
        if set(state['coverage'])!={'allocations','stored_elements','allocation_bytes','raw_bytes','values','allocations_complete'}:
            raise ValueError()
        if set(state['pin']['population'])!={'allocations','stored_elements','allocation_bytes','recorded_bindings',
                'retained_logical_bytes','retained_chunks'}:
            raise ValueError()
        counters = [state[k] for k in ('last_allocation_id','bindings_processed','batches',
            'primitive_elements_block_checked','values_individually_decoded',
            'matched_unconditional_bindings','matched_conditional_bindings','retained_bytes_swept',
            'retained_chunks_processed','unindexed_raw_bytes','unrecorded_views_checked')]
        counters += list(state['coverage'].values())+list(state['value_status_counts'].values())
        counters += list(state['pin']['population'].values())+list(state['slot_population'].values())
        if any(type(n) is not int or n<0 for n in counters):raise ValueError()
        if type(state['complete']) is not bool or state['phase'] not in ('ALLOCATIONS','RAW_UNINDEXED','BINDINGS','COMPLETE'):
            raise ValueError()
        if state['complete']!=(state['phase']=='COMPLETE'):raise ValueError()
        active=state['active'];cursor=state['binding_cursor']
        if active is not None and (state['phase']!='ALLOCATIONS' or set(active)!= {'id','raw_offset','next_element'}
                or any(type(n) is not int or n<0 for n in active.values()) or active['id']<=state['last_allocation_id']):
            raise ValueError()
        if cursor is not None and (not isinstance(cursor,list) or len(cursor)!=3 or
                any(type(n) is not int or n<0 for n in cursor)):raise ValueError()
        if (cursor is None)!=(state['bindings_processed']==0):raise ValueError()
        if state['phase'] in ('ALLOCATIONS','RAW_UNINDEXED') and state['bindings_processed']:raise ValueError()
        if state['phase']=='ALLOCATIONS' and (state['unindexed_raw_bytes'] or state['retained_bytes_swept'] or state['retained_chunks_processed']):
            raise ValueError()
        if state['phase']!='ALLOCATIONS' and (state['coverage']['allocations_complete']!=state['pin']['population']['allocations']
                or state['coverage']['values']!=state['pin']['population']['stored_elements']
                or state['coverage']['raw_bytes']!=state['pin']['population']['allocation_bytes']):raise ValueError()
        chunk=state['chunk_active'];key=state['last_chunk_key']
        if key is not None and (not isinstance(key,list) or len(key)!=3 or any(type(n) is not int or n<0 for n in key)):
            raise ValueError()
        if chunk is not None and (state['phase']!='RAW_UNINDEXED' or set(chunk)!= {'segment','cluster','logical_start','length','offset'}
                or any(type(n) is not int or n<0 for n in chunk.values())
                or not chunk['logical_start']<=chunk['offset']<=chunk['logical_start']+chunk['length']):raise ValueError()
        if state['phase'] in ('BINDINGS','COMPLETE') and (state['retained_bytes_swept']!=state['pin']['population']['retained_logical_bytes']
                or state['retained_chunks_processed']!=state['pin']['population']['retained_chunks']):raise ValueError()
    except (KeyError,TypeError,ValueError) as exc:
        raise InputValidationError('Invalid payload census coverage counters or cursor state') from exc
    return state


def _empty_state(pin):
    return dict(format='FSD_PAYLOAD_CENSUS',version=VERSION,pin=pin,phase='ALLOCATIONS',
        last_allocation_id=0,active=None,binding_cursor=None,bindings_processed=0,complete=False,batches=0,
        coverage=dict(allocations=0,stored_elements=0,allocation_bytes=0,raw_bytes=0,values=0,allocations_complete=0),
        value_status_counts={},slot_population=dict(unconditional=0,conditional=0,unknown_cardinality_elements=0),
        primitive_elements_block_checked=0,values_individually_decoded=0,
        matched_unconditional_bindings=0,matched_conditional_bindings=0,
        retained_bytes_swept=0,retained_chunks_processed=0,unindexed_raw_bytes=0,
        chunk_active=None,last_chunk_key=None,
        unrecorded_views_checked=0,
        policy='ALL_INDEXED_ALLOCATIONS; EXACT_INCOMING_ELEMENTS; MEMBERSHIP_AND_OWNERSHIP_SEPARATE')


def _validate(connection, state, *, deep=True):
    expected = state['pin']['population']
    rows,elements,size,raw_done,value_done,finished = connection.execute('''SELECT count(*),
        coalesce(sum(stored_elements),0),coalesce(sum(bytes),0),coalesce(sum(raw_done),0),
        coalesce(sum(value_done),0),coalesce(sum(complete),0) FROM allocations''').fetchone()
    observed = dict(allocations=rows,stored_elements=elements,allocation_bytes=size,
        raw_bytes=raw_done,values=value_done,allocations_complete=finished)
    if observed!=state['coverage'] or any(observed[k]>expected[k] for k in ('allocations','stored_elements','allocation_bytes')):
        raise InputValidationError('Payload allocation/counter coverage differs from committed rows')
    invalid=connection.execute('''SELECT count(*) FROM allocations WHERE raw_done<0 OR raw_done>bytes
        OR value_done<0 OR value_done>stored_elements OR bytes<0 OR stored_elements<0 OR complete NOT IN (0,1)
        OR complete=1 AND (raw_done!=bytes OR value_done!=stored_elements)''').fetchone()[0]
    unfinished=list(connection.execute('SELECT id,raw_done,value_done FROM allocations WHERE complete=0'))
    active=state['active']
    if invalid or unfinished!=([(active['id'],active['raw_offset'],active['next_element'])] if active else []):
        raise InputValidationError('Payload active allocation cursor differs from committed rows')
    last=connection.execute('SELECT coalesce(max(id),0) FROM allocations WHERE complete=1').fetchone()[0]
    if last!=state['last_allocation_id']:
        raise InputValidationError('Payload completed allocation cursor differs from ledger')
    for table,done,total in (('raw_ranges','raw_done','bytes'),('value_ranges','value_done','stored_elements')) if deep else ():
        invalid = connection.execute(f'''SELECT count(*) FROM {table} r LEFT JOIN allocations a ON a.id=r.allocation_id
          WHERE a.id IS NULL OR r.first<0 OR r.last<=r.first OR r.last>a.{total}''').fetchone()[0]
        gaps = connection.execute(f'''SELECT count(*) FROM (SELECT first,
          coalesce(lag(last) OVER(PARTITION BY allocation_id ORDER BY first),0) previous FROM {table}) WHERE first!=previous''').fetchone()[0]
        mismatch = connection.execute(f'''SELECT count(*) FROM allocations a WHERE a.{done}!=
          coalesce((SELECT max(last) FROM {table} r WHERE r.allocation_id=a.id),0)''').fetchone()[0]
        if invalid or gaps or mismatch:
            raise InputValidationError('Payload range overlap/gap/coverage differs from cursor')
    binding_count = connection.execute('SELECT coalesce(sum(count),0) FROM binding_ranges').fetchone()[0]
    if binding_count!=state['bindings_processed'] or binding_count>expected['recorded_bindings']:
        raise InputValidationError('Payload binding counts differ from committed source cursor')
    if connection.execute('SELECT count(*) FROM binding_ranges WHERE count<=0 OR last<=first').fetchone()[0]:
        raise InputValidationError('Invalid payload recorded binding range')
    matched=connection.execute('SELECT coalesce(sum(count*unconditional_matches),0),coalesce(sum(count*conditional_matches),0) FROM binding_ranges').fetchone()
    if tuple(matched)!=(state['matched_unconditional_bindings'],state['matched_conditional_bindings']):
        raise InputValidationError('Payload declaration match counters differ from retained bindings')
    statuses=dict(connection.execute('SELECT status,sum(last-first) FROM value_ranges GROUP BY status'))
    block_checked=statuses.get('NATIVE_PRIMITIVE_BLOCK_CHECKED',0)
    decoded=connection.execute('SELECT coalesce(sum(records_decoded),0) FROM value_ranges').fetchone()[0]
    if statuses!=state['value_status_counts'] or block_checked!=state['primitive_elements_block_checked'] or decoded!=state['values_individually_decoded']:
        raise InputValidationError('Payload interpretation counters differ from retained value ranges')
    if connection.execute('SELECT count(*) FROM value_ranges WHERE records_decoded<0 OR records_decoded>last-first').fetchone()[0]:
        raise InputValidationError('Invalid payload individual decode count')
    if connection.execute('SELECT coalesce(sum(bindings),0) FROM incoming_allocations').fetchone()[0]>binding_count:
        raise InputValidationError('Payload incoming allocation counts exceed recorded bindings')
    if connection.execute('SELECT coalesce(sum(bindings),0) FROM incoming_views').fetchone()[0]>binding_count:
        raise InputValidationError('Payload exact incoming view counts exceed recorded bindings')
    if connection.execute('SELECT coalesce(sum(last-first),0) FROM unrecorded_views').fetchone()[0]!=state['unrecorded_views_checked']:
        raise InputValidationError('Payload unrecorded source view counters differ from retained rows')
    if state['unrecorded_views_checked']>max(0,state['slot_population']['unconditional']-state['matched_unconditional_bindings']):
        raise InputValidationError('Payload inspected unrecorded views exceed source declaration population')
    if deep and connection.execute('''SELECT count(*) FROM unrecorded_views v LEFT JOIN allocations a ON a.id=v.allocation_id
        LEFT JOIN declarations d ON d.id=v.slot_id WHERE a.id IS NULL OR d.id IS NULL OR v.first<0
        OR v.last<=v.first OR v.last>a.value_done OR v.displacement<0 OR v.status NOT IN
        ('IMPLICIT_NULL_SOURCE_FIELD','MISSING_CAPTURED_BINDING','UNRECORDED_REFERENCE_NOT_PROVED_NULL')''').fetchone()[0]:
        raise InputValidationError('Invalid unrecorded source view selector')
    if deep and connection.execute('''SELECT count(*) FROM (SELECT first,max(last) OVER(
        PARTITION BY allocation_id,slot_id,displacement ORDER BY first ROWS BETWEEN UNBOUNDED PRECEDING
        AND 1 PRECEDING) previous FROM unrecorded_views) WHERE first<previous''').fetchone()[0]:
        raise InputValidationError('Overlapping unrecorded source field view ranges')
    unindexed=connection.execute('SELECT coalesce(sum(last-first),0) FROM unindexed_ranges').fetchone()[0]
    if unindexed!=state['unindexed_raw_bytes'] or state['retained_bytes_swept']>expected['retained_logical_bytes'] or unindexed>state['retained_bytes_swept']:
        raise InputValidationError('Payload unindexed retained byte counters differ from ranges')
    if deep and connection.execute('''SELECT count(*) FROM (SELECT first,last,
        max(last) OVER (PARTITION BY segment,cluster ORDER BY first ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) previous
        FROM unindexed_ranges) WHERE first<0 OR last<=first OR first<previous''').fetchone()[0]:
        raise InputValidationError('Overlapping or invalid unindexed retained logical byte ranges')
    if deep and connection.execute('''SELECT count(*) FROM incoming r LEFT JOIN allocations a ON a.id=r.allocation_id
        WHERE a.id IS NULL OR r.first<0 OR r.last<=r.first OR r.last>a.stored_elements''').fetchone()[0]:
        raise InputValidationError('Invalid exact incoming element interval')
    if deep and connection.execute('''SELECT count(*) FROM (SELECT first,lag(last) OVER(
        PARTITION BY allocation_id,status ORDER BY first) previous FROM incoming) WHERE first<previous''').fetchone()[0]:
        raise InputValidationError('Overlapping exact incoming element intervals')
    if deep and connection.execute('''SELECT count(*) FROM incoming_views v LEFT JOIN allocations a ON a.id=v.allocation_id
        WHERE a.id IS NULL OR v.first<0 OR v.last<=v.first OR v.last>a.stored_elements
        OR typeof(v.first)!='integer' OR typeof(v.last)!='integer'
        OR typeof(v.byte_displacement)!='integer' OR typeof(v.bindings)!='integer'
        OR v.byte_displacement<0 OR v.byte_displacement>=a.bytes OR v.bindings<v.last-v.first
        OR v.axis IS NULL OR v.view IS NULL OR v.status IS NULL
        OR v.status NOT IN ('SOURCE_DECLARED_FIELD_TARGET','POINTEE_TYPE_MISMATCH','POINTEE_TYPE_UNESTABLISHED')
        OR NOT ((v.axis='ELEMENT' AND ((v.view='EXACT_ELEMENT_START' AND v.byte_displacement=0)
          OR (v.view='EXACT_DECLARED_BASE_SUBOBJECT' AND v.byte_displacement>0)))
          OR (v.axis='INLINE_CHARACTER_BYTE' AND v.view='EXACT_INLINE_CHARACTER_BYTE' AND v.byte_displacement=0))''').fetchone()[0]:
        raise InputValidationError('Invalid exact incoming base or byte view')
    if deep and connection.execute('''SELECT count(*) FROM (SELECT first,max(last) OVER(
        PARTITION BY allocation_id,axis,byte_displacement,view,status ORDER BY first
        ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) previous FROM incoming_views)
        WHERE first<previous''').fetchone()[0]:
        raise InputValidationError('Overlapping exact incoming target view intervals')
    if deep and connection.execute('''SELECT count(*) FROM (SELECT allocation_id,status,sum(bindings) bindings
        FROM incoming_views GROUP BY allocation_id,status) v LEFT JOIN incoming_allocations a
        ON a.allocation_id=v.allocation_id AND a.status=v.status
        WHERE a.allocation_id IS NULL OR typeof(a.bindings)!='integer' OR v.bindings>a.bindings''').fetchone()[0]:
        raise InputValidationError('Payload exact incoming view counts differ from incoming allocation evidence')
    if deep:
        # Each PRM binding produces at most one exact view. Coalescing retains
        # its aggregate binding count separately from distinct addressed views.
        views='SELECT view,status,sum(bindings) FROM incoming_views GROUP BY view,status'
        bindings="""SELECT target_status,status,sum(count) FROM binding_ranges WHERE target_status IN
            ('EXACT_ELEMENT_START','EXACT_DECLARED_BASE_SUBOBJECT','EXACT_INLINE_CHARACTER_BYTE')
            GROUP BY target_status,status"""
        if any(connection.execute('SELECT count(*) FROM ('+left+' EXCEPT '+right+')').fetchone()[0]
                for left,right in ((views,bindings),(bindings,views))):
            raise InputValidationError('Payload exact incoming view counts differ from recorded target views')
        if connection.execute('''SELECT count(*) FROM incoming_views v WHERE NOT EXISTS(
            SELECT 1 FROM incoming r WHERE r.allocation_id=v.allocation_id AND r.status=v.status
            AND r.first<=CASE WHEN v.axis='ELEMENT' THEN v.first ELSE 0 END
            AND r.last>=CASE WHEN v.axis='ELEMENT' THEN v.last ELSE 1 END)''').fetchone()[0]:
            raise InputValidationError('Payload exact incoming views lack containing element evidence')
    if state['complete'] and (observed!=dict(allocations=expected['allocations'],stored_elements=expected['stored_elements'],
            allocation_bytes=expected['allocation_bytes'],raw_bytes=expected['allocation_bytes'],
            values=expected['stored_elements'],allocations_complete=expected['allocations'])
            or binding_count!=expected['recorded_bindings']):
        raise InputValidationError('Payload COMPLETE conflicts with remaining source population')
    if state['complete'] and raw_done+unindexed!=expected['retained_logical_bytes']:
        raise InputValidationError('Payload retained logical byte coverage has gaps or duplicated views')
    if state['complete'] and state.get('verification',{}).get('scope')!='SQLITE_QUICK_AND_FOREIGN_KEYS; ACCESSED_BLOBS_HASH_CHECKED':
        raise InputValidationError('Payload COMPLETE lacks required terminal verification')


def _file_token(path):
    s=path.stat()
    return s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns


def _summary(connection,state,path,*,capacity=None,status=None):
    result = dict(state)
    result['status'] = status or ('COMPLETE' if state['complete'] else 'PENDING')
    result['remaining'] = dict(allocations=state['pin']['population']['allocations']-state['coverage']['allocations_complete'],
        stored_elements=state['pin']['population']['stored_elements']-state['coverage']['values'],
        allocation_bytes=state['pin']['population']['allocation_bytes']-state['coverage']['raw_bytes'],
        recorded_bindings=state['pin']['population']['recorded_bindings']-state['bindings_processed'])
    logical=state['pin']['population']['retained_logical_bytes']
    result['retained_logical_coverage']=dict(retained_logical_bytes=logical,
        indexed_allocation_bytes=state['pin']['population']['allocation_bytes'],
        indexed_allocation_bytes_verified=state['coverage']['raw_bytes'],
        unindexed_retained_bytes_verified=state['unindexed_raw_bytes'],
        unique_retained_bytes_verified=state['coverage']['raw_bytes']+state['unindexed_raw_bytes'],
        remaining_retained_bytes=logical-state['coverage']['raw_bytes']-state['unindexed_raw_bytes'],
        retained_chunk_sweep_bytes=state['retained_bytes_swept'],
        status='COMPLETE_RETAINED_LOGICAL_SCOPE' if state['complete'] else 'PENDING_RETAINED_LOGICAL_SCOPE',
        unindexed_status='RAW_UNINDEXED; NO_MISSING_OBJECT_INFERENCE',physical_or_deallocated_history=False)
    result['remaining']['retained_logical_bytes']=result['retained_logical_coverage']['remaining_retained_bytes']
    result['remaining']['retained_sweep_bytes']=logical-state['retained_bytes_swept']
    result['incoming'] = dict(allocations_with_exact_source_declared_incoming=connection.execute(
        "SELECT count(DISTINCT allocation_id) FROM incoming WHERE status='SOURCE_DECLARED_FIELD_TARGET'").fetchone()[0],
        exact_addressed_elements=connection.execute("SELECT coalesce(sum(last-first),0) FROM incoming WHERE status='SOURCE_DECLARED_FIELD_TARGET'").fetchone()[0],
        incoming_element_intervals=connection.execute('SELECT count(*) FROM incoming').fetchone()[0],
        exact_target_view_counts=dict(connection.execute('SELECT view,sum(bindings) FROM incoming_views GROUP BY view')),
        exact_distinct_target_views=connection.execute('SELECT coalesce(sum(last-first),0) FROM incoming_views').fetchone()[0],
        compact_target_view_intervals=connection.execute('SELECT count(*) FROM incoming_views').fetchone()[0],
        allocations_with_any_recorded_incoming=connection.execute('SELECT count(DISTINCT allocation_id) FROM incoming_allocations').fetchone()[0],
        allocations_without_recorded_incoming=state['coverage']['allocations']-connection.execute('SELECT count(DISTINCT allocation_id) FROM incoming_allocations').fetchone()[0],
        incoming_allocation_binding_counts=dict(connection.execute('SELECT status,sum(bindings) FROM incoming_allocations GROUP BY status')),
        binding_status_counts=dict(connection.execute('SELECT status,sum(count) FROM binding_ranges GROUP BY status')),
        recorded_target_status_counts=dict(connection.execute('SELECT target_status,sum(count) FROM binding_ranges GROUP BY target_status')),
        first_element_reference_establishes_allocation_remainder=False,ownership='UNKNOWN')
    result['disk'] = dict(bytes=Path(path).stat().st_size,page_bytes=connection.execute('PRAGMA page_size').fetchone()[0],
        pages=connection.execute('PRAGMA page_count').fetchone()[0],capacity_bytes=capacity,
        rows={t:connection.execute(f'SELECT count(*) FROM {t}').fetchone()[0] for t in sorted(_KINDS)})
    result.update(original_fsd_required=False,portable_store_required_for_value_pages=True,
        application_semantics_complete=False,raw_logical_coverage_is_semantic_coverage=False)
    result['source_slots']=dict(state['slot_population'],
        matched_unconditional_recorded_bindings=state.get('matched_unconditional_bindings',0),
        matched_conditional_recorded_bindings=state.get('matched_conditional_bindings',0),
        unrecorded_unconditional_slots=max(0,state['slot_population']['unconditional']-state.get('matched_unconditional_bindings',0)),
        unrecorded_slot_status='SOURCE_DECLARATION_WITHOUT_CAPTURED_PRM; UNINSPECTED_NOT_INFERRED_NULL',
        individually_inspected_unrecorded_views=state['unrecorded_views_checked'],
        inspected_unrecorded_status_counts=dict(connection.execute('SELECT status,sum(last-first) FROM unrecorded_views GROUP BY status')),
        conditional_slot_cardinality='DECLARATION_VIEWS; ACTIVE_MEMBER_UNKNOWN')
    result['source_plan_type_status_counts']=dict(connection.execute('SELECT status,count(*) FROM plans GROUP BY status'))
    return result


def _validate_source(connection,state,source,plans,*,db):
    """Fresh indexed source admission: exact allocation identities and PRM order."""
    connection.execute('ATTACH DATABASE ? AS payload_source',(source.as_uri()+'?mode=ro',))
    try:
        end=state['active']['id'] if state['active'] else state['last_allocation_id']
        for left,right in (('SELECT id,stored_elements,bytes FROM main.allocations',
                'SELECT id,element_count,size FROM payload_source.allocations WHERE id<=?'),
                ('SELECT id,element_count,size FROM payload_source.allocations WHERE id<=?',
                'SELECT id,stored_elements,bytes FROM main.allocations')):
            if connection.execute('SELECT count(*) FROM ('+left+' EXCEPT '+right+')',(end,)).fetchone()[0]:
                raise InputValidationError('Payload allocation ledger differs from exact source prefix')
        slots=dict(unconditional=0,conditional=0,unknown_cardinality_elements=0)
        for name,tag,metadata,count in connection.execute('''SELECT n.name,a.native_tag,
                CASE WHEN length(CAST(t.metadata AS BLOB))<=? THEN t.metadata END,sum(a.element_count)
                FROM payload_source.allocations a JOIN payload_source.names n ON n.id=a.name_id
                JOIN payload_source.allocation_templates t ON t.id=a.template_id
                WHERE a.id<=? GROUP BY a.name_id,a.native_tag,a.template_id''',(MAX_BLOB_BYTES,end)):
            template=decode_json(metadata) if metadata is not None else {}
            admission=db.fields.schema_admission(dict(template,native_tag=tag,name=name))
            if metadata is None:admission['admitted']=False
            plan=plans[name] if admission['admitted'] else dict(counts={},error=
                'SOURCE_CLASS_ADMISSION_UNESTABLISHED' if admission['schema_name'] is not None else None)
            for key in ('unconditional','conditional'):slots[key]+=plan['counts'].get(key,0)*count
            if plan['error']:slots['unknown_cardinality_elements']+=count
        if slots!=state['slot_population']:
            raise InputValidationError('Payload source declaration population differs from source prefix')
        # Only allocation metadata is read here; exact-view counts/labels above
        # remain structural evidence, not a replay of target/schema semantics.
        for aid,axis,last,displacement in connection.execute('''SELECT allocation_id,axis,max(last),
                byte_displacement FROM incoming_views GROUP BY allocation_id,axis,byte_displacement'''):
            allocation=_allocation(db,aid)
            if axis=='INLINE_CHARACTER_BYTE':
                invalid=allocation['name']!='inline_char_bytes' or last>allocation.get('count',0)
            else:
                size=allocation.get('element_size',allocation['size'])
                stride=allocation.get('element_stride',size)
                header=allocation.get('array_header_size',0)
                invalid=(type(size) is not int or type(stride) is not int or type(header) is not int
                    or size<=0 or stride<=0 or header<0 or displacement>=min(size,stride)
                    or header+(last-1)*stride+displacement>=allocation['size'])
            if invalid:
                raise InputValidationError('Payload exact incoming view exceeds source element or byte bounds')
        active=state['chunk_active'];key=state['last_chunk_key'] or [-1,-1,-1]
        chunks,bytes_swept=connection.execute('''SELECT count(*),coalesce(sum(length),0) FROM payload_source.chunks
            WHERE (segment,cluster,logical_start)<= (?,?,?)''',tuple(key)).fetchone()
        if active:
            row=connection.execute('''SELECT length FROM payload_source.chunks WHERE
                segment=? AND cluster=? AND logical_start=?''',(active['segment'],active['cluster'],active['logical_start'])).fetchone()
            if row is None or row[0]!=active['length']:
                raise InputValidationError('Payload retained chunk cursor differs from source')
            expected_next=connection.execute('''SELECT segment,cluster,logical_start FROM payload_source.chunks
                WHERE (segment,cluster,logical_start)>(?,?,?) ORDER BY segment,cluster,logical_start LIMIT 1''',tuple(key)).fetchone()
            if tuple(expected_next or ())!=(active['segment'],active['cluster'],active['logical_start']):
                raise InputValidationError('Payload retained chunk cursor skipped source regions')
            bytes_swept+=active['offset']-active['logical_start']
        if chunks!=state['retained_chunks_processed'] or bytes_swept!=state['retained_bytes_swept']:
            raise InputValidationError('Payload retained chunk prefix differs from committed counters')
        if connection.execute('''SELECT count(*) FROM unindexed_ranges r LEFT JOIN payload_source.chunks c
                ON (r.segment,r.cluster,r.chunk_start)=(c.segment,c.cluster,c.logical_start)
                WHERE c.logical_start IS NULL OR r.chunk_length!=c.length OR r.first<c.logical_start OR r.last>c.logical_start+c.length
                OR EXISTS(SELECT 1 FROM payload_source.allocations a WHERE a.segment=r.segment
                    AND a.cluster=r.cluster AND a.logical_offset<r.last AND a.logical_offset+a.size>r.first)''').fetchone()[0]:
            raise InputValidationError('Payload unindexed byte selector overlaps indexed allocation or leaves retained chunk')
        maximum=[active[k] for k in ('segment','cluster','logical_start')] if active else key
        if connection.execute('''SELECT count(*) FROM unindexed_ranges WHERE (segment,cluster,chunk_start)>(?,?,?)
            OR ((segment,cluster,chunk_start)=(?,?,?) AND last>?)''',(*maximum,*maximum,
                active['offset'] if active else 9223372036854775807)).fetchone()[0]:
            raise InputValidationError('Payload unindexed evidence exceeds its retained chunk cursor')
        cursor=state['binding_cursor']
        actual=connection.execute('SELECT count(*) FROM payload_source.pointers WHERE '
            '(segment,cluster,logical_offset)<= (?,?,?)',tuple(cursor or (-1,-1,-1))).fetchone()[0]
        if actual!=state['bindings_processed']:
            raise InputValidationError('Payload binding cursor is not its complete source prefix')
        previous=None
        for row in connection.execute('''SELECT count,prm_first_segment,prm_first_cluster,prm_first_offset,
                prm_last_segment,prm_last_cluster,prm_last_offset FROM binding_ranges ORDER BY id'''):
            count=row[0];first=list(row[1:4]);last=list(row[4:7])
            if (len(first)!=3 or len(last)!=3 or any(type(n) is not int or n<0 for n in first+last)
                    or first>last or previous is not None and first<=previous):
                raise InputValidationError('Payload PRM range selector is invalid or overlapping')
            rows=connection.execute('''SELECT count(*) FROM payload_source.pointers WHERE
                (segment,cluster,logical_offset)>= (?,?,?) AND (segment,cluster,logical_offset)<= (?,?,?)''',
                (*first,*last)).fetchone()[0]
            if rows!=count:
                raise InputValidationError('Payload PRM range selector differs from source rows')
            previous=last
        if previous!=cursor:
            raise InputValidationError('Payload last PRM range differs from binding cursor')
    finally:
        connection.execute('DETACH DATABASE payload_source')


def discover_payload_census_batch(session: DiscoverySession, *, checkpoint: str | Path,
        max_allocations: int=1000,max_values: int=10000,max_bindings: int=10000,
        block_bytes: int=1048576,max_record_bytes: int=65536,max_leaves: int=4096,
        max_checkpoint_bytes: int=268435456,max_raw_bytes: int=4194304,progress=None) -> dict:
    """Commit one bounded range/binding batch; resume retains its exact prefix.

    Batch admission and disk capacity may increase on resume. Interpretation
    limits are pinned. A capacity failure rolls back the current batch and
    reports RESOURCE_BOUND with the prior trusted cursor and remaining work.
    max_values bounds primitive checking/individual decode admissions. A whole
    unsupported range may be classified arithmetically without interpreting
    every member; values_accounted is therefore a separate work counter.
    """
    with session_operation(session):
        for key,value,ceiling in (('max_allocations',max_allocations,100000),('max_values',max_values,1000000),
                ('max_bindings',max_bindings,1000000),('block_bytes',block_bytes,16777216),
                ('max_record_bytes',max_record_bytes,16777216),('max_leaves',max_leaves,100000),
                ('max_raw_bytes',max_raw_bytes,1073741824),
                ('max_checkpoint_bytes',max_checkpoint_bytes,1099511627776)):
            _limit(value,key,ceiling)
        db = session.db
        source = Path(db.path).resolve()
        path = _checkpoint_path(checkpoint,source,db.source_info.get('path'))
        path.parent.mkdir(parents=True,exist_ok=True)
        session.check_identity()
        execution_pin=runtime_identity()
        population = getattr(session,'_payload_census_population',None)
        if population is None:
            population=_population(db);session._payload_census_population=population
        plans=getattr(session,'_payload_census_plans',None)
        if plans is None:
            plans=_plans(session);session._payload_census_plans=plans
        store_pin = getattr(session,'_payload_census_store_pin',None)
        if store_pin is None:
            store_pin = dict(sha256=_store_digest(source),bytes=source.stat().st_size)
            session.check_identity()
            session._payload_census_store_pin = store_pin
        pin = dict(source=dict(db.source_info),store_path=str(source),store=store_pin,population=population,
            runtime_identity=execution_pin,config=dict(block_bytes=block_bytes,max_record_bytes=max_record_bytes,max_leaves=max_leaves),
            declarations_sha256=hashlib.sha256(_json(plans).encode()).hexdigest())
        fd = os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        connection = None
        try:
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InputValidationError('Payload census checkpoint is in use') from exc
            if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(path.stat().st_dev,path.stat().st_ino):
                raise InputValidationError('Payload checkpoint inode changed before locking')
            connection = sqlite3.connect(path,uri=True)
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('PRAGMA temp_store=FILE')
            page_size = connection.execute('PRAGMA page_size').fetchone()[0]
            connection.execute('PRAGMA max_page_count='+str(max(1,max_checkpoint_bytes//page_size)))

            def guard():
                session.check_identity()
                if dict(db.source_info)!=pin['source']:
                    raise InputValidationError('Payload source population changed before commit')
                if runtime_identity()!=pin['runtime_identity']:
                    raise InputValidationError('Payload runtime changed before commit')

            def commit():
                connection.execute("INSERT OR REPLACE INTO metadata VALUES('state',?)",(_json(state),))
                guard()
                connection.commit()

            empty = not connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone()
            if empty:
                guard()
                connection.execute('BEGIN')
                for statement in _SCHEMA.split(';'):
                    if statement.strip():
                        connection.execute(statement)
                for name,plan in plans.items():
                    connection.execute('INSERT INTO plans(type,status,unconditional,conditional,error) VALUES(?,?,?,?,?)',
                        (name,plan['status'],plan['counts'].get('unconditional',0),plan['counts'].get('conditional',0),plan['error']))
                    for slot in plan['slots']:
                        connection.execute('INSERT INTO declarations(type,path,evidence) VALUES(?,?,?)',(name,slot['path'],_json(slot)))
                state = _empty_state(pin)
                commit()
            else:
                state = _state(connection)
                if state['pin']!=pin:
                    raise InputValidationError('Payload source, store, runtime or interpretation configuration pin mismatch')
            token=getattr(session,'_payload_census_checkpoint_tokens',{}).get(str(path))
            fresh=token!=_file_token(path) or state['complete']
            _validate(connection,state,deep=fresh)
            if fresh:_validate_source(connection,state,source,plans,db=db)
            if state['complete']:
                guard()
                return _summary(connection,state,path,capacity=max_checkpoint_bytes)
            if path.stat().st_size>max_checkpoint_bytes:
                guard()
                return _summary(connection,state,path,capacity=max_checkpoint_bytes,status='RESOURCE_BOUND')
            connection.execute('BEGIN')
            work_allocations = work_values = work_bindings = work_raw_bytes = 0
            work_regions=0
            before_decoded=state['values_individually_decoded'];before_blocks=state['primitive_elements_block_checked']
            while state['phase']=='ALLOCATIONS' and work_allocations<max_allocations and work_values<max_values:
                if state['active'] is None:
                    row = db.store.connection.execute('SELECT id FROM allocations WHERE id>? ORDER BY id LIMIT 1',
                        (state['last_allocation_id'],)).fetchone()
                    if row is None:
                        state['phase']='RAW_UNINDEXED'
                        break
                    aid = row[0]
                    a = _allocation(db,aid)
                    count = a.get('count',1)
                    connection.execute('INSERT INTO allocations VALUES(?,0,0,?,?,0)',(aid,count,a['size']))
                    state['active']=dict(id=aid,raw_offset=0,next_element=0)
                    for key,value in (('allocations',1),('stored_elements',count),('allocation_bytes',a['size'])):
                        state['coverage'][key]+=value
                    plan = _allocation_plan(plans,a,db.fields)
                    for key in ('unconditional','conditional'):
                        state['slot_population'][key]+=plan['counts'].get(key,0)*count
                    if plan['error']:
                        state['slot_population']['unknown_cardinality_elements']+=count
                active = state['active']
                aid=active['id']; a=_allocation(db,aid)
                # Raw byte work is bounded independently of value admission.
                if active['raw_offset']<a['size']:
                    if work_raw_bytes==max_raw_bytes:break
                    first=active['raw_offset']; take=min(block_bytes,a['size']-first,max_raw_bytes-work_raw_bytes)
                    raw=db.read_at(a['segment'],a['cluster'],a['logical_offset']+first,take)
                    if len(raw)!=take:
                        raise InputValidationError('Short payload raw allocation block')
                    _range(connection,'raw_ranges',aid,first,first+take,'RAW_LOGICAL_BYTES_VERIFIED',
                        dict(selector='IMMUTABLE_SOURCE_ALLOCATION_BYTE_RANGE',semantics='UNESTABLISHED'))
                    active['raw_offset']+=take; state['coverage']['raw_bytes']+=take
                    work_raw_bytes+=take
                    connection.execute('UPDATE allocations SET raw_done=? WHERE id=?',(active['raw_offset'],aid))
                    # A large allocation cannot consume an unbounded batch of reads.
                    if active['raw_offset']<a['size']:
                        continue
                count=a.get('count',1)
                if active['next_element']<count:
                    first=active['next_element']; take=1
                    typ=db.fields.types.get(a['native_tag'],{})
                    ieee=a.get('vector') and a['native_tag'] in (5,6,19,21) and a.get('element_stride')==typ.get('size') and a.get('element_size')==typ.get('size')
                    primitive=_primitive_fast(db,a) or ieee
                    if primitive:
                        take=min(count-first,max(1,block_bytes//a['element_stride']),max(1,max_values-work_values))
                        raw=db.read_at(a['segment'],a['cluster'],a['logical_offset']+a.get('array_header_size',0)+first*a['element_stride'],take*a['element_stride'])
                        if len(raw)!=take*a['element_stride']:
                            raise InputValidationError('Short native primitive payload block')
                        status='NATIVE_PRIMITIVE_BLOCK_CHECKED'
                        detail=dict(typed_values_individually_inspected=False,native_tag=a['native_tag'],
                            per_field_raw_bits='AVAILABLE_IN_BOUNDED_IMMUTABLE_VALUE_PAGES')
                        state['primitive_elements_block_checked']+=take
                    else:
                        inline=a['name']=='inline_char_bytes'
                        if inline:
                            take=count-first
                        size=a['size'] if inline or not a.get('vector') else a['element_size']
                        if not typ:
                            status='UNKNOWN_NATIVE_TYPE';detail=dict(raw_retained=True)
                            take=count-first
                        elif size>max_record_bytes:
                            status='VALUE_DECODE_RESOURCE_BOUND';detail=dict(raw_retained=True,
                                limit_kind='RECORD_BYTES',record_bytes=size,max_record_bytes=max_record_bytes,max_leaves=max_leaves)
                            take=count-first
                        else:
                            admission = expansion_admission(db,a,max_leaves,context=dict(phase='payload_admission',
                                name=a['name'],native_tag=a['native_tag'],element_index=first,
                                segment=a['segment'],cluster=a['cluster'],logical_offset=a['logical_offset']))
                            if admission is not None:
                                state_kind = admission.pop('status')
                                status = 'VALUE_DECODE_ADMISSION_UNESTABLISHED' if state_kind=='UNESTABLISHED' else 'VALUE_DECODE_RESOURCE_BOUND'
                                detail=dict(admission,raw_retained=True)
                                if state_kind=='BOUND':detail['limit_kind']='EXPANSION'
                                take=count-first
                            else:
                                try:
                                    value=db.fields.decode(a,0 if inline else first,max_record_bytes=max_record_bytes)
                                    status=value['status'];detail=interpretation_facets(value)
                                    detail['decoded_record_units']='ONE_INLINE_CHARACTER_BLOCK' if inline else 'ONE_NATIVE_ELEMENT'
                                    selected_plan = _allocation_plan(plans,a,db.fields)
                                    if selected_plan['slots']:
                                        state['unrecorded_views_checked']+=_unrecorded_fields(session,connection,a,first,value,selected_plan['slots'])
                                    state['values_individually_decoded']+=1
                                except Exception as exc:
                                    require_source_failure(exc,dict(phase='payload_value',name=a['name'],element_index=first))
                                    status='VALUE_DECODE_UNRESOLVED';detail=dict(error_type=type(exc).__name__,error=str(exc),raw_retained=True)
                    _range(connection,'value_ranges',aid,first,first+take,status,detail)
                    state['value_status_counts'][status]=state['value_status_counts'].get(status,0)+take
                    active['next_element']+=take;state['coverage']['values']+=take;work_values+=take
                    connection.execute('UPDATE allocations SET value_done=? WHERE id=?',(active['next_element'],aid))
                if active['next_element']==count:
                    connection.execute('UPDATE allocations SET complete=1 WHERE id=?',(aid,))
                    state['coverage']['allocations_complete']+=1;state['last_allocation_id']=aid;state['active']=None
                    work_allocations+=1
            while state['phase']=='RAW_UNINDEXED' and work_regions<max_allocations:
                if state['chunk_active'] is None:
                    key=state['last_chunk_key'] or [-1,-1,-1]
                    row=db.store.connection.execute('''SELECT segment,cluster,logical_start,length FROM chunks
                        WHERE (segment,cluster,logical_start)>(?,?,?) ORDER BY segment,cluster,logical_start LIMIT 1''',tuple(key)).fetchone()
                    if row is None:
                        if state['coverage']['raw_bytes']+state['unindexed_raw_bytes']!=population['retained_logical_bytes']:
                            raise InputValidationError('Indexed/unindexed retained logical coverage leaves a gap')
                        state['phase']='BINDINGS'
                        break
                    state['chunk_active']=dict(segment=row[0],cluster=row[1],logical_start=row[2],length=row[3],offset=row[2])
                chunk=state['chunk_active'];position=chunk['offset'];end=chunk['logical_start']+chunk['length']
                allocation=db.allocation(chunk['segment'],chunk['cluster'],position)
                if allocation:
                    stop=min(end,allocation['logical_offset']+allocation['size'])
                else:
                    if work_raw_bytes==max_raw_bytes:break
                    next_allocation=db.store.connection.execute('''SELECT logical_offset FROM allocations
                        WHERE segment=? AND cluster=? AND logical_offset>? ORDER BY logical_offset LIMIT 1''',
                        (chunk['segment'],chunk['cluster'],position)).fetchone()
                    stop=min(end,next_allocation[0] if next_allocation else end,
                        position+block_bytes,position+max_raw_bytes-work_raw_bytes)
                    raw=db.read_at(chunk['segment'],chunk['cluster'],position,stop-position)
                    if len(raw)!=stop-position:raise InputValidationError('Short retained unindexed raw block')
                    old=connection.execute('''SELECT id,last FROM unindexed_ranges WHERE segment=? AND cluster=?
                        AND chunk_start=? ORDER BY first DESC LIMIT 1''',
                        (chunk['segment'],chunk['cluster'],chunk['logical_start'])).fetchone()
                    if old and old[1]==position:
                        connection.execute('UPDATE unindexed_ranges SET last=? WHERE id=?',(stop,old[0]))
                    else:
                        connection.execute('INSERT INTO unindexed_ranges(segment,cluster,chunk_start,chunk_length,first,last,status) VALUES(?,?,?,?,?,?,?)',
                            (chunk['segment'],chunk['cluster'],chunk['logical_start'],chunk['length'],position,stop,'RAW_UNINDEXED'))
                    state['unindexed_raw_bytes']+=stop-position;work_raw_bytes+=stop-position
                if stop<=position:raise InputValidationError('Retained logical sweep made no progress')
                chunk['offset']=stop;state['retained_bytes_swept']+=stop-position;work_regions+=1
                if stop==end:
                    state['last_chunk_key']=[chunk['segment'],chunk['cluster'],chunk['logical_start']]
                    state['retained_chunks_processed']+=1;state['chunk_active']=None
            if state['phase']=='BINDINGS':
                cursor=state['binding_cursor'] or [-1,-1,-1]
                rows=db.store.connection.execute('''SELECT segment,cluster,logical_offset,width,raw,status,
                    target_segment,target_cluster,target_offset,CASE WHEN status='UNRESOLVED' THEN metadata END FROM pointers
                    WHERE (segment,cluster,logical_offset)>(?,?,?) ORDER BY segment,cluster,logical_offset LIMIT ?''',
                    (*cursor,max_bindings))
                for segment,cluster,offset,width,raw,binding,ts,tc,to,metadata in rows:
                    source_a=db.allocation(segment,cluster,offset)
                    source_id=source_a['store_allocation_id'] if source_a else None
                    source_index=0;slot_id=None;target_a=None;view=None;declaration=None;matches=[]
                    source_bound=None
                    if source_a:
                        relative=offset-source_a['logical_offset']-source_a.get('array_header_size',0)
                        stride=source_a.get('element_stride',source_a['size'])
                        source_index,displacement=divmod(relative,stride) if stride>0 and relative>=0 else (-1,-1)
                        slots=_allocation_plan(plans,source_a,db.fields)['slots']
                        matches=_member_views(slots,displacement) if 0<=source_index<source_a.get('count',1) else []
                        candidates=[s for s in slots if any(v['path']==s['path'] for v in matches)]
                        if offset+width>source_a['logical_offset']+source_a['size']:
                            source_bound='SOURCE_SLOT_CROSSES_ALLOCATION'
                        elif source_index>=0 and displacement+width>source_a.get('element_size',source_a['size']):
                            source_bound='SOURCE_SLOT_CROSSES_ELEMENT'
                        elif db.read_at(segment,cluster,offset,width)!=raw:
                            source_bound='SOURCE_SLOT_RAW_MISMATCH'
                    else:
                        candidates=[]
                    unconditional=[s for s in candidates if not s['conditional_union']]
                    conditional=sum(s['conditional_union'] for s in candidates)
                    state['matched_unconditional_bindings']+=len(unconditional)
                    state['matched_conditional_bindings']+=conditional
                    if len(unconditional)==1:
                        slot=unconditional[0]
                        slot_id=connection.execute('SELECT id FROM declarations WHERE type=? AND path=?',(source_a['name'],slot['path'])).fetchone()[0]
                        declaration=_declared_pointee(session,dict(size=width,pointee_type=slot['pointee_type']),slot)
                        if source_bound:status=source_bound
                        elif width!=slot.get('size'):status='SOURCE_SLOT_WIDTH_MISMATCH'
                        elif binding=='NULL':status='NULL_SOURCE_FIELD'
                        elif binding!='RESOLVED':status='UNRESOLVED_SOURCE_FIELD'
                        else:
                            target_a,view=_location(db,dict(database=db.database_id,segment=ts,cluster=tc,offset=to),declaration)
                            status=view['status'] if 'canonical_address' not in view else _compatible(db,target_a,declaration,view)
                            if status not in ('POINTEE_TYPE_MISMATCH','POINTEE_TYPE_UNESTABLISHED') and 'canonical_address' in view:
                                status='SOURCE_DECLARED_FIELD_TARGET'
                    elif candidates:
                        status=source_bound or 'CONDITIONAL_OR_AMBIGUOUS_SOURCE_SLOT'
                    else:
                        status=source_bound or 'RECORDED_BINDING_WITHOUT_SOURCE_DECLARATION'
                    if binding=='RESOLVED' and target_a is None:
                        target_a=db.allocation(ts,tc,to)
                    if target_a is not None:
                        connection.execute('''INSERT INTO incoming_allocations(allocation_id,status,bindings) VALUES(?,?,1)
                            ON CONFLICT(allocation_id,status) DO UPDATE SET bindings=bindings+1''',
                            (target_a['store_allocation_id'],status))
                    target_status=(view or {}).get('status','CURRENT_ALLOCATION_PRESENT_UNPROVED_VIEW' if target_a
                        else 'NO_CURRENT_TARGET_ALLOCATION' if binding=='RESOLVED' else 'NULL' if binding=='NULL'
                        else 'UNRESOLVED_CONTEXT_NOT_RETAINED')
                    if metadata:
                        retained=decode_json(metadata)
                        target=retained.get('target') if isinstance(retained,Mapping) else None
                        context=target.get('database_context') if isinstance(target,Mapping) else None
                        if context is not None:
                            target_status='UNRESOLVED_CURRENT_SOURCE_CONTEXT' if context=={'source_database':True} else 'FOREIGN_OR_UNESTABLISHED_DATABASE_CONTEXT'
                    detail=dict(binding_status=binding,conditional_views=conditional,
                        unconditional_views=len(unconditional),ownership='UNKNOWN',
                        source_declaration_views=matches,recorded_target_status=target_status,
                        target_allocation_remainder='INSPECTION_CANDIDATE_ONLY; FIELD_LENGTH_UNKNOWN')
                    detail['captured_pointer_metadata']='RETAINED_IN_IMMUTABLE_SOURCE_PRM_SELECTOR'
                    detail['foreign_target_scope']='EXTERNAL_DATABASE_TARGETS_RETAINED_AS_UNRESOLVED_BY_STORE_CONTRACT'
                    if target_a and view and 'canonical_address' in view:
                        target_index=view['element_index']
                        # The scalar interval is the containing element; exact base
                        # displacement and inline character bytes remain separate views.
                        _incoming(connection,target_a['store_allocation_id'],target_index,status)
                        displacement=to-view['canonical_address']['offset']
                        _incoming_view(connection,target_a['store_allocation_id'],target_index,displacement,view['status'],status)
                    # Only adjacent PRM source-order rows may coalesce. Interleaved
                    # fields cannot be represented by a fictitious min/max selector.
                    old=connection.execute('SELECT id,source_id,slot_id,last,status,detail FROM binding_ranges ORDER BY id DESC LIMIT 1').fetchone()
                    encoded=_json(detail)
                    if source_id is not None and old and old[1:]==(source_id,slot_id,source_index,status,encoded):
                        connection.execute('''UPDATE binding_ranges SET last=?,count=count+1,
                            prm_last_segment=?,prm_last_cluster=?,prm_last_offset=? WHERE id=?''',
                            (source_index+1,segment,cluster,offset,old[0]))
                    else:
                        connection.execute('''INSERT INTO binding_ranges(source_id,slot_id,first,last,status,count,detail,
                            prm_first_segment,prm_first_cluster,prm_first_offset,prm_last_segment,prm_last_cluster,prm_last_offset,
                            unconditional_matches,conditional_matches,target_status) VALUES(?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)''',
                            (source_id,slot_id,source_index,source_index+1,status,encoded,
                            segment,cluster,offset,segment,cluster,offset,len(unconditional),conditional,target_status))
                    state['binding_cursor']=[segment,cluster,offset];state['bindings_processed']+=1;work_bindings+=1
                if work_bindings<max_bindings:
                    db.verify_source()
                    state['verification']=dict(scope='SQLITE_QUICK_AND_FOREIGN_KEYS; ACCESSED_BLOBS_HASH_CHECKED',original_fsd_opened=False,full_store_verification=False)
                    state['complete']=True;state['phase']='COMPLETE'
            state['batches']+=1
            _validate(connection,state,deep=state['complete'])
            commit()
            tokens=getattr(session,'_payload_census_checkpoint_tokens',{})
            tokens[str(path)]=_file_token(path);session._payload_census_checkpoint_tokens=tokens
            result=_summary(connection,state,path,capacity=max_checkpoint_bytes)
            result['batch_work']=dict(allocations_completed=work_allocations,values_accounted=work_values,
                recorded_bindings=work_bindings,raw_bytes=work_raw_bytes,
                retained_sweep_regions=work_regions,
                primitive_elements_block_checked=state['primitive_elements_block_checked']-before_blocks,
                records_individually_decoded=state['values_individually_decoded']-before_decoded)
            if progress:
                progress(dict(phase='payload_census',coverage=result['coverage'],remaining=result['remaining'],status=result['status']))
            return result
        except sqlite3.OperationalError as exc:
            if connection is not None:
                connection.rollback()
            if 'full' in str(exc).lower() and connection is not None:
                if connection.execute("SELECT name FROM sqlite_master WHERE name='metadata'").fetchone():
                    retained=_state(connection)
                    guard()
                    return _summary(connection,retained,path,capacity=max_checkpoint_bytes,status='RESOURCE_BOUND')
                guard()
                pending=_empty_state(pin)
                return dict(pending,status='RESOURCE_BOUND',checkpoint_initialized=False,
                    remaining=population,disk=dict(bytes=path.stat().st_size,capacity_bytes=max_checkpoint_bytes,rows={}),
                    application_semantics_complete=False,raw_logical_coverage_is_semantic_coverage=False)
            raise
        except BaseException:
            if connection is not None:connection.rollback()
            raise
        finally:
            if connection is not None:connection.close()
            os.close(fd)


@contextmanager
def _reader(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    connection=None
    try:
        try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InputValidationError('Payload census checkpoint is in use') from exc
        if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(path.stat().st_dev,path.stat().st_ino):
            raise InputValidationError('Payload checkpoint inode changed before reading')
        connection=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
        connection.execute('BEGIN')
        yield connection
    finally:
        if connection is not None:connection.close()
        os.close(fd)


def _validated_state(connection,path):
    """Reuse scalar/range admission only for unchanged bounded snapshot tokens.

    No retained value/detail JSON is parsed during structural validation. WAL
    and rollback-journal identities participate because their committed pages
    can change without changing the main database file's identity.
    """
    def token():
        companions=[Path(str(path)+suffix) for suffix in ('-wal','-journal')]
        return (_file_token(path),*( _file_token(p) if p.exists() else None for p in companions))
    before=token();state=_state(connection);key=str(path)
    if _VALIDATED_READERS.get(key)!=before:
        _validate(connection,state)
    if token()!=before:
        raise InputValidationError('Payload checkpoint changed during structural admission')
    _VALIDATED_READERS[key]=before;_VALIDATED_READERS.move_to_end(key)
    while len(_VALIDATED_READERS)>16:_VALIDATED_READERS.popitem(last=False)
    return state


def read_payload_census(checkpoint: str | Path) -> dict:
    """Validate retained evidence without refreshing runtime/native execution."""
    path=_checkpoint_path(checkpoint)
    with _reader(path) as connection:
        state=_validated_state(connection,path)
        return _summary(connection,state,path)


def _rows(connection,kind,after,limit):
    fields=[column[1] for column in connection.execute(f'PRAGMA table_info({kind})')]
    for row in connection.execute(f'SELECT * FROM {kind} WHERE id>? ORDER BY id LIMIT ?',(after,limit)):
        item=dict(zip(fields,row))
        for key in ('evidence','detail'):
            if key in item:item[key]=json.loads(item[key])
        if kind=='binding_ranges':
            item['source_selector']=dict(kind='SOURCE_PRM_PK_ORDER_RANGE_INCLUSIVE',
                first=[item['prm_first_'+k] for k in ('segment','cluster','offset')],
                last=[item['prm_last_'+k] for k in ('segment','cluster','offset')],
                recorded_rows=item['count'])
        elif kind in ('raw_ranges','value_ranges'):
            item['source_selector']=dict(kind='ALLOCATION_RELATIVE_BYTE_RANGE' if kind=='raw_ranges'
                else 'ALLOCATION_STORED_ELEMENT_RANGE',allocation_id=item['allocation_id'],
                first=item['first'],last=item['last'],interval='HALF_OPEN',
                source_proof='PINNED_IMMUTABLE_FSDX_ALLOCATION_ID')
        elif kind=='unindexed_ranges':
            item['source_selector']=dict(kind='RETAINED_LOGICAL_UNINDEXED_BYTE_RANGE',
                segment=item['segment'],cluster=item['cluster'],first=item['first'],last=item['last'],
                interval='HALF_OPEN',source_chunk=dict(segment=item['segment'],cluster=item['cluster'],
                    logical_start=item['chunk_start'],length=item['chunk_length']),allocation_ownership='UNESTABLISHED',physical_history=False,
                source_proof='PINNED_IMMUTABLE_FSDX_CHUNK_PK')
        elif kind=='incoming_views':
            item['source_selector']=dict(kind='EXACT_ADDRESSED_VIEW_RANGE',allocation_id=item['allocation_id'],
                first=item['first'],last=item['last'],axis=item['axis'],byte_displacement=item['byte_displacement'],
                interval='HALF_OPEN',bindings_count_scope='AGGREGATE_WITHIN_EXACT_VIEW_RANGE',
                ownership='UNKNOWN',allocation_remainder_linked=False)
        elif kind=='unrecorded_views':
            item['source_selector']=dict(kind='UNRECORDED_SOURCE_DECLARATION_ELEMENT_RANGE',
                allocation_id=item['allocation_id'],declaration_id=item['slot_id'],first=item['first'],last=item['last'],
                record_relative_offset=item['displacement'],interval='HALF_OPEN',
                evidence='INDIVIDUALLY_INSPECTED_UNCONDITIONAL_SOURCE_SLOT; NO_CAPTURED_PRM_ROW',ownership='UNKNOWN')
        yield dict(record=kind,**item)


def iter_payload_census(checkpoint: str | Path, *, kind: str='value_ranges',after_id: int=0,limit: int=1000) -> Iterator[dict]:
    """Read bounded retained evidence; source/native execution is not refreshed.

    Row IDs are a checkpoint keyset cursor; they are never payload membership
    intervals. Every returned row remains bound to the checkpoint header pin.
    """
    if kind not in _KINDS or type(after_id) is not int or after_id<0:
        raise InputValidationError('Invalid payload census row selector')
    _limit(limit,'limit',10000)
    path=_checkpoint_path(checkpoint)
    with _reader(path) as connection:
        state=_validated_state(connection,path)
        yield from _rows(connection,kind,after_id,limit)


def export_payload_census(checkpoint: str | Path,output: str | Path) -> dict:
    """Atomically publish compact retained evidence, without repeating payloads."""
    path=_checkpoint_path(checkpoint); output=_checkpoint_path(output,path)
    if os.path.lexists(output):raise FileExistsError(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    descriptor,name=tempfile.mkstemp(prefix='.payload-census-',dir=output.parent);os.close(descriptor)
    stage=Path(name)
    try:
        with _reader(path) as connection:
            retained=_validated_state(connection,path)
            state=_summary(connection,retained,path)
            for source in (state['pin']['store_path'],state['pin']['source'].get('path')):
                if source:_checkpoint_path(output,source)
            opener=gzip.open if output.suffix=='.gz' else open
            with opener(stage,'wt',encoding='utf-8') as stream:
                stream.write(_json(dict(record='header',summary=state,evidence_scope='RETAINED_CHECKPOINT_EXECUTION'))+'\n')
                for kind in sorted(_KINDS):
                    after=0
                    while True:
                        page=list(_rows(connection,kind,after,1000))
                        for item in page:stream.write(_json(item)+'\n')
                        if not page:break
                        after=page[-1]['id']
                stream.write(_json(dict(record='summary',summary=state))+'\n')
            with stage.open('rb') as stream:os.fsync(stream.fileno())
            os.link(stage,output)
            directory=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        return dict(output=str(output),bytes=output.stat().st_size,summary=state)
    finally:
        stage.unlink(missing_ok=True)
