"""Resumable source-independent FSDX decoding census; counts never imply semantics.

Exhaustive visits every captured allocation and every stored element. Stratified
visits evenly spaced allocations per native name and elements per allocation.
Integer/character primitive vectors use block validation of little-endian fixed
width storage; they do not construct per-value JSON or assert application meaning.
"""
from __future__ import annotations
from fsd_decoder.core.provenance import runtime_identity
from fsd_decoder.core.interpretation import interpretation_facets
import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import fcntl
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import tempfile
import time
from fsd_decoder.portable.facade import PortableDatabase
from fsd_decoder.portable.format import StoreError, standalone_source_identity
from fsd_decoder.core.diagnostics import (InputValidationError, MalformedSourceError,
    ResourceLimitError, attach_context, contextual, error_category, failure_record,
    require_source_failure, observe_rejections)
VERSION = 1
DEFAULTS = dict(mode='stratified', allocations_per_name=3, elements_per_allocation=3, batch_values=1000, block_bytes=1024 * 1024, max_record_bytes=8 * 1024 * 1024, max_array_elements=10000, cache_bytes=16 * 1024 * 1024)

class CensusTrace:
    """Disk diagnostics with counters recoverable to the exact JSON checkpoint.

    Successful scalar values are counted, not individually materialized. Events
    contain only failures and explicit interpretation gaps. The trace is a run
    artifact, not an FSDX container or a claim of complete source semantics.
    """

    def __init__(self, output: Path, pin: dict, *, resume: bool, checkpoint: dict | None):
        self.path = output / 'diagnostics.sqlite'
        if self.path.is_symlink() or (resume and not self.path.is_file()):
            raise InputValidationError('Missing safe census diagnostic trace')
        if not resume:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        self.connection = sqlite3.connect(self.path)
        self.reader_index = 0
        try:
            self.connection.execute('PRAGMA synchronous=FULL')
            self.connection.execute('PRAGMA temp_store=FILE')
            if not resume:
                self.connection.executescript('''
                    CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE events(id INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL,
                        kind TEXT NOT NULL, phase TEXT NOT NULL, name TEXT NOT NULL,
                        reason TEXT NOT NULL, allocation_id INTEGER, segment INTEGER,
                        cluster INTEGER, logical_offset INTEGER, element_index INTEGER,
                        native_tag INTEGER, field_path TEXT, detail TEXT NOT NULL);
                    CREATE INDEX events_reason ON events(kind,phase,name,reason);
                    CREATE INDEX events_address ON events(segment,cluster,logical_offset,element_index);
                    CREATE TABLE counters(family TEXT, label TEXT, name TEXT, count INTEGER NOT NULL,
                        PRIMARY KEY(family,label,name)) WITHOUT ROWID;
                    CREATE TABLE counter_checkpoints(generation INTEGER, family TEXT, label TEXT,
                        name TEXT, count INTEGER NOT NULL,
                        PRIMARY KEY(generation,family,label,name)) WITHOUT ROWID;
                    CREATE TABLE commits(generation INTEGER PRIMARY KEY, last_event_id INTEGER NOT NULL);
                    INSERT INTO commits VALUES(0,0);
                    CREATE VIEW reason_counts AS SELECT kind,phase,name,reason,COUNT(*) AS count
                        FROM events GROUP BY kind,phase,name,reason;
                ''')
                self.connection.execute('INSERT INTO metadata VALUES(?,?)', ('pin', json.dumps(pin, sort_keys=True)))
                self.connection.commit()
                self.generation = 0
            else:
                if not isinstance(checkpoint, dict) or checkpoint.get('format') != 'fsd-census-diagnostics-v1':
                    raise InputValidationError('Checkpoint has no compatible diagnostic trace policy; restart in a new output')
                stored = self.connection.execute("SELECT value FROM metadata WHERE key='pin'").fetchone()
                if stored is None or json.loads(stored[0]) != pin:
                    raise InputValidationError('Diagnostic trace content, interpreter or configuration pin mismatch')
                self.restore(checkpoint)
        except BaseException:
            self.connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    def restore(self, checkpoint: dict | None) -> None:
        """Discard speculative transactions/commits after the durable JSON cursor."""
        self.connection.rollback()
        if checkpoint is None:
            checkpoint = dict(generation=0, last_event_id=0, events=0)
        generation = checkpoint.get('generation')
        end = checkpoint.get('last_event_id')
        if type(generation) is not int or type(end) is not int:
            raise MalformedSourceError('Invalid diagnostic trace checkpoint cursor')
        row = self.connection.execute('SELECT last_event_id FROM commits WHERE generation=?', (generation,)).fetchone()
        actual, rows = self.connection.execute('SELECT COALESCE(MAX(id),0),COUNT(*) FROM events WHERE id<=?', (end,)).fetchone()
        if row is None or row[0] != end or actual != end or rows != checkpoint.get('events'):
            raise MalformedSourceError('Diagnostic trace is behind the census checkpoint')
        self.generation = generation
        self.connection.execute('DELETE FROM events WHERE id>?', (end,))
        self.connection.execute('DELETE FROM counters')
        self.connection.execute('INSERT INTO counters SELECT family,label,name,count FROM counter_checkpoints WHERE generation=?', (generation,))
        self.connection.execute('DELETE FROM counter_checkpoints WHERE generation>?', (generation,))
        self.connection.execute('DELETE FROM commits WHERE generation>?', (generation,))
        self.connection.commit()

    def source(self, source: dict) -> None:
        encoded = json.dumps(source, sort_keys=True)
        existing = self.connection.execute("SELECT value FROM metadata WHERE key='source'").fetchone()
        if existing and existing[0] != encoded:
            raise InputValidationError('Diagnostic trace source identity mismatch')
        self.connection.execute('INSERT OR IGNORE INTO metadata VALUES(?,?)', ('source', encoded))

    def count(self, family: str, label: str, name: str = '', amount: int = 1) -> None:
        self.connection.execute('INSERT INTO counters VALUES(?,?,?,?) ON CONFLICT(family,label,name) DO UPDATE SET count=count+excluded.count', (family, label, name, amount))

    def event(self, kind: str, reason: str, *, phase: str, allocation: dict | None = None,
              element_index: int | None = None, field_path: str = '', detail: dict | None = None,
              event_key: str | None = None) -> None:
        allocation = allocation or {}
        identifier = allocation.get('store_allocation_id')
        detail = dict(detail or {})
        if identifier is not None:
            address = dict(segment=allocation['segment'], cluster=allocation['cluster'], offset=allocation['logical_offset'])
            detail['allocation_address'] = address
            if element_index is not None:
                stride = allocation.get('element_stride', allocation.get('element_size', allocation['size']))
                header = allocation.get('array_header_size', 0) if allocation.get('vector') else 0
                detail['instance_address'] = dict(address, offset=address['offset'] + header + element_index * stride)
        key = event_key or json.dumps((kind, identifier, element_index, field_path, phase, reason))
        row = (key, kind, phase, allocation.get('name', ''), reason, identifier,
               allocation.get('segment'), allocation.get('cluster'), allocation.get('logical_offset'),
               element_index, allocation.get('native_tag'), field_path,
               json.dumps(detail, sort_keys=True, allow_nan=False))
        existing = self.connection.execute('SELECT event_key,kind,phase,name,reason,allocation_id,segment,cluster,logical_offset,element_index,native_tag,field_path,detail FROM events WHERE event_key=?', (key,)).fetchone()
        if existing is not None:
            if tuple(existing) != row:
                raise MalformedSourceError('Repeated diagnostic event differs from pinned trace')
            return
        self.connection.execute('INSERT INTO events(event_key,kind,phase,name,reason,allocation_id,segment,cluster,logical_offset,element_index,native_tag,field_path,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', row)

    def rejection(self, record: dict) -> None:
        """Initialization order identifies reader rejections exactly once on resume."""
        self.reader_index += 1
        context = record['context']
        allocation = {key: context[key] for key in ('name', 'segment', 'cluster', 'logical_offset', 'native_tag') if key in context}
        self.event('reader_rejection', record['reason'], phase=record['phase'], allocation=allocation,
                   element_index=context.get('element_index'), detail=record,
                   event_key='reader-rejection:' + str(self.reader_index))

    def checkpoint(self) -> dict:
        self.generation += 1
        end = self.connection.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
        self.connection.execute('INSERT INTO commits VALUES(?,?)', (self.generation, end))
        self.connection.execute('INSERT INTO counter_checkpoints SELECT ?,family,label,name,count FROM counters', (self.generation,))
        self.connection.commit()
        counts = dict(self.connection.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind'))
        return dict(format='fsd-census-diagnostics-v1', path='diagnostics.sqlite',
                    generation=self.generation, last_event_id=end, events=end,
                    event_counts=counts, exact_reason_selector='SELECT * FROM reason_counts ORDER BY kind,phase,name,reason',
                    instance_selector='SELECT * FROM events WHERE allocation_id=? AND element_index IS ? ORDER BY id',
                    exact_status_selector='SELECT * FROM counters ORDER BY family,name,label',
                    population='Failures, decode-limit skips and explicit uninterpreted record/field evidence only; successful primitive blocks are not individually enumerated.',
                    reader_rejections='Only rejections observed during this run are exact; earlier suppressed compiler diagnostics cannot be reconstructed.')

    def published(self) -> None:
        # Keep the JSON-committed snapshot plus any next pending transaction.
        self.connection.execute('DELETE FROM counter_checkpoints WHERE generation<?', (self.generation,))
        self.connection.execute('DELETE FROM commits WHERE generation<?', (self.generation,))
        self.connection.commit()

@contextmanager
def _census_database(path: Path, cache_bytes: int, trace: CensusTrace | None):
    with observe_rejections(trace.rejection) if trace else nullcontext():
        db = PortableDatabase(path, cache_bytes=cache_bytes)
    with db:
        if trace:
            trace.source(db.source_info)
        yield db

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def interpreter_pin():
    return runtime_identity()

def atomic_json(path, value, *, before_publish=None):
    stage = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.coverage-', delete=False) as stream:
            stage = Path(stream.name)
            json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if before_publish:
            before_publish()
        os.replace(stage, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if stage:
            stage.unlink(missing_ok=True)

def spread(count, limit):
    if count <= limit:
        return list(range(count))
    if limit == 1:
        return [0]
    return sorted({i * (count - 1) // (limit - 1) for i in range(limit)})

def add(metrics, key, amount=1):
    metrics[key] = metrics.get(key, 0) + amount

class _MetricDeltas(dict):
    """One already-bounded value; apply histogram preview caps only at merge."""

def histogram(metrics, key, label, amount=1, *, trace=None, name=''):
    if trace:
        trace.count(key, label, name, amount)
    counter = metrics.setdefault(key, {})
    if not isinstance(metrics, _MetricDeltas) and label not in counter and len(counter) >= 256:
        label = '__OTHER__'
    counter[label] = counter.get(label, 0) + amount

_ABSENT = object()

def _merge_metrics(metrics, increments, changes):
    """Commit small inspection deltas; journal only entries changed by this value."""
    for key, value in increments.items():
        if isinstance(value, dict):
            if key not in metrics:
                changes.append((metrics, key, _ABSENT))
                metrics[key] = {}
            counter = metrics[key]
            for label, amount in value.items():
                if label not in counter and len(counter) >= 256:
                    label = '__OTHER__'
                changes.append((counter, label, counter.get(label, _ABSENT)))
                counter[label] = counter.get(label, 0) + amount
        else:
            changes.append((metrics, key, metrics.get(key, _ABSENT)))
            metrics[key] = metrics.get(key, 0) + value

def _undo_metrics(changes):
    for counter, key, previous in reversed(changes):
        if previous is _ABSENT:
            counter.pop(key, None)
        else:
            counter[key] = previous

def inspect_value(value, metrics, *, trace=None, allocation=None, element_index=None):
    allocation = allocation or {}
    histogram(metrics, 'value_statuses', value.get('status', 'NO_STATUS'), trace=trace, name=allocation.get('name', ''))
    unresolved = ('UNSUPPORTED', 'UNKNOWN', 'UNRESOLVED', 'UNINTERPRETED', 'ARRAY_LIMIT')
    facets = interpretation_facets(value)
    if not facets['typed_fields_complete']:
        add(metrics, 'values_with_incomplete_interpretation')
        if trace and not value.get('status', '').startswith(unresolved):
            trace.event('uninterpreted_value', 'INCOMPLETE_TYPED_INTERPRETATION', phase='decode',
                        allocation=allocation, element_index=element_index, detail=facets)
    if trace and value.get('status', '').startswith(unresolved):
        trace.event('uninterpreted_value', value['status'], phase='decode', allocation=allocation, element_index=element_index)
    if value.get('discriminant_status') == 'PRESERVED_UNAPPLIED':
        add(metrics, 'values_with_unapplied_discriminants')
        if trace:
            trace.event('unapplied_discriminant', 'PRESERVED_UNAPPLIED', phase='decode', allocation=allocation, element_index=element_index)
    fields = value.get('fields')
    if fields is None:
        fields = [value]

    def walk(items, alternate=False, prefix='fields'):
        for field_index, field in enumerate(items):
            field_path = prefix + '/' + str(field_index)
            add(metrics, 'declared_alternative_fields' if alternate else 'fields_observed')
            status = field.get('status', '')
            histogram(metrics, 'field_statuses', status or field.get('kind', 'UNKNOWN'), trace=trace, name=allocation.get('name', ''))
            kind = field.get('kind')
            if kind in ('union', 'union_storage') or status == 'UNION_DECLARED_VIEWS':
                add(metrics, 'unions_without_established_active_member')
            elif kind in ('layout_bytes', 'runtime_code_word', 'floating_storage', 'bitfield_storage') or status.startswith(unresolved):
                add(metrics, 'fields_uninterpreted')
            elif not alternate:
                add(metrics, 'fields_interpreted')
            if trace and (kind in ('layout_bytes', 'runtime_code_word', 'floating_storage', 'bitfield_storage', 'union', 'union_storage') or status == 'UNION_DECLARED_VIEWS' or status.startswith(unresolved) or field.get('target_status') in ('UNRESOLVED', 'ZERO_WORD_UNRESOLVED')):
                trace.event('uninterpreted_field', status or field.get('target_status') or kind,
                    phase='decode', allocation=allocation, element_index=element_index,
                    field_path=field_path, detail=dict(kind=kind, status=status,
                        field_name=field.get('name'), offset=field.get('offset'), size=field.get('size'),
                        declared_alternative=alternate, target_status=field.get('target_status')))
            for view_index, view in enumerate(field.get('declared_views', [])):
                walk(view.get('fields', []), True, field_path + '/declared_views/' + str(view_index) + '/fields')
    walk(fields)
    regions = value.get('uninterpreted_regions', [])
    add(metrics, 'raw_regions_retained', len(regions))
    add(metrics, 'raw_region_bytes', sum((r.get('size', 0) for r in regions)))
    if trace:
        for index, region in enumerate(regions):
            trace.event('uninterpreted_region', region.get('status', 'UNINTERPRETED_BYTES'), phase='decode', allocation=allocation,
                element_index=element_index, field_path='uninterpreted_regions/' + str(index),
                detail={key: region[key] for key in ('offset', 'size', 'bit_offset', 'bit_width', 'status') if key in region})
    padding = value.get('padding_raw_hex', '')
    if padding:
        add(metrics, 'raw_regions_retained')
        add(metrics, 'raw_region_bytes', len(padding) // 2)
        if trace:
            trace.event('uninterpreted_region', 'PADDING_BYTES', phase='decode', allocation=allocation,
                element_index=element_index, field_path='padding_raw_hex', detail=dict(size=len(padding) // 2))
    for field in fields:
        if field.get('kind') in ('layout_bytes', 'union_storage', 'runtime_code_word'):
            add(metrics, 'raw_regions_retained')
            add(metrics, 'raw_region_bytes', field.get('size', 0))
    return not value.get('status', '').startswith(('UNSUPPORTED', 'UNKNOWN'))

def record_error(state, allocation, error, phase, element_index=None, *, trace=None):
    context = dict(phase=phase, segment=allocation['segment'], cluster=allocation['cluster'],
                   logical_offset=allocation['logical_offset'], name=allocation['name'], native_tag=allocation['native_tag'])
    if element_index is not None:
        context['element_index'] = element_index
    attach_context(error, context)
    category = error_category(error)
    if category == 'PROGRAMMING_FAILURE':
        raise error
    metrics = state['metrics']
    add(metrics, 'errors')
    histogram(metrics, 'error_kinds', phase + ':' + type(error).__name__, trace=trace, name=allocation['name'])
    histogram(metrics, 'error_categories', category, trace=trace, name=allocation['name'])
    if trace:
        trace.event('decode_limit' if phase == 'decode-limit' else 'error', str(error),
                    phase=phase, allocation=allocation, element_index=element_index,
                    detail=dict(error_category=category, error_type=type(error).__name__, context=error.context))
    if len(state['error_examples']) < 100:
        state['error_examples'].append(dict(allocation_id=allocation['store_allocation_id'], name=allocation['name'], segment=allocation['segment'], cluster=allocation['cluster'], logical_offset=allocation['logical_offset'], phase=phase, element_index=element_index, error=str(error)[:500]))
        detail = failure_record(error, status='CENSUS_VALUE_FAILED', context=context,
                                log_directory=trace.path.parent / 'logs' if trace else None)
        state['error_examples'][-1].update({k: detail[k] for k in ('error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})

def expansion_cost(db, allocation, cap):
    """Return admitted leaf count, or legacy cap+1 for any resource refusal."""
    from fsd_decoder.schema.expansion_admission import allocation_cost
    from fsd_decoder.schema.expansion_admission import ExpansionLimits, ExpansionMetadataError
    limits = ExpansionLimits(min(cap, db.fields.expansion_limits.max_decoded_leaves), db.fields.expansion_limits.max_expansion_work)
    try:
        cost = allocation_cost(db.fields, allocation, limits=limits)
    except ExpansionMetadataError:
        return cap + 1
    # Unknown bounded analysis is refused, never misreported as zero leaves.
    return cap + 1 if cost.exceeded(limits) else cost.leaves

def expansion_admission(db, allocation, cap, *, context):
    """Keep metadata uncertainty separate from established resource refusal.

    The integer compatibility adapter above deliberately retains its sentinel
    API. Reporting callers need the actual reason, saturated estimate and policy.
    """
    from fsd_decoder.schema.expansion_admission import allocation_cost, ExpansionLimits, ExpansionMetadataError
    limits = ExpansionLimits(min(cap,db.fields.expansion_limits.max_decoded_leaves),
        db.fields.expansion_limits.max_expansion_work)
    try:cost = allocation_cost(db.fields,allocation,limits=limits)
    except ExpansionMetadataError as exc:
        return dict(status='UNESTABLISHED',error_type=type(exc).__name__,reason=str(exc)[:1024],
            context=context)
    expansion = dict(decoded_fields=cost.leaves,work=cost.work,cost_established=cost.established,
        analysis_work=cost.analysis_work,max_decoded_leaves=limits.max_decoded_leaves,
        max_expansion_work=limits.max_expansion_work,count_semantics='SATURATED_ADMISSION_ESTIMATE')
    if not cost.established or cost.leaves is None:
        return dict(status='UNESTABLISHED',reason='EXPANSION_COST_UNESTABLISHED',expansion=expansion,context=context)
    if cost.exceeded(limits):
        return dict(status='BOUND',reason='EXPANSION_LIMIT_EXCEEDED',expansion=expansion,context=context)
    return None

def record_unestablished_admission(state,allocation,diagnostic,index,*,trace=None):
    """Record a refused estimate without inventing a decode/limit exception."""
    context = dict(diagnostic['context'],element_index=index)
    detail = dict(diagnostic,context=context,status='DECODE_ADMISSION_UNESTABLISHED',raw_retained=True)
    metrics = state['metrics']
    add(metrics,'errors')
    histogram(metrics,'error_kinds','decode-admission:'+diagnostic.get('error_type','UNESTABLISHED_COST'),
        trace=trace,name=allocation['name'])
    histogram(metrics,'error_categories','UNESTABLISHED_ADMISSION',trace=trace,name=allocation['name'])
    if trace:
        trace.event('decode_admission',detail['reason'],phase='decode-admission',allocation=allocation,
            element_index=index,detail=detail)
    if len(state['error_examples']) < 100:
        state['error_examples'].append(dict(allocation_id=allocation['store_allocation_id'],
            name=allocation['name'],segment=allocation['segment'],cluster=allocation['cluster'],
            logical_offset=allocation['logical_offset'],phase='decode-admission',element_index=index,
            error=detail['reason'],error_category='UNESTABLISHED_ADMISSION',**detail))

def _primitive_fast(db, allocation):
    typ = db.fields.types.get(allocation['native_tag'], {})
    name = typ.get('name', '')
    size = typ.get('size')
    return allocation.get('vector') and allocation['native_tag'] <= 42 and (allocation['native_tag'] not in (8, 14)) and (size in (1, 2, 4, 8)) and (not any((word in name for word in ('float', 'double')))) and (allocation.get('element_size', size) == size) and (allocation.get('element_stride', size) == size)

@contextual('census', store_path='store', output='output')
def _run_locked(store_path, output, *, resume=False, progress=None, stop_after_values=None, diagnostic_trace=False, **options):
    """Return report. stop_after_values is a bounded test/benchmark pause, resumable."""
    if type(diagnostic_trace) is not bool:
        raise InputValidationError('diagnostic_trace must be a boolean')
    started = time.monotonic()
    path = Path(store_path).resolve()
    output = Path(output)
    config = {**DEFAULTS, **options}
    if config['mode'] not in ('stratified', 'exhaustive'):
        raise InputValidationError('Unknown scope mode')
    for key, value in config.items():
        if key != 'mode' and (type(value) is not int or value <= 0):
            raise InputValidationError(key + ' must be a positive integer')
    if not path.is_file():
        raise InputValidationError('Store must be a regular file')
    if output.is_symlink():
        raise InputValidationError('Output directory cannot be a symlink')
    if output.resolve() == path:
        raise InputValidationError('Output collides with store')
    admitted_store = None

    def store_identity():
        try:
            return standalone_source_identity(path, admitted_identity=admitted_store)
        except StoreError as exc:
            raise MalformedSourceError('Store changed or is not an immutable standalone source; checkpoint was not published') from exc

    admitted_store = store_identity()
    pin = dict(store_path=str(path), store_sha256=digest(path), store_bytes=admitted_store[2], interpreter=interpreter_pin(), config=config, version=VERSION)
    identity_rejected = False
    checkpoint_failed = False

    def verify_identity(*, full=False):
        nonlocal identity_rejected
        try:
            if store_identity() != admitted_store:
                raise MalformedSourceError('Store changed during census; checkpoint was not published')
            if full and digest(path) != pin['store_sha256']:
                raise MalformedSourceError('Store content changed during census; checkpoint was not published')
            if interpreter_pin() != pin['interpreter']:
                raise InputValidationError('Interpreter changed during census; checkpoint was not published')
            if store_identity() != admitted_store:
                raise MalformedSourceError('Store changed during census identity check; checkpoint was not published')
        except BaseException:
            identity_rejected = True
            raise

    # The initial streaming hash must describe one stable source snapshot.
    if store_identity() != admitted_store:
        raise MalformedSourceError('Store changed while admitting census content pin')
    if diagnostic_trace:
        pin['diagnostic_trace'] = dict(format='fsd-census-diagnostics-v1', policy='DIAGNOSTICS_AND_EXACT_STATUS_COUNTS')
    checkpoint = output / 'checkpoint.json'
    if resume:
        if not checkpoint.is_file() or checkpoint.is_symlink():
            raise InputValidationError('Missing safe checkpoint')
        state = json.loads(checkpoint.read_text())
        if (not isinstance(state, dict) or not all(key in state for key in ('pin', 'status', 'last_allocation_id', 'active', 'metrics', 'error_examples', 'elapsed_seconds'))
                or not isinstance(state['metrics'], dict) or not isinstance(state['error_examples'], list)
                or not isinstance(state['pin'], dict)
                or state['active'] is not None and not isinstance(state['active'], dict)
                or state['status'] == 'COMPLETE' and not isinstance(state.get('captured'), dict)):
            raise MalformedSourceError('Invalid census checkpoint')
        if diagnostic_trace and 'diagnostic_trace' not in state:
            raise InputValidationError('Checkpoint has no compatible diagnostic trace policy; restart in a new output')
        if state['pin'] != pin:
            raise InputValidationError('Checkpoint content, interpreter or configuration pin mismatch')
    else:
        state = dict(pin=pin, status='RUNNING', last_allocation_id=0, active=None, metrics={}, error_examples=[], elapsed_seconds=0)
    trace = CensusTrace(output, pin, resume=resume, checkpoint=state.get('diagnostic_trace')) if diagnostic_trace else None
    trusted_trace = state.get('diagnostic_trace')
    try:
        if state['status'] == 'COMPLETE':
            report = make_report(state)
            verify_identity(full=True)
            atomic_json(output / 'report.json', report, before_publish=verify_identity)
            return report
        processed_this_run = 0
        with _census_database(path, config['cache_bytes'], trace) as db:
            db.fields.decoder.max_array_elements = config['max_array_elements']
            metrics = state['metrics']
            if 'captured' not in state:
                totals = db.store.connection.execute('SELECT COUNT(*) AS n, SUM(element_count) AS elements, SUM(size) AS bytes FROM allocations').fetchone()
                state['captured'] = dict(allocations=totals['n'], stored_elements=totals['elements'], allocation_bytes=totals['bytes'])
                if config['mode'] == 'stratified':
                    selected = []
                    names = db.store.connection.execute('SELECT id,name FROM names ORDER BY id').fetchall()
                    strata = []
                    for name in names:
                        count = db.store.connection.execute('SELECT COUNT(*) FROM allocations WHERE name_id=?', (name['id'],)).fetchone()[0]
                        for offset in spread(count, config['allocations_per_name']):
                            row = db.store.connection.execute('SELECT id FROM allocations WHERE name_id=? ORDER BY segment,cluster,logical_offset LIMIT 1 OFFSET ?', (name['id'], offset)).fetchone()
                            selected.append(row['id'])
                        strata.append(dict(name=name['name'], captured_allocations=count))
                    state['selected_ids'] = sorted(selected)
                    state['strata'] = strata
            raw_resolve = db.resolve

            def counted_resolve(*args, **kwargs):
                add(metrics, 'target_resolution_attempts')
                try:
                    target = raw_resolve(*args, **kwargs)
                    add(metrics, 'target_resolution_null' if target is None else 'target_resolution_successes')
                    if target is not None:
                        current = db.store.allocation_at(target.segment, target.cluster, target.offset)
                        add(metrics, 'targets_with_current_allocation' if current is not None else 'targets_without_current_allocation')
                    return target
                except Exception:
                    add(metrics, 'target_resolution_failures')
                    raise
            db.resolve = counted_resolve

            def save(status):
                nonlocal trusted_trace, checkpoint_failed
                try:
                    verify_identity()
                    state['status'] = status
                    state['elapsed_seconds'] += time.monotonic() - save.last
                    save.last = time.monotonic()
                    if trace:
                        state['diagnostic_trace'] = trace.checkpoint()
                    atomic_json(checkpoint, state, before_publish=verify_identity)
                    trusted_trace = state.get('diagnostic_trace')
                    if trace:
                        trace.published()
                except BaseException as exc:
                    checkpoint_failed = True
                    if trace:
                        try:
                            trace.restore(trusted_trace)
                        except BaseException as rollback_error:
                            exc.add_note('Diagnostic trace rollback failed: ' + str(rollback_error))
                    raise
                save.values = metrics.get('values_attempted', 0)
                report = make_report(state)
                atomic_json(output / 'report.json', report, before_publish=verify_identity)
                if progress:
                    progress(dict(status=status, allocations_attempted=metrics.get('allocations_attempted', 0), allocations_captured=state['captured']['allocations'], values_attempted=metrics.get('values_attempted', 0), elapsed_seconds=state['elapsed_seconds']))
                return report
            save.last = started
            save.values = metrics.get('values_attempted', 0)
            if not resume:
                save('RUNNING')
            elif progress:
                progress(dict(status='RUNNING', allocations_attempted=metrics.get('allocations_attempted', 0), allocations_captured=state['captured']['allocations'], values_attempted=metrics.get('values_attempted', 0), elapsed_seconds=state['elapsed_seconds']))

            def allocations():
                last = state['active']['id'] - 1 if state['active'] else state['last_allocation_id']
                if config['mode'] == 'stratified':
                    for identifier in state['selected_ids']:
                        if identifier > last:
                            row = db.store.connection.execute(db.store._allocation_query() + ' WHERE a.id=?', (identifier,)).fetchone()
                            yield db.store._allocation_record(row)
                else:
                    for row in db.store.connection.execute(db.store._allocation_query() + ' WHERE a.id>? ORDER BY a.id', (last,)):
                        yield db.store._allocation_record(row)
            try:
                for allocation in allocations():
                    identifier = allocation['store_allocation_id']
                    if state['active'] is None:
                        add(metrics, 'allocations_attempted')
                        state['active'] = dict(id=identifier, next_element=0, error=False, fully_typed=True, raw_checked=False)
                    if not state['active']['raw_checked']:
                        try:
                            for start in range(0, allocation['size'], config['block_bytes']):
                                raw = db.read_at(allocation['segment'], allocation['cluster'], allocation['logical_offset'] + start, min(config['block_bytes'], allocation['size'] - start))
                                if len(raw) != min(config['block_bytes'], allocation['size'] - start):
                                    raise MalformedSourceError('Short allocation byte read')
                            add(metrics, 'allocations_raw_read_verified')
                            add(metrics, 'allocation_raw_bytes_read_verified', allocation['size'])
                        except Exception as exc:
                            require_source_failure(exc, dict(phase='raw-read', segment=allocation['segment'], cluster=allocation['cluster'], logical_offset=allocation['logical_offset'], name=allocation['name']))
                            record_error(state, allocation, exc, 'raw-read', trace=trace)
                            state['active']['error'] = True
                        state['active']['raw_checked'] = True
                    active = state['active']
                    count = 1 if allocation['name'] == 'inline_char_bytes' else allocation.get('count', 1)
                    indices = range(count) if config['mode'] == 'exhaustive' else spread(count, config['elements_per_allocation'])
                    fast = config['mode'] == 'exhaustive' and _primitive_fast(db, allocation)
                    if fast:
                        size = db.fields.types[allocation['native_tag']]['size']
                        header = allocation.get('array_header_size', 0)
                        if header + count * size > allocation['size']:
                            record_error(state, allocation, MalformedSourceError('Primitive vector exceeds allocation'), 'primitive-block', trace=trace)
                            active['error'] = True
                        else:
                            while active['next_element'] < count:
                                begin = active['next_element']
                                take = min(count - begin, max(1, config['block_bytes'] // size))
                                raw = db.read_at(allocation['segment'], allocation['cluster'], allocation['logical_offset'] + header + begin * size, take * size)
                                if len(raw) != take * size:
                                    raise MalformedSourceError('Short primitive block')
                                add(metrics, 'values_attempted', take)
                                add(metrics, 'primitive_values_block_validated', take)
                                add(metrics, 'primitive_value_bytes_block_validated', len(raw))
                                active['next_element'] += take
                                processed_this_run += take
                                if processed_this_run >= (stop_after_values or float('inf')):
                                    return save('PAUSED')
                                if metrics.get('values_attempted', 0) - save.values >= config['batch_values']:
                                    save('RUNNING')
                    else:
                        admission = expansion_admission(db,allocation,config['max_array_elements'],
                            context=dict(phase='decode-admission',name=allocation['name'],native_tag=allocation['native_tag'],
                                segment=allocation['segment'],cluster=allocation['cluster'],logical_offset=allocation['logical_offset']))
                        for position, index in enumerate(indices):
                            if position < active['next_element']:
                                continue
                            if allocation.get('element_size', allocation['size']) > config['max_record_bytes'] or (not allocation.get('vector') and allocation['size'] > config['max_record_bytes']) or (admission is not None and admission['status']=='BOUND'):
                                record_error(state, allocation, ResourceLimitError('Record size or field expansion exceeds bounded decode limit; raw allocation retained in store'), 'decode-limit', index, trace=trace)
                                add(metrics, 'values_attempted')
                                add(metrics, 'values_skipped_decode_limit')
                                active['error'] = True
                            elif admission is not None:
                                record_unestablished_admission(state,allocation,admission,index,trace=trace)
                                add(metrics,'values_attempted')
                                add(metrics,'values_skipped_admission_unestablished')
                                active['error'] = True
                            else:
                                before_references = {key: metrics.get(key, 0) for key in ('target_resolution_attempts', 'target_resolution_failures', 'target_resolution_null', 'target_resolution_successes', 'targets_with_current_allocation', 'targets_without_current_allocation')}
                                before_typed = active['fully_typed']
                                value_increments = _MetricDeltas()
                                metric_changes = []
                                if trace:
                                    # Releasing an outermost SQLite SAVEPOINT commits;
                                    # only the guarded census checkpoint may commit.
                                    if not trace.connection.in_transaction:
                                        trace.connection.execute('BEGIN')
                                    trace.connection.execute('SAVEPOINT census_value')

                                def abandon_value():
                                    if active['next_element'] > position:
                                        return  # Completed value: counters and cursor agree.
                                    _undo_metrics(metric_changes)
                                    active['fully_typed'] = before_typed
                                    if trace:
                                        trace.connection.execute('ROLLBACK TO census_value')
                                    for key, previous in before_references.items():
                                        if previous:
                                            metrics[key] = previous
                                        else:
                                            metrics.pop(key, None)

                                try:
                                    value = db.fields.decode(allocation, index, max_record_bytes=config['max_record_bytes'])
                                    typed = inspect_value(value, value_increments, trace=trace, allocation=allocation, element_index=index)
                                    add(value_increments, 'values_decoded')
                                    add(value_increments, 'values_attempted')
                                    _merge_metrics(metrics, value_increments, metric_changes)
                                    active['fully_typed'] &= typed
                                    active['next_element'] = position + 1
                                except Exception as exc:
                                    try:
                                        require_source_failure(exc, dict(phase='decode', segment=allocation['segment'], cluster=allocation['cluster'], logical_offset=allocation['logical_offset'], name=allocation['name'], element_index=index))
                                    except BaseException:
                                        abandon_value()
                                        raise
                                    _undo_metrics(metric_changes)
                                    if trace:
                                        trace.connection.execute('ROLLBACK TO census_value')
                                    record_error(state, allocation, exc, 'decode', index, trace=trace)
                                    add(metrics, 'values_attempted')
                                    add(metrics, 'values_failed')
                                    active['error'] = True
                                    active['next_element'] = position + 1
                                except BaseException:
                                    abandon_value()
                                    raise
                                if trace:
                                    trace.connection.execute('RELEASE census_value')
                            active['next_element'] = position + 1
                            processed_this_run += 1
                            if processed_this_run >= (stop_after_values or float('inf')):
                                return save('PAUSED')
                            if metrics.get('values_attempted', 0) - save.values >= config['batch_values']:
                                save('RUNNING')
                    add(metrics, 'allocations_finished')
                    if not active['error']:
                        add(metrics, 'allocations_without_decode_errors')
                    if not active['error'] and active['fully_typed']:
                        add(metrics, 'allocations_without_unsupported_value_status')
                    state['last_allocation_id'] = identifier
                    state['active'] = None
                verify_identity(full=True)
                return save('COMPLETE')
            except BaseException as exc:
                if not identity_rejected and not checkpoint_failed:
                    try:
                        save('INTERRUPTED')
                    except BaseException as checkpoint_error:
                        exc.add_note('Interruption checkpoint was not published: ' + str(checkpoint_error))
                raise
    finally:
        if trace:
            # Covers rejection before/after a save as well as a partial decode.
            primary_error = sys.exception()
            try:
                trace.restore(trusted_trace)
            except BaseException as rollback_error:
                if primary_error is None:
                    raise
                primary_error.add_note('Diagnostic trace rollback failed: ' + str(rollback_error))
            finally:
                trace.close()

def run(store_path, output, *, resume=False, **options):
    """Hold the census lock; diagnostic_trace=True enables exact disk diagnostics.

    Resume requires the same trace policy and pinned source/runtime/configuration.
    Untraced historical checkpoints remain resumable without a trace; enabling a
    trace for one requires a fresh output because already suppressed events lack
    recoverable detail.
    """
    output = Path(output)
    if output.is_symlink():
        raise InputValidationError('Output directory cannot be a symlink')
    if resume:
        if not (output / 'checkpoint.json').is_file():
            raise InputValidationError('Missing safe checkpoint')
    else:
        output.mkdir(parents=True, exist_ok=False)
    lock_path = output / '.coverage.lock'
    if lock_path.is_symlink():
        raise InputValidationError('Coverage lock cannot be a symlink')
    with open(lock_path, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InputValidationError('Another coverage process holds this output lock') from exc
        return _run_locked(store_path, output, resume=resume, **options)

def make_report(state):
    exhaustive = state['pin']['config']['mode'] == 'exhaustive'
    report = dict(version=VERSION, status=state['status'], scope='EXHAUSTIVE_CAPTURED_ALLOCATIONS_AND_ELEMENTS' if exhaustive else 'STRATIFIED_SELECTED_ALLOCATIONS_AND_ELEMENTS', exhaustive_complete=exhaustive and state['status'] == 'COMPLETE', captured=state['captured'], selected_allocations=state['captured']['allocations'] if exhaustive else len(state['selected_ids']), metrics=state['metrics'], errors=state['error_examples'], elapsed_seconds=state['elapsed_seconds'], pin=state['pin'], reference_coverage='Resolved PRM addresses and presence in a current captured allocation are counted separately. A resolved address without a current allocation is not asserted to be a live object.', schema_semantics='Typed status does not prove application semantics, ownership, CRS, units, or active union alternatives.', primitive_fast_path='Only contiguous integer/character primitive vectors: verifies stored bytes and fixed-width representation bounds in blocks; aggregates values without scalar JSON expansion. Floating values, pointers and class fields use NativeFields.decode.', element_count_note='Captured stored_elements sums native counts; inline_char_bytes stores a character length but decodes as one character-byte record.', raw_retention='Raw bytes remain in the FSDX. Raw-read coverage verifies selected allocation readability; it is distinct from interpreted field coverage. Raw-region bytes can overlap declared union views.', claim='Finished scope traversal; inspect failed, skipped and unsupported counts before claiming decoding success.' if state['status'] == 'COMPLETE' else 'Partial resumable traversal; no exhaustive completion claim.', strata=state.get('strata', []))
    report['diagnostic_preview'] = dict(error_examples_limit=100, error_examples_suppressed=max(0, state['metrics'].get('errors', 0) - len(state['error_examples'])), status_histograms='Bounded preview; __OTHER__ combines additional labels. Exact counters require diagnostic_trace.', exact_trace_available='diagnostic_trace' in state)
    if 'diagnostic_trace' in state:
        report['diagnostic_trace'] = state['diagnostic_trace']
    return report

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('store', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--diagnostic-trace', action='store_true', help='Keep exact diagnostic/status rows in a pinned SQLite trace beneath --output; bounded previews stay separate')
    for key, default in DEFAULTS.items():
        parser.add_argument('--' + key.replace('_', '-'), default=default, choices=['stratified', 'exhaustive'] if key == 'mode' else None, type=str if key == 'mode' else int)
    parser.add_argument('--stop-after-values', type=int, help='Pause after this many values during this invocation')
    args = vars(parser.parse_args(argv))
    path = args.pop('store')
    output = args.pop('output')
    resume = args.pop('resume')
    stop = args.pop('stop_after_values')
    before = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        report = run(path, output, resume=resume, stop_after_values=stop, progress=lambda row: print(json.dumps(row), file=sys.stderr, flush=True), **args)
        print(json.dumps(report, sort_keys=True))
        return 0 if report['status'] == 'COMPLETE' else 3
    except KeyboardInterrupt:
        print('Coverage interrupted; resume the same pinned configuration.', file=sys.stderr)
        return 130
    except Exception as exc:
        detail = failure_record(exc, status='CENSUS_FAILED', context=dict(phase='census', store=str(path), output=str(output)))
        print(json.dumps(detail), file=sys.stderr, flush=True)
        if detail['error_category'] == 'PROGRAMMING_FAILURE':
            raise
        return 1
    finally:
        signal.signal(signal.SIGTERM, before)
if __name__ == '__main__':
    sys.exit(main())
