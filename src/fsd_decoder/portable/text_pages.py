"""Resumable, bounded plaintext pages over immutable indexed FSDX allocations.

The SQLite manifest defines committed coverage. Published files without a
committed page row are explicit uncommitted evidence, never completed work.
Element enumeration and retained allocation bytes are independent units.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
from typing import Callable
import uuid
import weakref

from fsd_decoder.core.diagnostics import InputValidationError, ResourceLimitError, require_source_failure, error_category
from fsd_decoder.core.interpretation import interpretation_facets
from fsd_decoder.core.json_io import iter_json
from fsd_decoder.core.provenance import runtime_identity
from fsd_decoder.discovery.decoding_coverage import expansion_admission
from fsd_decoder.portable.exports import _digest, _json_default, _decode_source_value

VERSION = 1
_COUNTERS = ('allocations', 'typed_elements', 'raw_elements', 'incomplete_elements',
             'allocation_bytes', 'header_bytes', 'padding_bytes', 'trailing_bytes', 'records')
_TABLES = {'state', 'pages', 'intents'}
_COLUMNS = dict(state=('id','value'),pages=('sequence','name','bytes','sha256','start_cursor','end_cursor','counts'),
                intents=('name','sequence','start_cursor','end_cursor','counts','bytes','sha256','committed'))


class _PageWatch:
    """Linux directory change notifications keep session reuse bounded."""
    def __init__(self, db, directory):
        self.valid = True
        libc = ctypes.CDLL(None,use_errno=True)
        self.fd = libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
        if self.fd < 0:raise OSError(ctypes.get_errno(),'Cannot monitor plaintext page identities')
        # MODIFIED, ATTRIB, CLOSE_WRITE, MOVED_FROM/TO, CREATE, DELETE, SELF_DELETE/MOVE.
        if libc.inotify_add_watch(self.fd,os.fsencode(directory),0x00000fce) < 0:
            error = ctypes.get_errno();os.close(self.fd)
            raise OSError(error,'Cannot monitor plaintext page directory')
        self.directory = directory
        self.finalizer = weakref.finalize(db,os.close,self.fd)

    def events(self):
        changed = set();overflow = False
        for _ in range(16):
            try:raw = os.read(self.fd,65536)
            except BlockingIOError:return changed,overflow
            except OSError:
                self.valid = False
                return changed,True
            at = 0
            while at < len(raw):
                _,mask,_,length = struct.unpack_from('iIII',raw,at)
                name = os.fsdecode(raw[at+16:at+16+length].split(b'\0',1)[0]);at += 16+length
                overflow |= bool(mask & 0x0000c000)  # queue overflow / ignored watch
                if name.startswith('page-'):changed.add(name)
                elif not name:overflow = True
                if overflow:self.valid = False
            if len(changed) > 4096:
                self.valid = False
                return set(),True
        self.valid = False
        return changed,True


class _FullAdmissionWatch:
    """Unsupported/failed watch setup makes every admission explicit/full."""
    def __init__(self,directory):
        self.directory = directory;self.valid = True;self.finalizer = None

    def events(self):return set(),True


def _watch(db,directory):
    watch = getattr(db,'_text_pages_watch',None)
    if watch is None or watch.directory != directory or not watch.valid:
        if watch is not None and watch.finalizer is not None:watch.finalizer()
        try:watch = _PageWatch(db,directory)
        except (OSError,AttributeError):watch = _FullAdmissionWatch(directory)
        db._text_pages_watch = watch
    return watch


def _json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'), sort_keys=True)


def _identity(path):
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _config(type_name, max_records, max_output_bytes, max_element_bytes, raw_chunk_bytes, max_schema_leaves):
    if type_name is not None and (not isinstance(type_name, str) or not type_name):
        raise InputValidationError('type_name must be one exact nonempty source type')
    result = dict(type_name=type_name, max_records=max_records, max_output_bytes=max_output_bytes,
                  max_element_bytes=max_element_bytes, raw_chunk_bytes=raw_chunk_bytes,
                  max_schema_leaves=max_schema_leaves)
    for key, low, high in (('max_records',1,100000), ('max_output_bytes',8192,67108864),
            ('max_element_bytes',1,1048576), ('raw_chunk_bytes',1,1048576), ('max_schema_leaves',1,100000)):
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise InputValidationError(f'{key} must be between {low} and {high}')
    return result


def _where(config):
    return (' AND n.name=?', (config['type_name'],)) if config['type_name'] is not None else ('', ())


def _totals(db, config, before=None):
    token = (_identity(Path(db.path)),config['type_name'])
    cached = getattr(db,'_text_pages_totals',None)
    if before is None and cached is not None and cached[0] == token:return dict(cached[1])
    extra, args = _where(config)
    if before is not None:
        extra += ' AND a.id<?'
        args += (before,)
    db.query_statistics['text_pages_population_queries'] += 1
    row = db.store.connection.execute('''SELECT count(*),coalesce(sum(CASE WHEN vector=1
        THEN element_count ELSE 1 END),0),coalesce(sum(size),0)
        FROM allocations a JOIN names n ON n.id=a.name_id WHERE 1=1''' + extra, args).fetchone()
    result = dict(allocations=row[0], elements=row[1], allocation_bytes=row[2])
    if before is None:db._text_pages_totals = (token,result)
    return result


def _allocation(db, aid):
    if type(aid) is not int or aid < 1:raise InputValidationError('Invalid allocation cursor id')
    cached = getattr(db,'_text_pages_allocation',None)
    if cached is not None and cached[0] == aid:return cached[1]
    row = db.store.connection.execute('SELECT segment,cluster,logical_offset FROM allocations WHERE id=?', (aid,)).fetchone()
    if row is None:
        raise InputValidationError('Page cursor allocation is absent')
    # Do not construct physical_spans over an entire huge allocation merely to
    # export a single bounded element/window.
    value = db.store.allocation_at(*row)
    if value is None or value['store_allocation_id'] != aid:
        raise InputValidationError('Page allocation index does not resolve exactly')
    db._text_pages_allocation = (aid,value)
    return value


def _next(db, config, after=0):
    extra, args = _where(config)
    row = db.store.connection.execute('''SELECT a.id FROM allocations a JOIN names n ON n.id=a.name_id
        WHERE a.id>?''' + extra + ' ORDER BY a.id LIMIT 1', (after,) + args).fetchone()
    if row is None:
        return None
    a = _allocation(db, row[0])
    return dict(allocation_id=row[0], segment=a['segment'], cluster=a['cluster'],
                allocation_offset=a['logical_offset'], type=a['name'], element_index=0,
                phase='ALLOCATION', byte_offset=0)


def _geometry(a):
    count = a['count'] if a.get('vector') else 1
    # Scalar decoder raw views may include allocation trailing bytes. Count
    # native element storage separately; inline character count is a length,
    # while this representation remains one logical value.
    size = a['count'] if a['name']=='inline_char_bytes' else a.get('element_size',a['size'])
    stride = a.get('element_stride', size) if a.get('vector') else size
    header = a.get('array_header_size', 0) if a.get('vector') else 0
    if any(type(v) is not int or v < 0 for v in (count,size,stride,header,a['size'])) or stride < size:
        raise InputValidationError('Invalid indexed allocation geometry')
    extent = header + ((count-1)*stride + size if count else 0)
    if extent > a['size']:
        raise InputValidationError('Indexed element range exceeds allocation bytes')
    return count, size, stride, header, a['size']-extent


def _local_prefix(db, config, cursor):
    if not isinstance(cursor, dict) or set(cursor) - {'allocation_id','segment','cluster','allocation_offset',
            'type','element_index','phase','byte_offset','raw_diagnostic'}:
        raise InputValidationError('Invalid plaintext continuation cursor')
    a = _allocation(db, cursor['allocation_id'])
    for key, source in (('segment','segment'),('cluster','cluster'),('allocation_offset','logical_offset'),('type','name')):
        if cursor[key] != a[source]:
            raise InputValidationError('Plaintext cursor identity differs from indexed allocation')
    if config['type_name'] is not None and a['name'] != config['type_name']:
        raise InputValidationError('Plaintext cursor is outside exact type selection')
    n,size,stride,head,tail = _geometry(a)
    index, offset, phase = cursor['element_index'], cursor['byte_offset'], cursor['phase']
    if type(index) is not int or not 0 <= index <= n or type(offset) is not int or offset < 0:
        raise InputValidationError('Invalid plaintext element/byte cursor')
    if phase == 'ALLOCATION':
        if index or offset:raise InputValidationError('Invalid allocation start cursor')
        local_bytes = elements = 0
    elif phase == 'HEADER':
        if index or not 0 <= offset < head:raise InputValidationError('Invalid header cursor')
        local_bytes, elements = offset, 0
    elif phase in ('ELEMENT','RAW_ELEMENT'):
        if index >= n or (phase == 'ELEMENT' and offset) or (phase == 'RAW_ELEMENT' and offset >= size):
            raise InputValidationError('Invalid element cursor')
        local_bytes, elements = head + index*stride + offset, index
    elif phase == 'PADDING':
        if index >= n-1 or not 0 <= offset < stride-size:raise InputValidationError('Invalid padding cursor')
        local_bytes, elements = head + index*stride + size + offset, index+1
    elif phase == 'TRAILER':
        if index != n or not 0 <= offset < tail:raise InputValidationError('Invalid trailing cursor')
        local_bytes, elements = a['size']-tail+offset, n
    else:
        raise InputValidationError('Unknown plaintext cursor phase')
    return dict(allocations=0,elements=elements,allocation_bytes=local_bytes)


def _prefix(db,config,cursor,expected):
    if cursor is None:return dict(expected)
    prefix = _totals(db,config,cursor['allocation_id'])
    local = _local_prefix(db,config,cursor)
    return {k:prefix[k]+local[k] for k in prefix}


def _between(db,config,start,end):
    """Source range delta; SQL visits crossed allocations rather than history."""
    if start is None:raise InputValidationError('Committed page starts beyond source scope')
    first = _local_prefix(db,config,start)
    if end is not None and end['allocation_id'] == start['allocation_id']:
        last = _local_prefix(db,config,end)
        result = {k:last[k]-first[k] for k in first}
    else:
        extra,args = _where(config)
        extra += ' AND a.id>=?';args += (start['allocation_id'],)
        if end is not None:
            extra += ' AND a.id<?';args += (end['allocation_id'],)
        db.query_statistics['text_pages_range_queries'] += 1
        row = db.store.connection.execute('''SELECT count(*),coalesce(sum(CASE WHEN vector=1
            THEN element_count ELSE 1 END),0),coalesce(sum(size),0)
            FROM allocations a JOIN names n ON n.id=a.name_id WHERE 1=1'''+extra,args).fetchone()
        whole = dict(zip(('allocations','elements','allocation_bytes'),row))
        last = _local_prefix(db,config,end) if end is not None else dict.fromkeys(first,0)
        result = {k:whole[k]-first[k]+last[k] for k in first}
    if any(v < 0 for v in result.values()):raise InputValidationError('Plaintext range moves backwards')
    return result


def _protected(db, directory):
    directory = Path(directory).absolute()
    if directory.is_symlink():raise InputValidationError('Plaintext directory may not be a symlink')
    directory = directory.resolve()
    protected = [Path(db.path).resolve()]
    if db.source_info.get('path'):protected.append(Path(db.source_info['path']).resolve())
    for p in protected:
        if directory == p or directory/'manifest.sqlite' == p:
            raise InputValidationError('Plaintext destination aliases source/store')
    return directory, protected


def _safe_file(path, protected):
    if path.is_symlink():raise InputValidationError('Plaintext artifact may not be a symlink')
    if path.exists():
        identity = _identity(path)[:2]
        for p in protected:
            if path.resolve() == p or (p.exists() and _identity(p)[:2] == identity):
                raise InputValidationError('Plaintext artifact aliases protected source/store')


def _pin(db, config):
    db.store.check_identity()
    path = Path(db.path).resolve()
    identity = _identity(path)
    cached = getattr(db,'_text_pages_store_hash',None)
    if cached is None or cached[0] != identity:
        db.verify_source()
        db.query_statistics['text_pages_source_quick_checks'] += 1
        digest = _digest(path)
        db.query_statistics['text_pages_store_hashes'] += 1
        if _identity(path) != identity:raise InputValidationError('Source store changed during hashing')
        cached = (identity,digest)
        db._text_pages_store_hash = cached
    return dict(version=VERSION,source=dict(db.source_info),store_path=str(path),store_sha256=cached[1],
        store_bytes=identity[2],runtime_identity=runtime_identity(),config=config)


def _save(connection, state):
    connection.execute('UPDATE state SET value=? WHERE id=1',(_json(state),))


@contextmanager
def _manifest(db, directory, config=None):
    directory, protected = _protected(db,directory)
    path = directory/'manifest.sqlite'
    if not path.exists():
        if config is None:raise InputValidationError('Plaintext manifest is absent')
        if directory.exists():raise FileExistsError('Unrelated existing plaintext directory')
        directory.mkdir(parents=True)
        fd,name = tempfile.mkstemp(prefix='.manifest-',dir=directory)
        os.close(fd);stage = Path(name)
        connection = None;published = False
        try:
            connection = sqlite3.connect(stage)
            connection.executescript('''PRAGMA synchronous=FULL;
                CREATE TABLE state(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);
                CREATE TABLE pages(sequence INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,start_cursor TEXT NOT NULL,end_cursor TEXT NOT NULL,counts TEXT NOT NULL);
                CREATE TABLE intents(name TEXT PRIMARY KEY,sequence INTEGER NOT NULL,start_cursor TEXT NOT NULL,
                    end_cursor TEXT,counts TEXT,bytes INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT,committed INTEGER NOT NULL DEFAULT 0 CHECK(committed IN(0,1)));
                CREATE INDEX intents_uncommitted ON intents(committed,name);''')
            expected = _totals(db,config)
            state = dict(version=VERSION,pin=_pin(db,config),expected=expected,cursor=_next(db,config),
                counts=dict.fromkeys(_COUNTERS,0),pages=0)
            connection.execute('INSERT INTO state VALUES(1,?)',(_json(state),))
            if _pin(db,config) != state['pin']:raise InputValidationError('Source/runtime changed before initial manifest commit')
            connection.commit();connection.close();connection = None
            with stage.open('rb') as stream:os.fsync(stream.fileno())
            if _pin(db,config) != state['pin']:raise InputValidationError('Source/runtime changed before initial manifest publication')
            os.link(stage,path);published = True;_sync(directory)
        finally:
            if connection is not None:connection.close()
            stage.unlink(missing_ok=True)
            if not published:
                try:directory.rmdir()
                except OSError:pass
    _safe_file(path,protected)
    for suffix in ('-journal','-wal','-shm'):_safe_file(Path(str(path)+suffix),protected)
    descriptor = os.open(path,os.O_RDWR|os.O_NOFOLLOW)
    connection = None
    try:
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise InputValidationError('Plaintext manifest is in use') from exc
        if _identity(path)[:2] != (os.fstat(descriptor).st_dev,os.fstat(descriptor).st_ino):
            raise InputValidationError('Plaintext manifest identity changed')
        connection = sqlite3.connect(path)
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('PRAGMA foreign_keys=ON')
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables != _TABLES:raise InputValidationError('Unrecognized plaintext manifest schema')
        for table,names in _COLUMNS.items():
            if tuple(row[1] for row in connection.execute('PRAGMA table_info('+table+')')) != names:
                raise InputValidationError('Unrecognized plaintext manifest column contract')
        if connection.execute('SELECT count(*) FROM state').fetchone()[0] != 1:
            raise InputValidationError('Plaintext manifest must contain exactly one accepted state')
        row = connection.execute('SELECT value FROM state WHERE id=1').fetchone()
        if row is None:raise InputValidationError('Plaintext manifest state is absent')
        if not isinstance(row[0],str) or len(row[0].encode()) > 1048576:
            raise InputValidationError('Plaintext state metadata exceeds admission bound')
        state = json.loads(row[0]);actual_config = state['pin']['config']
        if _config(**actual_config) != actual_config:
            raise InputValidationError('Invalid retained plaintext configuration')
        if config is not None and config != actual_config:raise InputValidationError('Plaintext configuration changed')
        pin = _pin(db,actual_config)
        if type(state['version']) is not int or state['version'] != VERSION or state['pin'] != pin:
            raise InputValidationError('Plaintext source/runtime/configuration pins changed')
        expected = _totals(db,actual_config)
        if state['expected'] != expected or any(type(v) is not int for v in state['expected'].values()):
            raise InputValidationError('Plaintext expected source population changed')
        _validate(db,connection,state,directory,protected)
        yield connection,state,directory,protected
    except (KeyError,TypeError,IndexError,json.JSONDecodeError) as exc:
        # Only manifest admission errors are converted; decoder/programming
        # errors after yield must retain their original type and traceback.
        if connection is not None and getattr(db,'_text_pages_manifest_admitted',False):raise
        raise InputValidationError('Malformed plaintext manifest structure') from exc
    finally:
        db._text_pages_manifest_admitted = False
        if connection is not None:connection.close()
        os.close(descriptor)


def _validate(db,connection,state,directory,protected):
    """Validate compact committed prefix once per stable manifest/session."""
    token = (_identity(Path(db.path)),_identity(directory/'manifest.sqlite'),_identity(directory))
    changes,overflow = _watch(db,directory).events()
    if getattr(db,'_text_pages_trusted',None) == token and not changes and not overflow:
        db._text_pages_manifest_admitted = True
        return
    if (set(state['counts']) != set(_COUNTERS) or any(type(v) is not int or v < 0 for v in state['counts'].values())
            or type(state['pages']) is not int or state['pages'] < 0):
        raise InputValidationError('Plaintext cached counters are invalid')
    cursor = _next(db,state['pin']['config']);counts = dict.fromkeys(_COUNTERS,0);number = 0
    for row in connection.execute('SELECT sequence,name,bytes,sha256,start_cursor,end_cursor,counts FROM pages ORDER BY sequence'):
        seq,name,size,digest,start,end,delta = row
        if seq != number+1 or Path(name).name != name or not name.startswith('page-'):
            raise InputValidationError('Plaintext page sequence/name is invalid')
        if json.loads(start) != cursor:raise InputValidationError('Plaintext page cursor continuity failed')
        next_cursor = json.loads(end)
        changes = json.loads(delta)
        if set(changes) != set(_COUNTERS) or any(type(v) is not int or v < 0 for v in changes.values()):
            raise InputValidationError('Plaintext page counters are invalid')
        for k in counts:counts[k] += changes[k]
        source_delta = _between(db,state['pin']['config'],cursor,next_cursor)
        if (source_delta['allocations'] != changes['allocations'] or source_delta['elements'] != changes['typed_elements']+changes['raw_elements']
                or source_delta['allocation_bytes'] != changes['allocation_bytes']):
            raise InputValidationError('Plaintext page range/counter reconciliation failed')
        cursor = next_cursor
        file = directory/name;_safe_file(file,protected)
        if (type(size) is not int or not 0 < size <= state['pin']['config']['max_output_bytes']
                or not file.is_file() or file.stat().st_size != size or len(digest) != 64):
            raise InputValidationError('Committed plaintext page is missing or its size changed')
        file_identity = _identity(file)
        db.query_statistics['text_pages_historical_page_hashes'] += 1
        if _digest(file) != digest:
            raise InputValidationError('Modified plaintext page hash differs')
        with file.open('rb') as stream:
            header = stream.readline(2049)
            summary = _read_page_summary(stream,size,db)
        if len(header)>2048 or not header.startswith(b'HEADER ') or not header.endswith(b'\n'):
            raise InputValidationError('Plaintext page header is invalid')
        envelope = json.loads(header[7:])
        if (envelope.get('pin_sha256') != hashlib.sha256(_json(state['pin']).encode()).hexdigest()
                or envelope.get('sequence') != seq or envelope.get('start_cursor') != json.loads(start)):
            raise InputValidationError('Plaintext immutable header differs from retained pin/range')
        if (set(summary) != {'counts','next_cursor','enumeration_complete','application_semantics_complete'}
                or not isinstance(summary['counts'],dict) or set(summary['counts']) != set(_COUNTERS)
                or any(type(v) is not int or v < 0 for v in summary['counts'].values())
                or summary['counts'] != changes or summary['next_cursor'] != next_cursor
                or type(summary['enumeration_complete']) is not bool
                or summary['enumeration_complete'] != (next_cursor is None)
                or summary['application_semantics_complete'] is not False):
            raise InputValidationError('Plaintext immutable page summary differs from retained counters/range')
        if _identity(file) != file_identity:
            raise InputValidationError('Plaintext page changed during immutable content admission')
        intent = connection.execute('SELECT committed,sequence,start_cursor,end_cursor,counts,bytes,sha256 FROM intents WHERE name=?',(name,)).fetchone()
        if intent != (1,seq,start,end,delta,size,digest):raise InputValidationError('Page publication intent disagrees with manifest')
        number += 1
    if number != state['pages'] or counts != state['counts'] or cursor != state['cursor']:
        raise InputValidationError('Plaintext cached progress differs from committed prefix')
    prefix = _prefix(db,state['pin']['config'],cursor,state['expected'])
    if (prefix['allocations'] != counts['allocations'] or prefix['elements'] != counts['typed_elements']+counts['raw_elements']
            or prefix['allocation_bytes'] != counts['allocation_bytes']):
        raise InputValidationError('Plaintext final source prefix reconciliation failed')
    if counts['incomplete_elements'] > counts['typed_elements']+counts['raw_elements']:
        raise InputValidationError('Plaintext interpretation counters are invalid')
    db._text_pages_trusted = token
    db._text_pages_manifest_admitted = True


def _read_page_summary(stream,size,db):
    """Read the writer's immutable final envelope with a fixed 2048-byte bound.

    The caller has authenticated the entire page hash; this footer prevents
    mutable page/intent/state counters from changing raw-versus-typed coverage.
    Stable session admission reuses the validated token rather than rereading
    historical envelopes for each append.
    """
    stream.seek(max(0,size-2048))
    tail = stream.read(min(size,2048))
    db.query_statistics['text_pages_page_summary_reads'] += 1
    db.query_statistics['text_pages_page_summary_bytes'] += len(tail)
    if not tail.endswith(b'\n'):
        raise InputValidationError('Plaintext immutable page summary is unterminated')
    footer = tail.rsplit(b'\n',2)[-2]
    if not footer.startswith(b'PAGE_SUMMARY '):
        raise InputValidationError('Plaintext immutable page summary is absent or exceeds envelope bound')
    try:summary = json.loads(footer[13:])
    except (ValueError,UnicodeDecodeError) as exc:
        raise InputValidationError('Plaintext immutable page summary is malformed') from exc
    if not isinstance(summary,dict):raise InputValidationError('Plaintext immutable page summary is invalid')
    return summary


def _encoded(kind,value,maximum):
    pieces = bytearray((kind+' ').encode())
    for chunk in iter_json(value,default=_json_default,ensure_ascii=True,allow_nan=False,separators=(',',':')):
        raw = chunk.encode('utf-8')
        if len(pieces)+len(raw)+1 > maximum:raise ResourceLimitError('Encoded plaintext record exceeds page admission')
        pieces.extend(raw)
    pieces.extend(b'\n')
    return bytes(pieces)


def _advance(db,config,cursor,a,counts):
    n,size,stride,head,tail = _geometry(a)
    phase,index = cursor['phase'],cursor['element_index']
    cursor = dict(cursor,byte_offset=0)
    cursor.pop('raw_diagnostic',None)
    if phase == 'ALLOCATION':
        cursor['phase'] = 'HEADER' if head else 'ELEMENT' if n else 'TRAILER'
    elif phase == 'HEADER':cursor['phase'] = 'ELEMENT' if n else 'TRAILER'
    elif phase in ('ELEMENT','RAW_ELEMENT'):
        if index < n-1 and stride > size:cursor['phase'] = 'PADDING'
        elif index+1 < n:cursor.update(phase='ELEMENT',element_index=index+1)
        else:cursor.update(phase='TRAILER',element_index=n)
    elif phase == 'PADDING':cursor.update(phase='ELEMENT',element_index=index+1)
    if cursor['phase'] == 'TRAILER':
        cursor['element_index'] = n
        if not tail or phase == 'TRAILER':
            counts['allocations'] += 1
            return _next(db,config,a['store_allocation_id'])
    return cursor


def _decode_admission(db,config,a,index,size,decode_bytes):
    context = dict(phase='plaintext_admission',type=a['name'],native_tag=a['native_tag'],
        element_index=index,segment=a['segment'],cluster=a['cluster'],
        logical_offset=a['logical_offset']+a.get('array_header_size',0)+index*a.get('element_stride',size))
    common = dict(phase='plaintext_admission',element_bytes=size,decode_bytes=decode_bytes,context=context)
    if decode_bytes > config['max_element_bytes']:
        return dict(common,status='DECODE_ADMISSION_BOUND',limit_kind='RECORD_BYTES',
            max_element_bytes=config['max_element_bytes'])
    admission = expansion_admission(db,a,config['max_schema_leaves'],context=context)
    if admission is not None:
        status = admission.pop('status')
        result = dict(common,**{key:value for key,value in admission.items() if key!='context'})
        result['status'] = 'DECODE_ADMISSION_UNESTABLISHED' if status=='UNESTABLISHED' else 'DECODE_ADMISSION_BOUND'
        if status=='BOUND':result['limit_kind']='EXPANSION'
        return result
    return None


def _evidence(db,config,cursor,maximum):
    """Return one bounded evidence record and its exact next position/delta."""
    a = _allocation(db,cursor['allocation_id']);n,size,stride,head,tail = _geometry(a)
    phase,index,offset = cursor['phase'],cursor['element_index'],cursor['byte_offset']
    delta = dict.fromkeys(_COUNTERS,0);delta['records'] = 1
    common = dict(allocation_id=cursor['allocation_id'],allocation_address=dict(database=db.database_id,
        segment=a['segment'],cluster=a['cluster'],offset=a['logical_offset']),type=a['name'],native_tag=a['native_tag'])
    if phase == 'ALLOCATION':
        metadata = dict(common,allocation_bytes=a['size'],stored_elements=n,element_size=size,
            element_stride=stride,array_header_size=head,trailing_bytes=tail,
            extent_semantics='INDEXED_ALLOCATION; FIELD_LENGTH_OWNERSHIP_UNESTABLISHED')
        data = _encoded('ALLOCATION',metadata,maximum)
        return data,_advance(db,config,cursor,a,delta),delta
    address = db.address(a['segment'],a['cluster'],a['logical_offset']+head+index*stride)
    if phase == 'ELEMENT':
        diagnostic = None
        try:
            decode_bytes = size if a.get('vector') else a['size']
            diagnostic = _decode_admission(db,config,a,index,size,decode_bytes)
            if diagnostic is None:
                value, diagnostic = _decode_source_value(db,a,index)
                if diagnostic is None:
                    facets = interpretation_facets(value)
                    record = dict(common,element_index=index,address=address,value=value,interpretation=facets,
                        raw_element_hex=db.read(address,size).hex(),element_bytes=size)
                    try:data = _encoded('VALUE',record,maximum)
                    except ResourceLimitError:diagnostic = dict(status='ENCODED_VALUE_ADMISSION_BOUND',element_bytes=size)
                    else:
                        delta.update(typed_elements=1,incomplete_elements=int(not facets['typed_fields_complete']),allocation_bytes=size)
                        return data,_advance(db,config,cursor,a,delta),delta
        except Exception as exc:
            require_source_failure(exc,dict(phase='plaintext_element',type=a['name'],element_index=index,
                segment=a['segment'],cluster=a['cluster'],logical_offset=address.offset))
            diagnostic = dict(status='SOURCE_DECODE_FAILED',error_type=type(exc).__name__,
                error_category=error_category(exc),message=str(exc)[:1024],context=exc.context)
        cursor = dict(cursor,phase='RAW_ELEMENT',raw_diagnostic=diagnostic)
        phase = 'RAW_ELEMENT'
    if phase == 'RAW_ELEMENT':start,total,byte_kind = head+index*stride,size,'ELEMENT_BYTES'
    elif phase == 'HEADER':start,total,byte_kind = 0,head,'ALLOCATION_HEADER'
    elif phase == 'PADDING':start,total,byte_kind = head+index*stride+size,stride-size,'STRIDE_PADDING'
    else:start,total,byte_kind = a['size']-tail,tail,'ALLOCATION_TRAILING_BYTES'
    take = min(config['raw_chunk_bytes'],total-offset,max(1,(maximum-2048)//2))
    at = db.address(a['segment'],a['cluster'],a['logical_offset']+start+offset)
    raw = db.read(at,take)
    record = dict(common,element_index=index if phase in ('RAW_ELEMENT','PADDING') else None,
        phase=phase,byte_kind=byte_kind,address=at,phase_byte_offset=offset,bytes=take,
        phase_bytes=total,raw_hex=raw.hex(),status='RAW_INDEXED_BYTES',
        diagnostic=cursor.get('raw_diagnostic'),application_semantics_complete=False)
    data = _encoded('RAW',record,maximum)
    delta['allocation_bytes'] = take
    if phase == 'HEADER':delta['header_bytes'] = take
    elif phase == 'PADDING':delta['padding_bytes'] = take
    elif phase == 'TRAILER':delta['trailing_bytes'] = take
    if offset+take == total:
        if phase == 'RAW_ELEMENT':delta.update(raw_elements=1,incomplete_elements=1)
        next_cursor = _advance(db,config,cursor,a,delta)
    else:next_cursor = dict(cursor,byte_offset=offset+take)
    return data,next_cursor,delta


def _report(connection,state,directory,*,db,page=None,hashes_verified=False):
    counts = state['counts'];expected = state['expected']
    _,protected = _protected(db,directory)
    orphans = connection.execute('SELECT count(*),coalesce(sum(bytes),0) FROM intents WHERE committed=0').fetchone()
    samples = [];published_bytes = stage_bytes = 0
    for row in connection.execute('SELECT name,sequence,start_cursor,end_cursor,counts,bytes,sha256 FROM intents WHERE committed=0 ORDER BY name'):
        if Path(row[0]).name != row[0] or not row[0].startswith('page-'):
            raise InputValidationError('Invalid uncommitted publication intent name')
        operation = row[0][5:-4];target = directory/row[0];stage = directory/('.text-page-'+operation+'.stage')
        _safe_file(target,protected);_safe_file(stage,protected)
        actual = target.stat().st_size if target.exists() else 0
        temporary = stage.stat().st_size if stage.exists() else 0
        published_bytes += actual;stage_bytes += temporary
        if len(samples) < 16:
            samples.append(dict(name=row[0],operation_id=operation,sequence=row[1],start_cursor=json.loads(row[2]),
                end_cursor=json.loads(row[3]) if row[3] is not None else None,
                counts=json.loads(row[4]) if row[4] is not None else None,bytes=row[5],sha256=row[6],
                published=target.exists(),published_bytes=actual,stage_name=stage.name,stage_bytes=temporary,
                content_integrity='UNCOMMITTED_CONTENT_HASH_NOT_REVERIFIED',coverage='UNCOMMITTED_AND_UNCOUNTED'))
    pending = expected['elements']-counts['typed_elements']-counts['raw_elements']
    pending_bytes = expected['allocation_bytes']-counts['allocation_bytes']
    return dict(format='FSDX_RESUMABLE_TEXT_PAGES',version=VERSION,manifest=str(directory/'manifest.sqlite'),
        pin=state['pin'],pages=state['pages'],expected=expected,counts=counts,next_cursor=state['cursor'],
        status='COMPLETE' if state['cursor'] is None else 'PARTIAL',enumeration_complete=state['cursor'] is None,
        pending_elements=pending,pending_allocation_bytes=pending_bytes,omitted_elements=0,
        selected_elements_reconciled=pending+counts['typed_elements']+counts['raw_elements']==expected['elements'],
        allocation_bytes_reconciled=pending_bytes+counts['allocation_bytes']==expected['allocation_bytes'],
        typed_values_complete=state['cursor'] is None and not counts['incomplete_elements'],
        application_semantics_complete=False,original_source_required=False,
        byte_scope='INDEXED_ALLOCATIONS_ONLY; HEADERS_ELEMENTS_STRIDE_PADDING_TRAILING_BYTES',
        page_hash_integrity='ALL_COMMITTED_PAGES_VERIFIED' if hashes_verified else 'COMMITTED_INDEX_AND_SIZE; ACCESSED_NEW_PAGE_HASH',
        full_store_verification_performed=False,
        store_integrity='SESSION_SQLITE_QUICK_FOREIGN_KEYS; PINNED_FSDX_HASH; ACCESSED_BLOBS',
        operation_checks={k:db.query_statistics[k] for k in ('text_pages_population_queries','text_pages_range_queries',
            'text_pages_source_quick_checks','text_pages_store_hashes','text_pages_historical_page_hashes',
            'text_pages_page_summary_reads','text_pages_page_summary_bytes')},
        session_identity_watch='FULL_ADMISSION_FALLBACK' if isinstance(_watch(db,directory),_FullAdmissionWatch) else 'LINUX_INOTIFY',
        uncommitted_intents=orphans[0],uncommitted_intent_bytes=orphans[1],uncommitted_samples=samples,
        uncommitted_published_bytes=published_bytes,uncommitted_stage_bytes=stage_bytes,
        uncommitted_samples_omitted=max(0,orphans[0]-len(samples)),
        uncommitted_evidence_policy='PRESERVED_AND_UNCOUNTED; NO_UNMANAGED_DIRECTORY_SCAN',page=page)


def export_text_page(db, directory: str | Path, *, type_name: str | None = None,
        max_records: int = 128, max_output_bytes: int = 8388608,
        max_element_bytes: int = 65536, raw_chunk_bytes: int = 32768,
        max_schema_leaves: int = 4096, progress: Callable[[dict],None] | None = None) -> dict:
    """Commit at most one bounded page; repeat unchanged options to resume.

    Existing page names are never replaced. A publication before a failed SQLite
    commit is reported by its intent and contributes no committed coverage.
    Bounds apply to encoded evidence records and output bytes, not process RSS.
    """
    config = _config(type_name,max_records,max_output_bytes,max_element_bytes,raw_chunk_bytes,max_schema_leaves)
    with _manifest(db,directory,config) as (connection,state,directory,protected):
        if state['cursor'] is None:
            if _pin(db,config) != state['pin']:raise InputValidationError('Source/runtime changed before completed-result reuse')
            return _report(connection,state,directory,db=db)
        name = 'page-'+uuid.uuid4().hex+'.txt';start = state['cursor']
        connection.execute('INSERT INTO intents(name,sequence,start_cursor) VALUES(?,?,?)',
            (name,state['pages']+1,_json(start)))
        if _pin(db,config) != state['pin']:raise InputValidationError('Source/runtime changed before publication intent commit')
        connection.commit()
        stage = directory/('.text-page-'+name[5:-4]+'.stage')
        fd = os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        page_counts = dict.fromkeys(_COUNTERS,0);cursor = start;written = records = 0;committed = False
        try:
            with os.fdopen(fd,'wb') as stream:
                header = _encoded('HEADER',dict(format='FSDX_TEXT_PAGE',version=VERSION,
                    pin_sha256=hashlib.sha256(_json(state['pin']).encode()).hexdigest(),
                    sequence=state['pages']+1,start_cursor=start),2048)
                stream.write(header);written += len(header)
                while cursor is not None and records < config['max_records']:
                    remaining = config['max_output_bytes']-written-2048
                    if remaining < 4096:break
                    evidence,next_cursor,delta = _evidence(db,config,cursor,remaining)
                    stream.write(evidence);written += len(evidence);records += 1;cursor = next_cursor
                    for k in page_counts:page_counts[k] += delta[k]
                if not records:raise ResourceLimitError('Page envelope leaves no evidence admission; progress unchanged')
                footer = _encoded('PAGE_SUMMARY',dict(counts=page_counts,next_cursor=cursor,
                    enumeration_complete=cursor is None,application_semantics_complete=False),2048)
                stream.write(footer);written += len(footer);stream.flush();os.fsync(stream.fileno())
            digest = _digest(stage)
            if written > max_output_bytes:raise ResourceLimitError('Plaintext page byte bound exceeded')
            connection.execute('UPDATE intents SET end_cursor=?,counts=?,bytes=?,sha256=? WHERE name=?',
                (_json(cursor),_json(page_counts),written,digest,name))
            if _pin(db,config) != state['pin']:raise InputValidationError('Source/runtime changed before encoded page intent commit')
            connection.commit()
            connection.execute('BEGIN IMMEDIATE')
            actual = json.loads(connection.execute('SELECT value FROM state WHERE id=1').fetchone()[0])
            if actual != state:raise InputValidationError('Plaintext progress changed during page encoding')
            target = directory/name;_safe_file(target,protected)
            os.link(stage,target);_sync(directory)
            if progress:progress(dict(phase='page_published_uncommitted',name=name,bytes=written))
            changed,overflow = _watch(db,directory).events()
            if changed-{name}:
                raise InputValidationError('Existing plaintext page changed before durable page commit')
            if overflow:_validate(db,connection,state,directory,protected)
            if _digest(target) != digest:
                raise InputValidationError('Published plaintext page changed before durable commit')
            state = dict(state,cursor=cursor,pages=state['pages']+1,counts=dict(state['counts']))
            for k in page_counts:state['counts'][k] += page_counts[k]
            connection.execute('INSERT INTO pages VALUES(?,?,?,?,?,?,?)',
                (state['pages'],name,written,digest,_json(start),_json(cursor),_json(page_counts)))
            connection.execute('UPDATE intents SET committed=1 WHERE name=?',(name,))
            if _pin(db,config) != state['pin']:raise InputValidationError('Source/runtime changed before page commit')
            source_delta = _between(db,config,start,cursor)
            if (source_delta['elements'] != page_counts['typed_elements']+page_counts['raw_elements']
                    or source_delta['allocation_bytes'] != page_counts['allocation_bytes']
                    or source_delta['allocations'] != page_counts['allocations']):
                raise InputValidationError('Plaintext page does not reconcile before commit')
            _save(connection,state)
            if _pin(db,config) != state['pin']:raise InputValidationError('Source/runtime changed immediately before page commit')
            connection.commit();_sync(directory)
            committed = True
            if progress:progress(dict(phase='page_committed',pages=state['pages'],**state['counts']))
            return _report(connection,state,directory,db=db,page=dict(sequence=state['pages'],name=name,bytes=written,sha256=digest))
        except BaseException:
            connection.rollback()
            raise
        finally:
            stage.unlink(missing_ok=True)
            changes,overflow = _watch(db,directory).events()
            if committed and not overflow and not (changes-{name}):
                db._text_pages_trusted = (_identity(Path(db.path)),_identity(directory/'manifest.sqlite'),_identity(directory))
            else:db._text_pages_trusted = None
            if committed and changes-{name}:
                raise InputValidationError('Existing plaintext page changed before caller acknowledgement')


def read_text_pages(db, directory: str | Path, *, verify_pages: bool = False) -> dict:
    """Validate compact source-pinned progress; optionally stream every page hash."""
    if type(verify_pages) is not bool:raise InputValidationError('verify_pages must be boolean')
    with _manifest(db,directory) as (connection,state,directory,protected):
        if verify_pages:
            for name,digest in connection.execute('SELECT name,sha256 FROM pages ORDER BY sequence'):
                _safe_file(directory/name,protected)
                if _digest(directory/name) != digest:raise InputValidationError('Committed plaintext page hash differs')
        if _pin(db,state['pin']['config']) != state['pin']:
            raise InputValidationError('Source/runtime changed before plaintext status result')
        return _report(connection,state,directory,db=db,hashes_verified=verify_pages)


def export_text_pages(db, directory: str | Path, *, max_pages: int = 1, **options) -> dict:
    """Commit a finite number of pages without materializing their aggregate."""
    if type(max_pages) is not int or not 1 <= max_pages <= 100000:
        raise InputValidationError('max_pages must be between 1 and 100000')
    for _ in range(max_pages):
        result = export_text_page(db,directory,**options)
        if result['enumeration_complete']:break
    return result
