"""Versioned, source-independent FSDX storage and scoped verification.

This module knows no ObjectStore packing. Ingestion must supply decoded logical
chunks, allocations, schema and pointer evidence, including explicit unresolved
bindings. An optional C++ helper screens JSON bytes, frames canonical SQL rows
and estimates bounded row sizes; Python owns parsing and integrity policy.
Captured numeric payloads retain their original binary representation.
"""
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, is_dataclass, dataclass
import hashlib
import json
import re
import os
from pathlib import Path
import sqlite3
import sys
import zlib
from fsd_decoder.core.json_scan import check as _native_json_check
FORMAT = 'fsdx-portable-store'
VERSION = 1
INDEXED_VERSION = 2
DOCUMENT_INDEX_VERSION = 1
APPLICATION_ID = 1179862104
DEFAULT_CHUNK_BYTES = 1024 * 1024
MAX_BLOB_BYTES = 16 * 1024 * 1024
METADATA_CACHE_BYTES = 8 * 1024 * 1024
METADATA_CACHE_ENTRIES = 4096

@dataclass(frozen=True)
class ResourcePolicy:
    """Reader policy, not native-format limits. Every JSON leaf is bounded."""
    max_stored_blob_bytes: int = MAX_BLOB_BYTES
    max_uncompressed_blob_bytes: int = MAX_BLOB_BYTES
    max_json_bytes: int = MAX_BLOB_BYTES
    max_json_depth: int = 64
    max_sqlite_length_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        for key, value in asdict(self).items():
            if type(value) is not int or value <= 0:
                raise StoreError(f'{key} must be a positive integer')
        if self.max_sqlite_length_bytes > (1 << 31)-1:
            raise StoreError('max_sqlite_length_bytes exceeds SQLite API integer range')
        if self.max_json_depth > 256:
            raise StoreError('max_json_depth exceeds safe parser policy (256)')

# A quoted token may end at EOF with a dangling escape. Syntax validation is
# still decode_json's responsibility; this scanner preserves the prior depth
# contract, including malformed text. Possessive repeats avoid backtracking
# stacks on long strings; do not replace finditer with aggregate findall.
_JSON_DEPTH_TOKENS = re.compile(r'"[^"\\]*+(?:\\[\s\S][^"\\]*+)*+(?:"|\\?\Z)|[\[\]{}]')

def _check_json_text_python(raw, policy):
    if isinstance(raw, bytes):
        if len(raw) > policy.max_json_bytes:
            raise StoreError('JSON bytes exceed resource policy')
        try:
            raw = raw.decode('utf-8')
        except UnicodeError as exc:
            raise StoreError('JSON requires valid UTF-8') from exc
    elif not isinstance(raw, str):
        raise StoreError('JSON must be UTF-8 bytes or text')
    elif len(raw) > policy.max_json_bytes or len(raw.encode('utf-8')) > policy.max_json_bytes:
        raise StoreError('JSON bytes exceed resource policy')
    depth = 0
    for token in _JSON_DEPTH_TOKENS.finditer(raw):
        char = raw[token.start()]
        if char in '[{':
            depth += 1
            if depth > policy.max_json_depth:
                raise StoreError('JSON nesting exceeds resource policy')
        elif char in ']}':
            depth -= 1
    return raw

def _check_json_text(raw, policy):
    if _native_json_check is None or type(raw) not in (bytes, str):
        return _check_json_text_python(raw, policy)
    if len(raw) > policy.max_json_bytes:
        raise StoreError('JSON bytes exceed resource policy')
    encoded = raw.encode('utf-8') if type(raw) is str else raw
    if len(encoded) > policy.max_json_bytes:
        raise StoreError('JSON bytes exceed resource policy')
    status = _native_json_check(encoded, policy.max_json_depth)
    if status == 2:
        # Preserve the Python error cause and UTF-8-before-depth precedence.
        return _check_json_text_python(raw, policy)
    if status == 1:
        raise StoreError('JSON nesting exceeds resource policy')
    if status != 0:
        raise RuntimeError('Native JSON preflight argument failure')
    return raw.decode('utf-8') if type(raw) is bytes else raw

def decode_json(raw, policy=None):
    policy = policy or ResourcePolicy()
    raw = _check_json_text(raw, policy)
    try:
        return json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise StoreError('Invalid JSON document') from exc

def _json_depth(value):
    maximum = 0
    pending = [(value, 0)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, (dict, list)):
            depth += 1
            maximum = max(maximum, depth)
            entries = value.values() if isinstance(value, dict) else value
            pending.extend(((child, depth) for child in entries if isinstance(child, (dict, list))))
    return maximum
DOCUMENT_INDEX_SCHEMA = '\nCREATE TABLE document_nodes(kind TEXT NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL,\n parent TEXT, member TEXT, ordinal INTEGER NOT NULL, node_type TEXT NOT NULL,\n child_count INTEGER NOT NULL, blob_sha256 TEXT REFERENCES blobs(sha256),\n PRIMARY KEY(kind,name,path), UNIQUE(kind,name,parent,member)) WITHOUT ROWID;\nCREATE INDEX document_children ON document_nodes(kind,name,parent,ordinal);\n'

def _row_orders(connection):
    result = dict(ROW_ORDERS)
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='document_nodes'").fetchone():
        result['document_nodes'] = 'kind,name,path'
    return result

class IndexedDocumentMapping(Mapping):
    """Read-only SQL-backed container; each lookup returns detached bounded data."""

    def __init__(self, store, kind, name, path, count):
        self.store, self.kind, self.name, self.path, self.count = (store, kind, name, path, count)

    def __len__(self):
        self.store._ensure_open()
        return self.count

    def __iter__(self):
        self.store._ensure_open()
        for row in self.store.connection.execute('SELECT ' + self.store._bounded_metadata('member') + ' FROM document_nodes WHERE kind=? AND name=? AND parent=? ORDER BY ordinal', (self.kind, self.name, self.path)):
            if row[0] is None: raise StoreError('Indexed document member bytes exceed resource policy')
            yield row[0]

    def __getitem__(self, key):
        self.store._ensure_open()
        if not isinstance(key, str):
            raise KeyError(key)
        row = self.store.connection.execute('SELECT ' + self.store._bounded_metadata('path') + ',node_type,child_count,blob_sha256 FROM document_nodes WHERE kind=? AND name=? AND parent=? AND member=?', (self.kind, self.name, self.path, key)).fetchone()
        if row is None:
            raise KeyError(key)
        return self.store._document_node(self.kind, self.name, row)

class IndexedDocumentSequence(Sequence):

    def __init__(self, store, kind, name, path, count):
        self.store, self.kind, self.name, self.path, self.count = (store, kind, name, path, count)

    def __len__(self):
        self.store._ensure_open()
        return self.count

    def __getitem__(self, index):
        self.store._ensure_open()
        if isinstance(index, slice):
            raise StoreError('Indexed document slices require explicit bounded iteration')
        if type(index) is not int:
            raise TypeError('Sequence index must be an integer')
        if index < 0:
            index += self.count
        if not 0 <= index < self.count:
            raise IndexError(index)
        row = self.store.connection.execute('SELECT ' + self.store._bounded_metadata('path') + ',node_type,child_count,blob_sha256 FROM document_nodes WHERE kind=? AND name=? AND parent=? AND ordinal=?', (self.kind, self.name, self.path, index)).fetchone()
        if row is None:
            raise StoreError('Indexed document child is missing')
        return self.store._document_node(self.kind, self.name, row)

def materialize_document(value):
    """Explicit aggregate expansion for callers choosing to allocate full JSON."""
    if isinstance(value, Mapping):
        return {k: materialize_document(v) for k, v in value.items()}
    if isinstance(value, Sequence) and (not isinstance(value, (str, bytes))):
        return [materialize_document(v) for v in value]
    return value

def is_immutable_document(value):
    """Whether container membership is a read-only, SQL-backed document view.

    JSON leaf values are detached copies, and callers may freeze their own copy.
    This predicate does not claim detached child dictionaries are immutable.
    """
    return isinstance(value, (IndexedDocumentMapping, IndexedDocumentSequence))

def _cache_size(value):
    """Conservative retained-memory charge; shared children count each time."""
    # Copy plans add several tuple levels per JSON level. Charge them without
    # consuming interpreter stack at the maximum supported parser depth.
    size = 0
    pending = [value]
    while pending:
        current = pending.pop()
        size += sys.getsizeof(current)
        if type(current) is dict:
            for key, child in current.items():
                pending.append(key)
                pending.append(child)
        elif type(current) in (list, tuple):
            pending.extend(current)
    return size

class _BoundedCache:

    def __init__(self, max_bytes=METADATA_CACHE_BYTES, max_entries=METADATA_CACHE_ENTRIES):
        self.values = OrderedDict()
        self.bytes = 0
        self.max_bytes = max_bytes
        self.max_entries = max_entries

    def get(self, key):
        entry = self.values.get(key)
        if entry is not None:
            self.values.move_to_end(key)
            return entry[0]
        return None

    def put(self, key, value):
        size = _cache_size(key) + _cache_size(value) + 256
        if size > self.max_bytes or not self.max_entries:
            return
        old = self.values.pop(key, None)
        if old is not None:
            self.bytes -= old[1]
        while self.values and (self.bytes + size > self.max_bytes or len(self.values) >= self.max_entries):
            _, old = self.values.popitem(last=False)
            self.bytes -= old[1]
        self.values[key] = (value, size)
        self.bytes += size

def _copy_plan(value):
    """Only JSON containers need copies; scalar objects are immutable."""
    if type(value) not in (dict, list):
        return (value, ())
    if type(value) is dict:
        children = tuple(((key, _copy_plan(item)) for key, item in value.items() if type(item) in (dict, list)))
    else:
        children = tuple(((key, _copy_plan(item)) for key, item in enumerate(value) if type(item) in (dict, list)))
    return (value, children)

def _copy_metadata(plan):
    value, children = plan
    if type(value) not in (dict, list):
        return value
    result = value.copy()
    for key, child in children:
        result[key] = _copy_metadata(child)
    return result

class StoreError(ValueError):
    pass


def _source_stat_identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _source_paths(path):
    main = str(path)
    return main, tuple(main + suffix for suffix in ('-journal', '-wal', '-shm'))


def _current_source_identity(main, sidecars):
    if any(os.path.lexists(sidecar) for sidecar in sidecars):
        raise StoreError('Portable source must be standalone; source journal/WAL/SHM sidecar detected')
    try:
        return _source_stat_identity(os.stat(main))
    except OSError as exc:
        raise StoreError('Portable source identity is unavailable') from exc


def _standalone_source_identity(main, sidecars, *, admitted_identity=None):
    current = _current_source_identity(main, sidecars)
    if admitted_identity is not None:
        if current != admitted_identity:
            raise StoreError('Portable source changed during reader session')
        return current
    # Persistent WAL mode remains in bytes 18/19 after checkpoint/close removes
    # sidecars. Reject before SQLite can replay or touch any source sidecar.
    with Path(main).open('rb') as source:
        header = source.read(20)
        if _source_stat_identity(os.fstat(source.fileno())) != current:
            raise StoreError('Portable source changed during reader admission')
    if len(header) != 20 or header[:16] != b'SQLite format 3\x00':
        raise StoreError('Invalid portable store SQL container')
    if header[18:20] != b'\x01\x01':
        raise StoreError('Portable source must be standalone non-WAL SQLite; WAL source rejected')
    if _current_source_identity(main, sidecars) != current:
        raise StoreError('Portable source changed during reader admission')
    return current


def standalone_source_identity(path, *, admitted_identity=None) -> tuple[int, ...]:
    """Admit/check a standalone immutable FSDX source, never a checkpoint ledger.

    Initial admission reads the SQLite header. Supplying the previously admitted
    identity checks main-file stats and absent sidecars without rereading it.
    """
    return _standalone_source_identity(*_source_paths(Path(path)), admitted_identity=admitted_identity)

def _json_default(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, bytes):
        return {'encoding': 'hex', 'data': value.hex()}
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f'Unsupported metadata value {type(value).__name__}')

_canonical_json_encoder = json.JSONEncoder(default=_json_default, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'))

def encode_json(value):
    return _canonical_json_encoder.encode(value).encode('utf-8')

def _builtin_json_probe(value, ceiling):
    """Check exact builtins without hooks; bound canonical UTF-8 conservatively.

    Six bytes per string character cover JSON escapes and UTF-8. Integer bit
    counts bound decimal digits; 32 bytes cover finite float spelling. Bytes
    include the canonical hex wrapper. Bounds are clamped, with only ancestor
    iterators retained. Cycles and oversized trees take the incremental path;
    unusual values retain canonical conversion and error ordering.
    """
    def scalar_size(item):
        kind = type(item)
        if kind is str:
            return 6 * len(item) + 2
        if kind is bytes:
            return 64 + 2 * len(item)
        if kind is int:
            return item.bit_length() + 2
        if kind is float:
            return 32
        return 5

    ancestors = set()
    pending = [(None, iter((value,)))]
    bound = 0
    scalar_types = (str, int, float, bool, bytes, type(None))
    key_types = (str, int, float, bool, type(None))
    while pending:
        identity, entries = pending[-1]
        try:
            item = next(entries)
        except StopIteration:
            pending.pop()
            if identity is not None:
                ancestors.remove(identity)
            continue
        kind = type(item)
        if kind in scalar_types:
            bound = min(ceiling + 1, bound + scalar_size(item))
            continue
        if kind not in (dict, list, tuple):
            return False, ceiling + 1
        if id(item) in ancestors:
            bound = ceiling + 1
            continue
        if kind is dict:
            for key in item:
                if type(key) not in key_types:
                    return False, ceiling + 1
                bound = min(ceiling + 1, bound + scalar_size(key) + 2)
            children = iter(item.values())
            bound = min(ceiling + 1, bound + 2 + 2 * len(item))
        else:
            children = iter(item)
            bound = min(ceiling + 1, bound + 2 + len(item))
        ancestors.add(id(item))
        pending.append((id(item), children))
    return True, bound

def _bounded_encode_json(value, ceiling):
    """Return canonical bytes at/below ceiling, otherwise fully validate.

    Exact builtin trees with a conservative byte bound at/below the ceiling
    use the C encoder. Larger trees retain incremental prefix validation.
    Only the retained prefix is bounded. Individual encoder/UTF-8 chunks,
    sorting, compression and the final bytes copy are outside that bound.
    Unusual values and expected error paths use canonical whole encoding.
    """
    eligible, bound = _builtin_json_probe(value, ceiling)
    if not eligible or bound <= ceiling:
        raw = encode_json(value)
        return raw if len(raw) <= ceiling else None
    encoder = json.JSONEncoder(default=_json_default, ensure_ascii=False,
        allow_nan=False, sort_keys=True, separators=(',', ':'))
    buffer = bytearray()
    try:
        for text in encoder.iterencode(value):
            raw = text.encode('utf-8')
            if buffer is not None:
                if len(buffer) + len(raw) > ceiling:
                    buffer = None
                else:
                    buffer.extend(raw)
            # Continue after overflow: a late invalid value must fail before
            # put_document can promote a v1 store or insert document rows.
    except (ValueError, TypeError, UnicodeError, RecursionError):
        # dumps validates the whole text before UTF-8 and uses the C encoder.
        # Replaying only pure builtin trees preserves competing error order,
        # exact diagnostics and C/Python recursion differences without hooks.
        raw = encode_json(value)
        return raw if len(raw) <= ceiling else None
    return None if buffer is None else bytes(buffer)
ROW_ORDERS = {'clusters': 'segment,cluster', 'chunks': 'segment,cluster,logical_start', 'extents': 'id', 'allocation_templates': 'id', 'allocation_contexts': 'id', 'names': 'id', 'allocations': 'id', 'pointers': 'segment,cluster,logical_offset', 'documents': 'kind,name'}

def _framed_rows(rows):
    from fsd_decoder.core.json_scan import frame_rows
    if frame_rows is not None:
        raw = frame_rows(rows)
        if raw is not None:
            return raw
    chunks = []
    for row in rows:
        raw = encode_json(list(row))
        chunks.extend((len(raw).to_bytes(8, 'big'), raw))
    return b''.join(chunks)

def _row_batches(cursor):
    """Keep row traversal guards and bound retained encoded expansion.

    Large individual rows remain supported, but never share a batch. Fetchmany
    alone cannot bound bytes when metadata strings vary in size.
    """
    from fsd_decoder.core.json_scan import estimate_row
    batch, size = [], 0
    for row in cursor:
        row = tuple(row)
        estimate = estimate_row(row) if estimate_row is not None else None
        if estimate is None:
            # Subclasses and custom objects retain Python length/error behavior.
            estimate = 10 + sum(6 * len(v) + 3 if isinstance(v, str) else
                                2 * len(v) + 32 if isinstance(v, bytes) else 32 for v in row)
        if batch and (len(batch) == 256 or size + estimate > 1024 * 1024):
            yield batch
            batch, size = [], 0
        batch.append(row)
        size += estimate
        if size > 1024 * 1024:
            yield batch
            batch, size = [], 0
    if batch:
        yield batch

def _row_integrity(connection, *, tables=None, cancel=None):
    """Hash all columns of selected supported tables in stable row order.

    With ``tables=None``, select every table declared by ``_row_orders``.
    Manifest entries and BLOB payloads are outside these relational proofs;
    payload verification is a separate check.
    """
    from fsd_decoder.core.json_scan import frame_rows
    proofs = {}
    orders = _row_orders(connection)
    if tables is not None and any(table not in orders for table in tables):
        raise StoreError('Unsupported relational integrity table')
    for table, order in orders.items():
        if tables is not None and table not in tables:
            continue
        digest = hashlib.sha256()
        count = 0
        cursor = connection.execute(f'SELECT * FROM {table} ORDER BY {order}')
        if frame_rows is None:
            # The simpler Python loop benchmarks faster without native framing.
            for row in cursor:
                if cancel is not None and count % 256 == 0:
                    cancel()
                raw = encode_json(list(row))
                digest.update(len(raw).to_bytes(8, 'big'))
                digest.update(raw)
                count += 1
        else:
            for rows in _row_batches(cursor):
                if cancel is not None:
                    cancel()
                digest.update(_framed_rows(rows))
                count += len(rows)
        proofs[table] = dict(rows=count, sha256=digest.hexdigest())
    return proofs

def _integer(value, name, maximum=(1 << 63) - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise StoreError(f'{name} must be a bounded nonnegative integer')
    return value

def _address(value):
    if is_dataclass(value):
        value = asdict(value)
    return (_integer(value['segment'], 'segment'), _integer(value['cluster'], 'cluster'), _integer(value.get('offset', value.get('logical_offset')), 'offset'))

def _validate_address_intervals(connection):
    """Check lookup preconditions in one ordered, bounded-memory pass.

    Containing-address lookups require disjoint positive intervals. Checking at
    completion avoids an extra overlap query for every ingested allocation.
    """
    for table, start_column, size_column in (('extents', 'logical_start', 'length'), ('allocations', 'logical_offset', 'size')):
        previous_cluster = None
        previous_end = 0
        query = f'SELECT a.segment,a.cluster,a.{start_column},a.{size_column},c.allocated_bytes\n                    FROM {table} a JOIN clusters c\n                    ON a.segment=c.segment AND a.cluster=c.cluster\n                    ORDER BY a.segment,a.cluster,a.{start_column}'
        for segment, cluster, start, size, limit in connection.execute(query):
            key = (segment, cluster)
            if type(start) is not int or type(size) is not int or start < 0 or (size <= 0) or (start + size > limit):
                raise StoreError(f'Invalid logical {table} interval')
            if key == previous_cluster and start < previous_end:
                raise StoreError(f'Overlapping logical {table}')
            previous_cluster, previous_end = (key, start + size)
SCHEMA = "\nCREATE TABLE manifest(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;\nCREATE TABLE blobs(sha256 TEXT PRIMARY KEY, codec TEXT NOT NULL CHECK(codec IN ('raw','zlib')),\n raw_length INTEGER NOT NULL CHECK(raw_length>=0), data BLOB NOT NULL) WITHOUT ROWID;\nCREATE TABLE clusters(segment INTEGER NOT NULL, cluster INTEGER NOT NULL, allocated_bytes INTEGER NOT NULL,\n metadata TEXT NOT NULL, PRIMARY KEY(segment,cluster)) WITHOUT ROWID;\nCREATE TABLE chunks(segment INTEGER NOT NULL, cluster INTEGER NOT NULL, logical_start INTEGER NOT NULL,\n length INTEGER NOT NULL CHECK(length>0), blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),\n PRIMARY KEY(segment,cluster,logical_start), FOREIGN KEY(segment,cluster) REFERENCES clusters(segment,cluster)) WITHOUT ROWID;\nCREATE TABLE extents(id INTEGER PRIMARY KEY, segment INTEGER NOT NULL, cluster INTEGER NOT NULL,\n logical_start INTEGER NOT NULL, physical_start INTEGER NOT NULL, length INTEGER NOT NULL,\n metadata TEXT NOT NULL, FOREIGN KEY(segment,cluster) REFERENCES clusters(segment,cluster));\nCREATE INDEX extents_address ON extents(segment,cluster,logical_start);\nCREATE TABLE allocation_templates(id INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL, metadata TEXT NOT NULL);\nCREATE TABLE allocation_contexts(id INTEGER PRIMARY KEY, digest TEXT UNIQUE NOT NULL, metadata TEXT NOT NULL);\nCREATE TABLE names(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);\nCREATE TABLE allocations(id INTEGER PRIMARY KEY, segment INTEGER NOT NULL, cluster INTEGER NOT NULL,\n logical_offset INTEGER NOT NULL, size INTEGER NOT NULL, native_tag INTEGER, name_id INTEGER NOT NULL REFERENCES names(id),\n element_count INTEGER NOT NULL, vector INTEGER NOT NULL CHECK(vector IN (0,1)), template_id INTEGER NOT NULL REFERENCES allocation_templates(id),\n context_id INTEGER NOT NULL REFERENCES allocation_contexts(id), page_offset INTEGER, tag_relative_offset INTEGER,\n tag_word_index INTEGER, instance_index INTEGER,\n UNIQUE(segment,cluster,logical_offset), FOREIGN KEY(segment,cluster) REFERENCES clusters(segment,cluster));\nCREATE INDEX allocations_type ON allocations(name_id,segment,cluster,logical_offset);\nCREATE TABLE pointers(segment INTEGER NOT NULL, cluster INTEGER NOT NULL, logical_offset INTEGER NOT NULL,\n width INTEGER NOT NULL CHECK(width IN (4,8)), raw BLOB NOT NULL,\n status TEXT NOT NULL CHECK(status IN ('RESOLVED','NULL','UNRESOLVED')),\n target_segment INTEGER, target_cluster INTEGER, target_offset INTEGER, metadata TEXT NOT NULL,\n PRIMARY KEY(segment,cluster,logical_offset), FOREIGN KEY(segment,cluster) REFERENCES clusters(segment,cluster),\n CHECK(length(raw)=width), CHECK((status='RESOLVED' AND target_segment IS NOT NULL AND target_cluster IS NOT NULL AND target_offset IS NOT NULL)\n OR (status!='RESOLVED' AND target_segment IS NULL AND target_cluster IS NULL AND target_offset IS NULL))) WITHOUT ROWID;\nCREATE TABLE documents(kind TEXT NOT NULL, name TEXT NOT NULL, blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),\n PRIMARY KEY(kind,name)) WITHOUT ROWID;\n"

class StoreWriter:
    """Create a new store; finish() is required before any Store can open it.

    finish() commits the COMPLETE state, closes and synchronizes the store.
    An exception after that commit can leave a completed store at this path.
    The caller owns subsequent full verification, publication and staging
    cleanup; this class does not roll back publication or later failures.
    """

    def __init__(self, path, *, source, compression_level=3, defer_allocation_index=False):
        if type(defer_allocation_index) is not bool:
            raise StoreError('Index deferral must be an explicit boolean')
        self._defer_allocation_index = defer_allocation_index
        self.path = Path(path).absolute()
        if not isinstance(source, dict) or not isinstance(source.get('sha256'), str) or len(source['sha256']) != 64:
            raise StoreError('Source metadata requires its SHA256')
        try:
            bytes.fromhex(source['sha256'])
        except ValueError as exc:
            raise StoreError('Invalid source SHA256') from exc
        if type(compression_level) is not int or not 0 <= compression_level <= 9:
            raise StoreError('Invalid compression level')
        sidecars = tuple(Path(str(self.path)+suffix) for suffix in ('-journal', '-wal', '-shm'))
        # Reservation failure touches nothing. Keep the descriptor open through
        # initialization so its inode remains a reliable cleanup ownership pin.
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        reserved = os.fstat(fd)
        identity = (reserved.st_dev, reserved.st_ino)
        self.connection = None
        self.closed = True
        preexisting_sidecars = set()

        def file_identity(path):
            try:
                info = path.lstat()
                return (info.st_dev, info.st_ino)
            except OSError:
                return None

        try:
            # SQLite can replay/delete journals at open; refuse a preexisting
            # sidecar before giving the database engine access to any of them.
            preexisting_sidecars = {sidecar for sidecar in sidecars if os.path.lexists(sidecar)}
            if preexisting_sidecars:
                raise FileExistsError('Portable stage sidecar already exists')
            if file_identity(self.path) != identity:
                raise StoreError('Portable stage reservation was replaced')
            self.connection = sqlite3.connect(self.path)
            self.closed = False
            self.connection.execute('PRAGMA foreign_keys=ON')
            self.connection.execute('PRAGMA journal_mode=DELETE')
            self.connection.execute('PRAGMA synchronous=FULL')
            self.connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
            self.connection.execute(f'PRAGMA user_version={VERSION}')
            schema = SCHEMA.replace('CREATE INDEX allocations_type ON allocations(name_id,segment,cluster,logical_offset);', '') if defer_allocation_index else SCHEMA
            self.connection.executescript(schema)
            self.compression_level = compression_level
            self.source = dict(source)
            self._intern_cache = _BoundedCache()
            self._name_cache = {}
            self._cluster_limits = {}
            for key, value in [('format', FORMAT), ('version', VERSION), ('state', 'INCOMPLETE'), ('source', source)]:
                self.set_manifest(key, value)
            self.connection.commit()
        except BaseException:
            created_sidecars = [(sidecar, file_identity(sidecar)) for sidecar in sidecars
                                if sidecar not in preexisting_sidecars]
            if self.connection is not None:
                try:
                    self.connection.close()
                except Exception:
                    pass
            self.closed = True
            # If another owner replaced the main path, preserve all names. A
            # matching main inode also gates sidecar cleanup; each sidecar must
            # still match the inode observed before connection close.
            if file_identity(self.path) == identity:
                for sidecar, sidecar_identity in created_sidecars:
                    if sidecar_identity is not None and file_identity(sidecar) == sidecar_identity:
                        try:
                            sidecar.unlink()
                        except OSError:
                            pass
                if file_identity(self.path) == identity:
                    try:
                        self.path.unlink()
                    except OSError:
                        pass
            raise
        finally:
            os.close(fd)

    def set_manifest(self, key, value):
        self.connection.execute('INSERT OR REPLACE INTO manifest VALUES (?,?)', (key, encode_json(value).decode('utf-8')))

    def _blob(self, raw, *, compressed=None):
        if not isinstance(raw, bytes) or len(raw) > MAX_BLOB_BYTES:
            raise StoreError(f'Blob must be bytes of at most {MAX_BLOB_BYTES} bytes; split bulk data into chunks')
        digest = hashlib.sha256(raw).hexdigest()
        packed = zlib.compress(raw, self.compression_level) if compressed is None else compressed
        codec, data = ('zlib', packed) if len(packed) < len(raw) else ('raw', raw)
        self.connection.execute('INSERT OR IGNORE INTO blobs VALUES (?,?,?,?)', (digest, codec, len(raw), data))
        return digest

    def add_cluster(self, record):
        segment, cluster = (_integer(record['segment'], 'segment'), _integer(record['cluster'], 'cluster'))
        allocated = _integer(record['allocated_bytes'], 'allocated_bytes')
        self.connection.execute('INSERT INTO clusters VALUES (?,?,?,?)', (segment, cluster, allocated, encode_json(record).decode()))
        self._cluster_limits[segment, cluster] = allocated

    def _bounds(self, segment, cluster, offset, size):
        for value, name in [(segment, 'segment'), (cluster, 'cluster'), (offset, 'offset'), (size, 'size')]:
            _integer(value, name)
        allocated = self._cluster_limits.get((segment, cluster))
        if allocated is None or offset + size > allocated:
            raise StoreError('Logical span exceeds known cluster')

    def add_chunk(self, segment, cluster, logical_start, raw):
        if not isinstance(raw, bytes) or not raw:
            raise StoreError('Chunks must contain nonempty bytes')
        self._bounds(segment, cluster, logical_start, len(raw))
        # Positive, disjoint stored intervals make the greatest start below
        # the new end sufficient, including when chunks arrive out of order.
        overlap = self.connection.execute('SELECT logical_start,length FROM chunks WHERE segment=? AND cluster=? AND logical_start<? ORDER BY logical_start DESC LIMIT 1', (segment, cluster, logical_start + len(raw))).fetchone()
        if overlap is not None and overlap[0] + overlap[1] > logical_start:
            raise StoreError('Overlapping logical chunks')
        sha = self._blob(raw)
        self.connection.execute('INSERT INTO chunks VALUES (?,?,?,?,?)', (segment, cluster, logical_start, len(raw), sha))

    def add_extent(self, record):
        seg, cid, start = (record['segment'], record['cluster'], record['logical_start'])
        length = _integer(record['length'], 'length')
        physical = _integer(record['physical_start'], 'physical_start')
        self._bounds(seg, cid, start, length)
        if length == 0:
            raise StoreError('Zero-length extent')
        self.connection.execute('INSERT INTO extents(segment,cluster,logical_start,physical_start,length,metadata) VALUES (?,?,?,?,?,?)', (seg, cid, start, physical, length, encode_json(record).decode()))

    def _prepare_allocation(self, record, *, context_raw=None):
        seg, cid, start = (record['segment'], record['cluster'], record['logical_offset'])
        size = _integer(record['size'], 'size')
        self._bounds(seg, cid, start, size)
        if size == 0:
            raise StoreError('Zero-length allocation')
        count = _integer(record.get('count', 1), 'element_count')
        if count == 0:
            raise StoreError('Zero element count')
        if context_raw is not None and type(context_raw) is not bytes:
            raise StoreError('Prepared allocation context must be immutable bytes')
        excluded = {'segment', 'cluster', 'logical_offset', 'size', 'native_tag', 'name', 'count', 'vector', 'address', 'physical_spans', 'source_metadata', 'page_offset', 'tag_relative_offset', 'tag_word_index', 'instance_index'}
        return (record, seg, cid, start, size, count,
                encode_json({k: v for k, v in record.items() if k not in excluded}),
                encode_json(record.get('source_metadata', {})) if context_raw is None else context_raw)

    def _allocation_row(self, prepared):
        record, seg, cid, start, size, count, template_raw, context_raw = prepared
        template = self._intern_raw('allocation_templates', template_raw)
        context = self._intern_raw('allocation_contexts', context_raw)
        name = record['name']
        if name not in self._name_cache:
            self.connection.execute('INSERT OR IGNORE INTO names(name) VALUES (?)', (name,))
            self._name_cache[name] = self.connection.execute('SELECT id FROM names WHERE name=?', (name,)).fetchone()[0]
        return (seg, cid, start, size, record.get('native_tag'), self._name_cache[name],
                count, int(bool(record.get('vector', False))), template, context,
                record.get('page_offset'), record.get('tag_relative_offset'),
                record.get('tag_word_index'), record.get('instance_index'))

    def add_allocation(self, record):
        row = self._allocation_row(self._prepare_allocation(record))
        cursor = self.connection.execute('INSERT INTO allocations(segment,cluster,logical_offset,size,native_tag,name_id,element_count,vector,template_id,context_id,page_offset,tag_relative_offset,tag_word_index,instance_index) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', row)
        return cursor.lastrowid

    def add_allocations(self, records: Sequence[dict]) -> None:
        """Bounded capture admission; preserve the single-row ID-returning API."""
        self._add_allocations(records)

    def _add_allocations(self, records, *, contexts=None):
        """Capture-only immutable encodings; public calls always encode afresh."""
        if len(records) > 256:
            raise StoreError('Allocation batch exceeds record budget')
        if contexts is not None and len(contexts) != len(records):
            raise StoreError('Prepared allocation context count disagrees')
        prepared, size = [], 0
        for index, record in enumerate(records):
            item = self._prepare_allocation(record, context_raw=None if contexts is None else contexts[index])
            size += len(item[-2]) + len(item[-1]) + len(record['name'].encode('utf-8')) + 256
            if size > 8 * 1024 * 1024:
                raise StoreError('Allocation batch exceeds metadata byte budget')
            prepared.append(item)
        rows = [self._allocation_row(item) for item in prepared]
        self.connection.executemany('INSERT INTO allocations(segment,cluster,logical_offset,size,native_tag,name_id,element_count,vector,template_id,context_id,page_offset,tag_relative_offset,tag_word_index,instance_index) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)

    def _intern(self, table, value):
        return self._intern_raw(table, encode_json(value))

    def _intern_raw(self, table, raw):
        key = (table, raw)
        cached = self._intern_cache.get(key)
        if cached is not None:
            return cached
        digest = hashlib.sha256(raw).hexdigest()
        self.connection.execute(f'INSERT OR IGNORE INTO {table}(digest,metadata) VALUES (?,?)', (digest, raw.decode()))
        row = self.connection.execute(f'SELECT id FROM {table} WHERE digest=?', (digest,)).fetchone()[0]
        self._intern_cache.put(key, row)
        return row

    def finish_allocations(self) -> None:
        """Build a deferred query index before discovery or reader use."""
        if self._defer_allocation_index:
            self.connection.execute('CREATE INDEX allocations_type ON allocations(name_id,segment,cluster,logical_offset)')
            self._defer_allocation_index = False

    def _pointer_row(self, segment, cluster, logical_offset, width, raw, target=None, *, status=None, metadata=None):
        if width not in (4, 8) or not isinstance(raw, bytes) or len(raw) != width:
            raise StoreError('Pointer width/raw bytes disagree')
        self._bounds(segment, cluster, logical_offset, width)
        status = status or ('RESOLVED' if target is not None else 'NULL')
        if status not in ('RESOLVED', 'NULL', 'UNRESOLVED') or (status == 'RESOLVED') != (target is not None):
            raise StoreError('Pointer target/status disagree')
        if is_dataclass(target):
            target = asdict(target)
        if target is not None and target.get('database') is not None and (target['database'] != self.source.get('database_id')):
            raise StoreError('External database pointer must be retained as UNRESOLVED')
        destination = _address(target) if target is not None else (None, None, None)
        if target is not None:
            self._bounds(*destination, 1)
        return (segment, cluster, logical_offset, width, raw, status, *destination, encode_json(metadata or {}).decode())

    def add_pointer(self, segment, cluster, logical_offset, width, raw, target=None, *, status=None, metadata=None):
        row = self._pointer_row(segment, cluster, logical_offset, width, raw, target,
                                status=status, metadata=metadata)
        self.connection.execute('INSERT INTO pointers VALUES (?,?,?,?,?,?,?,?,?,?)', row)

    def add_pointers(self, records: Iterable[dict]) -> None:
        """Validate a bounded PRM page before ordered batch insertion."""
        rows = []
        for record in records:
            if len(rows) >= 1024:
                raise StoreError('Pointer batch exceeds one 4 KiB PRM page')
            rows.append(self._pointer_row(**record))
        self.connection.executemany('INSERT INTO pointers VALUES (?,?,?,?,?,?,?,?,?,?)', rows)

    def _put_document_raw(self, kind, name, raw):
        """Store internally prepared canonical bytes with the usual byte/depth checks."""
        if not isinstance(raw, bytes) or len(raw) > MAX_BLOB_BYTES:
            raise StoreError('Prepared document bytes exceed leaf policy')
        _check_json_text(raw, ResourcePolicy())
        self.connection.execute('INSERT INTO documents VALUES (?,?,?)', (kind, name, self._blob(raw)))

    def _enable_document_index(self):
        if not self.connection.execute("SELECT 1 FROM sqlite_master WHERE name='document_nodes'").fetchone():
            self.connection.executescript(DOCUMENT_INDEX_SCHEMA)
            self.connection.execute(f'PRAGMA user_version={INDEXED_VERSION}')
            self.set_manifest('version', INDEXED_VERSION)
            self.set_manifest('required_capabilities', ['indexed_documents_v1'])
            self.set_manifest('document_index', dict(version=DOCUMENT_INDEX_VERSION, table='document_nodes', leaf_bytes=MAX_BLOB_BYTES, compatibility='Readers supporting only store version 1 must reject version 2'))

    def put_pointer_page(self, name, value):
        """Opt-in factoring; expose the same detached JSON through document()."""
        raw = _bounded_encode_json(value, MAX_BLOB_BYTES)
        if raw is not None and self._put_pointer_page_raw(name, raw):
            return
        self.put_document('pointer_page', name, value)

    def _put_pointer_page_raw(self, name, raw):
        """Reuse already bounded canonical bytes; return whether factoring won."""
        from .pointer_evidence import pack_pointer_page, CAPABILITY, FORMAT as PAGE_FORMAT
        packed = pack_pointer_page(raw)
        compressed = zlib.compress(packed, self.compression_level) if packed is not None else None
        if compressed is None or len(compressed) >= len(zlib.compress(raw, self.compression_level)):
            return False
        self._enable_document_index()
        row = self.connection.execute("SELECT value FROM manifest WHERE key='required_capabilities'").fetchone()
        capabilities = decode_json(row[0])
        if CAPABILITY not in capabilities:
            self.set_manifest('required_capabilities', [*capabilities, CAPABILITY])
            self.set_manifest('pointer_page_encoding', dict(version=1, format=PAGE_FORMAT,
                document_kind='pointer_page', canonical_json_preserved=True))
        self.connection.execute('INSERT INTO documents VALUES (?,?,?)',
            ('pointer_page', name, self._blob(packed, compressed=compressed)))
        return True

    def put_document(self, kind, name, value):
        """Store ordinary v1 JSON or a v2 indexed tree, without truncation.

        Exact builtin aggregates use full incremental validation and retain
        only a bounded prefix. Other values retain canonical conversion hooks.
        Reading fetches bounded leaves; an oversized scalar cannot be split.
        """
        raw = _bounded_encode_json(value, MAX_BLOB_BYTES)
        if raw is not None:
            self._put_document_raw(kind, name, raw)
            return
        if not isinstance(value, (dict, list)):
            raise StoreError('Oversized document scalar cannot be split')
        self._enable_document_index()

        def split(item, parts, parent=None, member=None, ordinal=0):
            if len(parts) > ResourcePolicy().max_json_depth:
                raise StoreError('Indexed document nesting exceeds resource policy')
            path = encode_json(parts).decode()
            if len(path.encode('utf-8')) > MAX_BLOB_BYTES:
                raise StoreError('Indexed document path bytes exceed resource policy')
            data = _bounded_encode_json(item, MAX_BLOB_BYTES)
            if data is not None:
                _check_json_text(data, ResourcePolicy(max_json_depth=max(1, 64 - len(parts))))
                node_type, count, digest = ('leaf', 0, self._blob(data))
            elif isinstance(item, (dict, list)):
                node_type, count, digest = ('mapping' if isinstance(item, dict) else 'sequence', len(item), None)
            else:
                raise StoreError('Oversized document scalar cannot be split')
            self.connection.execute('INSERT INTO document_nodes VALUES (?,?,?,?,?,?,?,?,?)', (kind, name, path, parent, member, ordinal, node_type, count, digest))
            if node_type != 'leaf':
                entries = item.items() if node_type == 'mapping' else enumerate(item)
                for index, (key, child) in enumerate(entries):
                    key = str(key)
                    split(child, parts + [key], path, key, index)
        self.connection.execute('SAVEPOINT put_document_index')
        try:
            marker = {'format': 'fsdx-document-index', 'version': DOCUMENT_INDEX_VERSION}
            self.connection.execute('INSERT INTO documents VALUES (?,?,?)', (kind, name, self._blob(encode_json(marker))))
            split(value, [])
            self.connection.execute('RELEASE put_document_index')
        except BaseException:
            self.connection.execute('ROLLBACK TO put_document_index')
            self.connection.execute('RELEASE put_document_index')
            raise

    def finish(self, *, pointer_resolution_complete=False, require_full_cluster_coverage=True):
        """Validate capture structure, commit COMPLETE, close and sync the file.

        ``pointer_resolution_complete`` records the caller's assertion that the
        supported pointer-binding enumeration is complete. It permits readers
        to treat an absent binding with an all-zero stored word as null. Explicit
        UNRESOLVED bindings remain unresolved even when this flag is True; it
        asserts neither universal target resolution nor application semantics.
        The field name is retained for compatibility. This method does not
        establish or compare that enumeration against the native source itself.

        ``require_full_cluster_coverage`` checks stored logical chunks cover
        each declared allocated cluster range. Return table counts on success.
        COMPLETE is committed before the final close/sync, so a later exception
        does not prove that the path contains an incomplete store. Publication
        and full source-comparison verification belong to the caller.
        """
        if type(pointer_resolution_complete) is not bool or type(require_full_cluster_coverage) is not bool:
            raise StoreError('Completion flags must be explicit booleans')
        if require_full_cluster_coverage:
            for seg, cid, allocated in self.connection.execute('SELECT segment,cluster,allocated_bytes FROM clusters'):
                end = 0
                for start, length in self.connection.execute('SELECT logical_start,length FROM chunks WHERE segment=? AND cluster=? ORDER BY logical_start', (seg, cid)):
                    if start != end:
                        raise StoreError('Logical chunk coverage has a gap')
                    end += length
                if end != allocated:
                    raise StoreError('Logical chunk coverage incomplete')
        bad = self.connection.execute('PRAGMA foreign_key_check').fetchone()
        if bad:
            raise StoreError(f'Foreign-key integrity failure: {bad}')
        _validate_address_intervals(self.connection)
        counts = {t: self.connection.execute(f'SELECT count(*) FROM {t}').fetchone()[0] for t in ('clusters', 'chunks', 'extents', 'allocations', 'allocation_templates', 'allocation_contexts', 'names', 'pointers', 'documents', 'blobs')}
        if self.connection.execute("SELECT 1 FROM sqlite_master WHERE name='document_nodes'").fetchone():
            counts['document_nodes'] = self.connection.execute('SELECT count(*) FROM document_nodes').fetchone()[0]
        self.finish_allocations()
        self.set_manifest('counts', counts)
        self.set_manifest('relational_integrity', _row_integrity(self.connection))
        self.set_manifest('pointer_resolution_complete', bool(pointer_resolution_complete))
        self.set_manifest('full_cluster_coverage', bool(require_full_cluster_coverage))
        self.set_manifest('state', 'COMPLETE')
        self.connection.commit()
        self.close()
        with self.path.open('rb') as stream:
            os.fsync(stream.fileno())
        return counts

    def close(self):
        if not self.closed:
            self.connection.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

def _sql_resource_error(error):
    if getattr(error, 'sqlite_errorcode', None) == sqlite3.SQLITE_TOOBIG:
        raise StoreError('SQLite row/value bytes exceed resource policy') from error
    raise error


class _PolicyCursor(sqlite3.Cursor):
    _source_rows = 0

    def _check_source(self):
        guard = getattr(self.connection, '_source_guard', None)
        if guard is not None:
            guard()

    def execute(self, *args, **kwargs):
        self._source_rows = 0
        self._check_source()
        try: return super().execute(*args, **kwargs)
        except sqlite3.Error as error: _sql_resource_error(error)
        finally: self._check_source()

    def fetchone(self):
        self._check_source()
        try: return super().fetchone()
        except sqlite3.Error as error: _sql_resource_error(error)
        finally: self._check_source()

    def fetchall(self):
        self._check_source()
        try: return super().fetchall()
        except sqlite3.Error as error: _sql_resource_error(error)
        finally: self._check_source()

    def fetchmany(self, *args):
        self._check_source()
        try: return super().fetchmany(*args)
        except sqlite3.Error as error: _sql_resource_error(error)
        finally: self._check_source()

    def __next__(self):
        # SQL reads use an immutable snapshot. Streaming selectors check first,
        # every 256 rows and exhaustion; at most 255 selectors lie between
        # checks. Actual public raw/cache reads and publication remain strict.
        if self._source_rows % 256 == 0:
            self._check_source()
        try:
            row = super().__next__()
        except StopIteration:
            self._check_source()
            raise
        except sqlite3.Error as error:
            self._check_source()
            _sql_resource_error(error)
        self._source_rows += 1
        if self._source_rows % 256 == 0:
            self._check_source()
        return row


def _closed_store_guard():
    raise StoreError('Portable store is closed')


class _PolicyConnection(sqlite3.Connection):
    def cursor(self, factory=_PolicyCursor):
        return super().cursor(factory)

    def execute(self, *args, **kwargs):
        return self.cursor().execute(*args, **kwargs)


class Store:
    """Read an immutable standalone FSDX; SQLite source sidecars are forbidden.

    Checkpoint ledgers use separate connections and are outside this contract.
    """

    def __init__(self, path, *, cache_bytes=32 * 1024 * 1024, resource_policy=None):
        self.resource_policy = resource_policy or ResourcePolicy()
        if not isinstance(self.resource_policy, ResourcePolicy):
            raise StoreError('Invalid reader resource policy')
        self.path = Path(path).resolve()
        self._source_path = self.path
        # Cache only immutable lexical inputs, never filesystem observations.
        self._source_paths = _source_paths(self.path)
        self._source_invalid = None
        self._source_identity = _standalone_source_identity(*self._source_paths)
        self.closed = False
        self.connection = sqlite3.connect(self.path.as_uri() + '?mode=ro&immutable=1', uri=True, factory=_PolicyConnection)
        self.connection._source_guard = self.check_identity
        try:
            self.connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, self.resource_policy.max_sqlite_length_bytes)
            self.sqlite_length_limit_bytes = self.connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute('PRAGMA query_only=ON')
            self.connection.execute('PRAGMA trusted_schema=OFF')
            self._cache = OrderedDict()
            self._cache_size = 0
            self.cache_bytes = _integer(cache_bytes, 'cache_bytes')
            self._metadata_cache = _BoundedCache()
            if self.connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID:
                raise StoreError('Not an FSDX portable store')
            store_version = self.connection.execute('PRAGMA user_version').fetchone()[0]
            if store_version not in (VERSION, INDEXED_VERSION):
                raise StoreError('Unsupported portable store version')
            if self.connection.execute('SELECT 1 FROM manifest WHERE length(CAST(value AS BLOB))>? OR length(CAST(key AS BLOB))>? LIMIT 1', (self.resource_policy.max_json_bytes, self.resource_policy.max_json_bytes)).fetchone():
                raise StoreError('Manifest JSON bytes exceed resource policy')
            self.manifest = {r['key']: decode_json(r['value'], self.resource_policy) for r in self.connection.execute('SELECT * FROM manifest')}
            if self.manifest.get('format') != FORMAT or type(self.manifest.get('version')) is not int or self.manifest.get('version') != store_version or self.manifest.get('state') != 'COMPLETE':
                raise StoreError('Portable store is incomplete or incompatible')
            capabilities = self.manifest.get('required_capabilities', [])
            if not isinstance(capabilities, list) or any((not isinstance(c, str) for c in capabilities)) or len(capabilities) != len(set(capabilities)) or set(capabilities) - {'indexed_documents_v1', 'compact_pointer_pages_v1'}:
                raise StoreError('Unsupported portable store capability')
            self._indexed = store_version == INDEXED_VERSION
            index = self.manifest.get('document_index')
            if not self._indexed and capabilities:
                raise StoreError('Portable store capability/version disagree')
            if self._indexed and ('indexed_documents_v1' not in capabilities or not isinstance(index, dict) or type(index.get('version')) is not int or index.get('version') != DOCUMENT_INDEX_VERSION):
                raise StoreError('Unsupported document index version')
            if self._indexed and (not self.connection.execute("SELECT 1 FROM sqlite_master WHERE name='document_nodes'").fetchone()):
                raise StoreError('Missing document index')
            self._compact_pointer_pages = 'compact_pointer_pages_v1' in capabilities
            declaration = self.manifest.get('pointer_page_encoding')
            if self._compact_pointer_pages:
                if (not isinstance(declaration, dict) or type(declaration.get('version')) is not int
                        or declaration['version'] != 1 or declaration.get('format') != 'fsdx-pointer-page'
                        or declaration.get('document_kind') != 'pointer_page'
                        or declaration.get('canonical_json_preserved') is not True):
                    raise StoreError('Unsupported compact pointer-page declaration')
            elif declaration is not None:
                raise StoreError('Pointer-page declaration requires its reader capability')
        except sqlite3.DatabaseError as exc:
            self.close()
            raise StoreError('Invalid portable store SQL container') from exc
        except Exception:
            self.close()
            raise

    def _check_source(self):
        if self._source_invalid is not None:
            raise StoreError(self._source_invalid)
        try:
            if self.path != self._source_path:
                raise StoreError('Portable source changed during reader session')
            _standalone_source_identity(*self._source_paths, admitted_identity=self._source_identity)
        except StoreError as exc:
            self._source_invalid = str(exc)
            raise

    def check_identity(self) -> None:
        """Reject main-file drift or source sidecars before read/publication."""
        if self.closed:
            raise StoreError('Portable store is closed')
        self._check_source()

    def _blob(self, digest):
        self._ensure_open()
        if digest in self._cache:
            self._cache.move_to_end(digest)
            return self._cache[digest]
        policy = self.resource_policy
        row = self.connection.execute("""SELECT
            CASE WHEN codec IN ('raw','zlib') THEN codec ELSE NULL END AS codec,
            CASE WHEN typeof(raw_length)='integer' THEN raw_length ELSE NULL END AS raw_length,
            length(data) AS stored_length,
            CASE WHEN codec IN ('raw','zlib') AND typeof(raw_length)='integer'
                AND raw_length BETWEEN 0 AND ? AND length(data) BETWEEN 0 AND ?
                AND typeof(data)='blob' AND (codec!='raw' OR length(data)=raw_length)
                THEN data ELSE NULL END AS admitted_data
            FROM blobs WHERE sha256=?""", (policy.max_uncompressed_blob_bytes,
                policy.max_stored_blob_bytes, digest)).fetchone()
        if row is None:
            raise StoreError('Missing blob')
        codec, size, stored = (row['codec'], row['raw_length'], row['stored_length'])
        if codec not in ('raw', 'zlib'):
            raise StoreError('Unknown blob codec')
        if type(size) is not int or not 0 <= size <= policy.max_uncompressed_blob_bytes:
            raise StoreError('Uncompressed blob bytes exceed resource policy')
        if type(stored) is not int or not 0 <= stored <= policy.max_stored_blob_bytes:
            raise StoreError('Stored blob bytes exceed resource policy')
        if codec == 'raw' and stored != size:
            raise StoreError('Blob length integrity failure')
        packed = row['admitted_data']
        if packed is None:
            raise StoreError('Blob changed or has invalid storage type')
        if row['codec'] == 'raw':
            raw = packed
        elif row['codec'] == 'zlib':
            try:
                decoder = zlib.decompressobj()
                raw = decoder.decompress(packed, size + 1)
                if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                    raise StoreError('Invalid or excessive compressed blob')
            except zlib.error as exc:
                raise StoreError('Invalid compressed blob') from exc
        else:
            raise StoreError('Unknown blob codec')
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise StoreError('Blob length/SHA256 integrity failure')
        if len(raw) <= self.cache_bytes:
            while self._cache and self._cache_size + len(raw) > self.cache_bytes:
                _, old = self._cache.popitem(last=False)
                self._cache_size -= len(old)
            self._cache[digest] = raw
            self._cache_size += len(raw)
        return raw

    def iter_clusters(self, segment=None):
        sql = 'SELECT ' + self._bounded_metadata('metadata') + ' AS metadata FROM clusters'
        args = ()
        if segment is not None:
            sql += ' WHERE segment=?'
            args = (segment,)
        for row in self.connection.execute(sql + ' ORDER BY segment,cluster', args):
            yield self._decode_metadata(row[0])

    def read(self, segment, cluster, offset, size):
        self.check_identity()
        for value, name in [(segment, 'segment'), (cluster, 'cluster'), (offset, 'offset'), (size, 'size')]:
            _integer(value, name)
        row = self.connection.execute('SELECT allocated_bytes FROM clusters WHERE segment=? AND cluster=?', (segment, cluster)).fetchone()
        if row is None or offset + size > row[0]:
            raise StoreError('Read exceeds cluster')
        result = []
        remaining = size
        while remaining:
            row = self.connection.execute('SELECT * FROM chunks WHERE segment=? AND cluster=? AND logical_start<=? ORDER BY logical_start DESC LIMIT 1', (segment, cluster, offset)).fetchone()
            if row is None or offset >= row['logical_start'] + row['length']:
                raise StoreError('Read crosses unstored logical gap')
            raw = self._blob(row['blob_sha256'])
            if len(raw) != row['length']:
                raise StoreError('Chunk/blob length mismatch')
            start = offset - row['logical_start']
            take = min(remaining, len(raw) - start)
            result.append(raw[start:start + take])
            offset += take
            remaining -= take
        raw = b''.join(result)
        self.check_identity()
        return raw

    def captured_unresolved_reference(self, segment, cluster, offset, width=4, raw=None):
        """Return checked explicit UNRESOLVED evidence, otherwise None.

        This opt-in evidence interface never resolves a target. Strict resolve
        remains authoritative for NULL/resolved entries and missing bindings.
        """
        if width not in (4, 8):
            raise StoreError('Unsupported pointer width')
        observed = self.read(segment, cluster, offset, width)
        if raw is not None and raw != observed:
            raise StoreError('Pointer bytes disagree with stored snapshot')
        row = self.connection.execute('SELECT width,raw,status,target_segment,target_cluster,target_offset,' +
            self._bounded_metadata('metadata') + ' AS metadata FROM pointers WHERE segment=? AND cluster=? AND logical_offset=?',
            (segment, cluster, offset)).fetchone()
        if row is None:
            if self.manifest.get('pointer_resolution_complete') and observed == bytes(width):
                self.check_identity()
                return None
            raise StoreError('Pointer binding is not recorded')
        if row['width'] != width or row['raw'] != observed:
            raise StoreError('Pointer binding width/bytes mismatch')
        if row['status'] not in ('NULL', 'RESOLVED', 'UNRESOLVED'):
            raise StoreError('Invalid captured pointer status')
        targets = tuple(row[key] for key in ('target_segment', 'target_cluster', 'target_offset'))
        if (row['status'] == 'RESOLVED' and any(type(v) is not int or v < 0 for v in targets)
                or row['status'] != 'RESOLVED' and any(v is not None for v in targets)):
            raise StoreError('Captured pointer status/target mismatch')
        self.check_identity()
        if row['status'] != 'UNRESOLVED':
            return None
        metadata = self._decode_metadata(row['metadata'])
        if not isinstance(metadata, dict):
            raise StoreError('Captured pointer metadata must be an object')
        self.check_identity()
        return dict(status='UNRESOLVED', width=width, raw_hex=observed.hex(),
            segment=segment, cluster=cluster, offset=offset, resolution_metadata=metadata)

    def resolve(self, segment, cluster, offset, width=4, raw=None):
        if width not in (4, 8):
            raise StoreError('Unsupported pointer width')
        observed = self.read(segment, cluster, offset, width)
        if raw is not None and raw != observed:
            raise StoreError('Pointer bytes disagree with stored snapshot')
        row = self.connection.execute('SELECT width,raw,status,target_segment,target_cluster,target_offset FROM pointers WHERE segment=? AND cluster=? AND logical_offset=?', (segment, cluster, offset)).fetchone()
        if row is None:
            if self.manifest.get('pointer_resolution_complete') and observed == bytes(width):
                return None
            raise StoreError('Pointer binding is not recorded')
        if row['width'] != width or row['raw'] != observed:
            raise StoreError('Pointer binding width/bytes mismatch')
        if row['status'] == 'NULL':
            return None
        if row['status'] == 'UNRESOLVED':
            raise StoreError('Pointer was explicitly unresolved during ingestion')
        return dict(segment=row['target_segment'], cluster=row['target_cluster'], offset=row['target_offset'])

    def iter_allocations(self, *, segment=None, cluster=None, name=None):
        terms = []
        args = []
        for key, value in [('a.segment', segment), ('a.cluster', cluster), ('n.name', name)]:
            if value is not None:
                terms.append(key + '=?')
                args.append(value)
        sql = self._allocation_query() + (' WHERE ' + ' AND '.join(terms) if terms else '') + ' ORDER BY a.segment,a.cluster,a.logical_offset'
        for row in self.connection.execute(sql, args):
            yield self._allocation_record(row)

    def _bounded_metadata(self, field):
        # Field names are exclusively internal constants; policy is a checked int.
        return f'CASE WHEN length(CAST({field} AS BLOB))<={self.resource_policy.max_json_bytes} THEN {field} ELSE NULL END'

    def _decode_metadata(self, raw):
        if raw is None: raise StoreError('Metadata JSON bytes exceed resource policy')
        return decode_json(raw, self.resource_policy)

    def _allocation_query(self):
        return ('SELECT a.*,' + self._bounded_metadata('n.name') + ' AS name,' +
            self._bounded_metadata('t.metadata') + ' AS template,' +
            self._bounded_metadata('c.metadata') + ' AS context FROM allocations a '
            'JOIN names n ON n.id=a.name_id JOIN allocation_templates t ON t.id=a.template_id '
            'JOIN allocation_contexts c ON c.id=a.context_id')

    def _allocation_record(self, row, *, for_proof=False):
        """Restore a record; proof-only children are borrowed for immediate hashing.

        Public readers always use detached metadata. The private proof path never
        exposes or mutates cached children and omits only normalized exclusions.
        """
        if row['name'] is None: raise StoreError('Allocation name bytes exceed resource policy')
        result = self._metadata_copy(row['template'], borrow=for_proof)
        if for_proof:
            result = {k: v for k, v in result.items() if k not in ('address', 'physical_spans', 'store_allocation_id')}
        result.update(segment=row['segment'], cluster=row['cluster'], logical_offset=row['logical_offset'], size=row['size'], native_tag=row['native_tag'], name=row['name'], count=row['element_count'], vector=bool(row['vector']), source_metadata=self._metadata_copy(row['context'], borrow=for_proof))
        if not for_proof:
            result['store_allocation_id'] = row['id']
        for key in ('page_offset', 'tag_relative_offset', 'tag_word_index', 'instance_index'):
            if row[key] is not None:
                result[key] = row[key]
            elif for_proof and result.get(key) is None:
                result.pop(key, None)
        return result

    def _metadata_copy(self, raw, *, borrow=False):
        if raw is None: raise StoreError('Metadata JSON bytes exceed resource policy')
        plan = self._metadata_cache.get(raw)
        if plan is None:
            plan = _copy_plan(decode_json(raw, self.resource_policy))
            self._metadata_cache.put(raw, plan)
        return plan[0] if borrow else _copy_metadata(plan)

    def allocation_at(self, segment, cluster, offset):
        """Return the current allocation containing an offset, or None."""
        for value, name in [(segment, 'segment'), (cluster, 'cluster'), (offset, 'offset')]:
            _integer(value, name)
        row = self.connection.execute(self._allocation_query() + ' WHERE a.segment=? AND a.cluster=? AND a.logical_offset<=? ORDER BY a.logical_offset DESC LIMIT 1', (segment, cluster, offset)).fetchone()
        return self._allocation_record(row) if row and offset < row['logical_offset'] + row['size'] else None

    def spans(self, segment, cluster, offset, size):
        """Source-file provenance only; no source file is opened."""
        for value, name in [(segment, 'segment'), (cluster, 'cluster'), (offset, 'offset'), (size, 'size')]:
            _integer(value, name)
        result = []
        remaining = size
        while remaining:
            row = self.connection.execute('SELECT id,segment,cluster,logical_start,physical_start,length,' + self._bounded_metadata('metadata') + ' AS metadata FROM extents WHERE segment=? AND cluster=? AND logical_start<=? ORDER BY logical_start DESC LIMIT 1', (segment, cluster, offset)).fetchone()
            if row is None or offset >= row['logical_start'] + row['length']:
                raise StoreError('Missing physical provenance extent')
            delta = offset - row['logical_start']
            take = min(remaining, row['length'] - delta)
            result.append(dict(segment=segment, cluster=cluster, logical_start=offset, physical_start=row['physical_start'] + delta, length=take, extent=self._decode_metadata(row['metadata'])))
            offset += take
            remaining -= take
        return result

    def _document_node(self, kind, name, row):
        path, node_type, count, digest = row
        if path is None: raise StoreError('Indexed document path bytes exceed resource policy')
        if type(count) is not int or count < 0:
            raise StoreError('Invalid indexed document child count')
        if node_type == 'leaf' and digest is not None and (count == 0):
            parts = decode_json(path, self.resource_policy)
            if not isinstance(parts, list) or len(parts) > self.resource_policy.max_json_depth:
                raise StoreError('Indexed document nesting exceeds resource policy')
            policy = self.resource_policy
            leaf_policy = ResourcePolicy(policy.max_stored_blob_bytes, policy.max_uncompressed_blob_bytes, policy.max_json_bytes, max(1, policy.max_json_depth - len(parts)), policy.max_sqlite_length_bytes)
            value = decode_json(self._blob(digest), leaf_policy)
            if len(parts) + _json_depth(value) > policy.max_json_depth:
                raise StoreError('Indexed document nesting exceeds resource policy')
            return value
        if digest is not None:
            raise StoreError('Invalid indexed document node blob')
        observed = self.connection.execute('SELECT count(*) FROM document_nodes WHERE kind=? AND name=? AND parent=?', (kind, name, path)).fetchone()[0]
        if count != observed:
            raise StoreError('Indexed document child count mismatch')
        if node_type == 'mapping':
            return IndexedDocumentMapping(self, kind, name, path, count)
        if node_type == 'sequence':
            return IndexedDocumentSequence(self, kind, name, path, count)
        raise StoreError('Unsupported indexed document node type')

    def document(self, kind, name, *, lazy=False):
        """v1 returns detached JSON; v2 split aggregates return lazy containers.

        lazy is accepted for callers declaring their intent; indexed aggregates
        always remain lazy. materialize_document explicitly expands an aggregate.
        """
        row = self.connection.execute('SELECT blob_sha256 FROM documents WHERE kind=? AND name=?', (kind, name)).fetchone()
        if row is None:
            raise StoreError(f'Missing document: {kind}/{name}')
        return self._document_from_raw(kind, name, self._blob(row[0]))

    def _document_from_raw(self, kind, name, raw):
        """Apply the same document contracts to already integrity-checked bytes."""
        if self._indexed:
            node = self.connection.execute('SELECT ' + self._bounded_metadata('path') + ',node_type,child_count,blob_sha256 FROM document_nodes WHERE kind=? AND name=? AND path=?', (kind, name, '[]')).fetchone()
            if node is not None:
                marker = decode_json(raw, self.resource_policy)
                if not isinstance(marker, dict) or type(marker.get('version')) is not int or marker != {'format': 'fsdx-document-index', 'version': DOCUMENT_INDEX_VERSION}:
                    raise StoreError('Invalid indexed document marker')
                return self._document_node(kind, name, node)
        value = decode_json(raw, self.resource_policy)
        if kind == 'pointer_page' and isinstance(value, dict) and value.get('format') == 'fsdx-pointer-page':
            if not self._compact_pointer_pages:
                raise StoreError('Compact pointer-page capability is missing')
            from .pointer_evidence import unpack_pointer_page
            return unpack_pointer_page(value, self.resource_policy)
        if self._indexed and value == {'format': 'fsdx-document-index', 'version': DOCUMENT_INDEX_VERSION}:
            raise StoreError('Missing indexed document root')
        return value

    def document_mapping(self, kind, name, *path):
        value = self.document(kind, name, lazy=True)
        for key in path:
            value = value[key]
        if not isinstance(value, Mapping):
            raise StoreError('Document path is not a mapping')
        return value

    def iter_documents(self, kind=None):
        sql = 'SELECT kind,name FROM documents'
        args = ()
        if kind is not None:
            sql += ' WHERE kind=?'
            args = (kind,)
        for row in self.connection.execute(sql + ' ORDER BY kind,name', args):
            yield tuple(row)

    def _verify_blobs_documents(self, lower=None, upper=None, cancel=None):
        """Check each BLOB and document use in an optional ordered digest range."""
        terms, args = [], []
        if lower is not None:
            terms.append('>=?')
            args.append(lower)
        if upper is not None:
            terms.append('<?')
            args.append(upper)
        blob_where = ' WHERE ' + ' AND '.join('sha256' + term for term in terms) if terms else ''
        document_where = ' WHERE ' + ' AND '.join('blob_sha256' + term for term in terms) if terms else ''
        blobs_checked = documents_checked = 0
        documents = iter(self.connection.execute(
            'SELECT blob_sha256,kind,name FROM documents' + document_where + ' ORDER BY blob_sha256,kind,name', args))
        document = next(documents, None)
        for row in self.connection.execute('SELECT sha256 FROM blobs' + blob_where + ' ORDER BY sha256', args):
            if cancel is not None:
                cancel()
            raw = self._blob(row[0])
            blobs_checked += 1
            while document is not None and document[0] == row[0]:
                self._document_from_raw(document[1], document[2], raw)
                documents_checked += 1
                document = next(documents, None)
            if document is not None and document[0] < row[0]:
                raise StoreError('Missing document blob')
        if document is not None:
            raise StoreError('Missing document blob')
        self.check_identity()
        return dict(blobs=blobs_checked, documents=documents_checked)

    def verify(self, *, full: bool = True, workers: int = 1) -> dict:
        if type(full) is not bool:
            raise StoreError('Verification mode must be an explicit boolean')
        if type(workers) is not int or not 1 <= workers <= 4:
            raise StoreError('Verification workers must be an integer from 1 to 4')
        if not full and workers != 1:
            raise StoreError('Parallel verification requires full mode')
        result = self.connection.execute('PRAGMA integrity_check' if full else 'PRAGMA quick_check').fetchone()[0]
        if result != 'ok':
            raise StoreError(f'SQLite integrity check failed: {result}')
        if self.connection.execute('PRAGMA foreign_key_check').fetchone():
            raise StoreError('Foreign-key integrity failure')
        if full:
            for table in _row_orders(self.connection):
                for column in self.connection.execute(f'PRAGMA table_info({table})'):
                    if column[2] in ('TEXT', 'BLOB'):
                        field = column[1]
                        if self.connection.execute(f'SELECT 1 FROM {table} WHERE length(CAST({field} AS BLOB))>? LIMIT 1', (self.resource_policy.max_json_bytes,)).fetchone():
                            raise StoreError('Relational metadata bytes exceed resource policy')
            _validate_address_intervals(self.connection)
            self._cache.clear()
            self._cache_size = 0
            if workers == 1:
                self._verify_blobs_documents()
            else:
                from .verification_workers import blob_document_proofs
                blob_document_proofs(self, workers)
            if self._indexed:
                self._verify_document_index()
            for table, expected in self.manifest.get('counts', {}).items():
                if table not in {*_row_orders(self.connection), 'blobs'}:
                    raise StoreError('Unknown table in declared counts')
                if self.connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0] != expected:
                    raise StoreError('Stored row counts differ from manifest')
            for cluster in self.connection.execute('SELECT segment,cluster,allocated_bytes FROM clusters'):
                end = 0
                for start, length in self.connection.execute('SELECT logical_start,length FROM chunks WHERE segment=? AND cluster=? ORDER BY logical_start', (cluster[0], cluster[1])):
                    if start != end or length <= 0:
                        raise StoreError('Logical chunk coverage has gaps or overlap')
                    end += length
                if self.manifest.get('full_cluster_coverage') and end != cluster[2]:
                    raise StoreError('Logical chunk coverage incomplete')
                if end > cluster[2]:
                    raise StoreError('Logical chunks exceed cluster')
            expected = self.manifest.get('relational_integrity')
            if expected is not None:
                if workers == 1:
                    observed = _row_integrity(self.connection)
                else:
                    from .verification_workers import table_proofs
                    observed = table_proofs(self, workers)
                if observed != expected:
                    raise StoreError('Relational metadata SHA256 integrity failure')
        return {'sqlite': 'ok', 'verification_mode': 'FULL_VERIFIED' if full else 'QUICK_CHECKED', 'full_verified': bool(full), 'quick_checked': not full, 'blob_hashes_verified': bool(full), 'source_required': False, 'address_intervals_verified': bool(full), 'relational_hashes_verified': bool(full and self.manifest.get('relational_integrity')), 'logical_coverage_verified': bool(full), 'relational_integrity_status': 'VERIFIED' if full and self.manifest.get('relational_integrity') else 'NOT_RECORDED' if not self.manifest.get('relational_integrity') else 'NOT_CHECKED'}

    def _verify_document_index(self):
        """Validate the complete tree with bounded row and leaf memory."""
        orphan = self.connection.execute("SELECT 1 FROM document_nodes n\n            LEFT JOIN documents d ON n.kind=d.kind AND n.name=d.name\n            LEFT JOIN document_nodes p ON n.kind=p.kind AND n.name=p.name AND n.parent=p.path\n            WHERE d.kind IS NULL OR (n.parent IS NOT NULL AND\n            (p.path IS NULL OR p.node_type NOT IN ('mapping','sequence'))) LIMIT 1").fetchone()
        if orphan:
            raise StoreError('Orphan indexed document node')
        for row in self.connection.execute('SELECT * FROM document_nodes ORDER BY kind,name,path'):
            parts = decode_json(row['path'], self.resource_policy)
            if not isinstance(parts, list) or any((not isinstance(p, str) for p in parts)) or len(parts) > self.resource_policy.max_json_depth:
                raise StoreError('Invalid indexed document path')
            if row['ordinal'] < 0:
                raise StoreError('Invalid indexed document ordinal')
            if not parts:
                if row['parent'] is not None or row['member'] is not None or row['ordinal'] != 0:
                    raise StoreError('Invalid indexed document root')
            elif row['parent'] != encode_json(parts[:-1]).decode() or row['member'] != parts[-1]:
                raise StoreError('Invalid indexed document parent path')
            value = self._document_node(row['kind'], row['name'], (row['path'], row['node_type'], row['child_count'], row['blob_sha256']))
            if row['node_type'] != 'leaf':
                ordinal = 0
                for member, index in self.connection.execute('SELECT member,ordinal FROM document_nodes WHERE kind=? AND name=? AND parent=? ORDER BY ordinal', (row['kind'], row['name'], row['path'])):
                    if index != ordinal or (row['node_type'] == 'sequence' and member != str(ordinal)):
                        raise StoreError('Invalid indexed document child ordering')
                    ordinal += 1
            elif len(parts) + _json_depth(value) > self.resource_policy.max_json_depth:
                raise StoreError('Indexed document nesting exceeds resource policy')

    def _ensure_open(self):
        self.check_identity()

    def close(self):
        if not self.closed:
            self.connection.close()
            self.closed = True
            # A bound guard keeps the closed Store (and its caches) alive via
            # Store -> connection -> guard -> Store. Preserve closed-cursor
            # rejection without retaining the reader until cyclic collection.
            self.connection._source_guard = _closed_store_guard
            cache = getattr(self, '_cache', None)
            if cache is not None:
                cache.clear()
            self._cache_size = 0
            metadata = getattr(self, '_metadata_cache', None)
            if metadata is not None:
                metadata.values.clear()
                metadata.bytes = 0

    def __enter__(self):
        self.check_identity()
        return self

    def __exit__(self, *args):
        self.close()
