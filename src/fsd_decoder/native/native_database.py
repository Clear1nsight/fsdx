"""Read-only ObjectStore facade over committed native directory metadata.

No file-wide metadata scans or candidate matching are performed. Unsupported
external addresses and global overflow tables fail explicitly. Pointer chains
are read from the owning segment/cluster's current metadata table.
"""
from functools import lru_cache
from collections import OrderedDict
from dataclasses import asdict
from pathlib import Path
import hashlib
import json
from fsd_decoder.core.native_storage import Address, AddressMap, Extent, MappingError
from fsd_decoder.native.native_directory import parse_database_directory
from fsd_decoder.native.current_metadata import CurrentMetadata
from fsd_decoder.native.prm_fields import decode_heads, walk_decoded_threads
from fsd_decoder.native.root_directory import read_native_roots
from fsd_decoder.native.native_tags import parse_tag_payload
from fsd_decoder.native.page_free_codec import decode_group

class DatabaseError(ValueError):
    pass

class NativeDatabase:
    """Immutable source snapshot with explicit database/segment/cluster addresses."""

    def __init__(self, data, directory=None):
        if not isinstance(data, bytes):
            raise DatabaseError('NativeDatabase requires an immutable bytes snapshot')
        self.data = data
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.directory = parse_database_directory(data) if directory is None else directory
        if not self.directory.get('complete') or self.directory.get('sha256') != self.sha256:
            raise DatabaseError('Directory is incomplete or belongs to another source')
        words = self.directory['header']['dbid']
        if len(words) != 3 or any((type(v) is not int or not 0 <= v <= 4294967295 for v in words)):
            raise DatabaseError('Invalid native database identity')
        self.database_id = ''.join((f'{v:08x}' for v in words))
        self.source_path = None
        self._clusters = {}
        for cluster in self.directory['clusters']:
            token = (cluster['segment'], cluster['cluster'])
            if token in self._clusters:
                raise DatabaseError('Duplicate effective cluster')
            self._clusters[token] = cluster
        extents = []
        for extent in self.directory['effective_extents']:
            if extent['component'] != 0:
                raise DatabaseError('External storage component unsupported')
            extents.append(Extent(self.database_id, extent['segment'], extent['cluster'], extent['logical_start'], extent['physical_start'], extent['length'], json.dumps(extent['provenance'], sort_keys=True)))
        self.address_map = AddressMap(data, extents)
        self._read_cached = lru_cache(maxsize=4096)(self.address_map.read)
        self.current_metadata = CurrentMetadata(data, self.directory)
        self._pointer_pages = OrderedDict()
        self.pointer_page_cache_limit = 512
        self._root_report = None

    @classmethod
    def from_path(cls, path):
        path = Path(path).resolve()
        instance = cls(path.read_bytes())
        instance.source_path = path
        return instance

    def verify_source(self):
        """Recheck a path-backed source after export without altering its bytes."""
        if self.source_path is None:
            return hashlib.sha256(self.data).hexdigest() == self.sha256
        digest = hashlib.sha256()
        with self.source_path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != self.sha256:
            raise DatabaseError('Source file changed after snapshot')
        return True

    def address(self, segment, cluster, offset):
        return Address(self.database_id, segment, cluster, offset)

    def _check_address(self, address):
        if not isinstance(address, Address) or address.database != self.database_id:
            raise DatabaseError('Address belongs to an unsupported external database')
        return address

    def read(self, address, size):
        address = self._check_address(address)
        if type(size) is not int or size < 0:
            raise DatabaseError('Read length must be a nonnegative integer')
        if size > 4096:
            return self.address_map.read(address, size)
        return self._read_cached(address, size)

    def read_at(self, segment, cluster, offset, size):
        return self.read(self.address(segment, cluster, offset), size)

    def spans(self, address, size):
        return self.address_map.spans(self._check_address(address), size)

    def iter_clusters(self, segment=None):
        if segment is not None:
            self.address(segment, 0, 0)
        for token in sorted(self._clusters):
            if segment is None or token[0] == segment:
                yield self._clusters[token]

    def cluster(self, segment, cluster):
        self.address(segment, cluster, 0)
        try:
            return self._clusters[segment, cluster]
        except KeyError as exc:
            raise DatabaseError('Unknown current segment/cluster') from exc

    @staticmethod
    def _entry(entry, table):
        if entry is None:
            return None
        result = dict(entry)
        result['payload'] = result['raw']
        result['table_index'] = table
        spans = result.get('payload_spans', [])
        result['physical_offset'] = spans[0]['physical_offset'] if spans else None
        return result

    def metadata(self, segment, cluster, key, table=1):
        self.cluster(segment, cluster)
        if type(table) is not int or table not in (0, 1):
            raise DatabaseError('Metadata table index must be zero or one')
        return self._entry(self.current_metadata.entry(segment, cluster, key, table_index=table), table)

    def iter_metadata(self, segment, cluster, table=None):
        self.cluster(segment, cluster)
        tables = (0, 1) if table is None else (table,)
        for number in tables:
            if type(number) is not int or number not in (0, 1):
                raise DatabaseError('Metadata table index must be zero or one')
            for entry in self.current_metadata.iter_entries(segment, cluster, table_index=number):
                yield self._entry(entry, number)

    def _page(self, segment, cluster, page_offset):
        self.cluster(segment, cluster)
        if type(page_offset) is not int or page_offset < 0 or page_offset % 4096:
            raise DatabaseError('Page offset must be nonnegative and aligned to 4096 bytes')
        return (segment, cluster, page_offset)

    def page_pointers(self, segment, cluster, page_offset):
        token = self._page(segment, cluster, page_offset)
        if token in self._pointer_pages:
            self._pointer_pages.move_to_end(token)
            return self._pointer_pages[token]
        entry = self.metadata(segment, cluster, page_offset // 4096 * 32 + 18)
        pointers = {}
        if entry is not None:
            heads = decode_heads(entry['raw'], source_segment=segment, source_cluster=cluster)
            available = min(4096, self.cluster(segment, cluster)['allocated_bytes'] - page_offset)
            if available <= 0:
                raise DatabaseError('PRM page lies outside current cluster allocation')
            chains = walk_decoded_threads(self.read_at(segment, cluster, page_offset, available), 0, heads)
            for chain in chains:
                for pointer in chain['pointers']:
                    offset = page_offset + pointer['physical_offset']
                    width = chain['head']['pointer_width'] // 8
                    spans = [asdict(span) for span in self.spans(self.address(segment, cluster, offset), width)]
                    pointers[offset] = {**pointer, 'logical_offset': offset, 'pointer_width': width, 'pointer_width_bits': width * 8, 'page_offset': pointer['physical_offset'], 'physical_offset': spans[0]['physical_start'] if len(spans) == 1 else None, 'physical_spans': spans, 'metadata_key': entry['key'], 'metadata_spans': entry['payload_spans'], 'leaf_reference': entry['leaf_reference']}
        self._pointer_pages[token] = pointers
        while len(self._pointer_pages) > self.pointer_page_cache_limit:
            self._pointer_pages.popitem(last=False)
        return pointers

    def resolve(self, address, width=4, raw=None):
        address = self._check_address(address)
        if width not in (4, 8):
            raise DatabaseError('Pointer width must be four or eight bytes')
        observed = self.read(address, width)
        if raw is not None and raw != observed:
            raise DatabaseError('Pointer bytes disagree with immutable source')
        pointer = self.page_pointers(address.segment, address.cluster, address.offset & ~4095).get(address.offset)
        if pointer is None:
            if observed == b'\x00' * width:
                return None
            raise DatabaseError('Nonzero pointer field is absent from current PRM')
        if pointer['pointer_width'] != width or pointer['raw_hex'] != observed.hex():
            raise DatabaseError('Requested pointer width disagrees with current PRM')
        target = pointer['target']
        if target['database_context'] != {'source_database': True}:
            raise DatabaseError('External database pointer unsupported')
        if target['segment'] is None or target['cluster'] is None:
            raise DatabaseError('Pointer target lacks complete source context')
        destination = self.address(target['segment'], target['cluster'], target['offset'])
        self.cluster(destination.segment, destination.cluster)
        self.address_map.spans(destination, 1)
        return destination

    def tag_payload(self, segment, cluster, page_offset, key_kind=16):
        self._page(segment, cluster, page_offset)
        if key_kind not in (16, 17):
            raise DatabaseError('Allocation key kind must be sixteen or seventeen')
        entry = self.metadata(segment, cluster, page_offset // 4096 * 32 + key_kind)
        return None if entry is None else entry['raw']

    def begin_free(self, segment, cluster, page_offset):
        self._page(segment, cluster, page_offset)
        page = page_offset // 4096
        entry = self.metadata(segment, cluster, ((page & ~15) << 5) + 1, table=0)
        if entry is None:
            raise DatabaseError('Page free-space metadata is absent')
        return decode_group(entry['raw'])['pages'][page & 15]['begin_free_bytes']

    def tags(self, segment, cluster, page_offset, sizes, key_kind=16):
        payload = self.tag_payload(segment, cluster, page_offset, key_kind)
        if payload is None:
            return None
        begin = 0 if key_kind == 17 else self.begin_free(segment, cluster, page_offset)
        return parse_tag_payload(payload, sizes, range_start=begin)

    def roots(self):
        if self._root_report is None:

            def read(address, size):
                return self.read_at(*address, size)

            def resolve(address, raw):
                target = self.resolve(self.address(*address), width=8, raw=raw)
                return None if target is None else (target.segment, target.cluster, target.offset)
            self._root_report = read_native_roots(read, resolve)
        return self._root_report
