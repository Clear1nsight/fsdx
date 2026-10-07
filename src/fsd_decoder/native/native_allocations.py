"""Current native allocation iterator over directory-owned metadata.

No file-wide candidate scanning or specimen offsets are used. The caller's
NativeDatabase supplies current table entries and an extent-aware address map.
"""
from __future__ import annotations
from collections import deque
from fsd_decoder.schema.directory_types import recover_directory_types
from fsd_decoder.native.native_tags import parse_tag_payload, TagError
from fsd_decoder.native.page_free_codec import decode_group

class AllocationError(ValueError):
    pass

def materialize_allocation(db, cluster: dict, entry: dict, begin: int, record: dict, provenance=None) -> dict:
    """Enrich a validated candidate using the immutable native address map.

    Cross-page admission remains the ordered iterator's responsibility.
    """
    seg, cid = cluster['segment'], cluster['cluster']
    page = (entry['key'] >> 5) * 4096
    offset, size = page + record['page_offset'], record['size']
    address = db.address(seg, cid, offset)
    spans = db.spans(address, size)
    header_size = record.get('array_header_size', 0)
    element_size = record.get('element_size', size)
    stride = record.get('element_stride', element_size)
    if record['vector']:
        data_end = header_size + (record['count'] - 1) * stride + element_size
    elif record['name'] == 'inline_char_bytes':
        data_end = record['count']
    else:
        data_end = element_size
    if not 0 <= data_end <= size:
        raise AllocationError('Element data exceeds allocation')
    record['terminal_padding_offset'] = data_end
    record['terminal_padding_size'] = size - data_end
    record['terminal_padding_hex'] = db.read_at(seg, cid, offset + data_end, size - data_end).hex() if size > data_end else ''
    record['array_header_hex'] = db.read_at(seg, cid, offset, header_size).hex() if header_size else ''
    record['inter_element_padding_size'] = stride - element_size if record['vector'] else 0
    if provenance is None:
        provenance = {k: v for k, v in entry.items() if k not in ('payload', 'raw')}
    record.update(segment=seg, cluster=cid, logical_offset=offset, address=address,
        physical_spans=spans, source_metadata=provenance, raw_tag_hex=record['tag_bytes'],
        huge=entry['key'] & 31 == 17, begin_free_bytes=begin)
    return record

def build_native_types(data, directory=None, *, allow_partial_representations=False):
    return recover_directory_types(data, directory, allow_partial_representations=allow_partial_representations)

class NativeAllocationReader:

    def __init__(self, database, native_types=None, *, page_preparer=None):
        self.database = database
        if native_types is None:
            self.types, self.type_evidence = build_native_types(database.data, database.directory)
        else:
            self.types, self.type_evidence = (native_types, None)
        self.stats = dict(clusters=0, tag_payloads=0, seek_indexes=0, allocations=0, free_tag_records=0, all_free_pages=0, duplicate_cross_page_records=0, huge_allocations=0)
        self.current_context = None
        self.page_preparer = page_preparer
        # Optional canonical encoding prepared by trusted page workers.
        # It is transient evidence, never a field in the allocation record.
        self.current_encoded_record = None

    def iter_allocations(self, include_free=False, segments=None):
        db = self.database
        segments = None if segments is None else set(segments)
        for cluster in db.iter_clusters():
            seg, cid = (cluster['segment'], cluster['cluster'])
            if segments is not None and seg not in segments:
                continue
            self.current_context = dict(segment=seg, cluster=cid, phase='current_cluster_metadata')
            self.stats['clusters'] += 1
            entries = sorted((e for e in db.iter_metadata(seg, cid, table=1) if e['key'] & 31 in (16, 17)), key=lambda e: (e['key'] >> 5, e['key'] & 31))
            if len({e['key'] for e in entries}) != len(entries):
                raise AllocationError('Duplicate current tag key')
            allocated = cluster['allocated_bytes']
            groups = {}
            recent = {}
            queue = deque()
            last_live_end = 0
            prepared = iter(self.page_preparer(cluster, entries, include_free)) if self.page_preparer else None
            for entry in entries:
                if prepared is not None:
                    prepared_page = next(prepared, None)
                    if prepared_page is None:
                        raise AllocationError('Missing prepared native page')
                else:
                    prepared_page = None
                if prepared_page is not None and prepared_page['key'] != entry['key']:
                    raise AllocationError('Prepared native page order disagrees')
                if prepared_page is not None and prepared_page.get('serial') is True:
                    prepared_page = None
                key = entry['key']
                page = (key >> 5) * 4096
                huge_key = key & 31 == 17
                self.current_context = dict(segment=seg, cluster=cid, metadata_key=key, logical_page_offset=page, huge=huge_key, phase='allocation_tag_payload')
                payload = entry.get('payload', entry.get('raw'))
                if not isinstance(payload, bytes):
                    raise AllocationError('Metadata payload must be bytes')
                begin = 0
                free_record = None
                if not huge_key:
                    number = page // 4096
                    group_key = ((number & ~15) << 5) + 1
                    if group_key not in groups:
                        free_entry = db.metadata(seg, cid, group_key, table=0)
                        if free_entry is None:
                            raise AllocationError(f'Missing free-space group for {seg}:{cid}:{page:#x}')
                        raw = free_entry.get('payload', free_entry.get('raw'))
                        groups[group_key] = decode_group(raw)
                    free_record = groups[group_key]['pages'][number & 15]
                    begin = free_record['begin_free_bytes']
                    if begin == 4096:
                        self.stats['all_free_pages'] += 1
                        continue
                if prepared_page is not None and prepared_page['begin'] != begin:
                    raise AllocationError('Prepared free-space context disagrees')
                trace = prepared_page['trace'] if prepared_page is not None else parse_tag_payload(payload, self.types, range_start=begin)
                if trace['framing']['huge'] != huge_key:
                    raise AllocationError('Metadata key and huge tag flag disagree')
                self.stats['tag_payloads'] += 1
                self.stats['seek_indexes'] += len(trace['indexes'])
                if huge_key and len(trace['records']) != 1:
                    raise AllocationError('Huge descriptor must describe one allocation')
                threshold = page - 65535
                while queue and queue[0][0] < threshold:
                    old, signature = queue.popleft()
                    if recent.get(old) == signature:
                        del recent[old]
                provenance = {k: v for k, v in entry.items() if k not in ('payload', 'raw')}
                for record_index, raw_record in enumerate(trace['records']):
                    record = dict(raw_record)
                    offset = page + record['page_offset']
                    size = record['size']
                    if offset < 0 or size < 0 or offset + size > allocated:
                        raise AllocationError(f'Allocation outside cluster {seg}:{cid}:{offset:#x}+{size}')
                    free = record['name'] == 'free_space_candidate'
                    if free:
                        self.stats['free_tag_records'] += 1
                        if not include_free:
                            continue
                    if size == 0:
                        if not free:
                            raise AllocationError('Zero-sized nonfree allocation')
                        continue
                    signature = (record['native_tag'], size, record['count'], record['vector'], record.get('element_stride'), tuple(record.get('discriminant_words', [])))
                    if offset in recent:
                        if recent[offset] != signature:
                            raise AllocationError('Conflicting cross-page allocation description')
                        self.stats['duplicate_cross_page_records'] += 1
                        continue
                    if not free:
                        if offset < last_live_end:
                            raise AllocationError('Overlapping or nonmonotonic native allocations')
                        last_live_end = offset + size
                    recent[offset] = signature
                    queue.append((offset, signature))
                    if prepared_page is None:
                        record = materialize_allocation(db, cluster, entry, begin, record, provenance)
                    self.current_encoded_record = prepared_page['encoded_records'][record_index] if prepared_page is not None else None
                    self.stats['allocations'] += 1
                    self.stats['huge_allocations'] += huge_key
                    yield record
            if prepared is not None and next(prepared, None) is not None:
                raise AllocationError('Unexpected extra prepared native page')

def iter_native_allocations(database, include_free=False, native_types=None, segments=None):
    """Yield each current allocation once, preserving native type/count metadata."""
    yield from NativeAllocationReader(database, native_types).iter_allocations(include_free, segments)
