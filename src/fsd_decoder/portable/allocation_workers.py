"""Opt-in bounded page preparation; ordered native admission stays in one owner.

Workers use the canonical tag grammar and immutable snapshot. They never open a
SQLite connection. Start the pool before opening the writer to avoid inheriting
its descriptors. Fork is currently restricted to single-threaded Linux parents.
"""
from collections import deque
from collections.abc import Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import os
import pickle
import signal
import sys
import threading
from typing import Any
from fsd_decoder.core.diagnostics import InputValidationError, ResourceLimitError
from fsd_decoder.native.native_allocations import AllocationError, materialize_allocation
from fsd_decoder.native.native_tags import parse_tag_payload
from fsd_decoder.native.page_free_codec import decode_group
from .format import encode_json

_DATABASE = _TYPES = None
MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_BATCH_RECORDS = 50000


def _initialize(database, types):
    global _DATABASE, _TYPES
    _DATABASE, _TYPES = database, types
    # Preparation jobs advance in page order and only reuse their current page.
    # Keep that page cached for resolve(), without retaining hundreds of pages.
    _DATABASE.pointer_page_cache_limit = 1
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def _ready():
    return os.getpid()

def _pack_records(records):
    """Factor dynamic field layouts; never select fields by object/type name."""
    layouts, ids, rows = [], {}, []
    for record in records:
        layout = tuple(record)
        index = ids.get(layout)
        if index is None:
            index = len(layouts)
            ids[layout] = index
            layouts.append(layout)
        rows.append((index, tuple(record.values())))
    return layouts, rows

def _unpack_records(packed):
    layouts, rows = packed
    return [dict(zip(layouts[index], values)) for index, values in rows]


def _prepare_batch(cluster, entries, include_free, max_bytes):
    # Import lazily: workers share the same normalized writer contract.
    from .writer import _normalized_allocation
    pages, groups, retained_bytes, records_count = [], {}, 0, 0
    for entry in entries:
        key = entry['key']
        page, huge = (key >> 5) * 4096, key & 31 == 17
        begin = 0
        if not huge:
            number = page // 4096
            group_key = ((number & ~15) << 5) + 1
            if group_key not in groups:
                free = _DATABASE.metadata(cluster['segment'], cluster['cluster'], group_key, table=0)
                if free is None:
                    raise AllocationError('Missing free-space group during page preparation')
                groups[group_key] = decode_group(free.get('payload', free.get('raw')))
            begin = groups[group_key]['pages'][number & 15]['begin_free_bytes']
        if begin == 4096:
            pages.append(dict(key=key, begin=begin, trace=None, encoded_records=[]))
            continue
        payload = entry.get('payload', entry.get('raw'))
        if not isinstance(payload, bytes):
            raise AllocationError('Metadata payload must be bytes')
        trace = parse_tag_payload(payload, _TYPES, range_start=begin, max_records=20000)
        if trace['framing']['huge'] != huge or (huge and len(trace['records']) != 1):
            raise AllocationError('Metadata key and huge allocation framing disagree')
        if len(trace['records']) > 20000:
            raise ResourceLimitError('Prepared page exceeds the experimental record budget; use serial decoding')
        records_count += len(trace['records'])
        if records_count > MAX_BATCH_RECORDS:
            raise ResourceLimitError('Prepared batch exceeds record budget; reduce allocation batch pages')
        encoded = []
        provenance = {k:v for k,v in entry.items() if k not in ('payload','raw')}
        for index, record in enumerate(trace['records']):
            offset, size = page + record['page_offset'], record['size']
            if offset < 0 or size < 0 or offset + size > cluster['allocated_bytes']:
                raise AllocationError('Allocation outside cluster during preparation')
            free = record['name'] == 'free_space_candidate'
            if size == 0 and not free:
                raise AllocationError('Zero-sized nonfree allocation')
            if size == 0 or (free and not include_free):
                encoded.append(None)
                continue
            materialized = materialize_allocation(_DATABASE, cluster, entry, begin, dict(record), provenance)
            raw = encode_json(_normalized_allocation(materialized))
            retained_bytes += len(raw)
            if retained_bytes > max_bytes // 2:
                raise ResourceLimitError('Prepared batch exceeds byte budget; reduce allocation batch pages')
            trace['records'][index] = materialized
            encoded.append(raw)
        trace['records'] = _pack_records(trace['records'])
        pages.append(dict(key=key, begin=begin, trace=trace, encoded_records=encoded))
    raw = pickle.dumps(pages, protocol=5)
    if len(raw) > max_bytes:
        raise ResourceLimitError('Serialized allocation batch exceeds its byte budget')
    return raw

def _prepare_pointer_result(cluster, entry):
    from .writer import _prepare_pointer_page
    page = _prepare_pointer_page(_DATABASE, cluster['segment'], cluster['cluster'],
                                 (entry['key'] >> 5) * 4096)
    page['records'] = _pack_records(page['records'])
    raw = pickle.dumps(page, protocol=5)
    if len(raw) > MAX_RESULT_BYTES:
        raise ResourceLimitError('Prepared pointer page exceeds byte budget; use serial decoding')
    return raw


class AllocationWorkers:
    """Bounded dynamic scheduling, consumed in canonical metadata page order."""
    def __init__(self, database: Any, types: dict, workers: int, batch_pages: int = 16,
                 pending_bytes: int = 64 * 1024 * 1024) -> None:
        if type(workers) is not int or not 2 <= workers <= 4:
            raise InputValidationError('Allocation workers must be an integer from 2 to 4')
        if type(batch_pages) is not int or not 1 <= batch_pages <= 64:
            raise InputValidationError('Allocation batch pages must be an integer from 1 to 64')
        if type(pending_bytes) is not int or pending_bytes < MAX_RESULT_BYTES:
            raise InputValidationError('Allocation pending-byte budget must admit one result slot')
        if sys.platform != 'linux' or threading.active_count() != 1:
            raise InputValidationError('Experimental allocation workers require a single-threaded Linux parent')
        if not isinstance(database.data, bytes):
            raise InputValidationError('Allocation workers require an immutable bytes snapshot')
        self.batch_pages = batch_pages
        self.slots = min(workers + 1, pending_bytes // MAX_RESULT_BYTES)
        self.pointer_slots = min(workers * 2, pending_bytes // MAX_RESULT_BYTES)
        self.pending_bytes = max(self.slots, self.pointer_slots) * MAX_RESULT_BYTES
        self.maximum_result_bytes = 0
        self.batches = self.result_bytes = 0
        self.split_batches = self.serial_allocation_pages = 0
        self.pool = ProcessPoolExecutor(max_workers=workers,
            mp_context=multiprocessing.get_context('fork'),
            initializer=_initialize, initargs=(database, types))
        try:
            # First submit starts all fork workers before the SQLite writer exists.
            self.pool.submit(_ready).result()
        except BaseException:
            self.pool.shutdown(wait=True, cancel_futures=True)
            raise

    def pages(self, cluster: dict, entries: list, include_free: bool) -> Iterator[dict]:
        jobs = ((cluster, entries[start:start + self.batch_pages], include_free, MAX_RESULT_BYTES)
                for start in range(0, len(entries), self.batch_pages))
        for raw in self._results(_prepare_batch, jobs):
            # Only our trusted child creates these responses; never unpickle FSD.
            pages = pickle.loads(raw)
            del raw
            for index, page in enumerate(pages):
                if page.get('trace') is not None:
                    page['trace']['records'] = _unpack_records(page['trace']['records'])
                pages[index] = None
                yield page
                del page
            del pages

    def pointer_pages(self, cluster: dict, entries: Iterable[dict]) -> Iterator[dict]:
        """One PRM page per result; same bounded pool, no SQLite in children."""
        jobs = ((cluster, entry) for entry in entries)
        for raw in self._results(_prepare_pointer_result, jobs):
            page = pickle.loads(raw)
            del raw
            page['records'] = _unpack_records(page['records'])
            yield page
            del page

    def _results(self, function, jobs):
        pending = deque()
        slots = self.pointer_slots if function is _prepare_pointer_result else self.slots
        jobs, exhausted = iter(jobs), False
        try:
            while not exhausted or pending:
                while not exhausted and len(pending) < slots:
                    try:
                        arguments = next(jobs)
                    except StopIteration:
                        exhausted = True
                        break
                    pending.append((self.pool.submit(function, *arguments), arguments))
                if not pending:
                    break
                future, arguments = pending.popleft()
                try:
                    raw = future.result()
                    del future
                except ResourceLimitError:
                    if function is not _prepare_batch:
                        raise
                    for raw in self._smaller_batches(arguments):
                        self._record_result(raw)
                        yield raw
                        del raw
                    del future
                else:
                    self._record_result(raw)
                    yield raw
                    del raw
        finally:
            for future, _ in pending:
                future.cancel()

    def _record_result(self, raw):
        if len(raw) > MAX_RESULT_BYTES:
            raise ResourceLimitError('Worker response exceeds its byte budget')
        self.maximum_result_bytes = max(self.maximum_result_bytes, len(raw))
        self.batches += 1
        self.result_bytes += len(raw)

    def _smaller_batches(self, arguments):
        """Retry one split at a time in the failed job's existing result slot.

        Later jobs stay queued in canonical order. Single-page budget failures
        use the owner's unchanged serial parser, not a larger worker budget.
        Only explicit resource-limit failures enter this path.
        """
        cluster, entries, include_free, max_bytes = arguments
        if len(entries) == 1:
            self.serial_allocation_pages += 1
            yield pickle.dumps([dict(key=entries[0]['key'], serial=True)], protocol=5)
            return
        self.split_batches += 1
        middle = len(entries) // 2
        for half in (entries[:middle], entries[middle:]):
            smaller = (cluster, half, include_free, max_bytes)
            try:
                raw = self.pool.submit(_prepare_batch, *smaller).result()
            except ResourceLimitError:
                yield from self._smaller_batches(smaller)
            else:
                yield raw
                del raw

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)
