"""Source-independent facade over compiled FSDX rows and logical byte chunks.

Original FSD paths are provenance only. ObjectStore header, directory, PRM, tag
and schema parsers are never invoked when opening or exporting this facade.
"""
from collections import Counter
from bisect import bisect_right
from pathlib import Path
from collections.abc import Mapping
from typing import Iterator
from fsd_decoder.core.native_storage import Address, PhysicalSpan
from .format import Store, StoreError, decode_json
from fsd_decoder.core.contracts import AllocationRecord, LayoutRecord, ValueRecord
from fsd_decoder.schema.native_fields import DEFAULT_MAX_RECORD_BYTES
from fsd_decoder.schema.expansion_admission import (ExpansionLimits, ExpansionMetadataError, schema_cost, admit_cost, DEFAULT_MAX_DECODED_LEAVES, DEFAULT_MAX_EXPANSION_WORK)

class CompiledSchema:

    def __init__(self, compiled, report):
        self.classes = compiled['classes']
        if not isinstance(self.classes, Mapping):
            raise StoreError('Compiled schema classes must be a mapping')
        self.schema_extents = compiled.get('schema_extents', [])
        self._report = report

    def layout(self, name: str) -> LayoutRecord:
        try:
            return self.classes[name]
        except KeyError as exc:
            raise StoreError('Class layout was not compiled into the portable store: ' + name) from exc

    def report(self):
        return self._report

class PortableDatabase:
    """Expose native logical addresses backed only by a read-only portable Store."""

    def __init__(self, source, *, cache_bytes=32 * 1024 * 1024, max_record_bytes: int=DEFAULT_MAX_RECORD_BYTES, max_decoded_leaves: int=DEFAULT_MAX_DECODED_LEAVES, max_expansion_work: int=DEFAULT_MAX_EXPANSION_WORK):
        if type(max_record_bytes) is not int or max_record_bytes <= 0:
            raise StoreError('max_record_bytes must be a positive integer')
        try:
            self.expansion_limits = ExpansionLimits(max_decoded_leaves, max_expansion_work)
        except ExpansionMetadataError as exc:
            raise StoreError(str(exc)) from exc
        self.max_record_bytes = max_record_bytes
        self._owns_store = not isinstance(source, Store)
        self.store = Store(source, cache_bytes=cache_bytes) if self._owns_store else source
        try:
            self.path = self.store.path
            self.source_info = dict(self.store.manifest['source'])
            self.sha256 = self.source_info['sha256']
            self.database_id = self.source_info['database_id']
            if not isinstance(self.database_id, str) or not self.database_id:
                raise StoreError('Portable source lacks database identity')
            self.source_path = Path(self.source_info['path']) if self.source_info.get('path') else None
            self.directory = self.store.document('source', 'directory')
            self.header = self.directory.get('header', {})
            self.provenance = dict(source=self.source_info, portable_path=str(self.path), original_source_accessed=False)
            self._roots = self.store.document('roots', 'current')
            self._clusters = {(r['segment'], r['cluster']): r for r in self.store.iter_clusters()}
            self._extents = {}
            metadata_limit = self.store.resource_policy.max_json_bytes
            # Check size and storage type in SQLite before any extent metadata
            # reaches Python. Keep the guarded projection as a second check.
            invalid = self.store.connection.execute(
                "SELECT 1 FROM extents WHERE typeof(metadata)!='text' OR length(CAST(metadata AS BLOB))>? LIMIT 1",
                (metadata_limit,)).fetchone()
            if invalid is not None:
                raise StoreError('Extent metadata type or bytes exceed resource policy')
            bounded_metadata = (
                "CASE WHEN typeof(metadata)='text' AND length(CAST(metadata AS BLOB))<="
                + str(metadata_limit) + ' THEN metadata ELSE NULL END AS metadata')
            for row in self.store.connection.execute(
                    'SELECT segment,cluster,logical_start,physical_start,length,'
                    + bounded_metadata + ' FROM extents ORDER BY segment,cluster,logical_start'):
                if row['metadata'] is None:
                    raise StoreError('Extent metadata type or bytes exceed resource policy')
                # Validate bounded JSON, retaining the original metadata text
                # used by PhysicalSpan.provenance for API compatibility.
                decode_json(row['metadata'], self.store.resource_policy)
                self._extents.setdefault((row['segment'], row['cluster']), []).append(dict(row))
            self._extent_starts = {key: [r['logical_start'] for r in rows] for key, rows in self._extents.items()}
            self.query_statistics = Counter()
            self.fields = self._restore_fields()
        except BaseException:
            if self._owns_store:
                self.store.close()
            raise

    @classmethod
    def from_path(cls, path, **kwargs):
        return cls(path, **kwargs)

    def check_identity(self) -> None:
        """Check the immutable standalone source before retained-value reuse."""
        self.store.check_identity()

    def _restore_fields(self):
        from fsd_decoder.schema.native_fields import FieldError, NativeFields
        report = self.store.document('schema', 'report', lazy=True)
        compiled = self.store.document('schema', 'compiled_layouts', lazy=True)
        try:
            return NativeFields.from_compiled(self, CompiledSchema(compiled, report), self.store.document('types', 'native', lazy=True), self.store.document('types', 'bindings', lazy=True), report, descriptors=self.store.document('types', 'descriptors', lazy=True), verified_nonvariable=compiled.get('verified_nonvariable', ()), max_record_bytes=self.max_record_bytes, max_decoded_leaves=self.expansion_limits.max_decoded_leaves, max_expansion_work=self.expansion_limits.max_expansion_work)
        except FieldError as exc:
            raise StoreError(str(exc)) from exc

    def address(self, segment: int, cluster: int, offset: int) -> Address:
        return Address(self.database_id, segment, cluster, offset)

    def _check(self, address):
        self.check_identity()
        if not isinstance(address, Address) or address.database != self.database_id:
            raise StoreError('Address belongs to another database')
        return address

    def read(self, address: Address, size: int) -> bytes:
        a = self._check(address)
        self.query_statistics['logical_reads'] += 1
        return self.store.read(a.segment, a.cluster, a.offset, size)

    def read_at(self, segment, cluster, offset, size):
        return self.read(self.address(segment, cluster, offset), size)

    def captured_unresolved_reference(self, address: Address, width: int=4,
            raw: bytes | None=None) -> Mapping | None:
        """Checked captured evidence for an explicitly requested partial view."""
        a = self._check(address)
        result = self.store.captured_unresolved_reference(a.segment, a.cluster, a.offset, width=width, raw=raw)
        self.check_identity()
        if result is None:
            return None
        return dict(result, source_address=dict(database=self.database_id,
            segment=a.segment, cluster=a.cluster, offset=a.offset), source_sha256=self.sha256)

    def resolve(self, address: Address, width: int=4, raw: bytes | None=None) -> Address | None:
        a = self._check(address)
        self.query_statistics['resolved_reference_lookups'] += 1
        target = self.store.resolve(a.segment, a.cluster, a.offset, width=width, raw=raw)
        return None if target is None else self.address(target['segment'], target['cluster'], target['offset'])

    def spans(self, address: Address, size: int) -> tuple[PhysicalSpan, ...]:
        a = self._check(address)
        if type(size) is not int or size < 0:
            raise StoreError('Span size must be a nonnegative integer')
        if not size:
            return ()
        key = (a.segment, a.cluster)
        rows = self._extents.get(key, [])
        index = bisect_right(self._extent_starts.get(key, []), a.offset) - 1
        cursor, end, result = (a.offset, a.offset + size, [])
        while cursor < end:
            if index < 0 or index >= len(rows):
                raise StoreError('Missing stored physical provenance extent')
            row = rows[index]
            delta = cursor - row['logical_start']
            if not 0 <= delta < row['length']:
                raise StoreError('Gap in stored physical provenance')
            take = min(end - cursor, row['length'] - delta)
            result.append(PhysicalSpan(cursor, row['physical_start'] + delta, take, row['metadata']))
            cursor += take
            index += 1
        return tuple(result)

    def roots(self):
        self.check_identity()
        return self._roots

    def discovery_report(self):
        """Read the optional capture-time report lazily; old stores stay usable.

        Absence means this store predates capture-time discovery. Reading it
        does not silently regenerate or upgrade that historical report.
        """
        self.check_identity()
        declaration = self.store.manifest.get('dataset_discovery')
        if declaration is None:
            return None
        from fsd_decoder.discovery.datasets import VERSION
        from fsd_decoder.discovery.complete import COMPLETE_VERSION
        if (not isinstance(declaration, dict) or type(declaration.get('version')) is not int
                or declaration['version'] not in (1, COMPLETE_VERSION, VERSION)
                or declaration.get('document_kind') != 'discovery'
                or declaration.get('document_name') != 'datasets'):
            raise StoreError('Unsupported dataset discovery report declaration')
        report = self.store.document('discovery', 'datasets', lazy=True)
        if (not isinstance(report, Mapping) or not isinstance(report.get('source'), Mapping)
                or report.get('format') != 'FSD_DATASET_DISCOVERY'
                or type(report.get('version')) is not int or report['version'] != declaration['version']
                or report.get('source', {}).get('sha256') != self.sha256
                or report.get('source', {}).get('database_id') != self.database_id
                or type(report.get('allocations_counted')) is not int
                or report['allocations_counted'] != self.store.manifest['counts']['allocations']):
            raise StoreError('Dataset discovery report identity or version disagrees with store')
        if report['version'] == COMPLETE_VERSION:
            accounting = report.get('accounting')
            if (not isinstance(accounting, Mapping) or accounting.get('complete') is not True
                    or type(accounting.get('allocations')) is not int
                    or accounting['allocations'] != self.store.manifest['counts']['allocations']
                    or type(accounting.get('pointer_bindings')) is not int
                    or accounting['pointer_bindings'] != self.store.manifest['counts']['pointers']):
                raise StoreError('Complete discovery accounting disagrees with store')
        return report

    def source_identification(self, **options: object) -> dict:
        """Project bounded retained native identities without decoding payloads.

        This is a separate live metadata view. Historical discovery reports and
        name-keyed payload checkpoints keep their existing versions/statuses.
        """
        from fsd_decoder.discovery.source_identification import build_source_identification
        return build_source_identification(self, **options)

    def inspect_root_payload_links(self, root_index: int, **options: object) -> dict:
        """Inspect exact current storage affiliation from one retained source root."""
        from fsd_decoder.discovery.root_relationships import inspect_root_payload_links
        return inspect_root_payload_links(self, root_index, **options)

    def export_root_payload_text(self, new_path: str | Path, *, root_index: int, **options: object) -> dict:
        """Publish bounded root-affiliated plaintext with explicit interpretation scope."""
        from fsd_decoder.exports.dataset_text import export_root_payload_text
        return export_root_payload_text(self, new_path, root_index=root_index, **options)

    def iter_clusters(self, segment=None):
        self.check_identity()
        for (sid, cid), cluster in sorted(self._clusters.items()):
            if segment is None or sid == segment:
                self.check_identity()
                yield cluster

    def cluster(self, segment, cluster):
        self.check_identity()
        try:
            return self._clusters[segment, cluster]
        except KeyError as exc:
            raise StoreError('Unknown portable cluster') from exc

    def _allocation(self, record):
        if record is None:
            return None
        result = dict(record)
        address = self.address(result['segment'], result['cluster'], result['logical_offset'])
        result['address'] = address
        result['physical_spans'] = self.spans(address, result['size'])
        return result

    def allocation(self, segment: int, cluster: int, offset: int) -> AllocationRecord | None:
        self.query_statistics['allocation_address_lookups'] += 1
        return self._allocation(self.store.allocation_at(segment, cluster, offset))

    def iter_allocations(self, *, segment=None, cluster=None, name=None, names=None) -> Iterator[AllocationRecord]:
        """Yield indexed rows; name/names filters never scan native class markers."""
        if name is not None and names is not None:
            raise StoreError('Specify name or names, not both')
        self.query_statistics['allocation_queries'] += 1
        if names is None:
            records = self.store.iter_allocations(segment=segment, cluster=cluster, name=name)
        else:
            if isinstance(names, str):
                raise StoreError('names must be an iterable of complete names, not one string')
            names = tuple(dict.fromkeys(names))
            if any((not isinstance(n, str) for n in names)):
                raise StoreError('Allocation names must be strings')
            if not names:
                return
            clauses = ['n.name IN (' + ','.join(('?' for _ in names)) + ')']
            args = list(names)
            for column, value in [('a.segment', segment), ('a.cluster', cluster)]:
                if value is not None:
                    clauses.append(column + '=?')
                    args.append(value)
            sql = self.store._allocation_query() + ' WHERE ' + ' AND '.join(clauses) + ' ORDER BY a.segment,a.cluster,a.logical_offset'
            records = (self.store._allocation_record(row) for row in self.store.connection.execute(sql, args))
        for record in records:
            self.query_statistics['allocation_rows_returned'] += 1
            yield self._allocation(record)

    def verify_source(self):
        """Compatibility quick-check hook; full relational/blob checks are explicit.

        The boolean reports successful SQLite quick and foreign-key checks. It
        does not establish full store integrity or reopen the original FSD.
        """
        self.store.verify(full=False)
        return True

    def close(self):
        if self._owns_store:
            self.store.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
