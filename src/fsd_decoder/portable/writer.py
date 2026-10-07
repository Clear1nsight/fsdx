"""Orchestrate native FSD capture, verification and FSDX publication.

Native and schema layers reconstruct the source's current logical storage,
allocations, declarations and pointer evidence. This module coordinates their
capture and source comparisons, then publishes the verified store. Restored
readers continue typed interpretation from captured bytes and compiled metadata;
capture completion does not establish complete application semantics.
"""
import hashlib
import os
from pathlib import Path
import time
import uuid
from .format import Store, StoreError, StoreWriter, DEFAULT_CHUNK_BYTES, encode_json, _bounded_encode_json, MAX_BLOB_BYTES
from fsd_decoder.core.provenance import runtime_identity

def _digest(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(DEFAULT_CHUNK_BYTES), b''):
            digest.update(block)
    return digest.hexdigest()

def _feed(digest, value):
    raw = encode_json(value)
    digest.update(len(raw).to_bytes(8, 'big'))
    digest.update(raw)

def _normalized_allocation(record):
    result = {k: v for k, v in record.items() if k not in ('address', 'physical_spans', 'store_allocation_id')}
    result.update(native_tag=record.get('native_tag'), count=record.get('count', 1), vector=bool(record.get('vector', False)), source_metadata=record.get('source_metadata', {}))
    for key in ('page_offset', 'tag_relative_offset', 'tag_word_index', 'instance_index'):
        if result.get(key) is None:
            result.pop(key, None)
    return result

def _prepare_pointer_page(database, segment, cluster, page_offset):
    """Canonical source checks and independent normalized proof for one PRM page."""
    from fsd_decoder.native.native_database import DatabaseError
    bindings = database.page_pointers(segment, cluster, page_offset)
    if len(bindings) > 1024:
        raise StoreError('PRM bindings exceed one 4 KiB page')
    records, digest, unresolved = [], hashlib.sha256(), 0
    for offset, pointer in sorted(bindings.items()):
        width, raw = pointer['pointer_width'], bytes.fromhex(pointer['raw_hex'])
        address = database.address(segment, cluster, offset)
        if database.read(address, width) != raw:
            raise StoreError('PRM source bytes disagree with logical storage')
        metadata = {}
        try:
            target = database.resolve(address, width=width, raw=raw)
            if target is None:
                raise StoreError('A live PRM binding unexpectedly resolved to null')
            status = 'RESOLVED'
        except DatabaseError as exc:
            target, status = None, 'UNRESOLVED'
            metadata.update(resolution_error=str(exc), target=pointer['target'])
            unresolved += 1
        records.append(dict(segment=segment, cluster=cluster, logical_offset=offset,
            width=width, raw=raw, target=target, status=status, metadata=metadata))
        _feed(digest, [segment, cluster, offset, width, raw, status,
            target.segment if target else None, target.cluster if target else None,
            target.offset if target else None, encode_json(metadata).decode()])
    raw = _bounded_encode_json(bindings, MAX_BLOB_BYTES)
    return dict(page_offset=page_offset, records=records, unresolved=unresolved,
        proof=dict(count=len(records), sha256=digest.hexdigest()),
        document_raw=raw, bindings=bindings if raw is None else None)

def encode(source, destination, progress=None, verify=True, *, compact_pointer_pages=False,
           allocation_workers: int = 1, allocation_batch_pages: int = 16):
    """Create a new single-file store, publishing only after full verification.

    ``verify`` must remain True: source preservation and stored-byte verification
    are mandatory. Progress receives dictionaries. Cleanup removes only staging
    reserved by this operation, including a completed stage if later checks fail.
    Publication and destination-directory synchronization are separate steps:
    an exception after publication can leave the verified destination present.
    Existing paths, including dangling symlinks, are never overwritten.
    """
    if type(compact_pointer_pages) is not bool:
        raise StoreError('compact_pointer_pages must be an explicit boolean')
    if verify is not True:
        raise StoreError('Portable ingestion requires full verification')
    if type(allocation_workers) is not int or not 1 <= allocation_workers <= 4:
        raise StoreError('Allocation workers must be an integer from 1 to 4')
    if type(allocation_batch_pages) is not int or not 1 <= allocation_batch_pages <= 64:
        raise StoreError('Allocation batch pages must be an integer from 1 to 64')
    source, destination = (Path(source).resolve(), Path(destination).absolute())
    if not source.is_file():
        raise StoreError('Source must be a regular file')
    if os.path.lexists(destination):
        raise FileExistsError(f'Destination already exists: {destination}')
    if not destination.parent.is_dir():
        raise StoreError('Destination parent directory does not exist')
    runtime = runtime_identity()
    started = time.monotonic()
    times = {}

    def emit(phase, **values):
        if progress is not None:
            progress({'phase': phase, 'elapsed_seconds': round(time.monotonic() - started, 3), **values})
    from fsd_decoder.native.native_database import NativeDatabase, DatabaseError
    from fsd_decoder.native.native_allocations import NativeAllocationReader
    from fsd_decoder.schema.native_fields import NativeFields
    emit('source_snapshot', source=str(source))
    db = NativeDatabase.from_path(source)
    source_info = dict(path=str(source), bytes=len(db.data), sha256=db.sha256, database_id=db.database_id)
    times['source_snapshot'] = time.monotonic() - started
    emit('file_information', information=dict(source_bytes=source_info['bytes'],
        source_sha256=db.sha256, database_id=db.database_id,
        storage_layout='SUPPORTED_OBJECTSTORE_LAYOUT',
        json_preflight_backend=runtime['json_preflight']['backend']))
    emit('compile_schema', source_sha256=db.sha256)
    mark = time.monotonic()
    fields = NativeFields(db, allow_partial_representations=True)
    report = fields.schema_report()
    compiled = dict(classes={name: fields.decoder.layout(name) for name in fields.schema.classes}, schema_extents=fields.schema.schema_extents, verified_nonvariable=sorted(fields._verified_nonvariable))
    roots = db.roots()
    times['compile_schema'] = time.monotonic() - mark
    stage = destination.parent / ('.' + destination.name + '.encoding-' + uuid.uuid4().hex)
    writer = None
    workers = None
    try:
        if allocation_workers > 1:
            from .allocation_workers import AllocationWorkers
            workers = AllocationWorkers(db, fields.types, allocation_workers, allocation_batch_pages)
        writer = StoreWriter(stage, source=source_info, defer_allocation_index=True)
        writer.set_manifest('runtime_identity', runtime)
        for kind, name, value in (('schema', 'report', report), ('schema', 'compiled_layouts', compiled), ('types', 'native', fields.types), ('types', 'descriptors', fields.descriptors), ('types', 'bindings', fields.dictionary_bindings), ('roots', 'current', roots), ('source', 'directory', db.directory)):
            writer.put_document(kind, name, value)
        clusters = list(db.iter_clusters())
        logical_total = sum((c['allocated_bytes'] for c in clusters))
        emit('file_information', information=dict(schema_classes=len(report['classes']),
            schema_complete=report['schema_complete'], native_type_bindings=len(fields.types),
            roots=len(roots.get('roots', [])), clusters=len(clusters),
            segments=len({c['segment'] for c in clusters}), logical_bytes=logical_total))
        for cluster in clusters:
            writer.add_cluster(cluster)
        for extent in db.directory['effective_extents']:
            writer.add_extent(extent)
        mark = time.monotonic()
        copied = 0
        emit('logical_bytes', completed_bytes=0, total_bytes=logical_total)
        for cluster in clusters:
            seg, cid = (cluster['segment'], cluster['cluster'])
            for offset in range(0, cluster['allocated_bytes'], DEFAULT_CHUNK_BYTES):
                size = min(DEFAULT_CHUNK_BYTES, cluster['allocated_bytes'] - offset)
                raw = db.read_at(seg, cid, offset, size)
                writer.add_chunk(seg, cid, offset, raw)
                copied += size
            emit('logical_bytes', segment=seg, cluster=cid, completed_bytes=copied, total_bytes=logical_total)
        times['logical_bytes'] = time.monotonic() - mark
        mark = time.monotonic()
        allocation_reader = NativeAllocationReader(db, fields.types, page_preparer=workers.pages) if workers else NativeAllocationReader(db, fields.types)
        emit('allocations', allocations=0)
        allocation_count = 0
        allocation_digest = hashlib.sha256()
        allocation_batch, allocation_batch_bytes = [], 0
        for allocation in allocation_reader.iter_allocations():
            prepared_encoding = getattr(allocation_reader, 'current_encoded_record', None)
            if prepared_encoding is None:
                prepared_encoding = encode_json(_normalized_allocation(allocation))
            allocation_digest.update(len(prepared_encoding).to_bytes(8, 'big'))
            allocation_digest.update(prepared_encoding)
            record_bytes = len(prepared_encoding) + 256
            if allocation_batch and (len(allocation_batch) >= 256 or allocation_batch_bytes + record_bytes > 1024 * 1024):
                writer.add_allocations(allocation_batch)
                allocation_batch, allocation_batch_bytes = [], 0
            if record_bytes > 1024 * 1024:
                writer.add_allocation(allocation)
            else:
                allocation_batch.append(allocation)
                allocation_batch_bytes += record_bytes
            allocation_count += 1
            if allocation_count % 10000 == 0:
                emit('allocations', allocations=allocation_count, context=allocation_reader.current_context)
        if allocation_batch:
            writer.add_allocations(allocation_batch)
        writer.finish_allocations()
        writer.put_document('ingest', 'allocation_statistics', allocation_reader.stats)
        times['allocations'] = time.monotonic() - mark
        emit('allocations', allocations=allocation_count, finished=True)
        if workers:
            emit('allocation_workers_complete', workers=allocation_workers,
                batch_pages=allocation_batch_pages, batches=workers.batches,
                result_bytes=workers.result_bytes, maximum_result_bytes=workers.maximum_result_bytes,
                pending_result_budget_bytes=workers.pending_bytes,
                split_batches=workers.split_batches, serial_allocation_pages=workers.serial_allocation_pages)
        mark = time.monotonic()
        pointer_count = unresolved = prm_pages = metadata_entries = 0
        pointer_proofs = {}
        emit('pointers', pointers=0, prm_pages=0)
        for cluster in clusters:
            seg, cid = (cluster['segment'], cluster['cluster'])
            prm_entries = (entry for entry in db.iter_metadata(seg, cid)
                           if entry['table_index'] == 1 and entry['key'] & 31 == 18)
            prepared = workers.pointer_pages(cluster, prm_entries) if workers else None
            for entry in db.iter_metadata(seg, cid):
                key, table = entry['key'], entry['table_index']
                writer.put_document('native_metadata', f'{seg}:{cid}:{table}:{key}', {k: v for k, v in entry.items() if k != 'payload'})
                metadata_entries += 1
                if table != 1 or key & 31 != 18:
                    continue
                page_offset = (key >> 5) * 4096
                page = next(prepared) if prepared is not None else _prepare_pointer_page(db, seg, cid, page_offset)
                if page['page_offset'] != page_offset:
                    raise StoreError('Prepared pointer page order differs from source metadata')
                writer.add_pointers(page['records'])
                name = f'{seg}:{cid}:{page_offset}'
                raw = page['document_raw']
                if raw is None:
                    if compact_pointer_pages:
                        writer.put_pointer_page(name, page['bindings'])
                    else:
                        writer.put_document('pointer_page', name, page['bindings'])
                elif not compact_pointer_pages or not writer._put_pointer_page_raw(name, raw):
                    writer._put_document_raw('pointer_page', name, raw)
                pointer_proofs[seg, cid, page_offset] = page['proof']
                unresolved += page['unresolved']
                old_count = pointer_count
                pointer_count += page['proof']['count']
                prm_pages += 1
                if pointer_count // 10000 != old_count // 10000:
                    emit('pointers', segment=seg, cluster=cid, pointers=pointer_count, unresolved_pointers=unresolved, prm_pages=prm_pages)
            if prepared is not None and next(prepared, None) is not None:
                raise StoreError('Prepared pointer pages exceed source metadata')
            emit('pointers', segment=seg, cluster=cid, pointers=pointer_count, unresolved_pointers=unresolved, prm_pages=prm_pages)
        times['pointers_and_metadata'] = time.monotonic() - mark
        if workers:
            emit('pointer_workers_complete', workers=allocation_workers, batches=workers.batches,
                result_bytes=workers.result_bytes, maximum_result_bytes=workers.maximum_result_bytes,
                pending_result_budget_bytes=workers.pending_bytes)
            workers.close()
            workers = None
        coverage = dict(raw_logical_storage_complete=True, current_allocations_complete=True, current_prm_membership_complete=True, unresolved_pointers=unresolved, schema_complete=report['schema_complete'], logical_bytes=logical_total, metadata_entries=metadata_entries, prm_pages=prm_pages)
        writer.set_manifest('coverage', coverage)
        writer.put_document('ingest', 'normalized_graph_proof', {'allocations': {'count': allocation_count, 'sha256': allocation_digest.hexdigest(), 'ordering': 'native iterator / stored allocation id'}, 'pointer_pages': {f'{s}:{c}:{p}': v for (s, c, p), v in pointer_proofs.items()}, 'method': 'length-framed canonical JSON SHA256 of source-normalized records'})
        writer.set_manifest('pointer_evidence', {'document_kind': 'pointer_page', 'document_name': '{segment}:{cluster}:{logical_offset & ~4095}', 'member_key': 'decimal logical_offset', 'description': 'Exact decoded PRM thread and source physical evidence for every binding.'})
        writer.set_manifest('semantic_limits', {'unknown_fields_preserved': True, 'unions_active_member_may_be_unknown': True, 'application_semantics_complete': False, 'meaning': 'COMPLETE describes capture coverage; consult schema and pointer diagnostics.'})
        from fsd_decoder.discovery.datasets import capture_discovery
        emit('dataset_discovery')
        mark = time.monotonic()
        discovery = capture_discovery(db, fields, writer, progress=progress)
        writer.put_document('discovery', 'datasets', discovery)
        writer.set_manifest('dataset_discovery', dict(version=discovery['version'],
            document_kind='discovery', document_name='datasets', optional=True,
            census_complete=discovery['census_complete'],
            objects_inspected=discovery['inspection']['objects_inspected'],
            enumeration_complete=discovery['inspection']['enumeration_complete'],
            accounting_complete=discovery['accounting']['complete']))
        times['dataset_discovery'] = time.monotonic() - mark
        writer.set_manifest('ingest_timings_seconds', times)
        counts = writer.finish(pointer_resolution_complete=True, require_full_cluster_coverage=True)
        emit('verify_store', counts=counts)
        mark = time.monotonic()
        with Store(stage) as stored:
            proof = stored.verify(full=True, workers=allocation_workers)
            if proof.get('verification_mode') != 'FULL_VERIFIED' or not proof.get('relational_hashes_verified'):
                raise StoreError('New portable store lacks relational integrity proof')
            restored_allocations = hashlib.sha256()
            restored_count = 0
            for row in stored.connection.execute(stored._allocation_query() + ' ORDER BY a.id'):
                _feed(restored_allocations, stored._allocation_record(row, for_proof=True))
                restored_count += 1
                if restored_count % 50000 == 0:
                    emit('verify_graph', allocations_compared=restored_count, total_allocations=allocation_count)
            if (restored_count, restored_allocations.hexdigest()) != (allocation_count, allocation_digest.hexdigest()):
                raise StoreError('Portable normalized allocations differ from native source records')
            restored_pointers = 0
            for (seg, cid, page), expected in pointer_proofs.items():
                restored_page = hashlib.sha256()
                count = 0
                for row in stored.connection.execute('SELECT * FROM pointers WHERE segment=? AND cluster=? AND logical_offset>=? AND logical_offset<? ORDER BY logical_offset', (seg, cid, page, page + 4096)):
                    _feed(restored_page, list(row))
                    count += 1
                if dict(count=count, sha256=restored_page.hexdigest()) != expected:
                    raise StoreError('Portable normalized pointer bindings differ from native source targets')
                restored_pointers += count
                if restored_pointers // 50000 != (restored_pointers - count) // 50000:
                    emit('verify_graph', pointers_compared=restored_pointers, total_pointers=pointer_count)
            if restored_pointers != pointer_count:
                raise StoreError('Portable normalized pointer count differs from source')
            for cluster in clusters:
                seg, cid = (cluster['segment'], cluster['cluster'])
                for offset in range(0, cluster['allocated_bytes'], DEFAULT_CHUNK_BYTES):
                    size = min(DEFAULT_CHUNK_BYTES, cluster['allocated_bytes'] - offset)
                    if stored.read(seg, cid, offset, size) != db.read_at(seg, cid, offset, size):
                        raise StoreError('Portable logical-byte reconstruction differs from source')
        times['verify_store'] = time.monotonic() - mark
        emit('verify_source')
        if _digest(source) != db.sha256:
            raise StoreError('Source changed during ingestion')
        emit('verify_runtime')
        if runtime_identity() != runtime:
            raise StoreError('Runtime code, resources or environment changed during ingestion')
        proof.update(status='PASS', logical_bytes_compared=logical_total, source_sha256_unchanged=True, normalized_allocations_compared=allocation_count, normalized_pointers_compared=pointer_count)
        os.link(stage, destination)
        stage.unlink()
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        result = dict(status='COMPLETE', verification=proof, verified=True, source_unchanged=True, source=source_info, runtime_identity=runtime, runtime_unchanged=True, output=str(destination), output_bytes=destination.stat().st_size, counts=counts, coverage=coverage, timings_seconds=times, elapsed_seconds=time.monotonic() - started)
        emit('complete', **result)
        return result
    finally:
        try:
            if workers is not None:
                workers.close()
        finally:
            if writer is not None:
                try:
                    writer.close()
                finally:
                    # A successful constructor exclusively reserved this stage.
                    # Failed O_EXCL reservations belong to another operation.
                    for suffix in ('', '-journal', '-wal', '-shm'):
                        try:
                            Path(str(stage) + suffix).unlink()
                        except FileNotFoundError:
                            pass
