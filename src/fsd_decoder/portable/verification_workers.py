"""Bounded independent table proofs using separate read-only connections."""
from __future__ import annotations
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import signal
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .format import Store

_STOP = None

def _initialize(stop):
    global _STOP
    _STOP = stop
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def _check_cancelled():
    if _STOP is not None and _STOP.is_set():
        from .format import StoreError
        raise StoreError('Parallel verification cancelled')


def _table_proof(path, table, policy, runtime):
    from fsd_decoder.core.provenance import runtime_identity
    from .format import Store, StoreError, _row_integrity
    _check_cancelled()
    if runtime_identity() != runtime:
        raise StoreError('Verification worker runtime differs from owner')
    with Store(path, cache_bytes=0, resource_policy=policy) as store:
        proof = _row_integrity(store.connection, tables=(table,), cancel=_check_cancelled)[table]
        store.check_identity()
    if runtime_identity() != runtime:
        raise StoreError('Verification worker runtime changed')
    return proof


def table_proofs(store: Store, workers: int) -> dict[str, dict]:
    """Each SHA256 stream stays ordered within one table, including all rows.

    Only the at-most-ten supported relational tables are submitted. Workers
    never perform native decoding, write SQLite, or return row payloads.
    Spawn avoids inheriting the owner's active connection. The executor joins
    children on success/failure/cancellation before control returns to caller.
    """
    from fsd_decoder.core.provenance import runtime_identity
    from .format import StoreError, _row_orders
    runtime = runtime_identity()
    orders = _row_orders(store.connection)
    context = multiprocessing.get_context('spawn')
    stop = context.Event()
    with ProcessPoolExecutor(max_workers=workers, mp_context=context,
            initializer=_initialize, initargs=(stop,)) as pool:
        pending = {}
        try:
            for table in orders:
                pending[table] = pool.submit(_table_proof, str(store.path), table,
                    store.resource_policy, runtime)
            result = {table: future.result() for table, future in pending.items()}
        finally:
            stop.set()
            for future in pending.values():
                future.cancel()
    store.check_identity()
    if runtime_identity() != runtime:
        raise StoreError('Verification owner runtime changed')
    return result


def _blob_document_proof(path, lower, upper, policy, runtime):
    from fsd_decoder.core.provenance import runtime_identity
    from .format import Store, StoreError
    _check_cancelled()
    if runtime_identity() != runtime:
        raise StoreError('Verification worker runtime differs from owner')
    with Store(path, cache_bytes=0, resource_policy=policy) as store:
        proof = store._verify_blobs_documents(lower, upper, _check_cancelled)
    if runtime_identity() != runtime:
        raise StoreError('Verification worker runtime changed')
    return proof


def blob_document_proofs(store: Store, workers: int) -> None:
    """Bounded contiguous ranges; payloads stay in read-only spawned workers."""
    from fsd_decoder.core.provenance import runtime_identity
    from .format import StoreError
    # A missing document target can lie outside every selected BLOB range.
    if store.connection.execute('SELECT 1 FROM documents d LEFT JOIN blobs b '
            'ON b.sha256=d.blob_sha256 WHERE b.sha256 IS NULL LIMIT 1').fetchone():
        raise StoreError('Missing document blob')
    count = store.connection.execute('SELECT count(*) FROM blobs').fetchone()[0]
    documents = store.connection.execute('SELECT count(*) FROM documents').fetchone()[0]
    if count < workers:
        proof = store._verify_blobs_documents()
        if proof != dict(blobs=count, documents=documents):
            raise StoreError('Parallel BLOB/document coverage disagrees')
        return
    boundaries = [None]
    for index in range(1, workers):
        row = store.connection.execute('SELECT ' + store._bounded_metadata('sha256') +
            ' FROM blobs ORDER BY sha256 LIMIT 1 OFFSET ?', (count * index // workers,)).fetchone()
        if row is None or row[0] is None:
            raise StoreError('BLOB digest exceeds resource policy')
        boundaries.append(row[0])
    boundaries.append(None)
    runtime = runtime_identity()
    context = multiprocessing.get_context('spawn')
    stop = context.Event()
    with ProcessPoolExecutor(max_workers=workers, mp_context=context,
            initializer=_initialize, initargs=(stop,)) as pool:
        pending = []
        try:
            for lower, upper in zip(boundaries, boundaries[1:]):
                pending.append(pool.submit(_blob_document_proof, str(store.path),
                    lower, upper, store.resource_policy, runtime))
            results = [future.result() for future in pending]
        finally:
            stop.set()
            for future in pending:
                future.cancel()
    store.check_identity()
    if runtime_identity() != runtime:
        raise StoreError('Verification owner runtime changed')
    if (sum(result['blobs'] for result in results) != count
            or sum(result['documents'] for result in results) != documents):
        raise StoreError('Parallel BLOB/document coverage disagrees')
