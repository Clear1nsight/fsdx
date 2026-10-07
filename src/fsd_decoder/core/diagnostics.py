"""Bounded discovery diagnostics and explicit command failure reporting.

Successful records are unchanged. Only known decoder exceptions are recoverable;
unexpected interpreter failures are logged and remain exceptions.
"""
from __future__ import annotations
from dataclasses import asdict, is_dataclass
from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
import errno
from functools import wraps
import inspect
import json
import os
from pathlib import Path
import sqlite3
import sys
import traceback
import uuid

class DiagnosticError(ValueError):
    category = 'MALFORMED_SOURCE'

class MalformedSourceError(DiagnosticError):
    pass

class UnsupportedLayoutError(DiagnosticError):
    category = 'UNSUPPORTED_LAYOUT'

class ResourceLimitError(DiagnosticError):
    category = 'RESOURCE_LIMIT'

class InputValidationError(DiagnosticError):
    """Invalid requested input/output paths, distinct from interpreter bugs."""
    category = 'INVALID_ARGUMENT'
_DOMAIN_ERRORS = {'StoreError', 'DatabaseError', 'FieldError', 'SchemaError', 'ObjectRecoveryError', 'StorageError', 'MappingError', 'AllocationError', 'ExportError', 'DirectoryError', 'RenderError', 'TagError', 'PackingError', 'PackedFreeError', 'RelationshipError', 'PackedPointError', 'CatalogError', 'Unsupported'}
_CONTEXT_KEYS = ('phase', 'address', 'segment', 'cluster', 'offset', 'logical_offset', 'descriptor_offset', 'type', 'name', 'native_tag', 'element_index', 'index', 'source', 'store', 'output')
_REJECTION_OBSERVER: ContextVar[Callable[[dict], None] | None] = ContextVar('fsd_rejection_observer', default=None)

@contextmanager
def observe_rejections(observer: Callable[[dict], None]) -> Iterator[None]:
    """Observe every rejection before preview caps; sink errors remain failures.

    Scoped to this execution context. Existing bounded in-memory reports retain
    their contract, and previously suppressed reasons cannot be reconstructed.
    """
    token = _REJECTION_OBSERVER.set(observer)
    try:
        yield
    finally:
        _REJECTION_OBSERVER.reset(token)

def error_category(exc):
    """Classify explicit/domain failures; bare builtin errors indicate bugs."""
    if isinstance(exc, DiagnosticError):
        return exc.category
    if isinstance(exc, json.JSONDecodeError):
        return 'MALFORMED_SOURCE'
    if isinstance(exc, (MemoryError, RecursionError)):
        return 'RESOURCE_LIMIT'
    if isinstance(exc, OSError):
        if exc.errno in (errno.ENOMEM, errno.ENOSPC, errno.EDQUOT, errno.EMFILE, errno.ENFILE, errno.EFBIG):
            return 'RESOURCE_LIMIT'
        return 'IO_FAILURE'
    if isinstance(exc, sqlite3.Error):
        if isinstance(exc, (sqlite3.ProgrammingError, sqlite3.InterfaceError)):
            return 'PROGRAMMING_FAILURE'
        if any((word in str(exc).lower() for word in ('disk is full', 'out of memory', 'too big'))):
            return 'RESOURCE_LIMIT'
        return 'MALFORMED_SOURCE'
    known = any((cls.__name__ in _DOMAIN_ERRORS and (cls.__module__.startswith('fsd_decoder.') or cls.__module__.split('.')[-1] in ('format', 'native_database', 'native_fields', 'schema_members', 'object_records', 'native_storage', 'native_allocations', 'native_directory', 'exports', 'rendering', 'native_tags', 'packed_stream', 'page_free_codec')) for cls in type(exc).__mro__))
    if known:
        message = str(exc).lower()
        if type(exc).__name__ == 'Unsupported':
            return 'MALFORMED_SOURCE' if any(word in message for word in ('truncated', 'missing terminator', 'missing22', 'missing24', 'invalid bytecode', 'descriptor lacks')) else 'UNSUPPORTED_LAYOUT'
        if any((word in message for word in ('resource policy', 'resource limit', 'exceeds limit', 'excessive', 'oversized', 'bounded profile', 'bounded packed'))):
            return 'RESOURCE_LIMIT'
        if any((word in message for word in ('unsupported', 'unknown', 'unmapped', 'unresolved', 'not implemented'))):
            return 'UNSUPPORTED_LAYOUT'
        return 'MALFORMED_SOURCE'
    if isinstance(exc, NotImplementedError):
        return 'UNSUPPORTED_LAYOUT'
    return 'PROGRAMMING_FAILURE'

def compact_context(context=None, exc=None):
    result = {}
    sources = [context or {}, getattr(exc, 'context', {})]
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in _CONTEXT_KEYS:
            if key not in source:
                continue
            value = source[key]
            if is_dataclass(value):
                value = asdict(value)
            if isinstance(value, (str, Path)):
                value = str(value)[:512]
            elif not isinstance(value, (int, float, bool, type(None))):
                value = {k: v for k, v in value.items() if k in ('database', 'segment', 'cluster', 'offset')} if isinstance(value, dict) else str(value)[:512]
            result[key] = value
    return result

def contextual(operation_phase, **argument_fields):
    """Attach available call context while preserving the original exception."""

    def decorate(function):
        signature = inspect.signature(function)

        @wraps(function)
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception as exc:
                try:
                    arguments = signature.bind_partial(*args, **kwargs).arguments
                except TypeError:
                    arguments = {}
                existing = getattr(exc, 'context', {})
                context = dict(existing) if isinstance(existing, dict) else {}
                context.setdefault('phase', operation_phase)
                for argument, field in argument_fields.items():
                    if argument in arguments:
                        context.setdefault(field, arguments[argument])
                exc.context = compact_context(context)
                raise
        return wrapped
    return decorate

def attach_context(exc, context):
    """Preserve deeper failure context when an operation adds its own details."""
    exc.context = compact_context(context, exc)
    return exc

def require_source_failure(exc, context=None):
    """Tolerant source recovery never absorbs programming, I/O or limits."""
    attach_context(exc, context)
    if error_category(exc) not in ('MALFORMED_SOURCE', 'UNSUPPORTED_LAYOUT'):
        raise exc

def command_errors(status):
    """Give small command adapters compact failures and developer tracebacks."""
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception as exc:
                record = failure_record(exc, status=status, context={'phase': status.lower()})
                print(json.dumps(record, ensure_ascii=True, default=str), file=sys.stderr, flush=True)
                if record['error_category'] == 'PROGRAMMING_FAILURE':
                    raise
                return 1
        return wrapped
    return decorate

def _default_log_directory():
    from fsd_decoder.core.paths import artifact_directory
    override = os.environ.get('FSD_ARTIFACT_ROOT')
    if override and not Path(override).expanduser().is_absolute():
        raise InputValidationError('FSD_ARTIFACT_ROOT must be absolute')
    return artifact_directory('logs')

def failure_record(exc, *, status, context=None, log_directory=None):
    """Return a compact CLI record and save the full developer traceback.

    Logging failure is reported separately and never replaces the original
    error. Callers must re-raise PROGRAMMING_FAILURE after emitting this record.
    """
    record = dict(status=status, error_type=type(exc).__name__, message=str(exc)[:1024], error_category=error_category(exc), context=compact_context(context, exc))
    try:
        directory = Path(log_directory) if log_directory is not None else _default_log_directory()
        directory.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        path = directory / f'{status.lower()}-{timestamp}-{uuid.uuid4().hex}.log'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=True, sort_keys=True, default=str) + '\n')
            traceback.print_exception(type(exc), exc, exc.__traceback__, file=stream)
        record['developer_log'] = str(path)
    except (OSError, InputValidationError) as log_error:
        record['developer_log_error'] = f'{type(log_error).__name__}: {log_error}'[:512]
    return record

class RejectedCandidates:
    """Deduplicate reasons, retain bounded context samples and exact totals."""

    def __init__(self, *, max_reasons=64, max_samples=4):
        if type(max_reasons) is not int or max_reasons < 1 or type(max_samples) is not int or (max_samples < 1):
            raise ValueError('Diagnostic bounds must be positive integers')
        self.max_reasons = max_reasons
        self.max_samples = max_samples
        self.total = 0
        self.unrecorded = 0
        self._reasons = {}

    def reject(self, exc, *, phase, **context):
        category = error_category(exc)
        if category == 'PROGRAMMING_FAILURE':
            raise exc
        observer = _REJECTION_OBSERVER.get()
        if observer is not None:
            observer(dict(phase=str(phase), error_category=category,
                          error_type=type(exc).__name__, reason=str(exc),
                          context=compact_context(context, exc)))
        self.total += 1
        reason = str(exc)[:512]
        key = (str(phase)[:128], category, type(exc).__name__, reason)
        record = self._reasons.get(key)
        if record is None:
            if len(self._reasons) >= self.max_reasons:
                self.unrecorded += 1
                return
            record = dict(phase=key[0], error_category=category, error_type=key[2], reason=reason, count=0, samples=[])
            self._reasons[key] = record
        record['count'] += 1
        sample = compact_context(context)
        if sample and sample not in record['samples'] and (len(record['samples']) < self.max_samples):
            record['samples'].append(sample)

    def report(self):
        return json.loads(json.dumps(dict(rejected_count=self.total, unrecorded_count=self.unrecorded, max_reasons=self.max_reasons, max_samples_per_reason=self.max_samples, reasons=list(self._reasons.values()))))

def write_rejection_report(diagnostics, *, context=None, log_directory=None):
    """Publish an explicit sidecar without changing compiled schema documents."""
    directory = Path(log_directory) if log_directory is not None else _default_log_directory()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f'schema-rejections-{uuid.uuid4().hex}.json'
    record = dict(format='fsd-schema-rejection-diagnostics', context=compact_context(context), diagnostics=diagnostics.report())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(record, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    return path
