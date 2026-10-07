"""Export the current native ObjectStore FSD snapshot as UTF-8 text.

Each line is a record name followed by JSON. Logical addresses retain database,
segment, cluster and byte offset. The source is opened read only. Existing
outputs are never replaced. Unsupported native structures fail explicitly.
"""
from __future__ import annotations
import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
import signal
from pathlib import Path
import sys
import tempfile
import time
from fsd_decoder.core.diagnostics import (InputValidationError, MalformedSourceError,
    ResourceLimitError, attach_context, contextual, failure_record, error_category,
    require_source_failure)
VERSION = '0.5.0'

def install_termination_handler():
    """Route cooperative process termination through existing cleanup paths."""

    def terminate(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)

def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def record(stream, kind, value):
    if hasattr(stream, 'write_record'):
        return stream.write_record(kind, value)
    stream.write(kind + ' ' + json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n')

def has_unsupported(value):
    if isinstance(value, dict):
        status = value.get('status', '')
        if isinstance(status, str) and status.startswith(('UNSUPPORTED', 'UNKNOWN', 'ARRAY_LIMIT', 'UNRESOLVED')):
            return True
        return any((has_unsupported(value[key]) for key in ('fields', 'declared_views', 'uninterpreted_regions') if key in value))
    if isinstance(value, list):
        return any((has_unsupported(child) for child in value))
    return False

def iter_recovery_allocations(database, native_types, on_error):
    """Resume only at independent current clusters after an allocation failure."""
    from fsd_decoder.native.native_allocations import NativeAllocationReader

    class ClusterView:

        def __init__(self, cluster):
            self.cluster = cluster

        def __getattr__(self, name):
            return getattr(database, name)

        def iter_clusters(self):
            return iter([self.cluster])
    logged_failures = 0
    for cluster in database.iter_clusters():
        view = ClusterView(cluster)
        last_allocation = None
        reader = NativeAllocationReader(view, native_types)
        try:
            for allocation in reader.iter_allocations():
                last_allocation = dict(segment=allocation['segment'], cluster=allocation['cluster'], offset=allocation['logical_offset'], size=allocation['size'], source_metadata=allocation.get('source_metadata'))
                yield allocation
        except Exception as exc:
            context = dict(phase='allocation_traversal', segment=cluster['segment'], cluster=cluster['cluster'])
            context.update(getattr(reader, 'current_context', {}) or {})
            require_source_failure(exc, context)
            diagnostic = dict(status='UNPARSED_CLUSTER_TAIL', segment=cluster['segment'], cluster=cluster['cluster'], last_enumerated_allocation=last_allocation, failed_metadata_context=getattr(reader, 'current_context', None), exception_type=type(exc).__name__, message=str(exc), continuation='Abandoned remaining cluster; resume next current directory-owned cluster.', missing_allocation_count=None)
            detail = (failure_record(exc, status='UNPARSED_CLUSTER_TAIL', context=context)
                      if logged_failures < 100 else dict(error_category=error_category(exc), context=exc.context))
            logged_failures += 1
            diagnostic.update({k: detail[k] for k in ('error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})
            on_error(diagnostic)

def write_snapshot(database, stream, progress=None, *, recover_values=False):
    from fsd_decoder.native.native_allocations import iter_native_allocations
    from fsd_decoder.schema.native_fields import NativeFields
    fields = NativeFields(database, allow_partial_representations=True) if recover_values else NativeFields(database)
    counts = Counter()
    segment_properties = []
    for sid, segment in sorted(database.directory.get('segments', {}).items(), key=lambda item: int(item[0])):
        properties = {key: segment[key] for key in ('mode', 'native_normalized_mode', 'owner', 'comment', 'pair') if key in segment}
        if properties:
            segment_properties.append(dict(segment=int(sid), **properties))
    record(stream, 'HEADER', dict(format='fsd-native-text', format_version=1, decoder_version=VERSION, source_sha256=database.sha256, source_bytes=len(database.data), database_id=database.database_id, address_units='bytes', current_directory=database.directory['selected_outer_segment'], directory_events=database.directory['event_count'], segment_native_properties=segment_properties, value_error_policy='PRESERVE_RAW_AND_CONTINUE' if recover_values else 'STOP'))
    for extent in database.directory['effective_extents']:
        record(stream, 'EXTENT', extent)
    schema = fields.schema_report()
    record(stream, 'SCHEMA', schema)
    counts['representation_errors'] = len(schema.get('representation_errors', []))
    counts['schema_incomplete'] = not schema.get('schema_complete', True)
    roots = database.roots()
    for root in roots['roots']:
        record(stream, 'ROOT', root)
        counts['roots'] += 1
    last_update = time.monotonic()

    def cluster_error(diagnostic):
        record(stream, 'RECOVERY_DIAGNOSTIC', diagnostic)
        counts['unparsed_clusters'] += 1
    allocations = iter_recovery_allocations(database, fields.types, cluster_error) if recover_values else iter_native_allocations(database, native_types=fields.types)
    for allocation in allocations:
        address = database.address(allocation['segment'], allocation['cluster'], allocation['logical_offset'])
        metadata = dict(allocation)
        metadata['address'] = asdict(address)
        metadata['physical_spans'] = [asdict(s) for s in database.spans(address, allocation['size'])]
        header_size = allocation.get('array_header_size', 0)
        if header_size:
            metadata['array_header_raw_hex'] = database.read(address, header_size).hex()
        if allocation.get('vector'):
            meaningful_end = header_size + (allocation['count'] - 1) * allocation['element_stride'] + allocation['element_size']
            if meaningful_end < allocation['size']:
                tail_address = database.address(address.segment, address.cluster, address.offset + meaningful_end)
                metadata['trailing_padding_raw_hex'] = database.read(tail_address, allocation['size'] - meaningful_end).hex()
        record(stream, 'ALLOCATION', metadata)
        counts['allocations'] += 1
        for index in range(allocation['count'] if allocation.get('vector') else 1):
            try:
                value = fields.decode(allocation, element_index=index)
            except Exception as exc:
                context = dict(phase='decode_value', address=asdict(address), name=allocation.get('name'), native_tag=allocation.get('native_tag'), element_index=index)
                attach_context(exc, context)
                if not recover_values:
                    raise
                require_source_failure(exc, context)
                if allocation.get('vector'):
                    offset = header_size + index * allocation['element_stride']
                    size = allocation['element_size']
                else:
                    offset, size = (0, allocation['size'])
                if offset < 0 or size <= 0 or offset + size > allocation['size']:
                    raise MalformedSourceError('Cannot preserve value with unverified allocation bounds') from exc
                value_address = database.address(address.segment, address.cluster, address.offset + offset)
                value = dict(status='UNSUPPORTED_VALUE_DECODING', native_tag=allocation['native_tag'], type_name=allocation.get('name'), element_index=index, source_address=asdict(value_address), size=size, raw_hex=database.read(value_address, size).hex(), fields=[], error=dict(exception_type=type(exc).__name__, message=str(exc)))
                detail = (failure_record(exc, status='UNSUPPORTED_VALUE_DECODING', context=context)
                          if counts['recovered_value_errors'] < 100 else
                          dict(error_category=error_category(exc), context=exc.context))
                value['error'].update({k: detail[k] for k in ('error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})
                counts['recovered_value_errors'] += 1
            padding = allocation.get('inter_element_padding_size', 0)
            if padding and index + 1 < allocation['count']:
                padding_address = database.address(address.segment, address.cluster, address.offset + header_size + index * allocation['element_stride'] + allocation['element_size'])
                value['stride_padding_raw_hex'] = database.read(padding_address, padding).hex()
            record(stream, 'VALUE', value)
            counts['values'] += 1
            counts['unresolved'] += has_unsupported(value)
            if progress and counts['values'] % 4096 == 0 and (time.monotonic() - last_update >= 10):
                progress(dict(counts))
                last_update = time.monotonic()
        if progress and time.monotonic() - last_update >= 10:
            progress(dict(counts))
            last_update = time.monotonic()
    status = 'INCOMPLETE' if any((counts[key] for key in ('unresolved', 'representation_errors', 'schema_incomplete', 'unparsed_clusters'))) else 'COMPLETE'
    summary = dict(counts, status=status, completion_scope='current allocated values in the supported native layout')
    record(stream, 'SUMMARY', summary)
    return summary

@contextual('native_text_export', source='source', output='output')
def export(source, output, *, max_input_bytes=1000000000, progress=None):
    from fsd_decoder.native.native_database import NativeDatabase
    source, output = (Path(source).resolve(), Path(output).absolute())
    if type(max_input_bytes) is not int or max_input_bytes <= 0:
        raise InputValidationError('Input size limit must be positive')
    if not source.is_file():
        raise InputValidationError('Source must be a regular file')
    if output.exists() or output.is_symlink():
        raise InputValidationError('Output exists; choose a new path')
    if source.stat().st_size > max_input_bytes:
        raise ResourceLimitError('Source exceeds input size limit')
    with source.open('rb') as f:
        data = f.read(max_input_bytes + 1)
    if len(data) > max_input_bytes:
        raise ResourceLimitError('Source grew beyond input size limit')
    database = NativeDatabase(data)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n', dir=output.parent, prefix='.fsd-native-', delete=False) as stream:
            temporary = Path(stream.name)
            stats = write_snapshot(database, stream, progress)
            stream.flush()
            os.fsync(stream.fileno())
        if digest_file(source) != database.sha256:
            raise MalformedSourceError('Source changed during export; output was not published')
        os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return dict(stats, source_sha256=database.sha256, source_unchanged=True, output=str(output), output_bytes=output.stat().st_size)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path, help='new text output path')
    parser.add_argument('--max-input-bytes', type=int, default=1000000000)
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    install_termination_handler()

    def progress(counts):
        print(f'Exported {counts.get('allocations', 0):,} allocations / {counts.get('values', 0):,} values', file=sys.stderr, flush=True)
    try:
        stats = export(args.source, args.output, max_input_bytes=args.max_input_bytes, progress=progress)
    except Exception as exc:
        detail = failure_record(exc, status='DUMP_FAILED', context=dict(phase='native_text_export', source=str(args.source), output=str(args.output)))
        print(json.dumps(detail), file=sys.stderr, flush=True)
        if detail['error_category'] == 'PROGRAMMING_FAILURE':
            raise
        return 1
    except KeyboardInterrupt:
        print('Interrupted; incomplete output was not published.', file=sys.stderr)
        return 130
    print(json.dumps(stats, sort_keys=True))
    return 0 if stats['status'] == 'COMPLETE' else 2
if __name__ == '__main__':
    raise SystemExit(main())
