"""Encode an FSD into one validated, self-contained portable store.

The source is read-only and the destination must be a new file. Encoding records
native structure and source bytes; text, geometry and image exports are separate
operations that consume the resulting store. Verification is mandatory.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import sys
from fsd_decoder.core.diagnostics import InputValidationError, failure_record

def encode(source, destination, *, progress, verify, compact_pointer_pages=False,
           allocation_workers=1, allocation_batch_pages=16):
    """Load the writer lazily so CLI argument validation precedes initialization."""
    from fsd_decoder.portable.writer import encode as write_store
    return write_store(source, destination, progress=progress, verify=verify,
                       compact_pointer_pages=compact_pointer_pages,
                       allocation_workers=allocation_workers,
                       allocation_batch_pages=allocation_batch_pages)

def checked_paths(source, destination):
    source = Path(source).resolve()
    destination = Path(destination).absolute()
    if destination.resolve() == source:
        raise InputValidationError('Source and output must be different files')
    if destination.exists() or destination.is_symlink():
        if destination.is_file() and source.is_file() and os.path.samefile(source, destination):
            raise InputValidationError('Source and output refer to the same file')
        raise InputValidationError('Output already exists; choose a new file')
    if not source.is_file():
        raise InputValidationError('Source must be an existing regular file')
    return (source, destination)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='Input FSD file')
    parser.add_argument('--output', required=True, type=Path, help='New portable store file')
    parser.add_argument('--compact-pointer-pages', action='store_true',
                        help='Opt-in lossless page factoring; requires a reader supporting compact_pointer_pages_v1')
    parser.add_argument('--workers', type=int, choices=(1, 2, 3, 4), default=1,
                        help='Experimental native page preparation workers (default: serial)')
    parser.add_argument('--allocation-batch-pages', type=int, choices=range(1, 65), default=16,
                        metavar='1..64', help='Allocation pages per worker batch (default: 16)')
    args = parser.parse_args(argv)
    previous_handler = None
    context = dict(phase='validate_arguments', source=str(args.source), output=str(args.output))
    try:
        source, destination = checked_paths(args.source, args.output)

        def terminate(signum, frame):
            raise KeyboardInterrupt('Encoding terminated')
        previous_handler = signal.signal(signal.SIGTERM, terminate)

        def progress(event):
            context.update(event)
            print(json.dumps(event, ensure_ascii=True, sort_keys=True, default=str), file=sys.stderr, flush=True)
        context['phase'] = 'encode'
        options = dict(progress=progress, verify=True)
        if args.compact_pointer_pages:
            options['compact_pointer_pages'] = True
        if args.workers != 1 or args.allocation_batch_pages != 16:
            options.update(allocation_workers=args.workers,
                           allocation_batch_pages=args.allocation_batch_pages)
        result = encode(source, destination, **options)
        if not isinstance(result, dict) or result.get('status') != 'COMPLETE' or result.get('verified') is not True or (result.get('source_unchanged') is not True) or (result.get('verification', {}).get('status') != 'PASS'):
            raise RuntimeError('Writer did not return a complete, verified, source-preserving result')
        context['phase'] = 'publish_result'
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, default=str), flush=True)
        return 0
    except KeyboardInterrupt:
        print('Encoding interrupted; writer cleanup removed any unpublished staging output.', file=sys.stderr)
        return 130
    except Exception as exc:
        record = failure_record(exc, status='ENCODING_FAILED', context=context)
        print(json.dumps(record, ensure_ascii=True, default=str), file=sys.stderr, flush=True)
        if record['error_category'] == 'PROGRAMMING_FAILURE':
            raise
        return 1
    finally:
        if previous_handler is not None:
            signal.signal(signal.SIGTERM, previous_handler)
if __name__ == '__main__':
    sys.exit(main())
