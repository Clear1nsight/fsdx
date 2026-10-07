"""Preserve uncertain FSD bytes and any available native decoding in a new bundle.

Recovery never guesses object boundaries. source.hex preserves every physical
byte, including unallocated and historical storage. interpreted.txt contains the
strict decoder's records up to a supported completion or an explicit failure.
Linux atomic directory publication follows fsd_export's existing policy.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from fsd_decoder.cli.dump import VERSION, record, write_snapshot, install_termination_handler
from fsd_decoder.exports.fsd_export import digest, publish_directory
from fsd_decoder.core.diagnostics import (InputValidationError, MalformedSourceError,
    ResourceLimitError, contextual, failure_record, require_source_failure)

class ObservedRecords:
    """Count actual completed output records even if traversal later fails."""

    def __init__(self, stream):
        self.stream = stream
        self.counts = Counter()
        self.last_address = None

    def write(self, line):
        kind, payload = line.rstrip('\n').split(' ', 1)
        value = json.loads(payload)
        written = self.stream.write(line)
        self.counts[kind] += 1
        if kind in ('VALUE', 'ALLOCATION'):
            self.last_address = value.get('source_address', value.get('address'))
        return written

    def write_record(self, kind, value):
        record(self.stream, kind, value)
        self.counts[kind] += 1
        if kind in ('VALUE', 'ALLOCATION'):
            self.last_address = value.get('source_address', value.get('address'))

def write_hex(data, path):
    with path.open('x', encoding='ascii', newline='\n') as stream:
        for offset in range(0, len(data), 64):
            stream.write(f'{offset:016x} {data[offset:offset + 64].hex()}\n')
        stream.flush()
        os.fsync(stream.fileno())

@contextual('recovery_bundle', source='source', destination='output')
def recovery_bundle(source, destination, *, max_input_bytes=1000000000, raw_only=False, progress=None):
    from fsd_decoder.native.native_database import NativeDatabase
    source, destination = (Path(source).resolve(), Path(destination).absolute())
    if destination.exists() or destination.is_symlink():
        raise InputValidationError('Destination exists; choose a new directory')
    if type(max_input_bytes) is not int or max_input_bytes <= 0:
        raise InputValidationError('Input size limit must be positive')
    if not source.is_file():
        raise InputValidationError('Invalid source or input size limit')
    if source.stat().st_size > max_input_bytes:
        raise ResourceLimitError('Invalid source or input size limit')
    with source.open('rb') as stream:
        data = stream.read(max_input_bytes + 1)
    if len(data) > max_input_bytes:
        raise ResourceLimitError('Source grew beyond input size limit')
    source_hash = hashlib.sha256(data).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.fsd-recovery-', dir=destination.parent))
    try:
        if progress:
            progress({'phase': 'Preserving all physical source bytes'})
        write_hex(data, staging / 'source.hex')
        diagnostics = []
        summary = None
        status = 'RAW_ONLY_REQUESTED'
        observed = None
        if not raw_only:
            with (staging / 'interpreted.txt').open('x', encoding='utf-8', newline='\n') as stream:
                observed = ObservedRecords(stream)
                phase = 'native_database_initialization'
                try:
                    database = NativeDatabase(data)
                    database.source_path = source
                    phase = 'strict_native_snapshot_export'
                    if progress:
                        progress({'phase': 'Decoding current native snapshot'})
                    summary = write_snapshot(database, observed, progress, recover_values=True)
                    status = 'COMPLETE_SUPPORTED_NATIVE_LAYOUT' if summary['status'] == 'COMPLETE' else 'PARTIAL_INTERPRETATION'
                except Exception as exc:
                    context = dict(phase=phase, source=str(source), address=observed.last_address)
                    require_source_failure(exc, context)
                    status = 'PARTIAL_INTERPRETATION'
                    diagnostics.append(dict(phase=phase, exception_type=type(exc).__name__, message=str(exc), last_successful_address=observed.last_address, continuation='Stopped interpretation; all physical source bytes retained.'))
                    detail = failure_record(exc, status='PARTIAL_INTERPRETATION', context=context)
                    diagnostics[-1].update({k: detail[k] for k in ('error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})
                    record(observed, 'RECOVERY_DIAGNOSTIC', diagnostics[-1])
                record(observed, 'RECOVERY_SUMMARY', dict(status=status, strict_summary=summary, observed_records=dict(observed.counts), all_source_bytes_preserved=True, unknown_coverage='Objects after a traversal failure are not enumerated.'))
                stream.flush()
                os.fsync(stream.fileno())
        if digest(source) != source_hash:
            raise MalformedSourceError('Source changed during recovery; output was not published')
        files = [dict(path=p.name, bytes=p.stat().st_size, sha256=digest(p)) for p in sorted(staging.iterdir()) if p.is_file()]
        manifest = dict(format='fsd-recovery-bundle', format_version=1, decoder_version=VERSION, source=str(source), source_bytes=len(data), source_sha256=source_hash, source_unchanged=True, status=status, byte_preservation='COMPLETE_PHYSICAL_SOURCE', hex_format='16-digit physical byte offset, space, up to 64 bytes in lowercase hexadecimal', interpretation_scope='Current allocated values in supported native layouts; may be a prefix.', observed_records=dict(observed.counts) if observed else {}, strict_summary=summary, diagnostics=diagnostics, files=files, limitations=['Physical bytes include free and historical storage; they are not all current objects.', 'A recovered source byte does not establish its type, value or application meaning.', 'Unsupported allocation boundaries stop interpretation rather than guessing subsequent objects.', 'Unrecognized schema layouts retain raw bytes and explicit unsupported status.', 'Unexpected programming errors, I/O errors and interruption prevent publication.'])
        with (staging / 'manifest.json').open('x', encoding='utf-8') as stream:
            json.dump(manifest, stream, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if digest(source) != source_hash:
            raise MalformedSourceError('Source changed during recovery; output was not published')
        preservation = validate_preservation(staging)
        publish_directory(staging, destination)
        return dict(status=status, source_sha256=source_hash, source_unchanged=True, output=str(destination), byte_preservation='COMPLETE_PHYSICAL_SOURCE', preservation_validation=preservation)
    finally:
        if staging.exists():
            shutil.rmtree(staging)

def validate_preservation(bundle):
    """Independently reconstruct the source digest from textual offset/hex rows."""
    bundle = Path(bundle)
    manifest = json.loads((bundle / 'manifest.json').read_text())
    if (not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list)
            or type(manifest.get('source_bytes')) is not int or manifest['source_bytes'] < 0
            or not isinstance(manifest.get('source_sha256'), str)
            or not isinstance(manifest.get('status'), str)):
        raise MalformedSourceError('Invalid recovery manifest')
    for entry in manifest['files']:
        if (not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                or type(entry.get('bytes')) is not int or entry['bytes'] < 0
                or not isinstance(entry.get('sha256'), str)):
            raise MalformedSourceError('Invalid recovery artifact record')
        name = entry['path']
        if Path(name).name != name or name in ('.', '..'):
            raise MalformedSourceError('Artifact path is not a local filename')
        path = bundle / name
        if path.stat().st_size != entry['bytes'] or digest(path) != entry['sha256']:
            raise MalformedSourceError('Artifact bytes or digest disagree')
    source_digest = hashlib.sha256()
    expected = 0
    with (bundle / 'source.hex').open('r', encoding='ascii') as stream:
        for line in stream:
            try:
                offset, encoded = line.rstrip('\n').split(' ')
                raw = bytes.fromhex(encoded)
                parsed_offset = int(offset, 16)
            except ValueError as exc:
                raise MalformedSourceError('Source hex offsets/row lengths disagree') from exc
            if len(offset) != 16 or parsed_offset != expected or (not 1 <= len(raw) <= 64):
                raise MalformedSourceError('Source hex offsets/row lengths disagree')
            if expected + len(raw) < manifest['source_bytes'] and len(raw) != 64:
                raise MalformedSourceError('Short nonterminal source hex row')
            source_digest.update(raw)
            expected += len(raw)
    if expected != manifest['source_bytes'] or source_digest.hexdigest() != manifest['source_sha256']:
        raise MalformedSourceError('Reconstructed source bytes or digest disagree')
    return dict(status='VERIFIED_COMPLETE_PHYSICAL_BYTE_PRESERVATION', source_bytes=expected, source_sha256=source_digest.hexdigest(), interpretation_status=manifest['status'], scope='Byte preservation only; not field or object completeness.')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True, help='new recovery directory')
    parser.add_argument('--raw-only', action='store_true', help='preserve bytes without native interpretation')
    parser.add_argument('--max-input-bytes', type=int, default=1000000000)
    args = parser.parse_args(argv)
    install_termination_handler()
    try:
        result = recovery_bundle(args.source, args.output, raw_only=args.raw_only, max_input_bytes=args.max_input_bytes, progress=lambda counts: print(json.dumps(counts), file=sys.stderr, flush=True))
    except Exception as exc:
        detail = failure_record(exc, status='RECOVERY_FAILED', context=dict(phase='recovery_bundle', source=str(args.source), output=str(args.output)))
        print(json.dumps(detail), file=sys.stderr, flush=True)
        if detail['error_category'] == 'PROGRAMMING_FAILURE':
            raise
        return 1
    except KeyboardInterrupt:
        print('Interrupted; unfinished recovery bundle was not published.', file=sys.stderr)
        return 130
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] in ('COMPLETE_SUPPORTED_NATIVE_LAYOUT', 'RAW_ONLY_REQUESTED') else 2
if __name__ == '__main__':
    raise SystemExit(main())
