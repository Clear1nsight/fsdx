"""Bounded, resumable Python corpus encoding and source-independent validation."""
from __future__ import annotations
from fsd_decoder.core.provenance import runtime_identity
from fsd_decoder.core.paths import default_run_directory
import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import errno
from pathlib import Path
import signal
import subprocess
import sys
import threading
import stat
import tempfile
import time
from fsd_decoder.core.diagnostics import (InputValidationError, MalformedSourceError, ResourceLimitError, command_errors, contextual, failure_record)
DECODER = Path(__file__).resolve().parents[1]
SOURCES = None
BASELINE_ROOT = None
CANCEL = threading.Event()
DEFAULT_MEMORY_BUDGET_BYTES = 2 * 1024 ** 3
DEFAULT_WORKER_BASE_BYTES = 256 * 1024 ** 2
DEFAULT_SOURCE_MEMORY_MULTIPLIER = 3
MEMORY_SEMANTICS = 'Admission bounds the sum of source-size-based estimates across encoding and validation coordinators in this output directory. Estimates are not measured RSS or a hard process/group RSS limit.'

def estimated_memory_bytes(source_bytes, *, base_bytes=DEFAULT_WORKER_BASE_BYTES, source_multiplier=DEFAULT_SOURCE_MEMORY_MULTIPLIER):
    """Planning estimate for snapshot, schema copies, caches and interpreter overhead."""
    for name, value, minimum in (('source_bytes', source_bytes, 0), ('base_bytes', base_bytes, 1), ('source_multiplier', source_multiplier, 1)):
        if type(value) is not int or value < minimum:
            raise InputValidationError(f'{name} must be an integer >= {minimum}')
    return base_bytes + source_bytes * source_multiplier

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def save(path, value):
    path = Path(path)
    if path.is_symlink():
        raise InputValidationError('Generated report destination cannot be a symlink')
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '-', suffix='.tmp')
    stage = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink():
            raise InputValidationError('Generated report destination cannot be a symlink')
        os.replace(stage, path)
    finally:
        stage.unlink(missing_ok=True)

def generated_lock(path):
    """Open an owned regular lock file without following symbolic links."""
    descriptor = None
    try:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise InputValidationError('Generated lock path cannot be a symlink') from exc
            raise
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise InputValidationError('Generated lock must be a regular file with one link')
        stream = os.fdopen(descriptor, 'r+', encoding='utf-8')
        descriptor = None
        return stream
    finally:
        if descriptor is not None:
            os.close(descriptor)

def code_pins():
    return runtime_identity()

@contextmanager
def worker_slot(output, *, estimated_bytes=DEFAULT_WORKER_BASE_BYTES, budget_bytes=DEFAULT_MEMORY_BUDGET_BYTES):
    """Reserve a child slot and estimated bytes across processes, released on death.

    Flock owns each live reservation. Unlocked files are stale and ignored; a
    separate admission lock makes the sum check and slot reservation atomic.
    No source is launched if its estimate exceeds the configured byte budget.
    """
    if type(estimated_bytes) is not int or estimated_bytes < 1:
        raise InputValidationError('estimated_bytes must be a positive integer')
    if type(budget_bytes) is not int or budget_bytes < estimated_bytes:
        raise ResourceLimitError('Worker memory estimate exceeds the positive memory byte budget')
    selected = None
    while selected is None:
        if CANCEL.is_set():
            raise InputValidationError('Corpus run interrupted before child admission')
        with generated_lock(output / '.memory_admission.lock') as admission:
            fcntl.flock(admission, fcntl.LOCK_EX)
            policy_path = output / 'memory_policy.json'
            policy = dict(budget_bytes=budget_bytes, semantics=MEMORY_SEMANTICS)
            if policy_path.exists():
                if json.loads(policy_path.read_text()) != policy:
                    raise InputValidationError('Output directory has a different memory admission policy')
            else:
                save(policy_path, policy)
            free, active_bytes = ([], 0)
            try:
                for index in range(3):
                    candidate = generated_lock(output / ('.worker_' + str(index) + '.lock'))
                    try:
                        fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        free.append(candidate)
                    except BlockingIOError:
                        try:
                            candidate.seek(0)
                            reservation = json.load(candidate)
                            amount = reservation['estimated_memory_bytes']
                            if type(amount) is not int or amount < 1:
                                raise InputValidationError('Invalid live memory reservation')
                            active_bytes += amount
                        finally:
                            candidate.close()
                if free and active_bytes + estimated_bytes <= budget_bytes:
                    candidate = free[0]
                    candidate.seek(0)
                    candidate.truncate()
                    json.dump(dict(pid=os.getpid(), estimated_memory_bytes=estimated_bytes), candidate)
                    candidate.flush()
                    selected = free.pop(0)
            finally:
                for candidate in free:
                    fcntl.flock(candidate, fcntl.LOCK_UN)
                    candidate.close()
        if selected is None:
            time.sleep(0.2)
    try:
        yield selected.fileno()
    finally:
        fcntl.flock(selected, fcntl.LOCK_UN)
        selected.close()

def run_child(command, stdout, stderr, *, resources=None, reservation_fd=None):
    """Own the child group and collect this child's kernel peak RSS with wait4.

    ru_maxrss is a high-water mark, not the sum of simultaneous group RSS. On
    Linux it can also reflect descendants reaped by the child. It is measured
    independently for each PID rather than differencing RUSAGE_CHILDREN.
    """
    if CANCEL.is_set():
        raise InputValidationError('Corpus run interrupted before child launch')
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True, pass_fds=() if reservation_fd is None else (reservation_fd,))
    terminate_deadline = None
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            if resources is not None:
                resources.update(child_pid=pid, measured_peak_rss_bytes=int(usage.ru_maxrss) * (1 if sys.platform == 'darwin' else 1024), rss_measurement='wait4 child ru_maxrss high-water mark; not aggregate process-group RSS', user_cpu_seconds=usage.ru_utime, system_cpu_seconds=usage.ru_stime)
            return process.returncode
        if CANCEL.is_set():
            if terminate_deadline is None:
                terminate_deadline = time.monotonic() + 10
                sig = signal.SIGTERM
            elif time.monotonic() >= terminate_deadline:
                sig = signal.SIGKILL
            else:
                time.sleep(0.05)
                continue
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
        time.sleep(0.05)

@contextual('corpus_execute', phase='phase', output='output')
def execute(project, phase, output, pins, *, memory_budget_bytes=DEFAULT_MEMORY_BUDGET_BYTES, worker_base_bytes=DEFAULT_WORKER_BASE_BYTES, source_memory_multiplier=DEFAULT_SOURCE_MEMORY_MULTIPLIER, baseline_root=None):
    label = project_label(project.get('label'))
    folder = output / label
    if folder.is_symlink():
        raise InputValidationError('Project output directory cannot be a symlink')
    folder.mkdir(exist_ok=True)
    if folder.is_symlink():
        raise InputValidationError('Project output directory cannot be a symlink')
    report_path = folder / (phase + '_result.json')
    if phase == 'validate':
        encode_result = folder / 'encode_result.json'
        while not encode_result.exists():
            summary = output / 'encode_summary.json'
            if summary.exists():
                state = json.loads(summary.read_text())
                if state.get('status') in ('FAIL', 'PASS', 'INTERRUPTED'):
                    raise InputValidationError(f'{label}: encoding ended without a published proof')
            time.sleep(2)
        if json.loads(encode_result.read_text()).get('status') != 'PASS':
            raise InputValidationError(f'{label}: encoding failed; validation cannot proceed')
    if report_path.exists():
        previous = json.loads(report_path.read_text())
        if previous.get('status') == 'PASS':
            if previous['source_sha256'] != project['sha256'] or previous['code_pins'] != pins:
                raise InputValidationError(f'{label}: saved proof has different source or code pins')
            if phase == 'encode' and digest(folder / (label + '.fsdx')) != previous['store_sha256']:
                raise InputValidationError(f'{label}: saved store changed')
            if digest(project['path']) != project['sha256']:
                raise InputValidationError(f'{label}: original source changed since the saved proof')
            if phase == 'validate':
                validation_path = folder / 'validation/validation.json'
                proof = previous.get('validation', {})
                current_validator = digest(DECODER / 'portable/validate_corpus.py')
                if digest(folder / (label + '.fsdx')) != proof.get('store_sha256') or current_validator != proof.get('validator_sha256') or (not validation_path.exists()) or (digest(validation_path) != previous.get('validation_report_sha256')):
                    raise InputValidationError(f'{label}: saved validation proof, validator or store changed')
            return previous
        raise InputValidationError(f'{label}: previous {phase} failed; inspect its evidence before retrying')
    if code_pins() != pins:
        raise InputValidationError('Decoder code changed during the pinned run')
    source = Path(project['path'])
    source_bytes = source.stat().st_size
    estimate = estimated_memory_bytes(source_bytes, base_bytes=worker_base_bytes, source_multiplier=source_memory_multiplier)
    if estimate > memory_budget_bytes:
        raise ResourceLimitError(f'{label}: estimated memory {estimate} exceeds byte budget {memory_budget_bytes}')
    before = digest(source)
    if before != project['sha256']:
        raise MalformedSourceError(f'{label}: original source hash differs from canonical pin')
    store = folder / (label + '.fsdx')
    if phase == 'encode':
        command = [sys.executable, '-B', '-m', 'fsd_decoder.cli.encode', str(source), '--output', str(store)]
    else:
        command = [sys.executable, '-B', '-m', 'fsd_decoder.portable.validate_corpus', '--source', str(source), '--store', str(store), '--baseline', str((baseline_root or BASELINE_ROOT) / label), '--output', str(folder / 'validation')]
    validator_pin = None
    reused_validation = None
    if phase == 'validate':
        validator_pin = json.loads((output / 'validator_pins.json').read_text())['validate_corpus.py']
        if digest(DECODER / 'portable/validate_corpus.py') != validator_pin:
            raise InputValidationError('Validator changed during the pinned run')
        validation_path = folder / 'validation/validation.json'
        if validation_path.exists():
            reused_validation = json.loads(validation_path.read_text())
            if reused_validation.get('validator_sha256') != validator_pin or reused_validation.get('source_sha256') != before or reused_validation.get('store_sha256') != digest(store) or (reused_validation.get('status') != 'PASS') or (reused_validation.get('data_verification') != 'PASS'):
                raise InputValidationError(f'{label}: existing validation is incompatible with this run')
    started = time.monotonic()
    resources = dict(source_bytes=source_bytes, estimated_memory_bytes=estimate, memory_budget_bytes=memory_budget_bytes, memory_semantics=MEMORY_SEMANTICS)
    event = dict(label=label, phase=phase, status='RUNNING', started_utc=datetime.now(timezone.utc).isoformat(), resources=resources)
    save(folder / (phase + '_state.json'), event)
    print(json.dumps(event), flush=True)
    with (folder / (phase + '_stdout.json')).open('xb') as stdout, (folder / (phase + '_progress.jsonl')).open('xb') as stderr:
        if reused_validation:
            stdout.write(json.dumps({'reused_verified_report': str(validation_path)}).encode())
            returncode = 0
            resources['rss_measurement'] = 'No child launched; verified report reused'
        else:
            with worker_slot(output, estimated_bytes=estimate, budget_bytes=memory_budget_bytes) as reservation_fd:
                returncode = run_child(command, stdout, stderr, resources=resources, reservation_fd=reservation_fd)
    after = digest(source)
    result = dict(event, status='PASS' if returncode == 0 else 'FAIL', returncode=returncode, elapsed_seconds=round(time.monotonic() - started, 3), source_sha256=before, source_unchanged=before == after, code_pins=pins, command=command)
    if before != after or code_pins() != pins:
        result['status'] = 'FAIL'
        result['error'] = 'Source or decoder code changed during execution'
    if validator_pin and digest(DECODER / 'portable/validate_corpus.py') != validator_pin:
        result['status'] = 'FAIL'
        result['error'] = 'Validator changed during execution'
    if phase == 'encode' and returncode == 0:
        proof = json.loads((folder / 'encode_stdout.json').read_text())
        if proof.get('status') != 'COMPLETE' or proof.get('verified') is not True or proof.get('verification', {}).get('status') != 'PASS':
            result['status'] = 'FAIL'
            result['error'] = 'Encoder did not provide a complete capture proof'
        result.update(store_bytes=store.stat().st_size, store_sha256=digest(store), capture=proof)
    elif phase == 'validate' and returncode == 0:
        proof = json.loads((folder / 'validation/validation.json').read_text())
        if proof.get('status') != 'PASS' or proof.get('data_verification') != 'PASS' or proof.get('source_unchanged') is not True:
            result['status'] = 'FAIL'
            result['error'] = 'Validator did not provide complete, source-preserving data verification'
        result['validation'] = proof
        result['validation_report_sha256'] = digest(folder / 'validation/validation.json')
        if reused_validation:
            result['reused_verified_report'] = True
    save(report_path, result)
    save(folder / (phase + '_state.json'), result)
    print(json.dumps({k: result[k] for k in ('label', 'phase', 'status', 'elapsed_seconds', 'source_unchanged')}), flush=True)
    return result

def project_label(label):
    """A manifest label is exactly one child directory, never a path."""
    if (not isinstance(label, str) or not label or label in ('.', '..')
            or any(character in label for character in ('/', '\\', '\0'))
            or Path(label).is_absolute() or Path(label).name != label):
        raise InputValidationError('Project label must be a safe single child name')
    return label

@command_errors('CORPUS_FAILED')
def main(argv=None):
    global SOURCES, BASELINE_ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--phase', choices=('encode', 'validate'), required=True)
    parser.add_argument('--workers', type=int, default=3)
    parser.add_argument('--sources', type=Path, required=True, help='Canonical source manifest (source bytes are inspected before admission)')
    parser.add_argument('--baseline-root', type=Path)
    parser.add_argument('--memory-budget-bytes', type=int, default=DEFAULT_MEMORY_BUDGET_BYTES, help='Shared estimated-byte admission budget; not a hard RSS limit')
    parser.add_argument('--worker-base-bytes', type=int, default=DEFAULT_WORKER_BASE_BYTES)
    parser.add_argument('--source-memory-multiplier', type=int, default=DEFAULT_SOURCE_MEMORY_MULTIPLIER)
    parser.add_argument('--label', action='append')
    parser.add_argument('--wait-for-encoding', action='store_true', help='Validate stores as the concurrent encoder publishes them; requires a fresh encoder heartbeat')
    args = parser.parse_args(argv)
    SOURCES = args.sources.resolve()
    BASELINE_ROOT = args.baseline_root.resolve() if args.baseline_root else None
    if args.phase == 'validate' and BASELINE_ROOT is None:
        parser.error('--baseline-root is required for validation')
    if args.output is None:
        args.output = default_run_directory('corpus')
    CANCEL.clear()

    def interrupt(signum, frame):
        CANCEL.set()
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    if not 1 <= args.workers <= 3:
        parser.error('Use 1 to 3 workers to bound concurrent child count')
    if min(args.memory_budget_bytes, args.worker_base_bytes, args.source_memory_multiplier) < 1:
        parser.error('Memory budget, worker base and source multiplier must be positive integers')
    planning = dict(budget_bytes=args.memory_budget_bytes, worker_base_bytes=args.worker_base_bytes, source_memory_multiplier=args.source_memory_multiplier, semantics=MEMORY_SEMANTICS)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with generated_lock(output / ('.' + args.phase + '.lock')) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pins = code_pins()
        pin_file = output / 'decoder_pins.json'
        if pin_file.exists() and json.loads(pin_file.read_text()) != pins:
            raise InputValidationError('This output directory belongs to a different decoder revision')
        if not pin_file.exists():
            save(pin_file, pins)
        if args.phase == 'validate':
            validator_pins = {'validate_corpus.py': digest(DECODER / 'portable/validate_corpus.py')}
            validator_file = output / 'validator_pins.json'
            if validator_file.exists() and json.loads(validator_file.read_text()) != validator_pins:
                raise InputValidationError('This output directory belongs to a different validator revision')
            if not validator_file.exists():
                save(validator_file, validator_pins)
        projects = json.loads(args.sources.read_text())
        if not isinstance(projects, list) or any(not isinstance(p, dict) or not all(k in p for k in ('label', 'path', 'bytes', 'sha256')) or not isinstance(p['label'], str) or not isinstance(p['path'], str) or type(p['bytes']) is not int or p['bytes'] < 0 for p in projects):
            raise MalformedSourceError('Source manifest requires a list of label/path/bytes/sha256 records')
        labels = [project_label(project['label']) for project in projects]
        if len(set(labels)) != len(labels):
            raise InputValidationError('Source manifest project labels must be unique')
        if args.label:
            unknown = set(args.label) - {p['label'] for p in projects}
            if unknown:
                raise InputValidationError(f'Unknown projects: {sorted(unknown)}')
            projects = [p for p in projects if p['label'] in args.label]
        projects.sort(key=lambda p: (-p['bytes'], p['label']))
        results = []
        estimates = {}
        for project in projects:
            try:
                estimates[project['label']] = estimated_memory_bytes(Path(project['path']).stat().st_size, base_bytes=args.worker_base_bytes, source_multiplier=args.source_memory_multiplier)
            except OSError as exc:
                detail = failure_record(exc, status='FAIL', context=dict(phase='source_admission', source=project['path'], name=project['label']))
                results.append(dict(label=project['label'], phase=args.phase, status='FAIL', error=str(exc), **{k: detail[k] for k in ('error_type', 'error_category', 'context', 'developer_log', 'developer_log_error') if k in detail}))
                continue
            if estimates[project['label']] > args.memory_budget_bytes:
                exc = ResourceLimitError('Source memory estimate exceeds configured byte budget')
                detail = failure_record(exc, status='FAIL', context=dict(phase='source_admission', source=project['path'], name=project['label']))
                results.append(dict(label=project['label'], phase=args.phase, status='FAIL', error=str(exc), estimated_memory_bytes=estimates[project['label']], memory_planning=planning,
                    **{k: detail[k] for k in ('error_type', 'error_category', 'context', 'developer_log', 'developer_log_error') if k in detail}))
        rejected = {r['label'] for r in results}
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            pending, futures = ([p for p in projects if p['label'] not in rejected], {})
            while pending or futures:
                active_estimated_bytes = sum((estimates[p['label']] for p in futures.values()))
                save(output / (args.phase + '_heartbeat.json'), dict(updated_unix=time.time(), pending=len(pending), active=len(futures), active_estimated_memory_bytes=active_estimated_bytes, memory_planning=planning))
                if CANCEL.is_set():
                    results.extend((dict(label=p['label'], phase=args.phase, status='CANCELLED', error='Corpus run interrupted before admission') for p in pending))
                    pending.clear()
                for project in list(pending):
                    if len(futures) >= args.workers:
                        break
                    estimate = estimates[project['label']]
                    if active_estimated_bytes + estimate > args.memory_budget_bytes:
                        continue
                    if args.phase == 'validate' and (not (output / project['label'] / 'encode_result.json').exists()):
                        summary = output / 'encode_summary.json'
                        if not summary.exists() or json.loads(summary.read_text()).get('status') == 'RUNNING':
                            heartbeat = output / 'encode_heartbeat.json'
                            if args.wait_for_encoding and heartbeat.exists() and (time.time() - json.loads(heartbeat.read_text())['updated_unix'] < 60):
                                continue
                            pending.remove(project)
                            error = 'No completed encoding proof; run encoding first or use --wait-for-encoding with an active encoder'
                            results.append(dict(label=project['label'], phase=args.phase, status='FAIL', error=error))
                            print(json.dumps(results[-1]), flush=True)
                            continue
                    pending.remove(project)
                    futures[pool.submit(execute, project, args.phase, output, pins, memory_budget_bytes=args.memory_budget_bytes, worker_base_bytes=args.worker_base_bytes, source_memory_multiplier=args.source_memory_multiplier, baseline_root=args.baseline_root)] = project
                    active_estimated_bytes += estimate
                if not futures:
                    if pending:
                        time.sleep(2)
                    continue
                done, _ = wait(futures, timeout=2, return_when=FIRST_COMPLETED)
                for future in done:
                    project = futures.pop(future)
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        detail = failure_record(exc, status='FAIL', context=dict(phase=args.phase, source=project['path'], name=project['label']))
                        result = dict(label=project['label'], phase=args.phase, status='FAIL', error=str(exc), **{k: detail[k] for k in ('error_type', 'error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})
                        results.append(result)
                        print(json.dumps(result), flush=True)
                        folder = output / project['label']
                        folder.mkdir(exist_ok=True)
                        save(folder / (args.phase + '_state.json'), result)
                    save(output / (args.phase + '_summary.json'), dict(status='RUNNING', completed=len(results), total=len(projects), passed=sum((r['status'] == 'PASS' for r in results)), elapsed_seconds=round(time.monotonic() - started, 3), memory_planning=planning, results=results))
        success = all((r['status'] == 'PASS' for r in results))
        save(output / (args.phase + '_summary.json'), dict(status='INTERRUPTED' if CANCEL.is_set() else 'PASS' if success else 'FAIL', completed=len(results), total=len(projects), passed=sum((r['status'] == 'PASS' for r in results)), elapsed_seconds=round(time.monotonic() - started, 3), memory_planning=planning, results=results))
        return 130 if CANCEL.is_set() else 0 if success else 1
if __name__ == '__main__':
    sys.exit(main())
