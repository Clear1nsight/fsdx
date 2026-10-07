#!/usr/bin/env python3
"""Browse FSD inputs and supervise the canonical encoder in a Rich terminal."""
from __future__ import annotations

import argparse
from itertools import islice
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.metadata
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import termios
import time
import traceback
import tty
import uuid

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:
    raise SystemExit("Rich is required for this interface. From the project root, run: python3 -m pip install '.[tui]'")

PROJECT = Path(__file__).resolve().parents[1]
MAX_LINE = 1024 * 1024
MAX_DISPLAY_ROWS = 1000


def elapsed_clock(seconds: float) -> str:
    hours, remainder = divmod(max(0, int(seconds)), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f'{hours:02}:{minutes:02}:{seconds:02}'


def display_text(value) -> str:
    """Source text is literal data, never terminal control sequences."""
    return ''.join(c for c in str(value) if c.isprintable())[:256]


def display_path(value: str | Path) -> str:
    """Show project paths from fsd/ while preserving external locations."""
    try:
        relative = Path(value).relative_to(PROJECT)
    except ValueError:
        return str(value)
    return str(Path(PROJECT.name) / relative)


class LiveDiscovery:
    """Bounded presentation of this worker's evidence, initially empty."""
    def __init__(self):
        self.information = {}
        self.rows = []
        self.index = {}
        self.entities = None
        self.families = None
        self.name_candidates = None
        self.enumerated = False
        self.rows_truncated = False
        self.unresolved_pointers = None
        self.semantic_complete = None
        self.stages_seen = set()
        self.schema_issues = None
        self.evidence_error = ""

    def update(self, event):
        phase = event.get('phase')
        if phase:
            self.stages_seen.add(phase)
        if type(event.get('unresolved_pointers')) is int:
            self.unresolved_pointers = event['unresolved_pointers']
        coverage = event.get('coverage', {})
        if type(coverage.get('unresolved_pointers')) is int:
            self.unresolved_pointers = coverage['unresolved_pointers']
        if type(event.get('application_semantics_complete')) is bool:
            self.semantic_complete = event['application_semantics_complete']
        if event.get('phase') == 'file_information':
            self.information.update(event.get('information', {}))
        for key in ('allocations', 'pointers', 'stored_elements'):
            if type(event.get(key)) is int:
                self.information[key] = event[key]
            if type(event.get('counts', {}).get(key)) is int:
                self.information[key] = event['counts'][key]
        for key, attribute in (('entities_discovered', 'entities'), ('candidate_families', 'families'),
                               ('name_candidates', 'name_candidates')):
            if type(event.get(key)) is int:
                setattr(self, attribute, event[key])
        if event.get('phase') == 'dataset_discovery_summary':
            self.enumerated = event.get('enumeration_complete') is True
        if event.get('phase') == 'dataset_discovery_rows':
            for row in event.get('datasets', []):
                identifier = row['id']
                if identifier in self.index:
                    self.rows[self.index[identifier]] = row
                elif len(self.rows) < MAX_DISPLAY_ROWS:
                    self.index[identifier] = len(self.rows)
                    self.rows.append(row)
                else:
                    self.rows_truncated = True


def inventory(directory: Path) -> list[tuple[Path, int]]:
    """List filesystem facts without opening sources or consulting sidecars."""
    files = [p for p in directory.iterdir() if p.suffix.lower() == '.fsd' and p.is_file()]
    files.sort(key=lambda p: [int(s) if s.isdigit() else s.lower()
                             for s in re.split(r'(\d+)', p.name)])
    return [(p.absolute(), p.stat().st_size) for p in files]


def progress_bounds(event: dict) -> tuple[int, int] | None:
    # Discovery budgets are not measured population totals.
    for done, total in (('completed_bytes', 'total_bytes'),
                        ('allocations_compared', 'total_allocations'),
                        ('pointers_compared', 'total_pointers')):
        a, b = event.get(done), event.get(total)
        if type(a) is int and type(b) is int and 0 <= a <= b and b > 0:
            return a, b
    return None


def verified_result(result: dict, output: Path, exit_code: int) -> bool:
    proof = result.get('verification')
    return (exit_code == 0 and result.get('status') == 'COMPLETE'
            and result.get('verified') is True and result.get('source_unchanged') is True
            and isinstance(proof, dict) and proof.get('status') == 'PASS'
            and result.get('output') == str(output) and output.is_file())


def open_store(output):
    """Use the maintained reader, never a parallel SQLite/JSON implementation."""
    runtime_path = str(PROJECT / 'src')
    if runtime_path not in sys.path:
        sys.path.insert(0, runtime_path)
    from fsd_decoder.portable.format import Store
    return Store(output, cache_bytes=1024 * 1024)


def schema_evidence(report):
    problems = report.get('layout_problems', {})
    errors = report.get('representation_errors', [])
    preview = []
    for name in islice(problems, 4):
        for issue in islice(problems[name], 2):
            reason = issue.get('kind') or issue.get('error') or 'Layout disagreement'
            preview.append(display_text(f'{name}: {issue.get("member", "")} {reason}'))
    for issue in islice(errors, 2):
        preview.append(display_text(f"{issue.get('name', 'Representation')}: {issue.get('error', 'Unsupported')}"))
    return dict(layout_problem_classes=len(problems), representation_errors=len(errors), preview=preview)


def read_schema_evidence(output):
    """Read a bounded schema preview with the canonical lazy FSDX reader."""
    with open_store(output) as store:
        return schema_evidence(store.document('schema', 'report', lazy=True))


def inventory_exports(files, directory):
    """Find saved filenames/sizes; filename association does not verify a source."""
    sources = {path.stem: path for path, _ in files}
    exports = {}
    orphans = []
    if not directory.exists():
        return files, exports
    for path in directory.rglob('*'):
        if path.suffix.lower() != '.fsdx' or path.is_symlink() or not path.is_file():
            continue
        try:
            stat = path.stat()
        except FileNotFoundError:
            continue  # An external cleanup may remove an export during refresh.
        path = path.absolute()
        source = sources.get(path.stem)
        if source is None:
            source = path
            orphans.append((path, stat.st_size))
        exports.setdefault(source, []).append(dict(path=path, bytes=stat.st_size, modified_ns=stat.st_mtime_ns))
    for candidates in exports.values():
        candidates.sort(key=lambda item: (item['modified_ns'], str(item['path'])), reverse=True)
    return files + sorted(orphans, key=lambda item: str(item[0])), exports


class SavedExport:
    """Detached bounded presentation of one saved store; owns no decoder process."""
    def __init__(self, source: Path, output: Path):
        self.source, self.output = source, output
        self.directory = output.parent
        self.status, self.event, self.error = 'Saved', {'phase': 'saved_export'}, ''
        self.elapsed = None
        self.discovery = LiveDiscovery()
        self.result = {'output_bytes': output.stat().st_size}
        state = self.discovery
        with open_store(output) as store:
            manifest = store.manifest
            recorded = manifest.get('source', {})
            self.saved_source = dict(recorded)
            self.store_version = manifest['version']
            backend = manifest.get('runtime_identity', {}).get('json_preflight', {}).get('backend')
            if backend is not None:
                state.information['json_preflight_backend'] = backend
            state.information.update({key: recorded[name] for key, name in (
                ('source_bytes', 'bytes'), ('source_sha256', 'sha256'), ('database_id', 'database_id')) if name in recorded})
            coverage = manifest.get('coverage', {})
            state.update({'coverage': coverage, 'counts': manifest.get('counts', {})})
            for key in ('schema_complete', 'logical_bytes'):
                if key in coverage:
                    state.information[key] = coverage[key]
            if 'clusters' in manifest.get('counts', {}):
                state.information['clusters'] = manifest['counts']['clusters']
            semantics = manifest.get('semantic_limits', {})
            state.semantic_complete = semantics.get('application_semantics_complete')
            if any(name == 'report' for _, name in store.iter_documents('schema')):
                report = store.document('schema', 'report', lazy=True)
                state.schema_issues = schema_evidence(report)
                state.information['schema_classes'] = len(report.get('classes', {}))
                for key in ('schema_complete',):
                    if key in report:
                        state.information[key] = report[key]
                if 'native_type_bindings' in report:
                    state.information['native_type_bindings'] = len(report['native_type_bindings'])
            else:
                state.evidence_error = 'No retained schema report in this store.'
            if not any(name == 'datasets' for _, name in store.iter_documents('discovery')):
                state.evidence_error = 'No retained discovery document in this store.'
                return
            discovery = store.document('discovery', 'datasets', lazy=True)
            metadata = discovery.get('file_metadata', {})
            for key, _ in FILE_INFORMATION_LABELS:
                if key in metadata:
                    state.information[key] = metadata[key]
            if discovery.get('format') != 'FSD_DATASET_DISCOVERY' or type(discovery.get('version')) is not int or discovery['version'] != 2:
                state.evidence_error = 'Unsupported discovery preview version; saved bytes and schema remain available.'
                return
            entities = discovery.get('objects')
            names = discovery.get('dataset_name_candidates')
            families = discovery.get('dataset_candidate_types')
            state.entities, state.name_candidates, state.families = (len(rows) if rows is not None else None for rows in (entities, names, families))
            state.enumerated = discovery.get('inspection', {}).get('enumeration_complete') is True
            state.semantic_complete = discovery.get('application_semantics_complete', state.semantic_complete)
            accounting = discovery.get('accounting', {})
            for key in ('allocations', 'stored_elements'):
                if key in accounting:
                    state.information[key] = accounting[key]
            if 'pointer_bindings' in accounting:
                state.information['pointers'] = accounting['pointer_bindings']
            for records, classification in ((entities, 'ESTABLISHED_ENTITY'),
                    (names, 'SOURCE_ENTITY_NAME_CANDIDATE'), (families, 'UNCONFIRMED_OBJECT_FAMILY')):
                for obj in islice(records if records is not None else (), max(0, MAX_DISPLAY_ROWS - len(state.rows))):
                    if classification == 'UNCONFIRMED_OBJECT_FAMILY':
                        row = dict(id='family:' + obj['type'], type=obj['type'][:256], names=[],
                            classification=classification, allocations=obj['allocations'], elements=obj.get('elements', 'not reported'))
                    else:
                        fields = obj.get('name_fields', [])
                        selected_fields = list(islice(fields, 4))
                        row = dict(id=obj['id'], type=obj['type'][:256], classification=classification,
                            names=[dict(text=f['text'][:256], status=f['status']) for f in selected_fields],
                            names_truncated=len(fields)>4 or any(len(f['text'])>256 for f in selected_fields),
                            status=obj.get('status', 'Not reported'),
                            address={key: obj['address'][key] for key in ('database', 'segment', 'cluster', 'offset') if key in obj.get('address', {})},
                            creation_time_fields=[{key: field[key] for key in ('raw_hex', 'value', 'unsigned_value') if key in field}
                                for field in islice(obj.get('creation_time_fields', []), 2)])
                    state.update({'phase': 'dataset_discovery_rows', 'datasets': [row]})
            state.rows_truncated = sum(len(rows) for rows in (entities, names, families) if rows is not None) > len(state.rows)




class ProcessResources:
    """Linux counters for the owned encoder PID, excluding the TUI and descendants.

    CPU 100% means one logical CPU. Affinity is not a cgroup CPU entitlement.
    Sampling is bounded in memory; full history belongs in the run's JSONL log.
    """
    def __init__(self, pid: int, *, include_descendants: bool = False):
        self.pid = pid
        self.include_descendants = include_descendants
        self.members = {}
        self.peak_pss_bytes = None
        self.ticks = os.sysconf('SC_CLK_TCK')
        self.page_bytes = os.sysconf('SC_PAGE_SIZE')
        self.identity = None
        self.previous = None
        self.first = None
        self.latest = None
        self.samples = 0
        self.peak_rss_bytes = 0
        self.peak_cpu_percent = None
        self.error = ''
        self.last_attempt = None

    def _tree(self, sample):
        """Sequential owned-tree snapshots; never count reaped CPU twice.

        Retain last observed counters after a child exits. Work between its last
        sample and exit, and children born/exited between samples, is unobserved.
        RSS counts shared pages repeatedly; PSS apportions those pages.
        """
        todo = [(self.pid, None)]
        seen, rows, warnings = set(), [], []
        while todo:
            pid, parent = todo.pop()
            if pid in seen:
                continue
            if len(seen) >= 128:
                warnings.append('Process tree exceeds 128-process sampling limit')
                break
            seen.add(pid)
            root = Path('/proc') / str(pid)
            try:
                fields = root.joinpath('stat').read_text().rsplit(')', 1)[1].split()
                identity = int(fields[19])
                if fields[0] in ('Z', 'X') or (parent is not None and int(fields[1]) != parent):
                    raise ValueError('Exited or reparented descendant')
                if pid == self.pid and identity != sample['start_ticks']:
                    raise ValueError('Encoder PID identity changed')
                pss = None
                try:
                    pss = next(int(line.split()[1]) * 1024 for line in
                        root.joinpath('smaps_rollup').read_text().splitlines() if line.startswith('Pss:'))
                except (OSError, ValueError, StopIteration):
                    pass
                io = {}
                try:
                    io = dict((key, int(value)) for key, value in
                        (line.split(':', 1) for line in root.joinpath('io').read_text().splitlines()))
                except (OSError, ValueError):
                    pass
                again = root.joinpath('stat').read_text().rsplit(')', 1)[1].split()
                if int(again[19]) != identity or again[0] in ('Z', 'X') or (parent is not None and int(again[1]) != parent):
                    raise ValueError('Process changed during tree sampling')
                rows.append(dict(pid=pid, start_ticks=identity,
                    cpu_seconds=(int(fields[11]) + int(fields[12])) / self.ticks,
                    rss_bytes=max(0, int(fields[21])) * self.page_bytes, pss_bytes=pss,
                    threads=int(fields[17]), read_bytes=io.get('read_bytes'), write_bytes=io.get('write_bytes')))
                try:
                    for task in root.joinpath('task').iterdir():
                        todo.extend((int(child), pid) for child in task.joinpath('children').read_text().split())
                except (OSError, ValueError):
                    warnings.append('Descendant enumeration incomplete')
            except (OSError, ValueError, IndexError) as exc:
                if pid == self.pid:
                    raise
                warnings.append(display_text(exc))
        for row in rows:
            key = (row['pid'], row['start_ticks'])
            if key not in self.members and len(self.members) >= 256:
                raise ValueError('Process lifetime ledger exceeds 256 identities')
            self.members[key] = row
        sample.update(process_cpu_seconds=sum(r['cpu_seconds'] for r in self.members.values()),
            rss_bytes=sum(r['rss_bytes'] for r in rows),
            pss_bytes=sum(r['pss_bytes'] for r in rows) if rows and all(r['pss_bytes'] is not None for r in rows) else None,
            threads=sum(r['threads'] for r in rows), processes=rows, process_count=len(rows),
            tree_warning='; '.join(dict.fromkeys(warnings)))
        # Linux parent I/O may absorb waited-child counters. Summing lifetime
        # rows would double-count them; retain per-PID evidence without totals.
        sample['read_bytes'] = sample['write_bytes'] = None
        return sample

    def sample(self, phase: str, *, force: bool = False) -> dict | None:
        now = time.monotonic()
        if not force and self.last_attempt is not None and now - self.last_attempt < 1:
            return None
        self.last_attempt = now
        try:
            root = Path('/proc') / str(self.pid)
            # comm can contain spaces and parentheses: field 3 follows the last ')'.
            fields = root.joinpath('stat').read_text().rsplit(')', 1)[1].split()
            identity = int(fields[19])  # starttime, field 22
            if self.identity is not None and identity != self.identity:
                raise ValueError('Encoder PID identity changed; counters rejected')
            if fields[0] in ('Z', 'X'):
                raise ValueError('Encoder has exited; last live sample retained')
            cpu = (int(fields[11]) + int(fields[12])) / self.ticks
            rss = max(0, int(fields[21])) * self.page_bytes
            status = dict(line.split(':', 1) for line in root.joinpath('status').read_text().splitlines() if ':' in line)
            hwm = int(status['VmHWM'].split()[0]) * 1024 if 'VmHWM' in status else rss
            virtual = int(status['VmSize'].split()[0]) * 1024 if 'VmSize' in status else None
            allowed = len(os.sched_getaffinity(self.pid))
            io = {}
            try:
                io = {key: int(value) for key, value in (line.split(':', 1) for line in root.joinpath('io').read_text().splitlines())}
            except (OSError, ValueError):
                pass  # I/O permissions do not suppress valid CPU/RAM counters.
            # Reject an exit/reuse race between reads rather than mixing processes.
            again = root.joinpath('stat').read_text().rsplit(')', 1)[1].split()
            if int(again[19]) != identity or again[0] in ('Z', 'X'):
                raise ValueError('Encoder exited or changed during sampling')
            self.identity = identity
            sample = dict(pid=self.pid, start_ticks=identity, monotonic_seconds=now,
                phase=phase, process_cpu_seconds=cpu, cpu_percent=None, effective_cores=None,
                rss_bytes=rss, virtual_bytes=virtual, threads=int(fields[17]),
                allowed_logical_cpus=allowed, system_logical_cpus=os.cpu_count(),
                read_bytes=io.get('read_bytes'), write_bytes=io.get('write_bytes'),
                read_bytes_per_second=None, write_bytes_per_second=None)
            if self.include_descendants:
                sample = self._tree(sample)
                cpu, rss = sample['process_cpu_seconds'], sample['rss_bytes']
                hwm = rss  # A sum of per-process historical peaks is not a tree peak.
            if self.previous is not None:
                seconds = now - self.previous['monotonic_seconds']
                if seconds > 0:
                    sample['effective_cores'] = max(0, cpu - self.previous['process_cpu_seconds']) / seconds
                    sample['cpu_percent'] = sample['effective_cores'] * 100
                    sample['interval_seconds'] = seconds
                    sample['interval_start_phase'] = self.previous['phase']
                    for direction in ('read', 'write'):
                        key = direction + '_bytes'
                        if sample[key] is not None and self.previous[key] is not None:
                            sample[key + '_per_second'] = max(0, sample[key] - self.previous[key]) / seconds
            self.peak_rss_bytes = max(self.peak_rss_bytes, rss, hwm)
            if sample['cpu_percent'] is not None:
                self.peak_cpu_percent = max(self.peak_cpu_percent or 0, sample['cpu_percent'])
            sample['observed_peak_rss_bytes'] = self.peak_rss_bytes
            if sample.get('pss_bytes') is not None:
                self.peak_pss_bytes = max(self.peak_pss_bytes or 0, sample['pss_bytes'])
            sample['observed_peak_pss_bytes'] = self.peak_pss_bytes
            self.first = self.first or sample
            self.previous = self.latest = sample
            self.samples += 1
            self.error = ''
            return sample
        except (OSError, ValueError, IndexError, KeyError) as exc:
            self.error = display_text(f'Resource counters unavailable: {exc}')
            return None

    def summary(self) -> dict:
        duration = cpu = None
        if self.first is not None and self.latest is not None:
            duration = self.latest['monotonic_seconds'] - self.first['monotonic_seconds']
            cpu = self.latest['process_cpu_seconds'] - self.first['process_cpu_seconds']
        return dict(scope=('owned_encoder_tree_excluding_tui' if self.include_descendants else
            'encoder_pid_only_including_threads_excluding_descendants_and_tui'),
            caveat='Sequential samples; short-lived children and work after their last sample may be missed. RSS double-counts shared pages; PSS is proportional, not an exact lifetime peak.',
            pid=self.pid, samples=self.samples, sampled_seconds=duration, sampled_cpu_seconds=cpu,
            average_effective_cores=cpu / duration if duration else None,
            peak_cpu_percent=self.peak_cpu_percent,
            observed_peak_rss_bytes=self.peak_rss_bytes if self.samples else None,
            observed_peak_pss_bytes=self.peak_pss_bytes,
            last_sample=self.latest, error=self.error)


def resource_lines(job, active: bool) -> list[Text]:
    monitor = getattr(job, 'resources', None)
    if monitor is None:
        return []
    sample = monitor.latest
    if sample is None or (active and monitor.error):
        return [Text(monitor.error or 'Decoder resources: waiting for CPU sample', style='dim')]
    if not active:
        summary = monitor.summary()
        average = summary['average_effective_cores']
        peak = summary['peak_cpu_percent']
        cpu = 'not sampled' if average is None else f'{average:.2f} cores average • {peak:.1f}% peak observed'
        memory = f'PSS peak: {monitor.peak_pss_bytes / 1048576:,.1f} MiB' if monitor.peak_pss_bytes is not None else f'RSS peak: {monitor.peak_rss_bytes / 1048576:,.1f} MiB'
        return [Text('CPU: ' + cpu), Text(f'{memory} observed • {monitor.samples} samples • ' + ('Encoder + descendants' if monitor.include_descendants else 'Encoder PID'))]
    cpu = 'warming up' if sample['cpu_percent'] is None else f'{sample["cpu_percent"]:.1f}% • {sample["effective_cores"]:.2f} cores'
    prefix = 'CPU' if active else 'Last sampled CPU'
    if monitor.include_descendants:
        pss = sample.get('pss_bytes')
        memory = f'PSS: {pss / 1048576:,.1f} MiB' if pss is not None else 'PSS unavailable'
        return [Text(f'{prefix}: {cpu} • {memory}'),
            Text(f'RSS sum: {sample["rss_bytes"] / 1048576:,.1f} MiB • {sample.get("process_count", 0)} processes • {sample["threads"]} threads'),
            Text(f'Encoder + descendants • excludes TUI • parent affinity: {sample["allowed_logical_cpus"]} CPUs', style='dim'),
            Text(sample.get('tree_warning') or '100% = 1 logical CPU • RSS counts shared pages repeatedly', style='yellow' if sample.get('tree_warning') else 'dim')]
    lines = [Text(f'{prefix}: {cpu} • RAM: {sample["rss_bytes"] / 1048576:,.1f} MiB'),
        Text(f'RAM peak observed: {sample["observed_peak_rss_bytes"] / 1048576:,.1f} MiB • Threads: {sample["threads"]}'),
        Text(f'Decoder PID {monitor.pid} • Allowed logical CPUs: {sample["allowed_logical_cpus"]} • 100% = 1 core', style='dim')]
    read, write = sample['read_bytes_per_second'], sample['write_bytes_per_second']
    if read is not None and write is not None:
        lines.append(Text(f'Disk I/O: read {read / 1048576:.2f} • write {write / 1048576:.2f} MiB/s', style='dim'))
    if getattr(job, 'resource_log_error', ''):
        lines.append(Text(job.resource_log_error, style='yellow'))
    return lines


class Job:
    """One owned subprocess, bounded pipe buffers and durable per-run logs."""
    def __init__(self, source: Path, selector: selectors.BaseSelector, *, workers: int = 1):
        if type(workers) is not int or workers not in (1, 2, 4):
            raise ValueError('TUI workers must be 1, 2 or 4')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.directory = PROJECT / 'artifacts' / 'exports' / f'{source.stem}_{stamp}_{uuid.uuid4().hex[:8]}'
        self.directory.mkdir(parents=True)
        self.source = source
        self.output = self.directory / f'{source.stem}.fsdx'
        self.command = [sys.executable, '-B', '-m', 'fsd_decoder.cli.encode',
                        str(source), '--output', str(self.output)]
        if workers > 1:
            self.command.extend(['--workers', str(workers)])
        env = dict(os.environ, PYTHONPATH=str(PROJECT / 'src'),
                   PYTHONDONTWRITEBYTECODE='1', FSD_PROJECT_ROOT=str(PROJECT),
                   FSD_ARTIFACT_ROOT=str(self.directory), TMPDIR=str(self.directory))
        self.selector = selector
        self.streams = {}
        self.logs = {}
        self.buffers = {}
        self.started = time.monotonic()
        self.event = {'phase': 'starting'}
        self.discovery = LiveDiscovery()
        self.result = {}
        self.error = ''
        self.status = 'Running'
        self.cancelled_at = None
        metadata = {'source': str(source), 'output': str(self.output), 'command': self.command,
                    'started_utc': stamp, 'rich_version': importlib.metadata.version('rich'),
                    'launcher': str(Path(__file__).resolve()),
                    'launcher_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        (self.directory / 'launch.json').write_text(json.dumps(metadata, indent=2) + '\n')
        try:
            self.process = subprocess.Popen(self.command, cwd=PROJECT, env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            start_new_session=True)
            self.resources = ProcessResources(self.process.pid, include_descendants=True)
            self.resource_log_error = ''
            for name in ('stdout', 'stderr'):
                stream = getattr(self.process, name)
                self.logs[name] = (self.directory / f'{name}.jsonl').open('wb')
                self.streams[name] = stream
                self.buffers[name] = bytearray()
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            try:
                self.logs['resources'] = (self.directory / 'resources.jsonl').open('w')
            except OSError as exc:
                self.resource_log_error = display_text(f'Resource log unavailable: {exc}')
            self.sample_resources(force=True)
        except Exception:
            if hasattr(self, 'process'):
                self.process.terminate()
                self.process.wait()
            self.close()
            raise

    def sample_resources(self, *, force: bool = False) -> None:
        sample = self.resources.sample(str(self.event.get('phase', 'starting')), force=force)
        if sample is not None and not self.resource_log_error:
            try:
                self.logs['resources'].write(json.dumps(sample) + '\n')
                self.logs['resources'].flush()
            except OSError as exc:
                self.resource_log_error = display_text(f'Resource log unavailable: {exc}')

    def consume(self, name: str) -> None:
        stream = self.streams[name]
        chunk = os.read(stream.fileno(), 65536)
        if not chunk:
            if self.buffers[name]:
                self.line(name, bytes(self.buffers[name]))
            self.selector.unregister(stream)
            stream.close()
            del self.streams[name]
            self.logs[name].close()
            return
        self.logs[name].write(chunk)
        self.logs[name].flush()
        buffer = self.buffers[name]
        buffer.extend(chunk)
        while b'\n' in buffer:
            line, _, rest = buffer.partition(b'\n')
            buffer[:] = rest
            self.line(name, line)
        if len(buffer) > MAX_LINE:
            self.error = 'Encoder exceeded the interface record limit; see logs.'
            buffer.clear()
            self.cancel()

    def line(self, name: str, data: bytes) -> None:
        if len(data) > MAX_LINE:
            self.error = 'Encoder exceeded the interface record limit; see logs.'
            self.cancel()
            return
        try:
            event = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            self.error = data.decode(errors='replace')[-500:]
            return
        if not isinstance(event, dict):
            return
        self.discovery.update(event)
        if name == 'stdout':
            self.result = event
        elif event.get('status') == 'ENCODING_FAILED':
            self.error = str(event.get('message') or event.get('error') or event)[-500:]
        elif event.get('phase') not in ('file_information', 'dataset_discovery_rows', 'dataset_discovery_summary'):
            self.event = event

    def cancel(self) -> None:
        if self.process.poll() is None and self.cancelled_at is None:
            self.cancelled_at = time.monotonic()
            self.status = 'Stopping'
            self.process.terminate()

    def force_stop(self) -> None:
        """Kill only this launch's session, or still-identifiable owned children."""
        if self.process.poll() is None:
            # Popen still owns an unreaped leader; its PID cannot have been reused.
            os.killpg(self.process.pid, signal.SIGKILL)
            return
        for row in getattr(self.resources, 'members', {}).values():
            try:
                fields = (Path('/proc') / str(row['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()
                if int(fields[19]) == row['start_ticks'] and os.getpgid(row['pid']) == self.process.pid:
                    os.kill(row['pid'], signal.SIGKILL)
            except (OSError, ValueError, IndexError):
                pass

    def poll(self) -> bool:
        if self.cancelled_at is not None and time.monotonic() - self.cancelled_at > 10:
            self.force_stop()
        code = self.process.poll()
        if code is None or self.streams:
            return False
        # A verified publication wins a cancellation race; retain and report it.
        if verified_result(self.result, self.output, code):
            self.status = 'Verified'
            try:
                self.discovery.schema_issues = read_schema_evidence(self.output)
            except Exception as exc:
                # Supplementary display failure cannot invalidate the worker's proof.
                self.discovery.evidence_error = display_text(f'Schema detail unavailable: {exc}')
                (self.directory / 'display_evidence_error.txt').write_text(traceback.format_exc())
        elif self.cancelled_at is not None:
            self.status = 'Cancelled'
        else:
            self.status = 'Failed'
            self.error = self.error or f'Encoder exited with code {code} without a verified result.'
        (self.directory / 'session.json').write_text(json.dumps({
            'status': self.status, 'exit_code': code, 'elapsed_seconds': time.monotonic() - self.started,
            'error': self.error, 'output': str(self.output), 'output_exists': self.output.is_file(),
            'display_evidence_error': self.discovery.evidence_error,
            'resources': self.resources.summary() if hasattr(self, 'resources') else None,
            'resource_log_error': getattr(self, 'resource_log_error', ''),
        }, indent=2) + '\n')
        return True

    def close(self) -> None:
        for stream in self.streams.values():
            try:
                self.selector.unregister(stream)
            except KeyError:
                pass
            stream.close()
        self.streams.clear()
        for log in self.logs.values():
            log.close()


@contextmanager
def terminal_keys():
    previous = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())
        yield
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, previous)


def discovery_rows(job, object_types=False):
    rows = job.discovery.rows if job else []
    return rows if object_types else [row for row in rows
        if row['classification'] != 'UNCONFIRMED_OBJECT_FAMILY']


def move_discovery_selection(job, selected, direction, object_types=False):
    return min(max(0, len(discovery_rows(job, object_types)) - 1), max(0, selected + direction))


FILE_INFORMATION_LABELS = (('fracsis_version', 'FracSIS version'), ('project_name', 'Project name'),
              ('creation_date', 'Database created'), ('header_timestamp_raw', 'Header time (raw)'),
              ('json_preflight_backend', 'JSON preflight'), ('storage_layout', 'Storage'), ('database_id', 'Database ID'),
              ('source_bytes', 'Source bytes'), ('source_sha256', 'SHA256'),
              ('schema_classes', 'Schema classes'), ('schema_complete', 'Schema complete'),
              ('native_type_bindings', 'Native types'), ('roots', 'Source roots'),
              ('segments', 'Segments'), ('clusters', 'Clusters'),
              ('logical_bytes', 'Logical bytes'), ('allocations', 'Allocations'),
              ('pointers', 'Pointers'), ('stored_elements', 'Stored elements'))


def file_information_rows(state, evidence_view=False):
    primary = {'json_preflight_backend', 'fracsis_version', 'project_name', 'creation_date', 'source_bytes', 'schema_classes', 'schema_complete'}
    rows = []
    for key, label in FILE_INFORMATION_LABELS:
        if key in state.information and (evidence_view or key in primary):
            value = state.information[key]
            if key == 'schema_complete':
                value = 'Complete layouts' if value is True else 'Incomplete layouts' if value is False else 'Not reported'
            rows.append((label, display_text(f'{value:,}' if type(value) is int else value)))
    return rows


def discovery_panels(job, row_limit, dataset_selected, object_types=False, focused=False, evidence_view=False):
    state = job.discovery if job else LiveDiscovery()
    information = Table(expand=True, box=None)
    information.add_column('Field', no_wrap=True)
    information.add_column('Discovered value', overflow='fold')
    for label, value in file_information_rows(state, evidence_view):
        information.add_row(label, Text(value))
    if not state.information:
        information.add_row('Waiting', 'No source information reported yet')
    datasets = Table(expand=True, box=None)
    datasets.add_column('Name', ratio=3, overflow='ellipsis', no_wrap=True)
    datasets.add_column('Source type', ratio=2, overflow='ellipsis', no_wrap=True)
    datasets.add_column('Evidence', ratio=2, overflow='ellipsis', no_wrap=True)
    rows = discovery_rows(job, object_types)
    selected = min(max(0, dataset_selected), max(0, len(rows) - 1))
    start = min(max(0, selected - row_limit // 2), max(0, len(rows) - row_limit))
    for index, row in enumerate(rows[start:start + row_limit], start):
        names = row.get('names', [])
        name = ' / '.join(field['text'] for field in names) or row['type']
        bounded = row.get('names_truncated') or any(field['status'] != 'TERMINATED' for field in names)
        if row['classification'] in ('ESTABLISHED_ENTITY', 'SOURCE_ENTITY_NAME_CANDIDATE'):
            evidence = ('Entity identified' if row['classification'] == 'ESTABLISHED_ENTITY' else 'Name field recovered') + ('; bounded name' if bounded else '')
            title = Text(display_text(name), style='cyan')
        else:
            evidence = 'Purpose unknown'
            title = Text(display_text(name), style='yellow')
        if focused and index == selected:
            title = Text('› ') + title
        datasets.add_row(title, Text(display_text(row['type'])), evidence,
                         style='bold white on blue' if focused and index == selected else '')
    if not rows:
        waiting = 'No retained name preview' if getattr(job, 'status', '') == 'Saved' else ('No names recovered' if state.enumerated else 'Waiting for names')
        datasets.add_row(waiting, '—', 'T shows types')
    missing = 'not reported' if getattr(job, 'status', '') == 'Saved' else 'pending'
    entities = missing if state.entities is None else f'{state.entities:,}'
    families = missing if state.families is None else f'{state.families:,}'
    candidates = missing if state.name_candidates is None else f'{state.name_candidates:,}'
    summary = Text(f'Entities {entities} • Partial names {candidates} • Type families {families}\n',
                   no_wrap=True, overflow='ellipsis')
    summary.append('Enumeration finished' if state.enumerated else ('Saved enumeration not established' if getattr(job, 'status', '') == 'Saved' else 'Discovery pending / in progress'), style='dim')
    summary.append(' • Names do not confirm dataset payloads.', style='dim')
    if state.rows_truncated:
        summary.append(f'\nDisplay retains first {MAX_DISPLAY_ROWS:,} rows; full evidence stays in the FSDX/logs.')
    return (Panel(information, title='Discovered file information'),
            Panel(Group(summary, datasets), title='Object types / entities' if object_types else 'Discovered names',
                  subtitle=f'Row {selected + 1 if rows else 0}/{len(rows)} • ' +
                           ('↑/↓ scroll' if focused else 'D to scroll') + ' • T names/types'))


def discovery_status(job):
    state = job.discovery if job else LiveDiscovery()
    capture = {'Verified': 'Verified capture', 'Failed': 'Failed', 'Cancelled': 'Cancelled', 'Saved': 'Saved; not reverified'}.get(
        getattr(job, 'status', ''), 'Awaiting verification' if job else 'Not started')
    complete = state.information.get('schema_complete')
    schema = 'Complete layouts' if complete is True else 'Incomplete layouts' if complete is False else 'Pending'
    unresolved = 'Not reported' if state.unresolved_pointers is None else f'{state.unresolved_pointers:,}'
    meaning = 'Not fully established' if state.semantic_complete is False else 'Not assessed'
    lines = [Text(f'Capture: {capture} • Schema: {schema}'),
             Text(f'Discovery: {"Finished" if state.enumerated else "Pending / in progress"} • Unresolved: {unresolved}'),
             Text('Dataset meaning: ' + meaning, style='dim')]
    return Panel(Group(*lines), title='Capture / interpretation')


def selected_row_panel(job, selected, object_types=False):
    rows = discovery_rows(job, object_types)
    if not rows:
        return Panel('No discovered row selected.', title='Selected row')
    row = rows[min(max(0, selected), len(rows) - 1)]
    names = row.get('names', [])
    text = Text()
    text.append('Name: ' + (' / '.join(display_text(f['text']) for f in names) or '(not recovered)') + '\n')
    text.append('Type: ' + display_text(row['type']) + '\n')
    text.append('Object ID: ' + display_text(row['id']) + '\n')
    label = {'ESTABLISHED_ENTITY': 'Entity identified', 'SOURCE_ENTITY_NAME_CANDIDATE':
             'Name field recovered; whole-class admission remains rejected',
             'UNCONFIRMED_OBJECT_FAMILY': 'Type identified; purpose unknown'}.get(row['classification'], 'Unestablished')
    text.append('Evidence: ' + label + '\n')
    if row.get('address'):
        text.append('Address: ' + display_text(json.dumps(row['address'], sort_keys=True)) + '\n')
    if row.get('status'):
        text.append('Source status: ' + display_text(row['status']) + '\n')
    if 'allocations' in row:
        text.append(f'Allocations: {row["allocations"]:,} • Stored elements: {row.get("elements", "not reported")}\n')
    for field in row.get('creation_time_fields', [])[:2]:
        value = field.get('unsigned_value', field.get('value', field.get('raw_hex', 'not reported')))
        text.append('Created (raw): ' + display_text(value) + ' • epoch/date meaning unknown\n')
    if row.get('names_truncated') or any(f['status'] != 'TERMINATED' for f in names):
        text.append('Name preview bounded; full retained evidence in FSDX.\n', style='yellow')
    text.append('Dataset payload / ownership: not confirmed by this row.', style='dim')
    return Panel(text, title='Selected row', subtitle='↑/↓ selection • E file evidence')



def evidence_rows(job):
    state = job.discovery if job else LiveDiscovery()
    rows = file_information_rows(state, evidence_view=True)
    rows.extend([('Capture', 'Verified capture' if getattr(job, 'status', '') == 'Verified' else ('Saved; not reverified' if getattr(job, 'status', '') == 'Saved' else 'Not verified')),
                 ('Name enumeration', 'Finished' if state.enumerated else 'Pending / in progress'),
                 ('Dataset meaning', 'Not fully established' if state.semantic_complete is False else 'Not assessed'),
                 ('Unresolved references', 'Not reported' if state.unresolved_pointers is None else f'{state.unresolved_pointers:,}')])
    if state.schema_issues is not None:
        issues = state.schema_issues
        rows.extend([('Layout problem classes', str(issues['layout_problem_classes'])),
                     ('Representation errors', str(issues['representation_errors']))])
        rows.extend(('Reason preview', display_text(reason)) for reason in issues['preview'])
        if issues['preview']:
            rows.append(('Preview limit', 'Bounded reasons; full evidence in FSDX schema/report'))
    elif job:
        rows.append(('Schema reasons', state.evidence_error or 'Available after verified capture'))
    if job:
        if state.schema_issues is not None and state.evidence_error:
            rows.append(('Preview status', state.evidence_error))
        rows.append(('Run directory', display_path(job.directory)))
        if job.status == 'Saved':
            rows.extend([('Saved FSDX', display_path(job.output)), ('FSDX version', str(job.store_version)),
                         ('Recorded source', display_path(job.saved_source.get('path', 'Not recorded'))),
                         ('Source association', 'Filename only; current source hash not checked')])
    return rows


def evidence_panel(job, selected, height):
    rows = evidence_rows(job)
    selected = min(max(0, selected), max(0, len(rows) - 1))
    count = max(1, height - 14)
    start = min(max(0, selected - count // 2), max(0, len(rows) - count))
    table = Table(expand=True, box=None)
    table.add_column('Field', ratio=1, no_wrap=True)
    table.add_column('Evidence / value', ratio=3, overflow='ellipsis', no_wrap=True)
    for i, (label, value) in enumerate(rows[start:start + count], start):
        table.add_row(('› ' if i == selected else '') + label, Text(display_text(value)),
                      style='bold white on blue' if i == selected else '')
    label, value = rows[selected]
    return Panel(Group(table, Text('\nSelected: ' + label, style='bold'), Text(display_text(value))), title='File evidence / unresolved information',
                 subtitle=f'Row {selected + 1}/{len(rows)} • ↑/↓ scroll • E back')


def phase_label(phase):
    if phase in ('starting', 'source_snapshot'):
        return 'Source snapshot'
    if phase == 'compile_schema':
        return 'Schema'
    if phase == 'logical_bytes':
        return 'Storage capture'
    if phase == 'allocations' or phase == 'pointers' or phase.startswith(('discovery_', 'dataset_discovery')):
        return 'Objects / references'
    if phase.startswith('verify_'):
        return 'Verification'
    if phase == 'complete':
        return 'Publication'
    return phase.replace('_', ' ').title()


def render(files, selected, statuses, job, active, message, console, dataset_selected=0, discovery_view=False, object_types=False, evidence_view=False, evidence_selected=0, exports=None, export_selected=0, workers=1):
    exports = exports or {}
    height = console.size.height
    table = Table(expand=True, box=None)
    table.add_column('FSD / FSDX', no_wrap=True)
    table.add_column('MiB', justify='right')
    table.add_column('FSDX', justify='right', no_wrap=True)
    table.add_column('State', no_wrap=True)
    wide = console.size.width >= 110
    resources = resource_lines(job, active)
    resource_height = (6 if active else 4) if resources else 0
    available_height = height - resource_height
    upper_height = max(8, (available_height - 2) // 2)
    count = max(1, upper_height - 4)
    start = max(0, selected - count // 2)
    start = min(start, max(0, len(files) - count))
    for i, (path, size) in enumerate(files[start:start + count], start):
        state = statuses.get(path, 'Export found' if exports.get(path) else 'Ready')
        style = 'bold white on blue' if i == selected else ''
        table.add_row(Text(('› ' if i == selected else '  ') + path.name),
                      f'{size / 1048576:.1f}', str(len(exports.get(path, []))) if exports.get(path) else '—', state, style=style)
    listing = Panel(table, title=f'Ingest / exports • {len(files)} files', subtitle=f'{selected + 1 if files else 0}/{len(files)}')
    detail = []
    if job:
        color = {'Verified': 'green', 'Failed': 'red', 'Cancelled': 'yellow'}.get(job.status, 'cyan')
        detail.extend([Text(job.source.name, style='bold'), Text(job.status, style=color)])
        elapsed = time.monotonic() - job.started if active else getattr(job, 'elapsed', 0)
        detail.append(Text('Elapsed ' + elapsed_clock(elapsed)) if elapsed is not None else Text('Elapsed: not retained in store'))
        phase = str(job.event.get('phase', 'starting'))
        if job.status not in ('Verified', 'Saved'):
            detail.append(Text('Stage: ' + phase_label(phase) + ' • ' + phase.replace('_', ' ').title()))
        reached = {phase_label(p) for p in job.discovery.stages_seen}
        if active:
            detail.append(Text('Stages reached: ' + ' → '.join(p for p in ('Source snapshot', 'Schema', 'Storage capture', 'Objects / references', 'Verification', 'Publication') if p in reached), overflow='fold'))
        if active:
            progress = Progress(TextColumn('{task.description}'), BarColumn(), TaskProgressColumn(), auto_refresh=False)
            bounds = progress_bounds(job.event)
            progress.add_task('Phase', total=bounds[1] if bounds else None,
                              completed=bounds[0] if bounds else 0)
            detail.append(progress)
        for key in ('completed_bytes', 'total_bytes', 'allocations', 'pointers', 'prm_pages',
                    'objects_inspected', 'collections', 'pointer_bindings', 'processed',
                    'allocations_compared', 'pointers_compared', 'unresolved_pointers'):
            value = job.event.get(key)
            if active and type(value) is int:
                detail.append(Text(f'{key.replace("_", " ").title()}: {value:,}'))
        if job.error and job.status != 'Verified':
            detail.append(Text(job.error, style='red'))
        if job.status == 'Saved':
            detail.append(Text('Current FSD hash not checked.', style='dim'))
        detail.extend([Text('Output' if job.status in ('Verified', 'Saved') else 'Run directory', style='bold'),
                       Text(display_path(job.output if job.status in ('Verified', 'Saved') else job.directory), overflow='fold')])
        if job.status in ('Verified', 'Saved'):
            result = getattr(job, 'result', {})
            detail.append(Text('Saved FSDX opened; not reverified' if job.status == 'Saved' else 'Capture verified • Source unchanged', style='yellow' if job.status == 'Saved' else 'green'))
            if type(result.get('output_bytes')) is int:
                detail.append(Text(f'FSDX size: {result["output_bytes"] / 1048576:,.2f} MiB'))
            state = job.discovery
            count = lambda value: 'not reported' if value is None else f'{value:,}'
            detail.append(Text(f'Names (partial): {count(state.name_candidates)} • Entity records: {count(state.entities)} • Type families: {count(state.families)}'))
            detail.append(Text('Unresolved references: ' + count(state.unresolved_pointers)))
            schema = state.information.get('schema_complete')
            schema = 'Complete layouts' if schema is True else 'Incomplete layouts' if schema is False else 'Not reported'
            detail.append(Text('Schema: ' + schema + ' • Names: ' + ('Enumeration finished' if state.enumerated else 'Not finished')))
            detail.append(Text('Dataset meaning: not fully established. E for evidence.', style='yellow'))
    else:
        candidates = exports.get(files[selected][0], []) if files else []
        if candidates:
            candidate = candidates[min(export_selected, len(candidates)-1)]
            detail.extend([Text(f'{len(candidates)} FSDX exports found', style='bold'),
                Text(display_path(candidate['path']), overflow='fold'),
                Text(f"FSDX size: {candidate['bytes'] / 1048576:,.2f} MiB"),
                Text('V view saved • [ / ] switch exports'),
                Text('Enter decodes FSD again into a new directory.'),
                Text('Filename association; source hash unchecked.', style='dim')])
        else:
            detail.extend([Text('Select a file and press Enter.', style='bold'),
                       Text('Creates a new FSDX and verifies it before reporting success.'),
                       Text('No decode starts until you select it.')])
    title = 'Saved FSDX' if job and job.status == 'Saved' else ('Saved exports' if not job and candidates else ('Decode summary' if job and not active else 'Decode progress'))
    details = Panel(Group(*detail), title=title)
    layout = Layout()
    parts = [Layout(name='header', size=1)]
    if resources:
        parts.append(Layout(Panel(Group(*resources), title='Decoder resources'), size=resource_height))
    parts.extend([Layout(name='body'), Layout(name='footer', size=1)])
    layout.split_column(*parts)
    if evidence_view:
        controls = '↑/↓ scroll • E back'
    elif discovery_view:
        controls = '↑/↓ scroll • D progress' if active else '↑/↓ scroll • D back'
    else:
        controls = 'D discovery' if active else '↑/↓ select • Enter decode • V saved'
    clock = 'Elapsed ' + elapsed_clock(elapsed) + ' • ' if job and active and (discovery_view or evidence_view) else ''
    if not wide:
        controls = '↑/↓ evidence • E back' if evidence_view else ('↑/↓ rows • D back' if discovery_view else ('D discovery' if active else '↑/↓ files • Enter decode • V saved'))
    shortcuts = f' • W workers:{workers} • E • C • T • Q' if wide else f' • W:{workers} • C • Q'
    layout['header'].update(Text('FSD • ' + clock + controls + shortcuts, style='bold'))
    layout['footer'].update(Text(message, style='yellow', overflow='ellipsis'))
    lower_height = available_height - 2 if discovery_view else available_height - 2 - upper_height
    row_limit = max(1, lower_height - 7) if wide else max(1, available_height - 16)
    source_panel, dataset_panel = discovery_panels(job, row_limit, dataset_selected, object_types, discovery_view, evidence_view)
    body = layout['body']
    if evidence_view:
        body.update(evidence_panel(job, evidence_selected, available_height))
    elif wide:
        if discovery_view:
            body.split_row(Layout(name='context', ratio=2), Layout(dataset_panel, ratio=3))
            body['context'].split_column(Layout(Group(source_panel, discovery_status(job))),
                                         Layout(selected_row_panel(job, dataset_selected, object_types)))
        else:
            body.split_column(Layout(name='upper', size=upper_height), Layout(name='lower'))
            if active:
                body['upper'].update(details)
            else:
                body['upper'].split_row(Layout(listing, ratio=2), Layout(details, ratio=3))
            body['lower'].split_row(Layout(Group(source_panel, discovery_status(job)), ratio=2), Layout(dataset_panel, ratio=3))
    elif discovery_view:
        detail_height = min(11, max(6, (available_height - 2) // 2))
        body.split_column(Layout(dataset_panel), Layout(selected_row_panel(job, dataset_selected, object_types), size=detail_height))
    elif active:
        body.update(details)
    else:
        body.split_column(Layout(listing, size=7 if job else None), Layout(details))
    return layout


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ingest-dir', type=Path, default=PROJECT / 'ingest')
    parser.add_argument('--workers', type=int, choices=(1, 2, 4), default=1,
                        help='Initial allocation preparation workers; W changes the next run')
    args = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error('Run this interface in an interactive terminal.')
    console = Console()
    if console.is_dumb_terminal:
        console.print('Use an ANSI terminal (TERM must not be dumb) for this interface.')
        return 2
    try:
        files, exports = inventory_exports(inventory(args.ingest_dir), PROJECT / 'artifacts' / 'exports')
    except OSError as exc:
        console.print(Text(str(exc), style='red'))
        return 2
    selected, statuses, job, active, quitting = 0, {}, None, False, False
    dataset_selected, discovery_view, object_types, evidence_view, evidence_selected = 0, False, False, False, 0
    export_selected = 0
    workers = args.workers
    message = 'One file is decoded at a time. All outputs stay under fsd/artifacts/exports/.'
    selector = selectors.DefaultSelector()
    selector.register(sys.stdin, selectors.EVENT_READ, 'keyboard')
    keys = b''
    previous_handlers = {}

    def request_quit(signum, frame):
        nonlocal quitting
        quitting = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[sig] = signal.signal(sig, request_quit)
    try:
        with terminal_keys(), Live(console=console, screen=True, auto_refresh=False) as live:
            while True:
                if quitting and active:
                    job.cancel()
                    message = 'Stopping the decoder before exiting…'
                if quitting and not active:
                    break
                for key, _ in selector.select(timeout=0.12):
                    if key.data != 'keyboard':
                        job.consume(key.data)
                        continue
                    keys += os.read(sys.stdin.fileno(), 64)
                    while keys:
                        if keys in (b'\x1b', b'\x1b['):
                            break
                        pressed, keys = (keys[:3], keys[3:]) if keys.startswith(b'\x1b[') else (keys[:1], keys[1:])
                        if pressed in (b'k', b'j', b'\x1b[A', b'\x1b[B'):
                            direction = -1 if pressed in (b'k', b'\x1b[A') else 1
                            if evidence_view:
                                evidence_selected = min(max(0, len(evidence_rows(job)) - 1), max(0, evidence_selected + direction))
                            elif discovery_view:
                                dataset_selected = move_discovery_selection(job, dataset_selected, direction, object_types)
                            elif not active and files:
                                selected = min(max(0, len(files) - 1), max(0, selected + direction))
                                export_selected = 0
                                if job and job.status == 'Saved' and job.source != files[selected][0]:
                                    job = None
                        elif pressed.lower() == b'q':
                            quitting = True
                        elif pressed.lower() == b'c' and active:
                            job.cancel()
                            message = 'Cancellation requested; waiting for staging cleanup.'
                        elif pressed.lower() == b'w':
                            if active:
                                message = 'Worker count is fixed for this run; change it after decoding finishes.'
                            else:
                                workers = {1: 2, 2: 4, 4: 1}[workers]
                                message = f'Next decode: {workers} allocation workers. Pointer capture and verification remain ordered; 2 workers performed best per resource used.'
                        elif pressed.lower() == b'v' or pressed in (b'[', b']'):
                            if active:
                                message = 'Wait for decoding to finish before opening a saved export.'
                            elif files:
                                candidates = exports.get(files[selected][0], [])
                                if not candidates:
                                    message = 'No saved FSDX for this file. R refreshes exports.'
                                else:
                                    if pressed in (b'[', b']'):
                                        export_selected = (export_selected + (1 if pressed == b']' else -1)) % len(candidates)
                                    try:
                                        saved = SavedExport(files[selected][0], candidates[export_selected % len(candidates)]['path'])
                                        if job and hasattr(job, 'close'):
                                            job.close()
                                        job = saved
                                        dataset_selected = evidence_selected = 0
                                        discovery_view, evidence_view = True, False
                                        message = f'Saved export {export_selected+1}/{len(candidates)} • [ / ] switch • D back • Enter from overview decodes again.'
                                    except Exception as exc:
                                        logs = PROJECT / 'artifacts' / 'logs'
                                        logs.mkdir(parents=True, exist_ok=True)
                                        log = logs / ('saved_export_' + uuid.uuid4().hex + '.txt')
                                        log.write_text(traceback.format_exc())
                                        message = f'Could not open saved FSDX: {display_text(exc)}. Log: {log.name}'
                        elif pressed.lower() == b'd':
                            evidence_view = False
                            discovery_view = not discovery_view
                        elif pressed.lower() == b'e':
                            evidence_view = not evidence_view
                        elif pressed.lower() == b't':
                            object_types = not object_types
                            dataset_selected = 0
                        elif pressed.lower() == b'r':
                            try:
                                files, exports = inventory_exports(inventory(args.ingest_dir), PROJECT / 'artifacts' / 'exports')
                                selected = min(selected, max(0, len(files) - 1))
                                export_selected = 0
                                if job and job.status == 'Saved' and not job.output.is_file():
                                    job = None
                                    message = 'Saved export was removed; list refreshed.'
                            except OSError as exc:
                                message = str(exc)
                        elif pressed in (b'\r', b'\n') and files:
                            if evidence_view:
                                message = 'Press E to return before starting a decode.'
                            elif discovery_view:
                                message = 'Press D to return to the file list before starting a decode.'
                            elif active:
                                message = 'A decode is already running. Cancel it or wait for verification.'
                            elif files[selected][0].suffix.lower() != '.fsd':
                                message = 'Original FSD is absent from ingest. V views this saved export.'
                            else:
                                try:
                                    if job and hasattr(job, 'close'):
                                        job.close()
                                    job = Job(files[selected][0], selector, workers=workers)
                                    dataset_selected = evidence_selected = 0
                                    active = True
                                    message = 'Decoding selected file; progress is reported by the canonical encoder.'
                                except OSError as exc:
                                    message = f'Could not start: {exc}'
                if active:
                    job.sample_resources()
                    if job.poll():
                        active = False
                        job.elapsed = time.monotonic() - job.started
                        message = f'{job.status}. Logs and result retained in the run directory.'
                        try:
                            files, exports = inventory_exports(inventory(args.ingest_dir), PROJECT / 'artifacts' / 'exports')
                        except OSError as exc:
                            message += ' Export refresh failed: ' + display_text(exc)
                    statuses[job.source] = job.status
                live.update(render(files, selected, statuses, job, active, message, console,
                                   dataset_selected, discovery_view, object_types, evidence_view, evidence_selected, exports, export_selected, workers), refresh=True)
    finally:
        if job and hasattr(job, 'process'):
            if job.process.poll() is None:
                job.cancel()
                try:
                    job.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    job.force_stop()
                    job.process.wait()
            job.close()
        selector.close()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    if job:
        console.print(Text(f'{job.status}: {display_path(job.output if job.status in ("Verified", "Saved") else job.directory)}'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
