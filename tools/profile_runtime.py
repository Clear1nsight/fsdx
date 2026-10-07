#!/usr/bin/env python3
"""Measure one bounded installed FSDX workload per fresh Python process.

Use separate invocations for attributable process RSS. Reconstruction includes
opening the store and restoring its compiled interpreter; pointer/value
timings exclude setup, while RSS includes interpreter and facade setup. Results
are observations on a shared host, not a controlled native-language comparison.
"""
from __future__ import annotations
import argparse
import cProfile
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import platform
import pstats
import resource
import sqlite3
import sys
import time


def measure(function, profile):
    profiler = cProfile.Profile() if profile else None
    wall = time.perf_counter(); cpu = time.process_time()
    if profiler: profiler.enable()
    result = function()
    if profiler: profiler.disable()
    observed = dict(wall_seconds=time.perf_counter()-wall, cpu_seconds=time.process_time()-cpu, result=result)
    if profiler:
        stats = pstats.Stats(profiler)
        ranked = sorted(stats.stats.items(), key=lambda item: item[1][2], reverse=True)
        observed['top_self_time'] = [dict(file=key[0], line=key[1], function=key[2], primitive_calls=value[0], calls=value[1],
            self_seconds=value[2], cumulative_seconds=value[3]) for key, value in ranked[:25]]
    return observed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('store', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workload', choices=('reconstruction','pointer_lookup','value_formatting'), required=True)
    parser.add_argument('--limit', type=int, default=10000, help='Maximum pointers or formatted values, ceiling 100000')
    parser.add_argument('--cache-bytes', type=int, default=16 << 20)
    parser.add_argument('--max-record-bytes', type=int, default=8 << 20)
    parser.add_argument('--allocation-name', action='append', help='Indexed type-name filter for value formatting; repeat to include more types')
    parser.add_argument('--max-array-elements', type=int, default=10000)
    parser.add_argument('--profile', action='store_true')
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 100000: parser.error('--limit must be in 1..100000')
    if not 1 <= args.cache_bytes <= 64 << 20: parser.error('--cache-bytes must be in 1..64 MiB')
    if not 1 <= args.max_record_bytes <= 8 << 20: parser.error('--max-record-bytes must be in 1..8 MiB')
    if not 1 <= args.max_array_elements <= 10000: parser.error('--max-array-elements must be in 1..10000')
    from fsd_decoder.portable.facade import PortableDatabase
    from fsd_decoder.portable.exports import _json_default
    from fsd_decoder.portable.format import StoreError
    from fsd_decoder.core.provenance import code_pins, environment_identity
    from fsd_decoder.discovery.decoding_coverage import expansion_cost
    from fsd_decoder.portable.validate_corpus import corpus_guard, assert_guard_clean
    box = {}
    def reconstruction():
        box['db'] = PortableDatabase(args.store, cache_bytes=args.cache_bytes)
        db = box['db']
        db.fields.decoder.max_array_elements = args.max_array_elements
        return dict(compiled_classes=len(db.fields.schema.classes), native_types=len(db.fields.types),
                    scope='Store open, physical extent index and compiled interpreter restoration; no aggregate schema/report serialization or value traversal')
    report = dict(workload=args.workload, store=str(args.store.resolve()), store_bytes=args.store.stat().st_size,
        python=sys.version, platform=platform.platform(), sqlite_version=sqlite3.sqlite_version,
        execution_environment=environment_identity(), runtime_module=sys.modules[PortableDatabase.__module__].__file__,
        limits=dict(items=args.limit, cache_bytes=args.cache_bytes, max_record_bytes=args.max_record_bytes, allocation_scan=args.limit*10,
                    max_array_elements=args.max_array_elements, allocation_names=args.allocation_name),
        integrity_scope='Open-time format/manifest checks and per-read blob checks; full store verification not performed',
        caveat='Single fresh process on shared host; wall timings exclude setup for pointer/value workloads; RSS includes interpreter/setup. No all-corpus value materialization; unsupported values retain their explicit status.')
    guards = ExitStack(); source_guard = guards.enter_context(corpus_guard())
    try:
        if args.workload == 'reconstruction':
            report['measured'] = measure(reconstruction, args.profile)
        else:
            report['setup'] = measure(reconstruction, False)
            db = box['db']
            if args.workload == 'pointer_lookup':
                def pointers():
                    digest = hashlib.sha256(); resolved = null = unresolved = 0
                    sql = 'SELECT segment,cluster,logical_offset,width,status FROM pointers ORDER BY segment,cluster,logical_offset LIMIT ?'
                    for row in db.store.connection.execute(sql, (args.limit,)):
                        address = db.address(row['segment'], row['cluster'], row['logical_offset'])
                        try:
                            value = db.resolve(address, width=row['width'])
                            if value is None: null += 1
                            else: resolved += 1
                        except StoreError:
                            if row['status'] != 'UNRESOLVED': raise
                            value = dict(status='UNRESOLVED'); unresolved += 1
                        digest.update(json.dumps(value, default=_json_default, sort_keys=True, separators=(',', ':')).encode()+b'\n')
                    return dict(pointer_slots=resolved+null+unresolved, resolved=resolved, null=null, retained_unresolved=unresolved, result_sha256=digest.hexdigest())
                report['measured'] = measure(pointers, args.profile)
            else:
                def values():
                    digest = hashlib.sha256(); formatted = skipped = encoded_bytes = visited = 0
                    statuses = {}; skip_reasons = {}
                    for allocation in db.iter_allocations(names=args.allocation_name):
                        visited += 1
                        size = allocation.get('element_size', allocation['size']) if allocation.get('vector') else allocation['size']
                        reason = ('record_bytes_limit' if size > args.max_record_bytes else
                                  'zero_elements' if allocation.get('count', 1) == 0 else
                                  'field_expansion_limit' if expansion_cost(db, allocation, args.max_array_elements) > args.max_array_elements else None)
                        if reason:
                            skipped += 1
                            skip_reasons[reason] = skip_reasons.get(reason, 0)+1
                        else:
                            value = db.fields.decode(allocation, element_index=0)
                            encoded = json.dumps(value, default=_json_default, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                            digest.update(encoded+b'\n'); encoded_bytes += len(encoded); formatted += 1
                            status = value.get('status','NO_STATUS'); statuses[status] = statuses.get(status,0)+1
                        if formatted >= args.limit or visited >= args.limit*10: break
                    return dict(formatted_values=formatted, allocations_visited=visited, skipped=skipped, element_scope='First element of each visited allocation',
                        encoded_json_bytes=encoded_bytes, statuses=statuses, skip_reasons=skip_reasons, result_sha256=digest.hexdigest())
                report['measured'] = measure(values, args.profile)
        db = box['db']
        report['source_sha256'] = db.sha256
        report['query_statistics'] = dict(db.query_statistics)
        report['runtime_pins'] = code_pins()
        report['peak_rss_kib_process'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report['rss_units'] = 'KiB on Linux; process lifetime high-water mark'
        assert_guard_clean(source_guard)
        report['source_independence_guard'] = source_guard
        report['original_source_accessed'] = False
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as stream: json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
        print(json.dumps(dict(workload=args.workload, wall_seconds=report['measured']['wall_seconds'], peak_rss_kib=report['peak_rss_kib_process'], result=report['measured']['result'])))
    finally:
        if 'db' in box: box['db'].close()
        guards.close()
    return 0


if __name__ == '__main__': raise SystemExit(main())
