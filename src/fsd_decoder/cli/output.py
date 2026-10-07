"""Inspect, export or render a decoded FSDX store without opening an FSD."""
from __future__ import annotations
import argparse
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
from fsd_decoder.core.diagnostics import failure_record
from fsd_decoder.core.json_io import dump_json

def _default(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {'encoding': 'hex', 'hex': value.hex()}
    raise TypeError(type(value).__name__)

def _address(value):
    try:
        parts = value.split(':')
        if len(parts) != 3:
            raise ValueError()
        numbers = [int(part, 16 if part.lower().startswith('0x') else 10) for part in parts]
        if any((number < 0 for number in numbers)):
            raise ValueError()
        return dict(zip(('segment', 'cluster', 'offset'), numbers))
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Use segment:cluster:offset, with decimal or 0x hexadecimal integers') from exc

def _publish_json(value, output):
    if output is None:
        dump_json(value, sys.stdout, default=_default, ensure_ascii=True, indent=2, allow_nan=False)
        sys.stdout.write('\n')
        return
    output = Path(output).absolute()
    if os.path.lexists(output):
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output.parent, prefix='.fsdx-report-', delete=False) as stream:
            temporary = Path(stream.name)
            dump_json(value, stream, default=_default, ensure_ascii=True, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('store', type=Path, help='Decoded .fsdx single file')
    commands = parser.add_subparsers(dest='command', required=True)
    for name, help_text in (('info', 'Original file provenance and stored coverage'), ('schema', 'Compiled schema and unresolved declarations'), ('catalog', 'Datasets, geometry, relationships and coordinate systems'), ('datasets', 'Grouped source storage roles and established Entity names; other roles remain unconfirmed'), ('reconcile', 'Fresh discovery, automatic membership and catalog differences'), ('verify', 'Fully verify the portable store without the original FSD')):
        command = commands.add_parser(name, help=help_text)
        command.add_argument('--output', type=Path, help='New JSON file; otherwise stdout')
        if name == 'reconcile':
            command.add_argument('--collection-limit', type=int, default=128)
            command.add_argument('--referrer-limit', type=int, default=10000)
            command.add_argument('--collection-members', type=int, default=100000)
            command.add_argument('--collection-slots', type=int, default=250000)
    command = commands.add_parser('discover', help='Source-driven type census and paginated dataset/reference candidates')
    command.add_argument('--output', type=Path, help='New JSON file; otherwise stdout')
    command.add_argument('--captured', action='store_true', help='Read the saved capture-time report; do not regenerate it')
    command.add_argument('--complete', action='store_true', help='Complete indexed allocation/element/reference accounting')
    command.add_argument('--all', action='store_true', help='Stream every object to --output JSONL; .gz compresses it')
    command.add_argument('--limit', type=int, default=2000, help='Objects per page, from 1 to 10000')
    command.add_argument('--cursor', type=Path, help='JSON next_cursor from an earlier page')
    command.add_argument('--type', dest='type_name', help='Exact source-derived allocation type to inspect')
    command.add_argument('--collection-limit', type=int, default=128, help='Collections to inspect in a complete report; at most 10000')
    command.add_argument('--referrer-limit', type=int, default=10000, help='Source referrer elements to scan; at most 100000')
    command.add_argument('--collection-members', type=int, default=100000, help='Whole-report member/reference budget; at most 100000')
    command.add_argument('--collection-slots', type=int, default=250000, help='Whole-report hash scan budget; at most 1000000')
    command = commands.add_parser('text', help='Streaming plain text typed object export')
    command.add_argument('--output', required=True, type=Path)
    command.add_argument('--allocation', action='append', type=_address, help='Exact allocation address segment:cluster:offset; repeat to select')
    command = commands.add_parser('membership', help='Resume source-pinned collection evidence in an exact-once checkpoint')
    from fsd_decoder.discovery.direct_collections import ACCEPTED_REFERRER_POLICIES, DEFAULT_REFERRER_POLICY
    command.add_argument('--referrer-policy', choices=ACCEPTED_REFERRER_POLICIES, default=DEFAULT_REFERRER_POLICY, help='Source-declared collection eligibility policy; resumed checkpoints require the same selected policy')
    command.add_argument('--checkpoint', required=True, type=Path, help='Persistent SQLite checkpoint; resumed only with matching source/runtime/configuration')
    command.add_argument('--output', type=Path, help='New JSON summary file; otherwise stdout')
    command.add_argument('--export', dest='export_path', type=Path, help='Stream persisted evidence to a new JSONL file after this batch')
    command.add_argument('--referrer-limit', type=int, default=10000)
    command.add_argument('--collection-limit', type=int, default=128)
    command.add_argument('--collection-members', type=int, default=100000)
    command.add_argument('--collection-slots', type=int, default=250000)
    command.add_argument('--collection-nodes', type=int, default=10000)
    command.add_argument('--max-batch-members', type=int, help='Whole-batch retained member budget; default max(100000, instance limit)')
    command.add_argument('--max-batch-slots', type=int, help='Whole-batch scanned/storage slot budget; default max(250000, instance limit)')
    command.add_argument('--max-batch-nodes', type=int, help='Whole-batch collection node budget; default max(10000, instance limit)')
    command.add_argument('--include-standalone', action='store_true', help='Also queue every indexed standalone collection; default scope follows eligible source referrers')
    command.add_argument('--collection-work-mode', choices=('RESUMABLE_PREFIX', 'BOUNDED_INSTANCE'), default='RESUMABLE_PREFIX', help='Persist within-instance node/slot prefixes, or retain bounded one-shot task semantics')
    command.add_argument('--batches', type=int, default=1, help='Maximum sequential bounded batches in this process, from 1 to 100000')
    command = commands.add_parser('payload-census', help='Resume compact incoming-link, value and retained logical raw-range accounting')
    command.add_argument('--checkpoint', required=True, type=Path)
    command.add_argument('--output', type=Path, help='New JSON summary; otherwise stdout')
    command.add_argument('--export', dest='export_path', type=Path, help='Stream retained census evidence to a new JSONL file')
    command.add_argument('--batches', type=int, default=1)
    command.add_argument('--allocation-limit', type=int, default=1000)
    command.add_argument('--value-limit', type=int, default=10000)
    command.add_argument('--binding-limit', type=int, default=10000)
    command.add_argument('--block-bytes', type=int, default=1048576)
    command.add_argument('--max-raw-bytes', type=int, default=4194304, help='Whole-batch raw bytes read across indexed allocation and unindexed retained ranges')
    command.add_argument('--record-bytes', type=int, default=65536)
    command.add_argument('--schema-leaves', type=int, default=4096)
    command.add_argument('--checkpoint-bytes', type=int, default=268435456, help='Operational disk capacity; increasing it can continue committed work')
    command = commands.add_parser('text-pages', help='Resume bounded source-independent plaintext pages with raw range evidence')
    command.add_argument('--directory', required=True, type=Path)
    command.add_argument('--output', type=Path, help='New JSON summary; otherwise stdout')
    command.add_argument('--type', dest='type_name')
    command.add_argument('--max-pages', type=int, default=1)
    command.add_argument('--max-records', type=int, default=128)
    command.add_argument('--max-output-bytes', type=int, default=8388608)
    command.add_argument('--max-element-bytes', type=int, default=65536)
    command.add_argument('--raw-chunk-bytes', type=int, default=32768)
    command.add_argument('--max-schema-leaves', type=int, default=4096)
    command = commands.add_parser('text-pages-status', help='Read committed plaintext page progress and optionally verify page hashes')
    command.add_argument('--directory', required=True, type=Path)
    command.add_argument('--verify-pages', action='store_true')
    command.add_argument('--output', type=Path)
    command = commands.add_parser('links', help='Bounded source-declared links from one exact Entity element')
    command.add_argument('--entity', required=True, type=_address)
    command.add_argument('--max-nodes', type=int, default=128)
    command.add_argument('--max-depth', type=int, default=4)
    command.add_argument('--max-links', type=int, default=1024)
    command.add_argument('--max-element-bytes', type=int, default=65536)
    command.add_argument('--output', type=Path, help='New JSON report; otherwise stdout')
    command = commands.add_parser('root-links', help='Bounded exact source-root affiliation with explicit native/current storage evidence')
    command.add_argument('--root-index', required=True, type=int)
    command.add_argument('--max-nodes', type=int, default=128)
    command.add_argument('--max-depth', type=int, default=4)
    command.add_argument('--max-links', type=int, default=1024)
    command.add_argument('--max-element-bytes', type=int, default=65536)
    command.add_argument('--output', type=Path, help='New JSON report; otherwise stdout')
    command = commands.add_parser('root-text', help='Bounded plaintext from one exact source root; affiliation does not establish ownership')
    command.add_argument('--root-index', required=True, type=int)
    command.add_argument('--output', required=True, type=Path)
    command.add_argument('--max-records', type=int, default=128)
    command.add_argument('--max-nodes', type=int, default=128)
    command.add_argument('--max-depth', type=int, default=4)
    command.add_argument('--max-links', type=int, default=1024)
    command.add_argument('--max-element-bytes', type=int, default=65536)
    command.add_argument('--max-output-bytes', type=int, default=8388608)
    command.add_argument('--collection-nodes', type=int, default=1000)
    command.add_argument('--collection-members', type=int, default=10000)
    command.add_argument('--collection-slots', type=int, default=100000)
    command.add_argument('--no-follow-reference-payloads', action='store_true')
    command = commands.add_parser('dataset-text', help='Bounded dataset plaintext with source-declared payloads and unresolved evidence')
    command.add_argument('--output', required=True, type=Path)
    selectors = command.add_mutually_exclusive_group(required=True)
    selectors.add_argument('--entity', action='append', type=_address, help='Exact Entity element; repeat to select')
    selectors.add_argument('--type', dest='entity_type', help='Exact source Entity allocation type')
    command.add_argument('--max-entities', type=int, default=10000)
    command.add_argument('--max-records', type=int, default=100000)
    command.add_argument('--max-nodes', type=int, default=128)
    command.add_argument('--max-links', type=int, default=1024)
    command.add_argument('--max-element-bytes', type=int, default=65536)
    command.add_argument('--max-depth', type=int, default=4)
    command.add_argument('--no-follow-reference-payloads', action='store_true', help='Retain pointer-array target links without following their exact payload records')
    command.add_argument('--collection-nodes', type=int, default=1000, help='Whole-export collection node budget')
    command.add_argument('--collection-members', type=int, default=10000, help='Whole-export retained collection member/reference budget')
    command.add_argument('--collection-slots', type=int, default=100000, help='Whole-export scanned collection storage-slot budget')
    command = commands.add_parser('payload-text', help='Project a verified linked record or one declared field allocation window')
    command.add_argument('--output', required=True, type=Path)
    command.add_argument('--entity', required=True, type=_address, help='Source Entity for bounded structural-link proof')
    command.add_argument('--record', required=True, type=_address, help='Exact current linked record to project')
    command.add_argument('--field', dest='field_path', help='Exact unconditional pointer field; omit for the linked record itself')
    command.add_argument('--start', dest='element_start', type=int, default=0)
    command.add_argument('--count', dest='element_count', type=int, default=3)
    command.add_argument('--max-records', type=int, default=128)
    command.add_argument('--max-nodes', type=int, default=128)
    command.add_argument('--max-links', type=int, default=256)
    command.add_argument('--max-depth', type=int, default=8)
    command.add_argument('--max-element-bytes', type=int, default=65536)
    command.add_argument('--max-output-bytes', type=int, default=8388608)
    command.add_argument('--collection-nodes', type=int, default=1000)
    command.add_argument('--collection-members', type=int, default=10000)
    command.add_argument('--collection-slots', type=int, default=100000)
    command.add_argument('--no-follow-reference-payloads', action='store_true')
    command = commands.add_parser('collection', help='Bounded membership/cardinality evidence for one source-declared list or set')
    command.add_argument('--allocation', required=True, type=_address, help='Exact collection element segment:cluster:offset')
    command.add_argument('--max-nodes', type=int, default=1000)
    command.add_argument('--max-members', type=int, default=10000)
    command.add_argument('--max-slots', type=int, default=100000, help='Hash directory/table scan budget, at most 1000000')
    command.add_argument('--referrer', type=_address, help='Exact current element whose source-typed collection field supplies context')
    command.add_argument('--field', dest='field_path', help='Exact decoded source field path; requires --referrer')
    command.add_argument('--output', type=Path, help='New JSON file; otherwise stdout')
    command = commands.add_parser('mesh-csv', help='Plain text coordinates and triangle indices')
    command.add_argument('--output', required=True, type=Path, help='New output directory')
    command.add_argument('--allocation', action='append', type=_address, help='Exact TriSurface address segment:cluster:offset; repeat to select')
    command = commands.add_parser('render', help='Separate native-frame dataset images and coverage report')
    command.add_argument('--output', required=True, type=Path, help='New output directory')
    command.add_argument('--dataset', action='append', help='Catalog dataset ID; repeat to select')
    command.add_argument('--width', type=int, default=800)
    command.add_argument('--height', type=int, default=600)
    command.add_argument('--azimuth', type=float, default=-60.0)
    command.add_argument('--elevation', type=float, default=25.0)
    args = parser.parse_args(argv)
    previous_handler = None
    status = 0
    context = dict(phase='validate_arguments', store=str(args.store), output=str(args.output) if args.output else None)
    try:
        if args.output is not None and os.path.lexists(args.output):
            raise FileExistsError(args.output)
        from fsd_decoder.portable.facade import PortableDatabase

        def terminate(signum, frame):
            raise KeyboardInterrupt('Export terminated')
        previous_handler = signal.signal(signal.SIGTERM, terminate)

        def progress(event):
            context.update(event)
            print(json.dumps(event, default=_default, ensure_ascii=True, sort_keys=True), file=sys.stderr, flush=True)
        context['phase'] = 'open_store'
        with PortableDatabase(args.store) as db:
            context['phase'] = args.command
            if args.command == 'info':
                result = dict(format='fsdx-file-information', source=db.source_info, store=db.store.manifest, directory=db.directory, original_fsd_required=False, preservation_scope='Current mapped logical bytes, indexed allocations, compiled schema and pointer bindings; the original FSD remains the archival record for physical history')
            elif args.command == 'schema':
                report_document = getattr(db.fields, 'schema_report_document', None)
                result = report_document() if callable(report_document) else db.fields.schema_report()
            elif args.command == 'catalog':
                from fsd_decoder.exports.catalog import build_portable_catalog
                result = build_portable_catalog(db, progress=progress)
            elif args.command == 'reconcile':
                from fsd_decoder.discovery.complete import build_complete_discovery
                from fsd_decoder.discovery.membership import reconcile_entities
                from fsd_decoder.exports.catalog import build_portable_catalog
                report = build_complete_discovery(db, progress=progress, collection_options=dict(
                    max_collections=args.collection_limit, max_referrers=args.referrer_limit,
                    max_members=args.collection_members, max_slots=args.collection_slots))
                catalog = build_portable_catalog(db, progress=progress)
                result = dict(source=db.source_info, original_fsd_required=False,
                    collection_evidence=report['collection_evidence'],
                    entity_reconciliation=reconcile_entities(report, report['collection_evidence'], catalog=catalog),
                    accounting=report['accounting'], dataset_roles=report['dataset_roles'])
                db.verify_source()
            elif args.command == 'datasets':
                from fsd_decoder.discovery.complete import build_complete_discovery
                from fsd_decoder.discovery.roles import build_role_inventory
                report = db.discovery_report()
                if report is None or report.get('version') != 2:
                    report = build_complete_discovery(db, progress=progress)
                result = build_role_inventory(db, report)
                db.verify_source()
            elif args.command == 'collection':
                from fsd_decoder.discovery.collections import inspect_portable_collection
                result = inspect_portable_collection(db, dict(database=db.database_id, **args.allocation),
                    max_nodes=args.max_nodes, max_members=args.max_members, max_slots=args.max_slots,
                    referrer=dict(database=db.database_id, **args.referrer) if args.referrer else None,
                    field_path=args.field_path)
                result.update(source=db.source_info, original_fsd_required=False)
                db.verify_source()
            elif args.command == 'discover':
                if args.captured:
                    if (args.all or args.complete or args.cursor is not None or args.type_name is not None or args.limit != 2000
                            or (args.collection_limit,args.referrer_limit,args.collection_members,args.collection_slots)!=(128,10000,100000,250000)):
                        parser.error('--captured cannot be combined with page selectors')
                    result = db.discovery_report()
                    if result is None:
                        result = dict(status='NOT_CAPTURED', original_fsd_required=False,
                            message='This store predates capture-time discovery; use discover without --captured to build a current page.')
                elif args.all:
                    if (args.complete or args.output is None or args.cursor is not None or args.type_name is not None or args.limit != 2000
                            or (args.collection_limit,args.referrer_limit,args.collection_members,args.collection_slots)!=(128,10000,100000,250000)):
                        parser.error('--all requires --output and cannot be combined with page selectors')
                    from fsd_decoder.discovery.complete import export_all_objects
                    result = export_all_objects(db, args.output, progress=progress)
                elif args.complete:
                    if args.cursor is not None or args.type_name is not None or args.limit != 2000:
                        parser.error('--complete cannot be combined with page selectors')
                    from fsd_decoder.discovery.complete import build_complete_discovery
                    result = build_complete_discovery(db, progress=progress, collection_options=dict(
                        max_collections=args.collection_limit, max_referrers=args.referrer_limit,
                        max_members=args.collection_members, max_slots=args.collection_slots))
                else:
                    if (args.collection_limit,args.referrer_limit,args.collection_members,args.collection_slots)!=(128,10000,100000,250000):
                        parser.error('Collection budget selectors require --complete')
                    from fsd_decoder.discovery.datasets import build_discovery
                    cursor = None
                    if args.cursor:
                        from fsd_decoder.portable.format import decode_json
                        from fsd_decoder.discovery.relationship_discovery import RelationshipError
                        with args.cursor.open('rb') as stream:
                            raw_cursor = stream.read(65537)
                        if len(raw_cursor) > 65536:
                            raise RelationshipError('Discovery cursor exceeds 65536 bytes')
                        cursor = decode_json(raw_cursor)
                    result = build_discovery(db, max_objects=args.limit, cursor=cursor,
                        type_name=args.type_name, progress=progress)
            elif args.command == 'verify':
                result = db.store.verify(full=True)
            elif args.command == 'text':
                from fsd_decoder.portable.exports import export_text
                result = export_text(db, args.output, allocation_addresses=args.allocation, progress=progress)
            elif args.command == 'membership':
                from fsd_decoder.discovery.datasets import DiscoverySession
                from fsd_decoder.discovery.membership import discover_membership_batch, export_membership_checkpoint
                session = DiscoverySession(db)
                with session.operation():
                    if not 1 <= args.batches <= 100000:
                        from fsd_decoder.core.diagnostics import InputValidationError
                        raise InputValidationError('--batches must be between 1 and 100000')
                    for _ in range(args.batches):
                        result = discover_membership_batch(session, checkpoint=args.checkpoint,
                            max_referrers=args.referrer_limit, max_collections=args.collection_limit,
                            max_members=args.collection_members, max_slots=args.collection_slots,
                            max_nodes=args.collection_nodes, include_standalone=args.include_standalone,
                            collection_work_mode=args.collection_work_mode, referrer_policy=args.referrer_policy,
                            max_batch_members=args.max_batch_members, max_batch_slots=args.max_batch_slots,
                            max_batch_nodes=args.max_batch_nodes, progress=progress)
                        if not result['continuation_required']:
                            break
                    if args.export_path:
                        result['evidence_export'] = export_membership_checkpoint(args.checkpoint, args.export_path)
                    if getattr(session, '_membership_completed_verified', False):
                        session.check_identity()
                        session.close()
                    else:
                        session.finish()
            elif args.command == 'payload-census':
                from fsd_decoder.core.diagnostics import InputValidationError
                from fsd_decoder.discovery.datasets import DiscoverySession
                from fsd_decoder.discovery.payload_census import discover_payload_census_batch, export_payload_census
                if not 1 <= args.batches <= 100000:
                    raise InputValidationError('--batches must be between 1 and 100000')
                session = DiscoverySession(db)
                with session.operation():
                    for _ in range(args.batches):
                        result = discover_payload_census_batch(session, checkpoint=args.checkpoint,
                            max_allocations=args.allocation_limit, max_values=args.value_limit,
                            max_bindings=args.binding_limit, block_bytes=args.block_bytes,
                            max_raw_bytes=args.max_raw_bytes,
                            max_record_bytes=args.record_bytes, max_leaves=args.schema_leaves,
                            max_checkpoint_bytes=args.checkpoint_bytes, progress=progress)
                        if result['complete'] or result['status'] == 'RESOURCE_BOUND':
                            break
                    if args.export_path:
                        result['evidence_export'] = export_payload_census(args.checkpoint, args.export_path)
                    session.finish()
            elif args.command == 'text-pages':
                from fsd_decoder.portable.text_pages import export_text_pages
                result = export_text_pages(db, args.directory, type_name=args.type_name,
                    max_pages=args.max_pages, max_records=args.max_records,
                    max_output_bytes=args.max_output_bytes, max_element_bytes=args.max_element_bytes,
                    raw_chunk_bytes=args.raw_chunk_bytes, max_schema_leaves=args.max_schema_leaves,
                    progress=progress)
            elif args.command == 'text-pages-status':
                from fsd_decoder.portable.text_pages import read_text_pages
                result = read_text_pages(db, args.directory, verify_pages=args.verify_pages)
            elif args.command == 'links':
                from fsd_decoder.discovery.payload_links import inspect_payload_links
                result = inspect_payload_links(db, dict(database=db.database_id, **args.entity),
                    max_nodes=args.max_nodes, max_depth=args.max_depth, max_links=args.max_links,
                    max_element_bytes=args.max_element_bytes)
                db.verify_source()
            elif args.command == 'root-links':
                from fsd_decoder.discovery.root_relationships import inspect_root_payload_links
                result = inspect_root_payload_links(db, args.root_index,
                    max_nodes=args.max_nodes, max_depth=args.max_depth, max_links=args.max_links,
                    max_element_bytes=args.max_element_bytes)
                db.verify_source()
            elif args.command == 'root-text':
                from fsd_decoder.exports.dataset_text import export_root_payload_text
                result = export_root_payload_text(db, args.output, root_index=args.root_index,
                    max_records=args.max_records, max_nodes=args.max_nodes, max_depth=args.max_depth,
                    max_links=args.max_links, max_element_bytes=args.max_element_bytes,
                    max_output_bytes=args.max_output_bytes,
                    follow_reference_payloads=not args.no_follow_reference_payloads,
                    max_collection_nodes=args.collection_nodes,
                    max_collection_members=args.collection_members,
                    max_collection_slots=args.collection_slots)
            elif args.command == 'dataset-text':
                from fsd_decoder.exports.dataset_text import export_dataset_text
                result = export_dataset_text(db, args.output,
                    entity_addresses=[dict(database=db.database_id, **a) for a in args.entity] if args.entity else None,
                    entity_type=args.entity_type, max_entities=args.max_entities,
                    max_records=args.max_records, max_nodes=args.max_nodes, max_links=args.max_links,
                    max_element_bytes=args.max_element_bytes, max_depth=args.max_depth,
                    follow_reference_payloads=not args.no_follow_reference_payloads,
                    max_collection_nodes=args.collection_nodes,
                    max_collection_members=args.collection_members,
                    max_collection_slots=args.collection_slots,
                    progress=progress)
            elif args.command == 'payload-text':
                from fsd_decoder.exports.dataset_text import export_payload_projection
                result = export_payload_projection(db, args.output,
                    entity_address=dict(database=db.database_id, **args.entity),
                    record_address=dict(database=db.database_id, **args.record), field_path=args.field_path,
                    element_start=args.element_start, element_count=args.element_count,
                    max_records=args.max_records, max_nodes=args.max_nodes, max_links=args.max_links,
                    max_depth=args.max_depth, max_element_bytes=args.max_element_bytes,
                    max_output_bytes=args.max_output_bytes,
                    max_collection_nodes=args.collection_nodes, max_collection_members=args.collection_members,
                    max_collection_slots=args.collection_slots,
                    follow_reference_payloads=not args.no_follow_reference_payloads,
                    progress=progress)
            elif args.command == 'mesh-csv':
                from fsd_decoder.portable.exports import export_mesh_csv
                manifest = export_mesh_csv(db, args.output, surface_addresses=args.allocation, progress=progress)
                details = json.loads(manifest.read_text())
                result = dict(manifest=str(manifest), complete=details['complete'], mesh_count=details['mesh_count'], unsupported_count=len(details['unsupported']))
            else:
                from fsd_decoder.portable.rendering import render_datasets
                manifest = render_datasets(db, args.output, dataset_ids=args.dataset, width=args.width, height=args.height, azimuth=args.azimuth, elevation=args.elevation, progress=progress)
                details = json.loads(manifest.read_text())
                result = dict(manifest=str(manifest), complete=details['complete'], dataset_count=details['dataset_count'], view_count=details['view_count'])
            context['phase'] = 'publish_result'
            if args.command in ('info', 'schema', 'catalog', 'datasets', 'collection', 'discover', 'reconcile', 'verify', 'membership', 'links', 'root-links', 'payload-census', 'text-pages', 'text-pages-status'):
                _publish_json(result, None if args.command == 'discover' and args.all else args.output)
            else:
                _publish_json(result, None)
            if args.command in ('text', 'mesh-csv', 'render', 'dataset-text', 'payload-text', 'root-text') and (result.get('complete') is False or result.get('status') in ('INCOMPLETE', 'PARTIAL')):
                status = 2
            if args.command == 'root-links' and (result.get('complete') is False or result.get('status') in ('INCOMPLETE', 'PARTIAL')):
                status = 2
            if args.command in ('payload-census', 'text-pages', 'text-pages-status') and result.get('status') != 'COMPLETE':
                status = 2
        return status
    except KeyboardInterrupt:
        print('Operation interrupted; unpublished staging output is removed by its exporter.', file=sys.stderr)
        return 130
    except Exception as exc:
        record = failure_record(exc, status='OUTPUT_FAILED', context=context)
        print(json.dumps(record, ensure_ascii=True, default=str), file=sys.stderr, flush=True)
        if record['error_category'] == 'PROGRAMMING_FAILURE':
            raise
        return 1
    finally:
        if previous_handler is not None:
            signal.signal(signal.SIGTERM, previous_handler)
if __name__ == '__main__':
    sys.exit(main())
