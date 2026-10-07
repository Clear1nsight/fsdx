"""Automatic bounded collection evidence and dataset reconciliation.

Actual compiled fields supply collection contexts. Membership, referring fields,
navigation links and application ownership remain separate facts. Work budgets
bound the whole report, rather than only each independently visited collection.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from contextlib import closing
import stat
import tempfile
import time

from fsd_decoder.core.diagnostics import InputValidationError, require_source_failure
from fsd_decoder.exports.catalog import addrkey, target
from .collections import inspect_collection, advance_collection
from .collection_progress import CollectionProgress, create_progress_tables, validate_progress_state, COSTS
from .datasets import DiscoverySession, session_operation, _allocation_rows
from .hash_sets import collection_type_context
from .relationship_discovery import _target_view
from .roles import supported_collection_family
from .direct_collections import (DEFAULT_REFERRER_POLICY, LEGACY_REFERRER_POLICY,
    DIRECT_LIST_REFERRER_POLICY, DIRECT_COLLECTION_REFERRER_POLICY, validate_referrer_policy,
    direct_collection_slot, direct_collection_candidate, direct_collection_exclusion_reason,
    direct_collection_context)


def _membership_population(session, referrer_policy=DEFAULT_REFERRER_POLICY):
    """Account for source declarations, including exclusions, without decoding."""
    validate_referrer_policy(referrer_policy)
    eligible, families, excluded = [], [], []
    for row in session.census:
        conditional = [s['path'] for s in row['slots']
                       if _template(s['path']) and s['conditional_union']]
        if conditional:
            excluded.append(dict(type=row['type'], elements=row['elements'],
                allocations=row['allocations'], reason='CONDITIONAL_UNION_COLLECTION_FIELDS',
                field_paths=conditional,conditional_field_declarations=len(conditional),
                population_unit='SOURCE_INSTANCE_DECLARATIONS_WITH_CONDITIONAL_FIELDS',
                excluded_instance_count=0,
                scope='FIELD_DECLARATIONS_ONLY; NOT_A_DISJOINT_INSTANCE_EXCLUSION; ACTIVE_ARM_NOT_INFERRED'))
        if not row['schema_class'] or row['diagnostics']:
            excluded.append(dict(type=row['type'], elements=row['elements'],
                allocations=row['allocations'], reason='NO_SCHEMA_CLASS' if not row['schema_class']
                else 'CENSUS_SCHEMA_DIAGNOSTICS', diagnostics=row['diagnostics'],
                population_unit='SOURCE_INSTANCES_EXCLUDED_FROM_REFERRER_ENUMERATION'))
            continue
        name = row['type'].removesuffix('[]')
        if any(session.reader.inherits(name, anchor) for anchor in ('os_collection', 'os_list', 'os_set', 'os_array')):
            families.append(dict(type=row['type'], elements=row['elements'], allocations=row['allocations']))
        # Exact policy-selected direct fields can supply list/array storage
        # contexts without element T. Retain selectors and reasons for the
        # remaining source declarations without changing V1/V2 selection.
        direct = [s for s in row['slots'] if not _template(s['path'])
                  and (direct_collection_candidate(session.reader, s) if referrer_policy == DIRECT_COLLECTION_REFERRER_POLICY
                       else _direct_collection_pointer(session.reader, s))
                  and not direct_collection_slot(session.reader, s, referrer_policy)]
        if direct:
            excluded.append(dict(type=row['type'], elements=row['elements'],
                allocations=row['allocations'], reason='DIRECT_COLLECTION_POINTER_CONTEXT_OUTSIDE_REFERRER_POLICY',
                field_paths=[s['path'] for s in direct],
                declaration_selectors=[dict(field_path=s['path'], offset=s.get('offset'),
                    descriptor_offset=s.get('descriptor_offset'),
                    pointee_type=s['pointee_type'], arrays=s.get('arrays', ()),
                    conditional_union=s['conditional_union'],
                    eligibility='KNOWN_EXCLUDED', inspection='UNATTEMPTED',
                    reason=direct_collection_exclusion_reason(session.reader, s, referrer_policy)) for s in direct],
                direct_field_declarations=len(direct), excluded_instance_count=0,
                population_unit='SOURCE_INSTANCE_DECLARATIONS_WITH_DIRECT_COLLECTION_POINTER_FIELDS',
                scope='FIELD_DECLARATIONS_ONLY; NOT_A_DISJOINT_INSTANCE_EXCLUSION; MEMBERSHIP_AND_OWNERSHIP_NOT_INFERRED'))
        paths = [s['path'] for s in row['slots'] if _template(s['path']) and not s['conditional_union']]
        if referrer_policy != LEGACY_REFERRER_POLICY:
            paths.extend(s['path'] for s in row['slots'] if direct_collection_slot(session.reader, s, referrer_policy)
                         and s['path'] not in paths)
        nav = session.reader.inherits(name, 'Fs__EntityNavTreeItem')
        if paths or nav:
            # A name cohort can contain admitted and unestablished native tags.
            # Keep all source-name candidates in the denominator; actual source
            # allocations must pass storage admission before decoding any field.
            unestablished = [g for g in row.get('native_tag_groups', ())
                             if not g['schema_admission']['admitted']]
            if unestablished:
                excluded.append(dict(type=row['type'],
                    elements=sum(g['elements'] for g in unestablished),
                    allocations=sum(g['allocations'] for g in unestablished),
                    reason='COLLECTION_REFERRER_SOURCE_STORAGE_UNESTABLISHED_TAG_GROUPS',
                    native_tag_groups=unestablished, field_paths=paths,
                    excluded_instance_count=0,
                    population_unit='DECLARED_NAME_CANDIDATES_REQUIRING_PER_INSTANCE_STORAGE_ADMISSION',
                    scope='CANDIDATES_REMAIN_IN_REFERRER_DENOMINATOR; SOURCE_FIELDS_AND_CONTEXT_NOT_ESTABLISHED'))
            eligible.append((row, paths, nav))
    eligible.sort(key=lambda item: (item[0]['elements'], item[0]['type']))
    families.sort(key=lambda f: (f['elements'], f['type']))
    return eligible, families, excluded


def _source_admission_diagnostic(session, allocation, address, kind, paths):
    admission = session.reader.fields.schema_admission(allocation)
    if admission['admitted']:
        return None
    return dict(address=address, type=kind, native_tag=allocation['native_tag'],
        allocation_id=allocation.get('store_allocation_id'), field_paths=list(paths),
        status='REFERRER_SOURCE_STORAGE_UNESTABLISHED', schema_admission=admission,
        eligibility='VISITED_DECLARED_NAME_CANDIDATE', inspection='SOURCE_FIELDS_UNATTEMPTED',
        scope='NO_SOURCE_FIELD_OR_COLLECTION_CONTEXT_PROMOTION')


def _direct_collection_pointer(reader, slot):
    """Recognize declared pointer storage family, never an element T context."""
    if slot.get('kind') != 'pointer':
        return False
    kind = slot.get('pointee_type')
    while kind and kind.get('kind') in ('alias', 'qualified'):
        if kind.get('unknown_qualifier_flags'):
            return False
        kind = kind.get('underlying')
    return bool(kind and kind.get('kind') == 'class'
                and supported_collection_family(reader, kind.get('name', '')))


def _template(path: str) -> bool:
    return ('::<os_Collection<' in path
            and path.endswith('::<os_outofline_collection>._coll'))


def _address(db, allocation, index=0):
    return asdict(db.address(allocation['segment'], allocation['cluster'],
        allocation['logical_offset'] + allocation['array_header_size']
        + index * allocation['element_stride']))


def discover_membership(session: DiscoverySession, *, objects: Sequence[Mapping] | None = None,
                        max_referrers: int = 10000, max_collections: int = 128,
                        max_members: int = 100000, max_slots: int = 250000,
                        max_nodes: int = 10000, referrer_policy: str = DEFAULT_REFERRER_POLICY, progress=None) -> dict:
    """Inspect source-declared contexts, then small standalone collection families.

The complete allocation census is cheap index accounting, not a promise to
expand every collection. Whole-report budgets and skipped populations are
reported explicitly. A page passes its existing objects to avoid another scan.
"""
    with session_operation(session):
        for name, value, ceiling in (('max_referrers', max_referrers, 100000),
                ('max_collections', max_collections, 10000), ('max_members', max_members, 100000),
                ('max_slots', max_slots, 1000000), ('max_nodes', max_nodes, 10000)):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise InputValidationError(f'{name} must be between 1 and {ceiling}')
        started = time.monotonic()
        db, reader = session.db, session.reader
        collections, references, navigation, diagnostics = [], [], [], []
        cache, contexts, visited = {}, defaultdict(set), set()
        usage = dict(referrers=0, collections=0, members=0, slots=0, nodes=0, storage_evidence_slots=0)
        bounds = dict(referrers=max_referrers, collections=max_collections, members=max_members,
                      slots=max_slots, nodes=max_nodes, storage_evidence_slots=max_slots)
        bounded = set()
        declarations = {r['type']: r for r in session.census}
        eligible, families, excluded = _membership_population(session, referrer_policy)
        eligible_types = {row['type']: (paths, nav) for row, paths, nav in eligible}

        def inspect(address, context=None):
            key = (*addrkey(address), context['element_type'] if context else None)
            if key in cache:
                return cache[key]
            if any(usage[n] >= bounds[n] for n in ('collections', 'members', 'slots', 'nodes', 'storage_evidence_slots')):
                bounded.update(n for n in ('collections', 'members', 'slots', 'nodes', 'storage_evidence_slots') if usage[n] >= bounds[n])
                return None
            result = inspect_collection(reader, address, type_context=context,
                max_members=max_members-usage['members'],
                max_slots=min(max_slots-usage['slots'], max_slots-usage['storage_evidence_slots']),
                max_nodes=max_nodes-usage['nodes'])
            index = len(collections)
            collections.append(dict(id=index, **result))
            cache[key] = index
            usage['collections'] += 1
            usage['members'] += sum(len(result.get(n, ())) for n in
                ('members', 'slot_references', 'incompatible_self_references'))
            usage['slots'] += result.get('scanned_slots', 0)
            usage['storage_evidence_slots'] += len(result.get('storage_slots', ()))
            usage['nodes'] += len(result.get('nodes', ()))
            if result['status'] == 'RESOURCE_BOUND':
                bounded.add('collection_instance')
            return index

        def consume(address, kind):
            if addrkey(address) in visited:
                return
            visited.add(addrkey(address))
            if usage['referrers'] >= max_referrers:
                bounded.add('referrers')
                return
            usage['referrers'] += 1
            try:
                allocation = reader.allocation(*addrkey(address))
                if allocation['element_size'] > 65536:
                    diagnostics.append(dict(address=address, status='ELEMENT_SIZE_BOUND'))
                    return
                paths, is_nav = eligible_types.get(kind, ([], False))
                admission_failure = _source_admission_diagnostic(session, allocation, address, kind, paths)
                if admission_failure is not None:
                    diagnostics.append(admission_failure)
                    return
                value = reader.value(address)
                for field in value.get('fields', ()):
                    path = field.get('path', '')
                    # Arrays have concrete indices in values and symbolic [] in slots.
                    declared_path = re.sub(r'\[\d+\]', '[]', path)
                    if declared_path not in paths or field.get('kind') != 'stored_reference':
                        continue
                    p = target(field)
                    if len(references) >= max_members:
                        bounded.add('referring_fields')
                        break
                    ref = dict(referrer_address=address, field_path=path, address=p,
                        status=field.get('target_status', 'UNRESOLVED'), collection_id=None,
                        meaning='CURRENT_REFERRING_FIELD; OWNERSHIP_NOT_INFERRED')
                    references.append(ref)
                    if referrer_policy != LEGACY_REFERRER_POLICY and not _template(path):
                        evidence = direct_collection_context(session, p, address, path, referrer_policy)
                        ref.update(direct_source_context=evidence, type_filter_applied=False,
                            element_type_status=evidence['element_type_status'], status=evidence['status'])
                        if evidence['status'] in ('DIRECT_LIST_CONTEXT_CONFIRMED', 'DIRECT_COLLECTION_CONTEXT_CONFIRMED'):
                            ref['collection_id'] = inspect(p)
                            ref['status'] = 'INSPECTED' if ref['collection_id'] is not None else 'REPORT_RESOURCE_BOUND'
                        continue
                    if not p:
                        continue
                    try:
                        context = collection_type_context(reader, p, address, path)
                        contexts[addrkey(p)].add(context['element_type'])
                        ref['element_type'] = context['element_type']
                        target_allocation = reader.allocation(*addrkey(p))
                        is_set = reader.inherits(target_allocation['name'].removesuffix('[]'), 'os_set')
                        # Lists have an independent slot-count contract; a template
                        # does not silently add an unimplemented list type filter.
                        ref['collection_id'] = inspect(p, context if is_set else None)
                        ref['status'] = 'INSPECTED' if ref['collection_id'] is not None else 'REPORT_RESOURCE_BOUND'
                        ref['type_filter_applied'] = is_set
                    except Exception as exc:
                        require_source_failure(exc, dict(phase='automatic_collection_context', address=address))
                        ref.update(status='CONTEXT_UNCONFIRMED', error=str(exc))
                if is_nav:
                    fields = [f for f in value.get('fields', ()) if f.get('path', '').endswith('.m_pEntity')]
                    if len(fields) == 1 and fields[0].get('kind') == 'stored_reference':
                        p = target(fields[0]); canonical = None
                        if p and p.get('database') == db.database_id:
                            a = db.allocation(*addrkey(p))
                            view = _target_view(db, a, p['offset']) if a else {}
                            if any(reader.inherits(n, 'Fs::Entity') for n in view.get('matching_schema_base_types', ())):
                                canonical = _address(db, a, view['element_index'])
                        navigation.append(dict(referrer_address=address, field_path=fields[0]['path'],
                            address=p, entity_address=canonical,
                            status='ENTITY_REFERENCE' if canonical else fields[0].get('target_status', 'UNCONFIRMED'),
                            scope='ALLOCATED_NAVIGATION_ITEM; ROOT_REACHABILITY_NOT_ESTABLISHED'))
                    else:
                        diagnostics.append(dict(address=address, status='NAVIGATION_FIELD_UNCONFIRMED'))
            except Exception as exc:
                require_source_failure(exc, dict(phase='automatic_membership_referrer', address=address))
                diagnostics.append(dict(address=address, status='REFERRER_UNCONFIRMED', error=str(exc)))

        if objects is not None:
            for obj in objects:
                if obj['type'] in eligible_types:
                    consume(obj['address'], obj['type'])
                row = declarations.get(obj['type'], {})
                if any(f['type'] == obj['type'] for f in families):
                    inspect(obj['address'])
            scope = 'CURRENT_PAGE_OBJECTS_ONLY'
            expected_referrers = sum(o['type'] in eligible_types for o in objects)
        else:
            expected_referrers = sum(row['elements'] for row, _, _ in eligible)
            for row, _, _ in eligible:
                for _, segment, cluster, offset in _allocation_rows(db, row['type'], 0):
                    allocation = reader.allocation(segment, cluster, offset)
                    for index in range(allocation['count']):
                        if usage['referrers'] >= max_referrers:
                            bounded.add('referrers'); break
                        consume(_address(db, allocation, index), row['type'])
                    if usage['referrers'] >= max_referrers:
                        break
                if usage['referrers'] >= max_referrers:
                    break
            # A large list family may contain millions of index/helper collections.
            # Account for it, but never launch an unbounded standalone sweep.
            for family in sorted(families, key=lambda f: (f['elements'], f['type'])):
                if family['elements'] > max_collections:
                    continue
                for _, segment, cluster, offset in _allocation_rows(db, family['type'], 0):
                    allocation = reader.allocation(segment, cluster, offset)
                    for index in range(allocation['count']):
                        address = _address(db, allocation, index)
                        if not any(key[:3] == addrkey(address) for key in cache):
                            inspect(address)
                    if bounded:
                        break
            scope = 'SOURCE_TYPED_REFERRERS_AND_SMALL_STANDALONE_COLLECTION_FAMILIES'
        if usage['referrers'] < expected_referrers:
            bounded.add('referrers')
        by_address = {addrkey(c['address']) for c in collections}
        family_types = {f['type'] for f in families}
        indexed_addresses = {addrkey(c['address']) for c in collections
            if reader.allocation(*addrkey(c['address']))['name'] in family_types}
        inventory = sum(f['elements'] for f in families)
        report = dict(format='FSD_COLLECTION_EVIDENCE', version=1, scope=scope,
            source=dict(db.source_info), ownership='NOT_INFERRED', collection_referrer_policy=referrer_policy,
            referrer_population_scope='DECLARED_NAME_CANDIDATES; PER_INSTANCE_STORAGE_ADMISSION_REQUIRED', collections=collections,
            referring_fields=references, navigation_entity_references=navigation,
            conflicting_contexts=[dict(address=dict(database=db.database_id, segment=k[0], cluster=k[1], offset=k[2]),
                element_types=sorted(types), status='DISTINCT_SOURCE_CONTEXTS; NOT_MERGED')
                for k, types in contexts.items() if len(types)>1],
            collection_families=families, indexed_collection_elements=inventory,
            excluded_populations=excluded,
            distinct_collections_inspected=len(by_address),
            distinct_indexed_collections_inspected=len(indexed_addresses),
            indexed_collections_not_inspected=inventory-len(indexed_addresses) if objects is None else None,
            referrers_expected=expected_referrers, referrers_scanned=usage['referrers'],
            referrer_scan_complete=usage['referrers']==expected_referrers and not diagnostics
                and 'referring_fields' not in bounded,
            status_counts=dict(Counter(c['status'] for c in collections)), diagnostics=diagnostics,
            resource_usage=usage, resource_limits=bounds, reached_bounds=sorted(bounded),
            elapsed_seconds=time.monotonic()-started,
            limitations=['Collection index accounting is separate from instance inspection.',
                'Membership and referring fields do not establish application ownership.',
                'Navigation-item references do not establish root-reachable navigation.',
                'List member type filters are not applied from template hints.'])
        session.check_identity()
        if progress:
            progress(dict(phase='automatic_membership', collections=len(collections),
                referrers=usage['referrers'], bounds=sorted(bounded), finished=True))
        return report


def reconcile_entities(report: Mapping, evidence: Mapping, *, catalog: Mapping | None = None) -> dict:
    """Compare address sets, labelling each denominator and incomplete scope."""
    if any(report.get('source', {}).get(k) != evidence.get('source', {}).get(k)
           for k in ('sha256', 'database_id')):
        raise InputValidationError('Reconciliation requires matching source evidence')
    allocated = {addrkey(o['address']) for o in report['objects'] if o['classification']=='ENTITY_DATASET'}
    navigation = {addrkey(r['entity_address']) for r in evidence['navigation_entity_references'] if r['entity_address']}
    checks = []
    for collection in evidence['collections']:
        context = collection.get('type_context')
        if collection['status']!='VERIFIED_CARDINALITY' or not context:
            continue
        # Source membership target types, not arbitrary template/name labels,
        # determine which observed members can be compared to the Entity census.
        members = {addrkey(m['address']) for m in collection['members'] if m['address']}
        entity_members = members & allocated
        if not entity_members:
            continue
        checks.append(dict(collection_id=collection['id'], element_type=context['element_type'],
            verified_members=len(members), members_in_entity_census=len(entity_members),
            allocated_entities_absent_from_this_collection=[list(k) for k in sorted(allocated-members)],
            other_members=[list(k) for k in sorted(members-allocated)],
            meaning='ADDRESS_SET_COMPARISON; GLOBAL_DATASET_REGISTRY_ROLE_NOT_ASSUMED'))
    result = dict(format='FSD_ENTITY_RECONCILIATION', version=1, allocated_entity_records=len(allocated),
        allocation_scope='COMPLETE_ENTITY_CENSUS' if report.get('version')==2 else 'CURRENT_PAGE_ONLY',
        collection_checks=checks, allocated_navigation_item_entity_targets=len(navigation),
        navigation_referrer_scan_complete=evidence['referrer_scan_complete'],
        entities_without_observed_navigation_item_reference=[list(k) for k in sorted(allocated-navigation)],
        navigation_targets_absent_from_entity_census=[list(k) for k in sorted(navigation-allocated)],
        catalog_status='NOT_CHECKED', application_ownership='NOT_INFERRED',
        limitations=['Missing from one collection does not prove a missing dataset.',
            'Absence from navigation can be concluded only within the stated scan scope.'])
    result['reference_gaps'] = {k:report.get('accounting', {}).get(k) for k in
        ('source_bindings_without_allocation', 'resolved_targets_without_allocation')}
    result['collections_with_unverified_membership'] = [dict(id=c['id'], address=c['address'], status=c['status'])
        for c in evidence['collections'] if c['status'] not in ('VERIFIED_CARDINALITY','EMPTY_DIRECTORY')]
    roles = report.get('dataset_roles', {})
    result['unconfirmed_storage_groups'] = [dict(type=g['type'], template_id=g['template_id'],
        role=g['role'], allocations=g['allocations'], stored_elements=g['stored_elements'],
        bytes=g['bytes'], selector=g['selector'], application_role=g['application_role'])
        for g in roles.get('groups', ()) if g['application_role']=='UNCONFIRMED']
    result['payload_association_status'] = 'INSTANCE_OWNERSHIP_NOT_ENUMERATED; GROUP_SELECTORS_RETAIN_ACCESS'
    if 'payload_census_access' in report:
        result['payload_census_access']=dict(report['payload_census_access'])
    if catalog is not None:
        if catalog.get('source', {}).get('sha256')!=report['source']['sha256']:
            raise InputValidationError('Catalog source differs from discovery')
        catalogued = {addrkey(e['address']) for e in catalog['entities']}
        result.update(catalog_status='COMPLETE' if catalog['complete'] else 'PARTIAL',
            catalogued_entities=len(catalogued),
            entities_absent_from_catalog=[list(k) for k in sorted(allocated-catalogued)],
            catalogued_entities_absent_from_census=[list(k) for k in sorted(catalogued-allocated)],
            root_reachable_entities_not_in_navigation=catalog['coverage']['entities_not_in_navigation'],
            unassigned_geometry_ids=catalog['coverage']['unassigned_geometry_ids'],
            unsupported_geometry=catalog['unhandled_objects'], catalog_diagnostics=catalog['diagnostics'])
    return result


_MEMBERSHIP_CHECKPOINT_VERSION = 3
_MEMBERSHIP_LIMITS = dict(max_referrers=100000, max_collections=10000,
    max_members=100000, max_slots=1000000, max_nodes=10000)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _checkpoint_path(checkpoint, source=None, original=None):
    path = Path(checkpoint).absolute()
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise InputValidationError('Membership checkpoint must be a regular nonsymlink file')
    if source is not None and (path.resolve() == Path(source).resolve()
            or path.exists() and os.path.samefile(path, source)):
        raise InputValidationError('Membership checkpoint collides with source store')
    if original is not None and (path.resolve() == Path(original).resolve()
            or path.exists() and Path(original).exists() and os.path.samefile(path, original)):
        raise InputValidationError('Membership checkpoint collides with retained original FSD')
    return path


def _store_digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _checkpoint_state(connection, *, validate_coverage=True, allowed_versions=(3,)):
    try:
        row = connection.execute("SELECT value FROM metadata WHERE key='state'").fetchone()
        state = json.loads(row[0]) if row else None
        if (not isinstance(state, dict) or type(state.get('version')) is not int
                or state.get('version') not in allowed_versions
                or type(state.get('referrers_processed')) is not int
                or type(state.get('standalone_processed')) is not int
                or type(state.get('referrers_expected')) is not int
                or type(state.get('standalone_expected')) is not int
                or not isinstance(state.get('pin'), dict)
                or any(key not in state for key in ('cursor', 'standalone_cursor', 'referrers_expected',
                    'standalone_expected', 'families', 'excluded', 'batches_completed', 'elapsed_seconds',
                    'metrics', 'collection_state_counts', 'status_counts', 'completion_verified'))
                or not 0 <= state['referrers_processed'] <= state['referrers_expected']
                or not 0 <= state['standalone_processed'] <= state['standalone_expected']):
            raise ValueError('missing or invalid state')
        metric_keys = {'referring_fields','navigation_entity_references','diagnostics',
            'conflicting_context_addresses','members','slots','nodes','storage_evidence_slots',
            'provisional_interpretations'}
        state_keys = {'PENDING','DEFERRED_BATCH_BUDGET','PROCESSED','BLOCKED_RESOURCE_BOUND'}
        if state['version']==3:
            metric_keys.update(('collection_steps','progress_records','control_reads','control_bytes'))
            state_keys.add('CONTINUING')
        if (type(state['completion_verified']) is not bool or type(state['metrics']) is not dict
                or set(state['metrics']) != metric_keys or type(state['collection_state_counts']) is not dict
                or set(state['collection_state_counts']) != state_keys or type(state['status_counts']) is not dict
                or any(type(value) is not int or value < 0 for values in
                       (state['metrics'],state['collection_state_counts'],state['status_counts'])
                       for value in values.values())):
            raise ValueError('invalid checkpoint counter or completion types')
        if validate_coverage:
            # A trusted unchanged session token skips only row reconciliation.
            # Fresh sessions and externally changed checkpoints always check it.
            if state['referrers_processed'] != connection.execute('SELECT count(*) FROM referrers').fetchone()[0]:
                raise ValueError('referrer coverage differs from committed cursor')
            if state['standalone_processed'] != connection.execute('SELECT count(*) FROM standalone').fetchone()[0]:
                raise ValueError('standalone coverage differs from committed cursor')
            for table, cursor in (('referrers', state['cursor']), ('standalone', state['standalone_cursor'])):
                last = connection.execute(f'SELECT id FROM {table} ORDER BY rowid DESC LIMIT 1').fetchone()
                if (json.loads(last[0]) if last else None) != cursor:
                    raise ValueError(f'{table} cursor differs from committed coverage')
        return state
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
        raise InputValidationError(f'Invalid membership checkpoint: {exc}') from exc


def _checkpoint_validation_token(source, path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise InputValidationError('Membership checkpoint must be a regular nonsymlink file')
    sidecars = []
    for suffix in ('-wal', '-shm', '-journal'):
        try:
            sidecar = Path(str(path) + suffix).lstat()
        except FileNotFoundError:
            identity = None
        else:
            if not stat.S_ISREG(sidecar.st_mode):
                raise InputValidationError('Membership checkpoint sidecar must be a regular nonsymlink file')
            identity = (sidecar.st_dev, sidecar.st_ino, sidecar.st_size,
                        sidecar.st_mtime_ns, sidecar.st_ctime_ns)
        sidecars.append((suffix, identity))
    return (str(source), str(path.resolve()), info.st_dev, info.st_ino,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, tuple(sidecars))


def _validate_checkpoint_scalars(connection, state, session=None):
    """Reconcile scalar row structure once per unchanged session checkpoint.

    This deliberately does not select or parse result/provisional JSON. Export
    performs the separate full streaming evidence/cost reconciliation.
    """
    counts = Counter(dict(connection.execute('SELECT state,count(*) FROM collections GROUP BY state')))
    statuses = Counter(dict(connection.execute('''SELECT status,count(*) FROM collections
        WHERE state IN ('PROCESSED','BLOCKED_RESOURCE_BOUND') GROUP BY status''')))
    if (counts != Counter(state['collection_state_counts'])
            or statuses != Counter(state['status_counts'])):
        raise InputValidationError('Checkpoint scalar collection state/status counts differ from retained rows')
    invalid = connection.execute('''SELECT count(*) FROM collections WHERE
        (state IN ('PROCESSED','BLOCKED_RESOURCE_BOUND') AND (result IS NULL OR status IS NULL)) OR
        (state IN ('PENDING','DEFERRED_BATCH_BUDGET','CONTINUING') AND (result IS NOT NULL OR status IS NOT NULL)) OR
        (state='DEFERRED_BATCH_BUDGET' AND provisional_result IS NULL) OR
        (state='BLOCKED_RESOURCE_BOUND' AND status!='RESOURCE_BOUND') OR
        (state='PROCESSED' AND status='RESOURCE_BOUND')''').fetchone()[0]
    if invalid:
        raise InputValidationError('Checkpoint scalar collection state/status counts differ from retained rows')
    if (state['completion_verified'] and (counts['PENDING'] or counts['DEFERRED_BATCH_BUDGET'] or counts['CONTINUING']
            or state['standalone_processed'] < state['standalone_expected']
            or state['referrers_processed'] < state['referrers_expected'] and not state.get('blocked_referrer'))):
        raise InputValidationError('Checkpoint completion verification conflicts with pending source work')
    for table, metric in (('referring_fields','referring_fields'),
            ('navigation','navigation_entity_references'),('diagnostics','diagnostics')):
        if connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0] != state['metrics'][metric]:
            raise InputValidationError(f'Checkpoint scalar {metric} count differs from retained rows')
    provisional = connection.execute('SELECT count(*) FROM collections WHERE provisional_result IS NOT NULL').fetchone()[0]
    conflicts = connection.execute('''SELECT count(*) FROM (SELECT segment,cluster,offset
        FROM collections WHERE element_type!='' GROUP BY segment,cluster,offset HAVING count(*)>1)''').fetchone()[0]
    if (provisional != state['metrics']['provisional_interpretations']
            or conflicts != state['metrics']['conflicting_context_addresses']):
        raise InputValidationError('Checkpoint scalar context/provisional counts differ from retained rows')
    if state['version']==3:
        _validate_collection_progress(connection,state,session)


def _validate_collection_progress(connection,state,session=None):
    """Reconcile prefix scalar costs/coverage once at fresh checkpoint admission."""
    invalid=connection.execute('''SELECT count(*) FROM collection_records WHERE
        kind NOT IN ('nodes','node_controls','storage_slots','directory_slots','members',
                     'slot_references','incompatible_self_references','hash_tables') OR
        typeof(members)!='integer' OR typeof(slots)!='integer' OR typeof(nodes)!='integer' OR
        typeof(storage_evidence_slots)!='integer' OR
        members!=CASE WHEN kind IN ('members','slot_references','incompatible_self_references') THEN 1 ELSE 0 END OR
        slots!=CASE WHEN kind IN ('storage_slots','directory_slots') THEN 1 ELSE 0 END OR
        nodes!=CASE WHEN kind='nodes' THEN 1 ELSE 0 END OR
        storage_evidence_slots!=CASE WHEN kind='storage_slots' THEN 1 ELSE 0 END OR
        (kind IN ('storage_slots','directory_slots','members','slot_references','incompatible_self_references') AND slot_index<0)
        ''').fetchone()[0]
    if invalid:raise InputValidationError('Collection progress record costs/indices differ from evidence categories')
    cumulative=Counter()
    for task_id,raw,task_state,address,context,task_status in connection.execute('''SELECT p.task_id,p.state,c.state,c.address,c.context,c.status
            FROM collection_progress p LEFT JOIN collections c ON c.id=p.task_id'''):
        progress=json.loads(raw)
        validate_progress_state(progress)
        if (task_state is None or progress.get('address')!=json.loads(address)
                or progress.get('type_context')!=(json.loads(context) if context else None)
                or type(progress.get('sequence')) is not int or progress['sequence']<0
                or type(progress.get('terminal')) is not bool
                or progress['terminal']!=(task_state in ('PROCESSED','BLOCKED_RESOURCE_BOUND'))
                or progress['terminal'] and task_status!=progress['status']
                or not progress['terminal'] and task_state!='CONTINUING'):
            raise InputValidationError('Collection progress state differs from queued task')
        row=connection.execute('''SELECT count(*),coalesce(max(sequence),0),coalesce(sum(members),0),
            coalesce(sum(slots),0),coalesce(sum(nodes),0),coalesce(sum(storage_evidence_slots),0)
            FROM collection_records WHERE task_id=?''',(task_id,)).fetchone()
        record_counts=Counter(dict(connection.execute('SELECT kind,count(*) FROM collection_records WHERE task_id=? GROUP BY kind',(task_id,))))
        if (row[0]!=progress['sequence'] or row[1]!=progress['sequence']
                or record_counts!=Counter(progress.get('record_counts',{}))
                or any(type(progress['resource_usage'].get(name)) is not int or
                       row[index+2]!=progress['resource_usage'][name] for index,name in enumerate(COSTS))):
            raise InputValidationError('Collection progress prefix counters differ from retained scalar records')
        if progress['observed_count']!=record_counts['members']:
            raise InputValidationError('Collection observed cardinality differs from committed member slots')
        cumulative.update(progress['resource_usage'])
        cumulative['progress_records']+=row[0]
        cumulative['control_reads']+=progress['control_reads'];cumulative['control_bytes']+=progress['control_bytes']
        cumulative['collection_steps']+=progress['steps']
        if session is not None:
            from .collection_progress import scalar,exact_element,members,pointer
            inspector=CollectionProgress(connection,task_id,progress['address'],progress['type_context'])
            allocation=exact_element(session.reader,progress['address'])
            kind=allocation['name'].removesuffix('[]')
            if progress.get('root_kind') is not None and kind!=progress['root_kind']:
                raise InputValidationError('Collection progress root differs from current source declaration')
            if progress['adapter']=='ARRAY' and progress['controls']:
                actual={key:scalar(session.reader,inspector,progress['address'],kind,key)
                        for key in ('list_entries','list_size','lower_bound')}
                if actual!=progress['controls'] or progress['declared_count']!=actual['list_entries']:
                    raise InputValidationError('Collection progress controls differ from current source')
                _,start=pointer(session.reader,inspector,progress['address'],kind,'alist')
                if progress.get('storage_address') is not None and start!=progress['storage_address']:
                    raise InputValidationError('Collection progress storage differs from current source')
            elif progress['adapter']=='LIST' and progress['declared_count'] is not None:
                if scalar(session.reader,inspector,progress['address'],kind,'card')!=progress['declared_count']:
                    raise InputValidationError('List progress total differs from current source')
                current=progress.get('current_node')
                if current:
                    actual=exact_element(session.reader,current['address'])['name'].removesuffix('[]')
                    capacity=members(session.reader.fields.schema.layout(actual))['pointers'][1]['count']
                    if (actual!=current['kind'] or capacity!=current['capacity'] or
                            scalar(session.reader,inspector,current['address'],actual,'_local_card')!=current['local']):
                        raise InputValidationError('List progress node controls differ from current source')
            elif progress['adapter']=='HASH_SET' and progress['controls']:
                actual={key:scalar(session.reader,inspector,progress['address'],kind,key) for key in progress['controls']}
                if actual!=progress['controls']:
                    raise InputValidationError('Hash progress controls differ from current source')
                _,directory=pointer(session.reader,inspector,progress['address'],kind,'index_sp',wrapper=True)
                if progress.get('directory_address') is not None and directory!=progress['directory_address']:
                    raise InputValidationError('Hash progress directory differs from current source')
                if progress['type_context'] is not None:
                    context=progress['type_context']
                    derived=collection_type_context(session.reader,progress['address'],context['referrer_address'],context['field_path'])
                    if context!=derived:
                        raise InputValidationError('Hash progress context differs from current source')
                current=progress.get('current_table')
                if current:
                    actual_counts={key:scalar(session.reader,inspector,current['address'],current['kind'],key)
                                   for key in current['counts']}
                    if actual_counts!=current['counts']:
                        raise InputValidationError('Hash progress table controls differ from current source')
                    _,contents=pointer(session.reader,inspector,current['address'],current['kind'],'_contents')
                    _,bitmap=pointer(session.reader,inspector,current['address'],current['kind'],'bitmap')
                    if contents!=current['contents'] or bitmap!=current['bitmap']:
                        raise InputValidationError('Hash progress storage differs from current source')
        if progress['status']=='VERIFIED_CARDINALITY' and (not progress['complete'] or not progress['equal']
                or not progress['membership_complete'] or progress['declared_count']!=progress['observed_count']
                or connection.execute("SELECT count(*) FROM collection_queue WHERE task_id=? AND state='PENDING'",(task_id,)).fetchone()[0]):
            raise InputValidationError('Collection progress verification lacks traversal/count closure')
        cursor=progress.get('cursor')
        if progress.get('phase') in ('ARRAY_SLOTS','HASH_DIRECTORY'):
            kind='storage_slots' if progress['phase']=='ARRAY_SLOTS' else 'directory_slots'
            node=progress['storage_address'] if progress['phase']=='ARRAY_SLOTS' else progress['directory_address']
            next_index=cursor
        elif progress.get('phase') in ('LIST_SLOTS','HASH_SLOTS'):
            current=progress.get('current_node') or progress.get('current_table')
            kind='storage_slots';node=current['address'];next_index=current['index']
            if cursor.get('next_slot')!=next_index:
                raise InputValidationError('Collection progress cursor differs from current node')
        else:continue
        coverage=connection.execute('''SELECT count(*),coalesce(max(slot_index),-1),coalesce(min(slot_index),0) FROM collection_records
            WHERE task_id=? AND kind=? AND node_key=?''',(task_id,kind,_json(node))).fetchone()
        capacity=(progress['controls']['list_size'] if progress['phase']=='ARRAY_SLOTS' else
                  progress['controls']['n_HashTables'] if progress['phase']=='HASH_DIRECTORY' else
                  current['capacity'] if progress['phase']=='LIST_SLOTS' else current['counts']['_n_slots'])
        if type(next_index) is not int or not 0<=next_index<=capacity or coverage!=(next_index,next_index-1,0):
            raise InputValidationError('Collection progress cursor differs from retained slot prefix')
        if progress['status']=='VERIFIED_CARDINALITY' and progress['phase']=='ARRAY_SLOTS' and next_index!=progress['controls']['list_size']:
            raise InputValidationError('Collection progress verification precedes storage closure')
    if connection.execute('''SELECT count(*) FROM collection_records r LEFT JOIN collection_progress p
            ON p.task_id=r.task_id WHERE p.task_id IS NULL''').fetchone()[0]:
        raise InputValidationError('Orphan collection prefix evidence')
    if state['pin']['config'].get('collection_work_mode')=='RESUMABLE_PREFIX' and any(
            cumulative[name]!=state['metrics'][name] for name in (*COSTS,'progress_records','control_reads','control_bytes','collection_steps')):
        raise InputValidationError('Checkpoint progressive counters differ from retained task prefixes')


def _save_checkpoint(connection, state):
    connection.execute("""INSERT INTO metadata VALUES ('state',?) ON CONFLICT(key)
        DO UPDATE SET value=excluded.value WHERE value!=excluded.value""", (_json(state),))


def _collection_costs(result):
    return dict(members=sum(len(result.get(n, ())) for n in
        ('members', 'slot_references', 'incompatible_self_references')),
        slots=result.get('scanned_slots', 0), nodes=len(result.get('nodes', ())),
        storage_evidence_slots=len(result.get('storage_slots', ())))


def _checkpoint_summary(connection, state):
    counts = state['collection_state_counts']
    status_counts = state['status_counts']
    attempted = counts.get('PROCESSED', 0) + counts.get('BLOCKED_RESOURCE_BOUND', 0)
    pending = counts.get('PENDING', 0) + counts.get('DEFERRED_BATCH_BUDGET', 0) + counts.get('CONTINUING',0)
    blocked = counts.get('BLOCKED_RESOURCE_BOUND', 0)
    ref_complete = state['referrers_processed'] == state['referrers_expected']
    standalone_complete = state['standalone_processed'] == state['standalone_expected']
    enumeration_complete = ref_complete and standalone_complete and not pending
    blocked_referrer = state.get('blocked_referrer')
    work_continuation = bool(pending or not standalone_complete or not ref_complete and not blocked_referrer)
    status = ('VERIFICATION_PENDING' if not work_continuation and not state['completion_verified'] else
              'BLOCKED_RESOURCE_BOUND' if blocked_referrer or enumeration_complete and blocked else
              'COMPLETE' if enumeration_complete else 'PARTIAL')
    metrics = state['metrics']
    diagnostics = metrics['diagnostics']
    referring_fields = metrics['referring_fields']
    conflicts = metrics['conflicting_context_addresses']
    resumable=state['pin']['config'].get('collection_work_mode')=='RESUMABLE_PREFIX'
    return dict(format='FSD_MEMBERSHIP_CHECKPOINT_STATUS', version=state['version'],
        status=status, source=state['pin']['source'], checkpoint_pin=state['pin'],
        ownership='NOT_INFERRED',
        referrer_population_scope='DECLARED_NAME_CANDIDATES; PER_INSTANCE_STORAGE_ADMISSION_REQUIRED',
        collection_referrer_policy=state['pin']['config'].get('collection_referrer_policy', LEGACY_REFERRER_POLICY),
        referrers_expected=state['referrers_expected'],
        referrers_processed=state['referrers_processed'], referrers_scanned=state['referrers_processed'],
        referrer_enumeration_complete=ref_complete,
        referrer_scan_complete=ref_complete and diagnostics == 0 and not state.get('blocked_referrer'),
        standalone_collections_expected=state['standalone_expected'],
        standalone_collections_processed=state['standalone_processed'],
        standalone_enumeration_complete=standalone_complete,
        collection_families=state['families'], excluded_populations=state['excluded'],
        scope='ELIGIBLE_REFERRERS_AND_ALL_STANDALONE_COLLECTIONS' if state['pin']['config']['include_standalone']
            else 'ELIGIBLE_REFERRERS_ONLY',
        indexed_collection_elements=sum(f['elements'] for f in state['families']),
        standalone_collection_elements_outside_scope=0 if state['pin']['config']['include_standalone']
            else sum(f['elements'] for f in state['families']),
        collections_total=sum(counts.values()), collections_processed=attempted,
        collections_pending=pending, collections_blocked=blocked, collection_state_counts=counts,
        collections_resource_excluded=blocked if resumable else 0,
        resource_exclusion_scope='COLLECTION_INTERPRETATIONS; SINGLE_ELEMENT_RAW_SIZE; EXACT_SELECTORS_RETAINED' if resumable else None,
        collections_deferred_batch_budget=counts.get('DEFERRED_BATCH_BUDGET',0),
        collections_continuing=counts.get('CONTINUING',0),
        progress_records=metrics.get('progress_records',0),collection_steps=metrics.get('collection_steps',0),
        control_reads=metrics.get('control_reads',0),control_bytes=metrics.get('control_bytes',0),
        control_read_scope='ADVANCEMENT_CONTROLS; FRESH_ADMISSION_SOURCE_REVALIDATION_IS_ADDITIONAL',
        provisional_interpretations=metrics['provisional_interpretations'],
        status_counts=status_counts, diagnostics_count=diagnostics,
        referring_fields=referring_fields, conflicting_context_addresses=conflicts,
        navigation_entity_references=metrics['navigation_entity_references'],
        enumeration_complete=enumeration_complete,
        collection_inspection_complete=enumeration_complete and blocked == 0,
        verified_membership_collections=status_counts.get('VERIFIED_CARDINALITY',0)+status_counts.get('EMPTY_DIRECTORY',0),
        unverified_membership_collections=attempted-status_counts.get('VERIFIED_CARDINALITY',0)-status_counts.get('EMPTY_DIRECTORY',0),
        completion_scope='QUEUED_ADAPTER_WORK_TERMINAL; MEMBERSHIP_VERIFICATION_SEPARATE_BY_TASK_STATUS',
        continuation_required=work_continuation or not state['completion_verified'],
        work_continuation_required=work_continuation,
        integrity_completed=state['completion_verified'],
        integrity_scope='SQLITE_QUICK_AND_FOREIGN_KEY_CHECKS; ACCESSED_BLOBS_VALIDATED; NOT_FULL_INTEGRITY',
        next_cursor=state['cursor'], standalone_cursor=state['standalone_cursor'],
        blocked_referrer=state.get('blocked_referrer'),
        resource_limits=dict(state['pin']['config'], max_standalone_elements=state['pin']['config']['max_referrers'],
            max_referring_fields=state['pin']['config']['max_batch_members'], max_element_bytes=65536,
            storage_evidence_slots=state['pin']['config']['max_slots']),
        resource_limit_scopes=dict(instance=[] if resumable else ['max_members','max_slots','max_nodes','storage_evidence_slots'],
            step=['max_members','max_slots','max_nodes','storage_evidence_slots'] if resumable else [],
            batch=['max_referrers','max_collections','max_batch_members','max_batch_slots','max_batch_nodes',
                   'max_standalone_elements','max_referring_fields']),
        last_batch=state.get('last_batch'),
        reached_bounds=state.get('last_batch', {}).get('reached_bounds', []),
        resource_usage=dict(referrers=state['referrers_processed'], referring_fields=referring_fields,
            standalone_elements=state['standalone_processed'], collections=metrics.get('collection_steps',0) if resumable else attempted+metrics['provisional_interpretations'],
            members=metrics['members'], slots=metrics['slots'], nodes=metrics['nodes'],
            storage_evidence_slots=metrics['storage_evidence_slots']),
        resource_limit_scope='EXPLICIT_STEP_AND_BATCH_LIMITS; CUMULATIVE_COLLECTION_USAGE_MAY_EXCEED_ONE_STEP_OR_BATCH' if resumable else
            'EXPLICIT_INSTANCE_AND_BATCH_LIMITS; CUMULATIVE_USAGE_MAY_EXCEED_ONE_BATCH_LIMIT',
        batches_completed=state['batches_completed'], elapsed_seconds=state['elapsed_seconds'],
        scheduler='RESUMABLE_SLOT_AND_NODE_PREFIX; MAX_COLLECTIONS_BOUNDS_ADAPTER_STEPS' if resumable else
            'REMAINING_BATCH_BUDGET; REDUCED_BUDGET_BOUND_IS_PROVISIONAL_AND_RETRIED_WITH_FULL_BUDGET',
        limitations=['Committed referrers and collection contexts are reused exactly once.',
            'Interrupted work and explicitly provisional reduced-budget attempts may be retried; completed interpretations are reused.',
            'Step/batch exhaustion preserves committed cursor work; unsupported raw element size remains a separate exclusion.' if resumable else
            'Per-instance resource bounds remain blocked under the pinned configuration.',
            'Standalone collection families are outside scope unless explicitly included.',
            'Membership does not establish ownership, active union arms, CRS or units.'])


def _membership_elements(session, rows, cursor):
    """Resume strictly after a committed allocation/element cursor."""
    names = [row['type'] for row in rows]
    start = 0
    if cursor is not None:
        if (not isinstance(cursor, dict) or set(cursor) != {'type', 'allocation_id', 'element_index'}
                or cursor['type'] not in names or type(cursor['allocation_id']) is not int
                or cursor['allocation_id'] < 1 or type(cursor['element_index']) is not int
                or cursor['element_index'] < 0):
            raise InputValidationError('Invalid membership continuation cursor')
        actual = session.db.store.connection.execute('''SELECT n.name,a.element_count FROM allocations a
            JOIN names n ON n.id=a.name_id WHERE a.id=?''', (cursor['allocation_id'],)).fetchone()
        if not actual or actual[0] != cursor['type'] or cursor['element_index'] >= actual[1]:
            raise InputValidationError('Membership cursor is outside its source allocation')
        start = names.index(cursor['type'])
    for row in rows[start:]:
        name = row['type']
        after = cursor['allocation_id'] if cursor and cursor['type'] == name else 0
        for aid, segment, cluster, offset in _allocation_rows(session.db, name, after):
            allocation = session.reader.allocation(segment, cluster, offset)
            if allocation['store_allocation_id'] != aid:
                raise InputValidationError('Membership allocation index differs from its source')
            first = cursor['element_index'] + 1 if cursor and cursor['type'] == name and aid == after else 0
            for index in range(first, allocation['count']):
                yield dict(type=name, allocation_id=aid, element_index=index), allocation, _address(session.db, allocation, index)


def _next_collection(connection):
    """Select the globally earliest eligible task using indexed state heads.

    An IN predicate ordered by the global ID can sort the eligible population.
    Each equality seek uses pending_collections(state,id), so committed task
    count does not increase the work needed to find the next eligible task.
    """
    heads = [connection.execute('''SELECT id,address,context,state FROM collections
        WHERE state=? ORDER BY id LIMIT 1''', (state,)).fetchone()
        for state in ('PENDING', 'CONTINUING', 'DEFERRED_BATCH_BUDGET')]
    return min((row for row in heads if row is not None), key=lambda row: row[0], default=None)


def _queue_collection(connection, state, address, context=None):
    # Context and context-free views are distinct interpretations. The source
    # referrer itself is retained in referring_fields, not part of the cache key.
    element_type = context['element_type'] if context else ''
    inserted = connection.execute('''INSERT OR IGNORE INTO collections(segment,cluster,offset,element_type,address,context,state)
        VALUES (?,?,?,?,?,?,'PENDING')''', (*addrkey(address), element_type, _json(address),
        _json(context) if context else None)).rowcount
    if inserted:
        state['collection_state_counts']['PENDING'] += 1
        if element_type:
            count = connection.execute('''SELECT count(*) FROM collections
                WHERE segment=? AND cluster=? AND offset=? AND element_type!='' ''', addrkey(address)).fetchone()[0]
            if count == 2:
                state['metrics']['conflicting_context_addresses'] += 1
    return connection.execute('''SELECT id FROM collections WHERE segment=? AND cluster=? AND offset=? AND element_type=?''',
        (*addrkey(address), element_type)).fetchone()[0]


def _referrer_evidence(session, address, kind, paths, is_nav, referrer_policy=DEFAULT_REFERRER_POLICY):
    """Decode one bounded referrer; collection work is queued separately."""
    references, navigation, diagnostics, tasks = [], [], [], []
    db, reader = session.db, session.reader
    try:
        allocation = reader.allocation(*addrkey(address))
        if allocation['element_size'] > 65536:
            return references, navigation, [dict(address=address, status='ELEMENT_SIZE_BOUND')], tasks
        admission_failure = _source_admission_diagnostic(session, allocation, address, kind, paths)
        if admission_failure is not None:
            return references, navigation, [admission_failure], tasks
        value = reader.value(address)
        for field in value.get('fields', ()):
            path = field.get('path', '')
            if re.sub(r'\[\d+\]', '[]', path) not in paths or field.get('kind') != 'stored_reference':
                continue
            p = target(field)
            ref = dict(referrer_address=address, field_path=path, address=p,
                status=field.get('target_status', 'UNRESOLVED'), collection_id=None,
                meaning='CURRENT_REFERRING_FIELD; OWNERSHIP_NOT_INFERRED')
            references.append(ref)
            if referrer_policy != LEGACY_REFERRER_POLICY and not _template(path):
                evidence = direct_collection_context(session, p, address, path, referrer_policy)
                ref.update(direct_source_context=evidence, type_filter_applied=False,
                    element_type_status=evidence['element_type_status'], status=evidence['status'])
                if evidence['status'] in ('DIRECT_LIST_CONTEXT_CONFIRMED', 'DIRECT_COLLECTION_CONTEXT_CONFIRMED'):
                    ref['status'] = 'QUEUED'
                    tasks.append((len(references)-1, p, None))
                continue
            if p:
                try:
                    context = collection_type_context(reader, p, address, path)
                    target_allocation = reader.allocation(*addrkey(p))
                    is_set = reader.inherits(target_allocation['name'].removesuffix('[]'), 'os_set')
                    ref.update(element_type=context['element_type'], type_filter_applied=is_set, status='QUEUED')
                    tasks.append((len(references)-1, p, context if is_set else None))
                except Exception as exc:
                    require_source_failure(exc, dict(phase='automatic_collection_context', address=address))
                    ref.update(status='CONTEXT_UNCONFIRMED', error=str(exc))
        if is_nav:
            fields = [f for f in value.get('fields', ()) if f.get('path', '').endswith('.m_pEntity')]
            if len(fields) == 1 and fields[0].get('kind') == 'stored_reference':
                p = target(fields[0]); canonical = None
                if p and p.get('database') == db.database_id:
                    a = db.allocation(*addrkey(p))
                    view = _target_view(db, a, p['offset']) if a else {}
                    if any(reader.inherits(n, 'Fs::Entity') for n in view.get('matching_schema_base_types', ())):
                        canonical = _address(db, a, view['element_index'])
                navigation.append(dict(referrer_address=address, field_path=fields[0]['path'],
                    address=p, entity_address=canonical,
                    status='ENTITY_REFERENCE' if canonical else fields[0].get('target_status', 'UNCONFIRMED'),
                    scope='ALLOCATED_NAVIGATION_ITEM; ROOT_REACHABILITY_NOT_ESTABLISHED'))
            else:
                diagnostics.append(dict(address=address, status='NAVIGATION_FIELD_UNCONFIRMED'))
    except Exception as exc:
        require_source_failure(exc, dict(phase='automatic_membership_referrer', address=address))
        diagnostics.append(dict(address=address, status='REFERRER_UNCONFIRMED', error=str(exc)))
    return references, navigation, diagnostics, tasks


def discover_membership_batch(session: DiscoverySession, *, checkpoint: str | Path,
        max_referrers: int = 10000, max_collections: int = 128,
        max_members: int = 100000, max_slots: int = 250000,
        max_nodes: int = 10000, include_standalone: bool = False,
        max_batch_members: int | None = None, max_batch_slots: int | None = None,
        max_batch_nodes: int | None = None, collection_work_mode: str = 'RESUMABLE_PREFIX', referrer_policy: str = DEFAULT_REFERRER_POLICY, progress=None) -> dict:
    """Advance a source/config/runtime-pinned, disk-backed discovery checkpoint.

    Referrer groups and result groups check source/runtime identity before
    committing evidence and counters. Default resumable work retains exact
    slot/node prefixes on disk; member/slot/node ceilings admit each step and
    max_collections limits step invocations. Batch totals stay independently
    bounded. BOUNDED_INSTANCE preserves the historical one-operation/provisional
    policy. Unsupported raw elements remain explicit policy exclusions.
    """
    with session_operation(session):
        from fsd_decoder.core.provenance import runtime_identity
        config = dict(max_referrers=max_referrers, max_collections=max_collections,
            max_members=max_members, max_slots=max_slots, max_nodes=max_nodes,
            include_standalone=include_standalone,collection_work_mode=collection_work_mode,
            collection_referrer_policy=validate_referrer_policy(referrer_policy))
        if collection_work_mode not in ('RESUMABLE_PREFIX','BOUNDED_INSTANCE'):
            raise InputValidationError('Unknown collection work mode')
        if type(include_standalone) is not bool:
            raise InputValidationError('include_standalone must be a boolean')
        for name, ceiling in _MEMBERSHIP_LIMITS.items():
            if type(config[name]) is not int or not 1 <= config[name] <= ceiling:
                raise InputValidationError(f'{name} must be between 1 and {ceiling}')
        for key, value, instance, default, ceiling in (
                ('max_batch_members',max_batch_members,max_members,100000,100000),
                ('max_batch_slots',max_batch_slots,max_slots,250000,1000000),
                ('max_batch_nodes',max_batch_nodes,max_nodes,10000,10000)):
            total = max(instance,default) if value is None else value
            if type(total) is not int or not instance <= total <= ceiling:
                raise InputValidationError(f'{key} must be between its instance limit {instance} and {ceiling}')
            config[key] = total
        source = getattr(session.db, 'path', None)
        if source is None:
            raise InputValidationError('Membership checkpoints require a retained file-backed store')
        source = Path(source).resolve()
        path = _checkpoint_path(checkpoint, source, session.db.source_info.get('path'))
        path.parent.mkdir(parents=True, exist_ok=True)
        session.check_identity()
        eligible, families, excluded = _membership_population(session, referrer_policy)
        retained_store_pin = getattr(session, '_membership_store_pin', None)
        if retained_store_pin is None:
            session.db.verify_source()
            session.check_identity()
            retained_store_pin = dict(path=str(source), sha256=_store_digest(source), bytes=source.stat().st_size)
            session.check_identity()
            session._membership_store_pin = retained_store_pin
            session._membership_initial_verified = True
        pin = dict(version=_MEMBERSHIP_CHECKPOINT_VERSION, source=dict(session.db.source_info),
            store_path=str(source), store_sha256=retained_store_pin['sha256'], store_bytes=retained_store_pin['bytes'],
            runtime_identity=runtime_identity(), config=config,
            population_sha256=hashlib.sha256(_json(dict(eligible=eligible, families=families, excluded=excluded)).encode()).hexdigest())
        pin_json = _json(pin)
        session.check_identity()
        started = time.monotonic()
        # Lock the checkpoint inode itself: no separate lock-path symlink or alias
        # can make concurrent callers commit competing cursors.
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InputValidationError('Membership checkpoint is already in use') from exc
            if os.fstat(fd).st_ino != path.stat().st_ino or os.fstat(fd).st_dev != path.stat().st_dev:
                raise InputValidationError('Membership checkpoint path changed before locking')
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (source.stat().st_dev, source.stat().st_ino):
                raise InputValidationError('Membership checkpoint aliases source store')
            connection = sqlite3.connect(path)
            try:
                admission_token = _checkpoint_validation_token(source,path)
                # WAL may change logical rows without touching the main inode.
                # Reconcile every WAL admission conservatively, even when its
                # observed sidecar timestamps happen to match the cached token.
                structural_validated = (getattr(session,'_membership_checkpoint_validation',None) == admission_token
                    and dict(admission_token[-1])['-wal'] is None)

                def commit_trusted():
                    _save_checkpoint(connection, state)
                    session.check_identity()
                    current_eligible,current_families,current_excluded = _membership_population(session, referrer_policy)
                    population_sha256 = hashlib.sha256(_json(dict(eligible=current_eligible,
                        families=current_families,excluded=current_excluded)).encode()).hexdigest()
                    if (_json(state['pin']) != pin_json or dict(session.db.source_info) != pin['source']
                            or population_sha256 != pin['population_sha256']):
                        connection.rollback()
                        raise InputValidationError('Source, configuration or population changed before membership checkpoint commit')
                    if runtime_identity() != pin['runtime_identity']:
                        connection.rollback()
                        raise InputValidationError('Runtime changed before membership checkpoint commit')
                    connection.commit()
                    if structural_validated:
                        session._membership_checkpoint_validation = _checkpoint_validation_token(source,path)

                connection.execute('PRAGMA synchronous=FULL')
                empty = not connection.execute('SELECT name FROM sqlite_master WHERE type=\'table\'').fetchone()
                if empty:
                    connection.executescript('''
                        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                        CREATE TABLE referrers(id TEXT PRIMARY KEY,address TEXT NOT NULL);
                        CREATE TABLE standalone(id TEXT PRIMARY KEY,address TEXT NOT NULL);
                        CREATE TABLE collections(id INTEGER PRIMARY KEY,segment INTEGER,cluster INTEGER,offset INTEGER,
                            element_type TEXT,address TEXT NOT NULL,context TEXT,state TEXT NOT NULL,status TEXT,result TEXT,provisional_result TEXT,
                            UNIQUE(segment,cluster,offset,element_type));
                        CREATE INDEX pending_collections ON collections(state,id);
                        CREATE INDEX collection_state_status ON collections(state,status);
                        CREATE TABLE referring_fields(id INTEGER PRIMARY KEY,collection_id INTEGER,evidence TEXT NOT NULL);
                        CREATE TABLE navigation(id INTEGER PRIMARY KEY,evidence TEXT NOT NULL);
                        CREATE TABLE diagnostics(id INTEGER PRIMARY KEY,evidence TEXT NOT NULL);
                    ''')
                    create_progress_tables(connection)
                    state = dict(version=_MEMBERSHIP_CHECKPOINT_VERSION, pin=pin, cursor=None,
                        standalone_cursor=None, referrers_processed=0,
                        referrers_expected=sum(row['elements'] for row, _, _ in eligible),
                        standalone_processed=0, standalone_expected=sum(f['elements'] for f in families) if include_standalone else 0,
                        families=families, excluded=excluded, batches_completed=0, elapsed_seconds=0, completion_verified=False,
                        collection_state_counts={'PENDING':0,'DEFERRED_BATCH_BUDGET':0,'CONTINUING':0,'PROCESSED':0,'BLOCKED_RESOURCE_BOUND':0},
                        status_counts={}, metrics=dict(referring_fields=0,navigation_entity_references=0,diagnostics=0,
                            conflicting_context_addresses=0,members=0,slots=0,nodes=0,storage_evidence_slots=0,provisional_interpretations=0,
                            collection_steps=0,progress_records=0,control_reads=0,control_bytes=0))
                    commit_trusted()
                else:
                    state = _checkpoint_state(connection, validate_coverage=not structural_validated)
                    if state['pin'] != pin:
                        raise InputValidationError('Membership checkpoint source, store, runtime or configuration pin mismatch')
                expected = dict(referrers_expected=sum(row['elements'] for row,_,_ in eligible),
                    standalone_expected=sum(f['elements'] for f in families) if include_standalone else 0,
                    families=families,excluded=excluded)
                if any(_json(state[key]) != _json(value) for key,value in expected.items()):
                    raise InputValidationError('Checkpoint expected counts/families/exclusions differ from current source population')
                if not structural_validated:
                    _validate_checkpoint_scalars(connection,state,session)
                    structural_validated = True
                    session._membership_checkpoint_validation = _checkpoint_validation_token(source,path)
                # Validate both cursors even if their scan has already completed.
                ref_rows = [row for row, _, _ in eligible]
                if state['cursor']:
                    next(_membership_elements(session, ref_rows, state['cursor']), None)
                if state['standalone_cursor']:
                    next(_membership_elements(session, families, state['standalone_cursor']), None)
                before = _checkpoint_summary(connection, state)
                if not before['continuation_required']:
                    session.check_identity()
                    if runtime_identity() != pin['runtime_identity']:
                        raise InputValidationError('Runtime changed before completed membership reuse')
                    return before
                usage = dict(referrers=0, referring_fields=0, standalone_elements=0,
                             collections=0, members=0, slots=0, nodes=0, storage_evidence_slots=0,control_reads=0,control_bytes=0)
                reached = set()
                declarations = {row['type']: (paths, nav) for row, paths, nav in eligible}
                for cursor, allocation, address in _membership_elements(session, ref_rows, state['cursor']):
                    if state.get('blocked_referrer'):
                        break
                    if usage['referrers'] >= max_referrers:
                        reached.add('referrers'); break
                    paths, nav = declarations[cursor['type']]
                    refs, navigation, diagnostics, tasks = _referrer_evidence(session, address, cursor['type'], paths, nav, referrer_policy)
                    if usage['referring_fields'] + len(refs) > config['max_batch_members']:
                        reached.add('referring_fields')
                        if len(refs) > config['max_batch_members']:
                            state['blocked_referrer'] = dict(cursor=cursor, address=address,
                                status='REFERRING_FIELDS_RESOURCE_BOUND', fields=len(refs), limit=config['max_batch_members'])
                            commit_trusted()
                        break
                    connection.execute('INSERT INTO referrers VALUES (?,?)', (_json(cursor), _json(address)))
                    for index, p, context in tasks:
                        refs[index]['collection_id'] = _queue_collection(connection, state, p, context)
                    for ref in refs:
                        connection.execute('INSERT INTO referring_fields(collection_id,evidence) VALUES (?,?)',
                            (ref['collection_id'], _json(ref)))
                    for table, rows in (('navigation', navigation), ('diagnostics', diagnostics)):
                        connection.executemany(f'INSERT INTO {table}(evidence) VALUES (?)', ((_json(row),) for row in rows))
                    state['cursor'] = cursor
                    state['referrers_processed'] += 1
                    state['metrics']['referring_fields'] += len(refs)
                    state['metrics']['navigation_entity_references'] += len(navigation)
                    state['metrics']['diagnostics'] += len(diagnostics)
                    usage['referrers'] += 1
                    usage['referring_fields'] += len(refs)
                    if usage['referrers'] % 250 == 0:
                        commit_trusted()
                    if usage['referrers'] % 500 == 0:
                        session.check_identity()
                        if progress:
                            progress(dict(phase='membership_referrers', processed=state['referrers_processed'],
                                          total=state['referrers_expected']))
                commit_trusted()
                # Enumerating standalone instances queues disk-backed tasks without
                # expanding their members. This queue scan has its own explicit
                # element budget, equal to the pinned referrer batch limit.
                for cursor, allocation, address in _membership_elements(session, families if include_standalone else [], state['standalone_cursor']):
                    if usage['standalone_elements'] >= max_referrers:
                        reached.add('standalone_elements'); break
                    # Preserve current behavior: any source-derived context at
                    # this address supplies its independent interpretation.
                    if not connection.execute('SELECT 1 FROM collections WHERE segment=? AND cluster=? AND offset=? LIMIT 1',
                                              addrkey(address)).fetchone():
                        _queue_collection(connection, state, address)
                    connection.execute('INSERT INTO standalone VALUES (?,?)', (_json(cursor), _json(address)))
                    state['standalone_cursor'] = cursor
                    state['standalone_processed'] += 1
                    usage['standalone_elements'] += 1
                    if usage['standalone_elements'] % 250 == 0:
                        commit_trusted()
                commit_trusted()
                while usage['collections'] < max_collections:
                    row = _next_collection(connection)
                    if not row:
                        break
                    remaining = {name:min(config['max_'+name],config['max_batch_'+name]-usage[name])
                                 for name in ('members','slots','nodes')}
                    if (not any(value>0 for value in remaining.values()) if collection_work_mode=='RESUMABLE_PREFIX' else
                            any(value <= 0 for value in remaining.values())):
                        reached.update(name for name,value in remaining.items() if value<=0)
                        break
                    session.check_identity()
                    if collection_work_mode=='RESUMABLE_PREFIX':
                        prefix=CollectionProgress(connection,row[0],json.loads(row[1]),json.loads(row[2]) if row[2] else None)
                        old_sequence=prefix.state['sequence']
                        result=advance_collection(session.reader,prefix,max_members=remaining['members'],
                            max_slots=remaining['slots'],max_nodes=remaining['nodes'])
                        session.check_identity()
                        task_state=('BLOCKED_RESOURCE_BOUND' if result['terminal'] and result['status']=='RESOURCE_BOUND' else
                                    'PROCESSED' if result['terminal'] else 'CONTINUING')
                        state['collection_state_counts'][row[3]]-=1
                        state['collection_state_counts'][task_state]+=1
                        connection.execute('UPDATE collections SET state=?,status=?,result=? WHERE id=?',
                            (task_state,result['status'] if result['terminal'] else None,
                             _json(dict(id=row[0],**prefix.summary())) if result['terminal'] else None,row[0]))
                        if result['terminal']:
                            state['status_counts'][result['status']]=state['status_counts'].get(result['status'],0)+1
                        for name,cost in result['step_usage'].items():
                            usage[name]+=cost;state['metrics'][name]+=cost
                        for name in ('control_reads','control_bytes'):
                            cost=result['step_'+name];usage[name]+=cost;state['metrics'][name]+=cost
                        state['metrics']['progress_records']+=result['sequence']-old_sequence
                        state['metrics']['collection_steps']+=1;usage['collections']+=1
                        if usage['collections']%16==0:
                            commit_trusted()
                        if not result['terminal'] and not any(result['step_usage'].values()):
                            reached.add('collection_step_budget');break
                        continue
                    result = inspect_collection(session.reader, json.loads(row[1]),
                        type_context=json.loads(row[2]) if row[2] else None,
                        max_members=remaining['members'], max_slots=remaining['slots'], max_nodes=remaining['nodes'])
                    session.check_identity()
                    provisional = result['status']=='RESOURCE_BOUND' and any(
                        remaining[name] < config['max_'+name] for name in remaining)
                    task_state = ('DEFERRED_BATCH_BUDGET' if provisional else
                        'BLOCKED_RESOURCE_BOUND' if result['status']=='RESOURCE_BOUND' else 'PROCESSED')
                    state['collection_state_counts'][row[3]] -= 1
                    state['collection_state_counts'][task_state] += 1
                    encoded = _json(dict(id=row[0], **result))
                    if provisional:
                        connection.execute('UPDATE collections SET state=?,status=NULL,provisional_result=? WHERE id=?',
                            (task_state,encoded,row[0]))
                        state['metrics']['provisional_interpretations'] += 1
                        reached.add('provisional_collection_batch_bound')
                    else:
                        connection.execute('UPDATE collections SET state=?,status=?,result=? WHERE id=?',
                            (task_state,result['status'],encoded,row[0]))
                        state['status_counts'][result['status']] = state['status_counts'].get(result['status'],0)+1
                    costs = _collection_costs(result)
                    usage['collections'] += 1
                    for name,cost in costs.items():
                        usage[name] += cost
                        state['metrics'][name] += cost
                    if task_state=='BLOCKED_RESOURCE_BOUND':
                        reached.add('collection_instance')
                    if usage['collections'] % 16 == 0 or provisional:
                        commit_trusted()
                    if provisional:
                        break
                commit_trusted()
                if usage['collections'] == max_collections and connection.execute("SELECT 1 FROM collections WHERE state IN ('PENDING','DEFERRED_BATCH_BUDGET','CONTINUING') LIMIT 1").fetchone():
                    reached.add('collections')
                terminal = _checkpoint_summary(connection,state)
                if not terminal['work_continuation_required'] and not getattr(session,'_membership_completed_verified',False):
                    session.finish()
                if not terminal['work_continuation_required']:
                    state['completion_verified'] = True
                state['batches_completed'] += 1
                state['elapsed_seconds'] += time.monotonic() - started
                state['last_batch'] = dict(resource_usage=usage, reached_bounds=sorted(reached))
                commit_trusted()
                if state['completion_verified']:
                    session._membership_completed_verified = True
                summary = _checkpoint_summary(connection, state)
                if progress:
                    progress(dict(phase='membership_batch', status=summary['status'],
                        processed=summary['collections_processed'], total=summary['collections_total'],
                        referrers_processed=state['referrers_processed'], referrers_total=state['referrers_expected'], finished=True))
                return summary
            finally:
                connection.close()
        finally:
            os.close(fd)


def _export_bounded_checkpoint(checkpoint: str | Path, output: str | Path) -> dict:
    """Stream retained checkpoint evidence to an atomically published JSONL file.

    A read transaction supplies one consistent snapshot. Export does not decode
    or refresh historical execution pins, and supports explicitly partial runs.
    """
    path = _checkpoint_path(checkpoint)
    if not path.is_file():
        raise InputValidationError('Missing membership checkpoint')
    output = Path(output).absolute()
    if os.path.lexists(output):
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True)
    descriptor, name = tempfile.mkstemp(prefix='.membership-', dir=output.parent)
    os.close(descriptor)
    stage = Path(name)
    try:
        connection.execute('BEGIN')
        state = _checkpoint_state(connection,allowed_versions=(2,3))
        summary = _checkpoint_summary(connection, state)
        observed_states,observed_statuses = Counter(),Counter()
        observed_costs = Counter()
        observed_records = Counter()
        opener = gzip.open if output.suffix == '.gz' else open
        with opener(stage, 'wt', encoding='utf-8') as stream:
            def emit(value):
                stream.write(_json(value) + '\n')
            emit(dict(record='header', format='FSD_MEMBERSHIP_EVIDENCE_STREAM', version=1,
                pin=state['pin'], collection_families=state['families'], excluded_populations=state['excluded'],
                evidence_scope='RETAINED_CHECKPOINT_EXECUTION; SOURCE_AND_RUNTIME_NOT_REFRESHED_BY_EXPORT'))
            for row in connection.execute('SELECT id,address,context,state,result,provisional_result FROM collections ORDER BY id'):
                final = json.loads(row[4]) if row[4] else None
                provisional = json.loads(row[5]) if row[5] else None
                observed_states[row[3]] += 1
                if bool(final) != (row[3] in ('PROCESSED','BLOCKED_RESOURCE_BOUND')):
                    raise InputValidationError('Checkpoint result differs from its committed collection state')
                if final:
                    observed_statuses[final['status']] += 1
                    observed_costs.update(_collection_costs(final))
                if provisional:
                    observed_records['provisional_interpretations'] += 1
                    observed_costs.update(_collection_costs(provisional))
                emit(dict(record='collection', id=row[0], state=row[3], address=json.loads(row[1]),
                    context=json.loads(row[2]) if row[2] else None,
                    collection=final, provisional_attempt=provisional,
                    provisional_attempt_meaning='REDUCED_BATCH_BUDGET_ATTEMPT; NOT_FINAL_MEMBERSHIP_EVIDENCE' if row[5] else None))
            for segment, cluster, offset in connection.execute('''SELECT segment,cluster,offset
                    FROM collections WHERE element_type!='' GROUP BY segment,cluster,offset HAVING count(*)>1'''):
                observed_records['conflicting_context_addresses'] += 1
                types = [r[0] for r in connection.execute('''SELECT element_type FROM collections
                    WHERE segment=? AND cluster=? AND offset=? AND element_type!='' ORDER BY element_type''',
                    (segment, cluster, offset))]
                emit(dict(record='conflicting_context', address=dict(database=state['pin']['source']['database_id'],
                    segment=segment, cluster=cluster, offset=offset), element_types=types,
                    status='DISTINCT_SOURCE_CONTEXTS; NOT_MERGED'))
            for table, record in (('referring_fields', 'referring_field'), ('navigation', 'navigation_entity_reference'),
                                  ('diagnostics', 'diagnostic')):
                for identifier, evidence in connection.execute(f'SELECT id,evidence FROM {table} ORDER BY id'):
                    observed_records[dict(referring_fields='referring_fields',navigation='navigation_entity_references',
                                          diagnostics='diagnostics')[table]] += 1
                    value = json.loads(evidence)
                    if table == 'referring_fields' and value.get('collection_id') is not None:
                        task = connection.execute('SELECT state,status FROM collections WHERE id=?',
                                                  (value['collection_id'],)).fetchone()
                        value['status'] = 'INSPECTED' if task[0] == 'PROCESSED' else task[0]
                        value['collection_status'] = task[1]
                    emit(dict(record=record, id=identifier, evidence=value))
            if (observed_states != Counter(state['collection_state_counts'])
                    or observed_statuses != Counter(state['status_counts'])
                    or any(state['metrics'][key] != observed_costs[key] for key in
                           ('members','slots','nodes','storage_evidence_slots'))
                    or any(state['metrics'][key] != observed_records[key] for key in
                           ('provisional_interpretations','referring_fields','navigation_entity_references',
                            'diagnostics','conflicting_context_addresses'))):
                raise InputValidationError('Checkpoint counters differ from retained evidence')
            emit(dict(record='summary', **summary))
        with stage.open('rb') as stream:
            os.fsync(stream.fileno())
        os.link(stage, output)
        directory = os.open(output.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return dict(summary, output=str(output))
    finally:
        connection.close()
        stage.unlink(missing_ok=True)


def export_membership_checkpoint(checkpoint: str | Path, output: str | Path) -> dict:
    """Stream bounded old interpretations or new disk-backed prefix records."""
    path=_checkpoint_path(checkpoint)
    if not path.is_file():raise InputValidationError('Missing membership checkpoint')
    with closing(sqlite3.connect(f'{path.as_uri()}?mode=ro',uri=True)) as connection, connection:
        state=_checkpoint_state(connection,allowed_versions=(2,3))
    if state['pin']['config'].get('collection_work_mode')!='RESUMABLE_PREFIX':
        return _export_bounded_checkpoint(checkpoint,output)
    output=Path(output).absolute()
    if os.path.lexists(output):raise FileExistsError(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    descriptor,name=tempfile.mkstemp(prefix='.membership-',dir=output.parent);os.close(descriptor)
    stage=Path(name)
    connection=sqlite3.connect(f'{path.as_uri()}?mode=ro',uri=True)
    try:
        connection.execute('BEGIN')
        state=_checkpoint_state(connection)
        _validate_checkpoint_scalars(connection,state)
        summary=_checkpoint_summary(connection,state)
        opener=gzip.open if output.suffix=='.gz' else open
        with opener(stage,'wt',encoding='utf-8') as stream:
            def emit(value):stream.write(_json(value)+'\n')
            emit(dict(record='header',format='FSD_MEMBERSHIP_EVIDENCE_STREAM',version=2,
                checkpoint_version=3,pin=state['pin'],collection_families=state['families'],
                excluded_populations=state['excluded'],
                evidence_scope='RETAINED_CHECKPOINT_EXECUTION; SOURCE_AND_RUNTIME_NOT_REFRESHED_BY_EXPORT',
                collection_encoding='APPEND_ONLY_PREFIX_RECORDS_AND_COMPACT_CLOSURE_SUMMARIES'))
            for task_id,sequence,kind,evidence in connection.execute('''SELECT task_id,sequence,kind,evidence
                    FROM collection_records ORDER BY task_id,sequence'''):
                emit(dict(record='collection_evidence',collection_id=task_id,sequence=sequence,
                          kind=kind,evidence=json.loads(evidence)))
            for task_id,address,context,task_state,result,progress_raw in connection.execute('''SELECT c.id,c.address,
                    c.context,c.state,c.result,p.state FROM collections c LEFT JOIN collection_progress p
                    ON p.task_id=c.id ORDER BY c.id'''):
                retained=None
                if progress_raw:
                    prefix=CollectionProgress(connection,task_id,json.loads(address),json.loads(context) if context else None)
                    retained=dict(id=task_id,**prefix.summary())
                emit(dict(record='collection',id=task_id,state=task_state,address=json.loads(address),
                    context=json.loads(context) if context else None,collection=retained,
                    evidence_records='PRECEDING_COLLECTION_EVIDENCE_ROWS; NOT_RECONSTRUCTED_IN_MEMORY'))
            for table,record in (('referring_fields','referring_field'),('navigation','navigation_entity_reference'),
                                 ('diagnostics','diagnostic')):
                for identifier,evidence in connection.execute(f'SELECT id,evidence FROM {table} ORDER BY id'):
                    value=json.loads(evidence)
                    if table=='referring_fields' and value.get('collection_id') is not None:
                        task=connection.execute('SELECT state,status FROM collections WHERE id=?',(value['collection_id'],)).fetchone()
                        value['status']='INSPECTED' if task[0]=='PROCESSED' else task[0]
                        value['collection_status']=task[1]
                    emit(dict(record=record,id=identifier,evidence=value))
            emit(dict(record='summary',**summary))
        with stage.open('rb') as stream:os.fsync(stream.fileno())
        os.link(stage,output)
        directory=os.open(output.parent,os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        return dict(summary,output=str(output))
    finally:
        connection.close();stage.unlink(missing_ok=True)
