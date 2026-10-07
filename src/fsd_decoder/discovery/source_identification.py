"""Bounded reconciliation of retained declarations and allocated native tags.

This projection neither decodes payloads nor changes name-keyed discovery plans.
Compact descriptors, class descriptors and allocations remain separate evidence.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fsd_decoder.core.diagnostics import InputValidationError

VERSION = 1
_GROUPS = '''SELECT a.native_tag,n.name,a.vector,count(*) allocations,
    sum(a.element_count) stored_elements,sum(a.size) allocation_bytes
    FROM allocations a JOIN names n ON n.id=a.name_id
    GROUP BY a.native_tag,n.name,a.vector'''


def _limit(value: int, name: str, ceiling: int) -> None:
    if type(value) is not int or not 1 <= value <= ceiling:
        raise InputValidationError(f'{name} must be an integer from 1 to {ceiling}')


def _preview(value: Any, depth: int, paths: int, state: dict) -> Any:
    """Detach only bounded issue metadata, including nested source context."""
    if value is None or type(value) in (int, bool, float):
        return value
    if isinstance(value, str):
        if len(value) > 1024:
            state['truncated'] = True
        return value[:1024]
    if depth == 0:
        state['truncated'] = True
        return {'status': 'ISSUE_DEPTH_BOUND'}
    if isinstance(value, Mapping):
        result = {}
        for index, key in enumerate(value):
            if index == paths:
                state['truncated'] = True
                break
            result[key] = _preview(value[key], depth - 1, paths, state)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if len(value) > paths:
            state['truncated'] = True
        return [_preview(value[index], depth - 1, paths, state)
                for index in range(min(len(value), paths))]
    raise InputValidationError('Identification issue metadata must be JSON containers')


def _binding(binding: Mapping, database_id: str) -> dict:
    # A physical scanner offset is not a logical address. Only the retained
    # logical offset or an explicit current PRM descriptor address is used.
    address = binding.get('descriptor_address')
    if address is not None:
        address = {key: address.get(key) for key in ('database', 'segment', 'cluster', 'offset')}
    elif type(binding.get('descriptor_logical_offset')) is int:
        address = dict(database=database_id, segment=0, cluster=0,
                       offset=binding['descriptor_logical_offset'])
    return dict(selector=dict(database_id=database_id, native_tag=binding.get('native_tag'),
                dictionary_id=binding.get('dictionary_id'), compact_descriptor_address=address),
        name=binding.get('name'), binding_active=binding.get('binding_active'),
        compact_descriptor_address_status='RETAINED_LOGICAL_ADDRESS' if address is not None else 'UNAVAILABLE',
        binding_allocation_address=None if binding.get('binding_allocation_address') is None else dict(binding['binding_allocation_address']),
        descriptor_reference_address=None if binding.get('descriptor_reference_address') is None else dict(binding['descriptor_reference_address']))


def _class_evidence(report: Mapping, name: str, bounds: dict, candidates: dict,
                    candidate_complete: bool, candidate_status: str) -> dict:
    classes = report.get('classes', {})
    layout = classes.get(name)
    state = {'truncated': False}
    problems = report.get('layout_problems', {}).get(name, ())
    issues = _preview(problems, bounds['max_issue_depth'], bounds['max_issue_paths'], state)
    matches = candidates.get(name, ())
    ambiguous = any(row.get('status') == 'DUPLICATE_NAME_AMBIGUITY' for row in matches)
    status = ('DUPLICATE_NAME_AMBIGUITY' if ambiguous else
              ('ACCEPTED_INCOMPLETE_LAYOUT' if problems else 'ACCEPTED_CLASS') if layout is not None else
              'NO_ACCEPTED_CLASS_IN_RETAINED_SCOPE' if candidate_complete else
              'UNKNOWN_CANDIDATE_EVIDENCE_UNAVAILABLE')
    if len(matches) > bounds['max_issue_paths']:
        state['truncated'] = True
    preview = [dict(descriptor_offset=row.get('descriptor_offset'),
                    descriptor_address_space=row.get('descriptor_address_space'),
                    status=row.get('status'), candidate_count_for_name=row.get('candidate_count_for_name'))
               for row in matches[:bounds['max_issue_paths']]]
    return dict(class_status=status,
        class_descriptor_offset=None if layout is None else layout.get('descriptor_offset'),
        class_descriptor_address_space=report.get('descriptor_address_space'),
        association_status='AMBIGUOUS_NAME_CORRELATION' if ambiguous else
            'UNIQUE_ACCEPTED_NAME_CORRELATION' if layout is not None and candidate_complete else
            'ACCEPTED_NAME_CORRELATION_CANDIDATE_HISTORY_INCOMPLETE' if layout is not None else 'UNAVAILABLE',
        association_witnessed=False, candidate_evidence_status=candidate_status,
        class_candidates=preview, candidate_reconciliation_complete=candidate_complete,
        declaration_issue_count=len(problems),
        declaration_issues=issues, declaration_issues_truncated=state['truncated'])


def build_source_identification(db: Any, *, kind: str = 'allocation_groups',
        max_rows: int = 100, cursor: Mapping | None = None, max_bindings: int = 4096,
        max_candidates: int = 4096,
        max_issue_paths: int = 16, max_issue_depth: int = 8,
        plans: Mapping | None = None) -> dict:
    """Page exact native allocation groups or retained dictionary declarations.

    ``plans`` accepts already available name-keyed plan records. Their statuses
    are correlated metadata; this function never opens or migrates checkpoints.
    Metadata/issue previews are bounded independently from page enumeration.
    """
    for value, name, ceiling in ((max_rows, 'max_rows', 1000),
            (max_bindings, 'max_bindings', 65536), (max_candidates, 'max_candidates', 65536),
            (max_issue_paths, 'max_issue_paths', 64),
            (max_issue_depth, 'max_issue_depth', 32)):
        _limit(value, name, ceiling)
    if kind not in ('allocation_groups', 'dictionary_bindings'):
        raise InputValidationError('Unknown source identification page population')
    if plans is not None and not isinstance(plans, Mapping):
        raise InputValidationError('Identification plans must be a mapping')
    bounds = dict(max_bindings=max_bindings, max_candidates=max_candidates, max_issue_paths=max_issue_paths,
                  max_issue_depth=max_issue_depth)
    pin = dict(version=VERSION, source_sha256=db.sha256,
               database_id=db.database_id, kind=kind, bounds=bounds)
    offset = 0
    if cursor is not None:
        if (not isinstance(cursor, Mapping) or set(cursor) != {*pin, 'offset'}
                or type(cursor.get('version')) is not int
                or any(cursor[key] != value for key, value in pin.items())
                or type(cursor['offset']) is not int or cursor['offset'] < 0):
            raise InputValidationError('Invalid source identification cursor or changed bounds/source')
        offset = cursor['offset']
    db.check_identity()
    connection = db.store.connection
    report = db.fields.schema_report_document()
    bindings = db.fields.dictionary_bindings
    if report.get('source_sha256') != db.sha256 or report.get('database_id') != db.database_id:
        raise InputValidationError('Identification schema report source identity disagrees')
    total_bindings = len(bindings)
    scanned = min(total_bindings, max_bindings)
    binding_index = {}
    for index in range(scanned):
        binding = bindings[index]
        if binding.get('binding_active') and binding.get('native_tag'):
            binding_index.setdefault(binding['native_tag'], []).append(binding)
    evidence = report.get('class_candidate_evidence', {})
    inventory = evidence.get('candidates', {})
    candidate_index = {}
    for index, key in enumerate(inventory):
        if index == max_candidates:
            break
        candidate = inventory[key]
        candidate_index.setdefault(candidate.get('name'), []).append(dict(
            descriptor_offset=candidate.get('descriptor_offset'), status=candidate.get('status'),
            candidate_count_for_name=candidate.get('candidate_count_for_name'),
            descriptor_address_space=evidence.get('descriptor_address_space')))
    candidate_complete = evidence.get('complete') is True and len(inventory) <= max_candidates
    candidate_status = evidence.get('status', 'HISTORICAL_EVIDENCE_UNAVAILABLE')
    errors = report.get('representation_errors', ())
    representation_errors = {}
    for index in range(min(len(errors), max_bindings)):
        error = errors[index]
        binding = error.get('binding', error)
        representation_errors[(binding.get('native_tag'), binding.get('dictionary_id'))] = error
    representation_complete = len(errors) <= max_bindings
    allocations, elements, size = connection.execute('''SELECT count(*),
        coalesce(sum(element_count),0),coalesce(sum(size),0) FROM allocations''').fetchone()
    grouped = connection.execute('''SELECT count(*),coalesce(sum(allocations),0),
        coalesce(sum(stored_elements),0),coalesce(sum(allocation_bytes),0) FROM ('''
        + _GROUPS + ')').fetchone()
    group_count = grouped[0]
    if allocations != db.store.manifest['counts']['allocations']:
        raise InputValidationError('Identification allocation population disagrees with manifest')
    if tuple(grouped[1:]) != (allocations, elements, size):
        raise InputValidationError('Identification native groups do not reconcile with allocation population')
    population = group_count if kind == 'allocation_groups' else total_bindings
    if offset > population:
        raise InputValidationError('Identification cursor exceeds page population')
    rows = []

    def enrich(row, name, plan_name):
        row.update(_class_evidence(report, name, bounds, candidate_index,
                                   candidate_complete, candidate_status))
        plan = None if plans is None else plans.get(plan_name)
        row['plan_status'] = 'UNATTEMPTED' if plan is None else plan.get('status')
        row['plan_association_status'] = 'UNAVAILABLE' if plan is None else 'DISPLAY_NAME_CORRELATION'
        if plan is not None:
            state = {'truncated': False}
            row['plan_error'] = _preview(plan.get('error'), max_issue_depth, max_issue_paths, state)
            row['plan_error_truncated'] = state['truncated']

    def binding_row(binding):
        row = _binding(binding, db.database_id)
        error = representation_errors.get((binding.get('native_tag'), binding.get('dictionary_id')))
        descriptors = getattr(db.fields, 'descriptors', {})
        descriptor = descriptors.get(binding.get('dictionary_id'))
        row['representation_status'] = ('COMPILER_REJECTION' if error is not None else
            'COMPILED_COMPACT_LAYOUT' if descriptor is not None else
            'UNAVAILABLE_REPRESENTATION_EVIDENCE')
        row['representation_error_reconciliation_complete'] = representation_complete
        if error is not None:
            state = {'truncated': False}
            row['representation_error'] = _preview(error, max_issue_depth, max_issue_paths, state)
            row['representation_error_truncated'] = state['truncated']
        return row

    if kind == 'allocation_groups':
        query = _GROUPS + ' ORDER BY a.native_tag,n.name,a.vector LIMIT ? OFFSET ?'
        for tag, name, vector, count, stored, nbytes in connection.execute(query, (max_rows, offset)):
            matches = binding_index.get(tag, ())
            row = dict(selector=dict(database_id=db.database_id, native_tag=tag,
                display_name=name, vector=bool(vector)), allocations=count,
                stored_elements=stored, allocation_bytes=nbytes,
                dictionary_bindings=[binding_row(binding) for binding in matches],
                dictionary_association_status='CURRENT_NATIVE_TAG_CORRELATION' if matches else
                    'UNAVAILABLE_BINDING_SCAN_BOUND' if scanned < total_bindings else 'NO_RETAINED_ACTIVE_BINDING',
                dictionary_association_witnessed=False)
            row['representation_status'] = ('COMPILED_NATIVE_REPRESENTATION'
                if tag in getattr(db.fields, 'types', {}) else 'UNAVAILABLE_REPRESENTATION_EVIDENCE')
            enrich(row, name.removesuffix('[]'), name)
            rows.append(row)
    else:
        for index in range(offset, min(population, offset + max_rows)):
            binding = bindings[index]
            row = binding_row(binding)
            tag = binding.get('native_tag')
            active = bool(binding.get('binding_active') and tag)
            counts = connection.execute('''SELECT count(*),coalesce(sum(element_count),0),
                coalesce(sum(size),0) FROM allocations WHERE native_tag=?''', (tag,)).fetchone() if active else (0, 0, 0)
            row.update(allocations=counts[0], stored_elements=counts[1], allocation_bytes=counts[2],
                allocation_association_status='CURRENT_NATIVE_TAG_CORRELATION' if active else 'UNBOUND_DECLARATION',
                allocation_association_witnessed=False)
            enrich(row, binding.get('name', ''), binding.get('name', ''))
            rows.append(row)
    end = offset + len(rows)
    db.check_identity()
    return dict(format='FSD_SOURCE_IDENTIFICATION', version=VERSION,
        source=dict(database_id=db.database_id, sha256=db.sha256), kind=kind, rows=rows,
        population=dict(allocations=allocations, stored_elements=elements, allocation_bytes=size,
                        allocation_groups=group_count, dictionary_bindings=total_bindings),
        inspection=dict(offset=offset, rows_returned=len(rows), max_rows=max_rows,
            next_cursor=dict(pin, offset=end) if end < population else None,
            enumeration_complete=end == population, binding_rows_scanned=scanned,
            binding_rows_unscanned=total_bindings - scanned,
            binding_reconciliation_complete=scanned == total_bindings, bounds=bounds,
            candidate_rows_scanned=min(len(inventory), max_candidates),
            candidate_rows_unscanned=max(0, len(inventory) - max_candidates),
            candidate_evidence=dict(status=candidate_status, scope=evidence.get('scope'),
                complete=evidence.get('complete'), candidate_limit=evidence.get('candidate_limit'),
                observed_count=evidence.get('observed_count'), retained_count=evidence.get('retained_count'),
                truncated_count=evidence.get('truncated_count')),
            candidate_reconciliation_complete=candidate_complete,
            representation_error_rows_scanned=min(len(errors), max_bindings),
            representation_error_reconciliation_complete=representation_complete,
            issue_previews_complete=all(not row['declaration_issues_truncated']
                and not row.get('plan_error_truncated', False) for row in rows)),
        original_source_required=False, original_source_accessed=False, application_semantics_complete=False,
        policy='RETAINED_DECLARATIONS_AND_CURRENT_ALLOCATION_INDEX; CORRELATION_NOT_WITNESSED_IDENTITY')
