"""Typed allocation-element interpretation for native and restored databases.

`NativeFields(database).decode(allocation, element_index=0)` accepts logical
allocation dictionaries from the native tag iterator. ``from_compiled`` restores
the interpreter from captured schema and representation metadata without native
source parsing. Class fields use compiled source declarations; primitive and
bootstrap storage uses statically corroborated compact representation metadata.
Both paths read immutable logical bytes and consult the database's reference
interface, including for zero words. Native access uses current PRM; restored
access uses captured bindings and the store's binding-completeness policy.
"""
from collections.abc import Mapping, Sequence
from collections import OrderedDict
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any, Iterable
from fsd_decoder.resources.loader import load_json
import json
import math
import struct
from fsd_decoder.schema.schema_members import MemberSchema, SchemaError
from fsd_decoder.schema.decode_members import MemberDecoder
from fsd_decoder.schema.expansion_admission import (ExpansionLimits, ExpansionMetadataError, schema_cost, admit_cost, DEFAULT_MAX_DECODED_LEAVES, DEFAULT_MAX_EXPANSION_WORK)
from fsd_decoder.schema.expansion_admission import allocation_cost
from fsd_decoder.schema.bootstrap_sizes import Evaluator, compile_dynamic_bindings
from fsd_decoder.schema.probe_types import extended_dictionary
from fsd_decoder.core.contracts import AllocationRecord, LayoutRecord, LogicalDatabase, SchemaLayouts, ValueRecord
from fsd_decoder.core.diagnostics import require_source_failure, failure_record, ResourceLimitError
DEFAULT_MAX_RECORD_BYTES = 8 * 1024 * 1024

def _record_byte_limit(value):
    if type(value) is not int or value <= 0:
        raise FieldError('max_record_bytes must be a positive integer')
    return value

BOOT = load_json('bootstrap_sizes.json')
BOOT_TYPES = {r['tag']: r for r in BOOT['entries']}
BOOT_DESCRIPTORS = {r['rd_number']: r for r in BOOT['descriptors']}
OPCODES = {r['opcode']: r for r in load_json('bytecode_opcodes.json')}

POINTER_POLICIES = ('strict', 'captured_unresolved_partial')

def validate_pointer_policy(value: str) -> str:
    """Validate the explicit pointer discovery policy before any source access."""
    if type(value) is not str or value not in POINTER_POLICIES:
        raise FieldError('pointer_policy must be strict or captured_unresolved_partial')
    return value

class FieldError(ValueError):
    pass

def _plain(value):
    """Return detached JSON containers, including immutable lazy store documents."""
    kind = type(value)
    if value is None or kind in (str, int, float, bool, bytes):
        return value
    if kind is dict:
        return {key: _plain(item) for key, item in value.items()}
    if kind is list or kind is tuple:
        return [_plain(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, Sequence) and (not isinstance(value, (str, bytes))):
        return [_plain(item) for item in value]
    return value

def _snapshot(value, depth=0):
    kind = type(value)
    if kind not in (dict, list, tuple, str, int, bool, float, type(None)):
        from fsd_decoder.portable.format import is_immutable_document
        if is_immutable_document(value):
            return value
    if depth > 256:
        raise FieldError('Compiled document exceeds nesting resource limit')
    if value is None or kind in (str, int, bool):
        return value
    if kind is float:
        if math.isfinite(value):
            return value
        raise FieldError('Compiled document contains a non-JSON value')
    if kind is dict:
        return MappingProxyType({key: _snapshot(item, depth + 1) for key, item in value.items()})
    if kind is list or kind is tuple:
        return tuple((_snapshot(item, depth + 1) for item in value))
    if isinstance(value, Mapping):
        return MappingProxyType({key: _snapshot(item, depth + 1) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple((_snapshot(item, depth + 1) for item in value))
    raise FieldError('Compiled document contains a non-JSON value')

def _unavailable_class_candidates(address_space, *, historical):
    return dict(status='HISTORICAL_EVIDENCE_UNAVAILABLE' if historical else 'CANDIDATE_EVIDENCE_UNAVAILABLE',
        scope='STRUCTURALLY_ACCEPTED_CLASS_DESCRIPTORS',
        descriptor_address_space=address_space, complete=False, candidate_limit=None,
        observed_count=None, retained_count=0, truncated_count=None, accepted_count=None,
        ambiguous_candidate_count=None, ambiguous_name_count=None, candidates={})


class _HistoricalClassCandidateReport(Mapping):
    """Add unavailable historical evidence without expanding an indexed report."""

    def __init__(self, report):
        self._report = report
        self._unavailable = _snapshot(_unavailable_class_candidates(
            report.get('descriptor_address_space'), historical=True))

    def __getitem__(self, key):
        if key == 'class_candidate_evidence':
            return self._unavailable
        return self._report[key]

    def __iter__(self):
        yield from self._report
        yield 'class_candidate_evidence'

    def __len__(self):
        return len(self._report) + 1

class _CheckedLayouts(Mapping):
    """Validate each layout when fetched, so indexed class maps stay bounded."""

    def __init__(self, layouts):
        self._layouts = layouts

    def __len__(self):
        return len(self._layouts)

    def __iter__(self):
        return iter(self._layouts)

    def __getitem__(self, name):
        layout = self._layouts[name]
        if not isinstance(name, str) or not isinstance(layout, Mapping) or layout.get('name') != name:
            raise FieldError('Compiled class layout name disagrees')
        if layout.get('size') is not None and (type(layout['size']) is not int or layout['size'] < 0):
            raise FieldError('Invalid compiled class size')
        if type(layout.get('descriptor_offset')) is not int or layout['descriptor_offset'] < 0:
            raise FieldError('Invalid compiled class descriptor address')
        for key in ('members', 'bases', 'unresolved'):
            if not isinstance(layout.get(key), Sequence) or isinstance(layout[key], (str, bytes)):
                raise FieldError('Compiled class layout lacks ' + key)
        return _plain(layout)

class _CheckedRepresentations(Mapping):

    def __init__(self, records, *, native):
        self._records = records
        self._native = native
        self._keys = {}
        for key in records:
            if type(key) is int:
                number = key
            elif isinstance(key, str) and key.isdecimal() and (str(int(key)) == key):
                number = int(key)
            else:
                raise FieldError('Compiled representation key must be a canonical integer')
            if number < 0 or number in self._keys:
                raise FieldError('Compiled representation keys collide or are negative')
            self._keys[number] = key

    def __len__(self):
        return len(self._keys)

    def __iter__(self):
        return iter(self._keys)

    def __getitem__(self, number):
        record = self._records[self._keys[number]]
        if not isinstance(record, Mapping) or not isinstance(record.get('name'), str):
            raise FieldError('Compiled representation needs a type name')
        if type(record.get('size')) is not int or record['size'] < 0:
            raise FieldError('Invalid compiled representation size')
        if self._native and 'native_tag' in record and (record['native_tag'] != number):
            raise FieldError('Compiled native representation tag disagrees')
        if self._native and 'tag' in record and (record['tag'] != number):
            raise FieldError('Compiled primitive representation tag disagrees')
        if not self._native and 'rd_number' in record and (record['rd_number'] != number):
            raise FieldError('Compiled representation descriptor number disagrees')
        return _plain(record)

@dataclass(frozen=True)
class _CompiledSchema:
    classes: Mapping
    schema_extents: Sequence
    _report: Mapping

    def layout(self, name: str) -> LayoutRecord:
        return self.classes[name]

    def report(self) -> dict[str, Any]:
        return _plain(self._report)

def _expansion_limits(leaves, work):
    try:
        return ExpansionLimits(leaves, work)
    except ExpansionMetadataError as exc:
        raise FieldError(str(exc)) from exc

class NativeFields:
    _expansion_opcode_names = OPCODES

    def __init__(self, database: LogicalDatabase, *, allow_partial_representations=False, max_record_bytes: int=DEFAULT_MAX_RECORD_BYTES, max_decoded_leaves: int=DEFAULT_MAX_DECODED_LEAVES, max_expansion_work: int=DEFAULT_MAX_EXPANSION_WORK):
        self.expansion_limits = _expansion_limits(max_decoded_leaves, max_expansion_work)
        self.max_record_bytes = _record_byte_limit(max_record_bytes)
        self.database = database
        extents = [e for e in database.directory['effective_extents'] if e['segment'] == 0 and e['cluster'] == 0]
        self.schema = MemberSchema(database.data, schema_extents=extents)
        self.decoder = MemberDecoder(database.data, self.schema, max_decoded_leaves=max_decoded_leaves, max_expansion_work=max_expansion_work)
        bindings = extended_dictionary(self.schema.data, database=database)
        dynamic = compile_dynamic_bindings(bindings)
        self.representation_errors = [dict(name=e['binding']['name'], dictionary_id=e['binding']['dictionary_id'], native_tag=e['binding']['native_tag'], error=e['error'], binding=e['binding']) for e in dynamic['errors']]
        if self.representation_errors and (not allow_partial_representations):
            raise FieldError('Cannot compile native application representation: ' + json.dumps(self.representation_errors, sort_keys=True))
        active_tags = [b['native_tag'] for b in bindings if b['native_tag'] and b['binding_active']]
        if len(set(active_tags)) != len(active_tags) or any((tag in BOOT_TYPES for tag in active_tags)):
            raise FieldError('Application native tags duplicate or collide with bootstrap types')
        self.types = {**BOOT_TYPES, **{r['native_tag']: r for r in dynamic['entries'] if r['native_tag'] and r['binding']['binding_active']}}
        self.descriptors = {**BOOT_DESCRIPTORS, **{r['rd_number']: r for r in dynamic['entries']}}
        self.dictionary_bindings = bindings
        self._schema_report = None
        self._problem_cache = {}
        self._admission_cache = OrderedDict()
        from fsd_decoder.native.native_allocations import NativeAllocationReader
        schema_allocations = [a for a in NativeAllocationReader(database, self.types).iter_allocations(segments=[0]) if a['cluster'] == 0]
        self._verified_nonvariable = {a['logical_offset'] for a in schema_allocations if a['name'] == '_Member_type'}
        self.schema.verified_field_members = {a['logical_offset'] for a in schema_allocations if a['name'] == '_Field_member_variable' and a['size'] == 104}
        self.schema.register_native_descriptors(schema_allocations, self._schema_pointer_target)

    @classmethod
    def from_compiled(cls, database: LogicalDatabase, schema: SchemaLayouts, representations: Mapping, bindings: Sequence, report: Mapping, *, descriptors: Mapping, verified_nonvariable: Iterable[int]=(), max_depth: int=64, max_array_elements: int=1000000, max_record_bytes: int=DEFAULT_MAX_RECORD_BYTES, max_decoded_leaves: int=DEFAULT_MAX_DECODED_LEAVES, max_expansion_work: int=DEFAULT_MAX_EXPANSION_WORK):
        """Construct an interpreter without invoking any native source parser.

        Plain documents are detached into immutable snapshots. Indexed immutable
        store documents remain lazy; layouts and representations are validated
        on access. Report identity and decoder resource limits are checked here.
        All ordinary decode byte/coverage/reference checks remain active.
        """
        limits = _expansion_limits(max_decoded_leaves, max_expansion_work)
        max_record_bytes = _record_byte_limit(max_record_bytes)
        if type(max_depth) is not int or max_depth <= 0 or type(max_array_elements) is not int or (max_array_elements <= 0):
            raise FieldError('Compiled decoder limits must be positive integers')
        if not isinstance(getattr(database, 'database_id', None), str) or not database.database_id:
            raise FieldError('Compiled decoder requires database identity')
        sha = getattr(database, 'sha256', None)
        if not isinstance(sha, str) or len(sha) != 64 or any((c not in '0123456789abcdef' for c in sha)):
            raise FieldError('Compiled decoder requires source SHA256')
        if any((not callable(getattr(database, method, None)) for method in ('address', 'read', 'resolve'))):
            raise FieldError('Compiled decoder requires logical database access')
        address = database.address(0, 0, 0)
        if getattr(address, 'database', None) != database.database_id:
            raise FieldError('Compiled decoder logical address identity disagrees')
        if not isinstance(report, Mapping) or report.get('source_sha256') != sha or report.get('database_id') != database.database_id:
            raise FieldError('Compiled schema report belongs to another source or lacks identity')
        if not isinstance(getattr(schema, 'classes', None), Mapping) or not isinstance(getattr(schema, 'schema_extents', None), Sequence) or isinstance(schema.schema_extents, (str, bytes)):
            raise FieldError('Compiled schema requires class layouts and schema extents')
        if not isinstance(representations, Mapping) or not isinstance(descriptors, Mapping):
            raise FieldError('Compiled representations must be mappings')
        if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
            raise FieldError('Compiled dictionary bindings must be a sequence')
        if not isinstance(report.get('layout_problems', {}), Mapping):
            raise FieldError('Compiled layout problems must be a mapping')
        errors = report.get('representation_errors', ())
        if not isinstance(errors, Sequence) or isinstance(errors, (str, bytes)):
            raise FieldError('Compiled representation errors must be a sequence')
        verified_offsets = tuple(verified_nonvariable)
        if any((type(offset) is not int or offset < 0 for offset in verified_offsets)):
            raise FieldError('Compiled member descriptor offsets must be nonnegative integers')
        verified = frozenset(verified_offsets)
        active_tags = []
        for binding in bindings:
            if not isinstance(binding, Mapping):
                raise FieldError('Compiled dictionary binding must be a mapping')
            if binding.get('binding_active') and binding.get('native_tag'):
                tag = binding['native_tag']
                if type(tag) is not int or tag < 0:
                    raise FieldError('Compiled dictionary native tag must be a nonnegative integer')
                active_tags.append(tag)
        if len(set(active_tags)) != len(active_tags) or any((tag in BOOT_TYPES for tag in active_tags)):
            raise FieldError('Application native tags duplicate or collide with bootstrap types')
        frozen_report = _snapshot(report)
        if 'class_candidate_evidence' not in frozen_report:
            frozen_report = _HistoricalClassCandidateReport(frozen_report)
        instance = object.__new__(cls)
        instance.expansion_limits = limits
        instance.max_record_bytes = max_record_bytes
        instance.database = database
        instance.schema = _CompiledSchema(_CheckedLayouts(_snapshot(schema.classes)), _snapshot(schema.schema_extents), frozen_report)
        instance.decoder = MemberDecoder(b'', instance.schema, max_depth=max_depth, max_array_elements=max_array_elements, max_decoded_leaves=max_decoded_leaves, max_expansion_work=max_expansion_work)
        instance.types = _CheckedRepresentations(_snapshot(representations), native=True)
        instance.descriptors = _CheckedRepresentations(_snapshot(descriptors), native=False)
        instance.dictionary_bindings = _snapshot(bindings)
        instance.representation_errors = frozen_report.get('representation_errors', ())
        instance._verified_nonvariable = verified
        instance._problem_cache = {}
        instance._admission_cache = OrderedDict()
        instance._schema_report = frozen_report
        instance._compiled = True
        from fsd_decoder.portable.format import is_immutable_document
        for original, checked in ((schema.classes, instance.schema.classes), (representations, instance.types), (descriptors, instance.descriptors)):
            if not is_immutable_document(original):
                for key in checked:
                    checked[key]
        return instance

    def schema_admission(self, allocation_or_native_tag):
        """Pure metadata admission of an exact tag or current allocation view.

        Storage corroboration permits a source-declared structural view. It
        does not witness native-tag to source-class identity or pointee roles.
        """
        from fsd_decoder.schema.schema_admission import schema_admission
        allocation = allocation_or_native_tag if isinstance(allocation_or_native_tag, Mapping) else None
        tag = allocation.get('native_tag') if allocation is not None else allocation_or_native_tag
        if type(tag) is not int or tag < 0:
            raise FieldError('Schema admission requires an exact nonnegative native tag')
        if tag not in self._admission_cache:
            self._admission_cache[tag] = schema_admission(self.schema, self.types, self.descriptors, tag,
                verified_nonvariable=self._verified_nonvariable)
            if len(self._admission_cache) > 4096:
                self._admission_cache.popitem(last=False)
        result = _plain(self._admission_cache[tag])
        if allocation is not None and result['admitted']:
            typ = self.types[tag]
            name = allocation.get('name', typ['name']).removesuffix('[]')
            size = allocation.get('element_size', typ['size'])
            stride = allocation.get('element_stride', size)
            if (name != result['schema_name'] or type(size) is not int or size != typ['size'] or
                    type(stride) is not int or stride < size):
                result.update(admitted=False, status='SOURCE_COMPACT_STORAGE_MISMATCH',
                              reasons=['ALLOCATION_NAME_SIZE_OR_STRIDE_DISAGREES'])
        return result

    def _schema_pointer_target(self, slot):
        try:
            address = self.database.address(0, 0, slot)
            raw = self.schema.span(slot, 8)
            if self.database.read(address, 8) != raw:
                raise SchemaError('Schema pointer bytes differ from current snapshot')
            target = self.database.resolve(address, width=8, raw=raw)
            if target is None:
                return None
            if (target.segment, target.cluster) != (0, 0):
                raise SchemaError('Native type reference outside schema address space')
            return target.offset
        except Exception as exc:
            require_source_failure(exc, dict(phase='schema_pointer', descriptor_offset=slot))
            raise SchemaError(str(exc)) from exc

    def schema_report_document(self) -> Mapping[str, Any]:
        """Return a read-only report view, retaining indexed documents lazily.

        ``schema_report()`` continues to return detached plain containers for
        compiled stores. Output adapters can stream this view while the store
        remains open, without expanding the complete report into memory.
        """
        if getattr(self, '_compiled', False):
            return self._schema_report
        return _snapshot(self.schema_report())

    def schema_report(self) -> dict[str, Any]:
        if getattr(self, '_compiled', False):
            return _plain(self._schema_report)
        if self._schema_report is None:
            report = self.schema.report()

            def annotate(layout):
                declarations = []
                problems = []
                for issue in layout['unresolved']:
                    if issue['kind'] == 'non_variable_member' and issue['descriptor_offset'] in self._verified_nonvariable:
                        declaration = dict(issue, kind='nested_type_declaration', native_type='_Member_type')
                        try:
                            slot = issue['descriptor_offset'] + 40
                            target = self._schema_pointer_target(slot)
                            declaration.update(declared_type=self.schema.type(target), declared_type_pointer_raw_hex=self.schema.span(slot, 8).hex(), declared_type_reference_address=asdict(self.database.address(0, 0, slot)), declared_type_evidence='CURRENT_MEMBER_TYPE_ALLOCATION_AND_PRM')
                        except Exception as exc:
                            require_source_failure(exc, dict(phase='schema_declaration', descriptor_offset=issue['descriptor_offset'], name=layout.get('name')))
                            declaration.update(declared_type_status='UNRESOLVED_DECLARATION', diagnostic=str(exc))
                            detail = failure_record(exc, status='UNRESOLVED_DECLARATION', context=dict(phase='schema_declaration', descriptor_offset=issue['descriptor_offset']))
                            declaration.update({k: detail[k] for k in ('error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})
                        declarations.append(declaration)
                    elif issue['kind'] == 'non_instance_storage' and issue.get('storage_class') in (1, 2):
                        declarations.append(issue)
                    else:
                        problems.append(issue)
                layout['unresolved'] = problems
                layout['declarations'] = declarations
                for base in layout['bases']:
                    annotate(base['layout'])
            for layout in report['classes'].values():
                annotate(layout)
            report['source_sha256'] = self.database.sha256
            report['database_id'] = self.database.database_id
            report['layout_problems'] = {name: self._layout_problems(name) for name in self.schema.classes if self._layout_problems(name)}
            report['representation_errors'] = self.representation_errors
            report['representation_complete'] = not self.representation_errors
            report['schema_layouts_complete'] = not report['layout_problems']
            report['schema_complete'] = report['schema_layouts_complete'] and report['representation_complete']
            candidates = getattr(self.schema, 'class_candidate_evidence', None)
            report['class_candidate_evidence'] = _plain(candidates) if candidates is not None else _unavailable_class_candidates(report.get('descriptor_address_space'), historical=False)
            report['native_type_bindings'] = [dict(native_tag=k, name=v['name'], size=v['size'], needs_discriminants=v.get('needs_discriminants', False)) for k, v in sorted(self.types.items())]
            report['native_tags'] = {k: dict(name=v['name'], size=v['size']) for k, v in sorted(self.types.items())}
            report['native_dictionary_bindings'] = self.dictionary_bindings
            report['native_dictionary_evidence'] = 'CURRENT_NATIVE_ALLOCATIONS_AND_PRM'
            self._schema_report = report
        return self._schema_report

    def _layout_problems(self, name, seen=None):
        if getattr(self, '_compiled', False):
            return _plain(self._schema_report.get('layout_problems', {}).get(name, []))
        if name in self._problem_cache:
            return self._problem_cache[name]
        seen = set() if seen is None else seen
        if name in seen:
            return []
        seen = seen | {name}
        layout = self.decoder.layout(name)
        problems = []
        for issue in layout['unresolved']:
            if issue['kind'] == 'non_instance_storage' and issue.get('storage_class') in (1, 2):
                continue
            if issue['kind'] == 'non_variable_member' and issue.get('descriptor_offset') in self._verified_nonvariable:
                continue
            problems.append(dict(class_name=name, **issue))
        for base in layout['bases']:
            problems.extend(self._layout_problems(base['type']['name'], seen))

        def check(typ, path):
            kind = typ['kind']
            if kind in ('class', 'union'):
                problems.extend(self._layout_problems(typ['name'], seen))
            elif kind in ('alias', 'qualified'):
                if typ.get('unknown_qualifier_flags'):
                    problems.append(dict(class_name=name, member=path, kind='unknown_qualifiers', type=typ))
                check(typ['underlying'], path)
            elif kind == 'array':
                check(typ['element'], path)
            elif kind in ('unknown', 'recursive', 'void', 'incomplete_class'):
                problems.append(dict(class_name=name, member=path, kind='unresolved_type', type=typ))
        for member in layout['members']:
            check(member['type'], member['name'])
        self._problem_cache[name] = problems
        return problems

    def _captured_unresolved(self, address, raw, pointer_policy, relative=None):
        if pointer_policy == 'strict':
            return None
        reader = getattr(self.database, 'captured_unresolved_reference', None)
        if not callable(reader):
            raise FieldError('Partial pointer discovery requires checked captured binding access')
        evidence = reader(address, width=len(raw), raw=raw)
        if evidence is None:
            return None
        if (not isinstance(evidence, Mapping) or evidence.get('status') != 'UNRESOLVED'
                or evidence.get('width') != len(raw) or evidence.get('raw_hex') != raw.hex()
                or evidence.get('source_address') != asdict(address)
                or evidence.get('source_sha256') != self.database.sha256):
            raise FieldError('Captured unresolved reference identity/slot/bytes disagree')
        from fsd_decoder.core.contracts import CapturedUnresolvedReference
        return CapturedUnresolvedReference(address, raw, self.database.sha256,
            _snapshot(evidence['resolution_metadata']), relative)

    def _resolve(self, address, width, word, pointer_policy='strict', relative=None):
        captured = self._captured_unresolved(address, word.to_bytes(width, 'little'), pointer_policy, relative)
        if captured is not None:
            return captured
        target = self.database.resolve(address, width=width, raw=word.to_bytes(width, 'little'))
        return None if target is None else dict(status='CURRENT_NATIVE_PRM', address=asdict(target))

    def _pointer(self, address, raw, pointer_policy='strict'):
        captured = self._captured_unresolved(address, raw, pointer_policy)
        if captured is not None:
            return dict(kind='stored_reference', stored_word=int.from_bytes(raw, 'little'),
                target=None, target_status='UNRESOLVED', captured_reference=dict(
                    binding_status='UNRESOLVED', width=len(raw), raw_hex=raw.hex(),
                    source_address=asdict(address), source_sha256=captured.source_sha256,
                    resolution_metadata=_plain(captured.resolution_metadata)))
        target = self.database.resolve(address, width=len(raw), raw=raw)
        return dict(kind='stored_reference', stored_word=int.from_bytes(raw, 'little'), target=None if target is None else asdict(target), target_status='NULL' if target is None else 'CURRENT_NATIVE_PRM')

    @staticmethod
    def _float(raw):
        if len(raw) not in (4, 8):
            raise FieldError('Unsupported IEEE float width')
        value = struct.unpack('<f' if len(raw) == 4 else '<d', raw)[0]
        if math.isfinite(value):
            decimal = repr(value)
            if struct.pack('<f' if len(raw) == 4 else '<d', float(decimal)) != raw:
                raise FieldError('Floating decimal roundtrip failed')
            return dict(value=value, decimal=decimal, encoding='IEEE754_LITTLE_ENDIAN')
        return dict(value=repr(value), encoding='IEEE754_LITTLE_ENDIAN', exact_nan_payload_in_raw_hex=True)

    def _primitive(self, typ, raw, address, pointer_policy='strict'):
        name = typ['name']
        tag = typ['tag']
        if tag in (8, 14):
            return self._pointer(address, raw, pointer_policy)
        if name in ('float', 'double') or 'ieees float' in name or 'ieeed double' in name or ('ieeed long double' in name):
            return dict(kind='floating', **self._float(raw))
        if 'float' in name or 'double' in name:
            return dict(kind='floating_storage', status='UNSUPPORTED_FLOAT_ENCODING', format_name=name)
        if name == '_OS_align_1':
            return dict(kind='alignment_byte', value=raw[0])
        signed = 'unsigned' not in name and 'char' not in name
        value = int.from_bytes(raw, 'little', signed=signed)
        r = dict(kind='integer', value=value, signed=signed, encoding='LITTLE_ENDIAN')
        if 'char' in name:
            r.update(kind='character', codepoint=value)
        return r

    def _compact_array_limit(self, trace, limit, path='', depth=0):
        from fsd_decoder.schema.expansion_admission import compact_cost
        try:
            cost = compact_cost(trace, limit, self.descriptors, limits=self.expansion_limits,
                max_depth=self.decoder.max_depth - depth,
                max_array_elements=self.decoder.max_array_elements, opcode_names=OPCODES)
        except ExpansionMetadataError as exc:
            raise FieldError(str(exc)) from exc
        admit_cost(cost, self.expansion_limits)
        return cost.rejected_array

    def _check_compact_depth(self, depth):
        if depth > self.decoder.max_depth:
            raise FieldError('Recursive compact representation exceeds configured max_depth')

    def _compact_fields(self, trace, raw, address, relative=0, path='', depth=0, limit=None, pointer_policy='strict'):
        self._check_compact_depth(depth)
        limit = len(raw) if limit is None else limit
        cursor = 0
        fields = []
        for i, step in enumerate(trace):
            size = step['size']
            op = int(step['opcode'], 16)
            if cursor + size > limit:
                raise FieldError('Compact field exceeds class base extent')
            at = relative + cursor
            span = raw[cursor:cursor + size]
            label = f'{path}/{i}:{OPCODES.get(op, {}).get('name', step['opcode'])}'
            target_address = self.database.address(address.segment, address.cluster, address.offset + cursor)
            if size == 0:
                continue
            if 'reference_rd' in step and op != 46:
                self._check_compact_depth(depth + 1)
                child = self.descriptors.get(step['reference_rd'])
                if child is None:
                    raise FieldError('Missing referenced native representation')
                fields.extend(self._compact_fields(child['trace'], span, target_address, at, label, depth + 1, size, pointer_policy))
            elif 'array_count' in step:
                if step['array_count']:
                    self._check_compact_depth(depth + 1)
                stride = step['array_stride']
                element = step['element_layout']
                for n in range(step['array_count']):
                    start = n * stride
                    childaddr = self.database.address(address.segment, address.cluster, target_address.offset + start)
                    fields.extend(self._compact_fields(element['trace'], span[start:start + stride], childaddr, at + start, label + f'[{n}]', depth + 1, element['size'], pointer_policy))
            else:
                f = dict(path=label, record_relative_offset=at, source_address=asdict(target_address), size=size, raw_hex=span.hex(), opcode=step['opcode'])
                if op in (23, 24, 53, 54):
                    f.update(self._pointer(target_address, span, pointer_policy))
                elif op in (1, 2, 3, 4, 5):
                    f.update(kind='ordinal_storage', unsigned_value=int.from_bytes(span, 'little'), signed_value=int.from_bytes(span, 'little', signed=True))
                elif op in (17, 18):
                    f.update(kind='floating', **self._float(span))
                elif op in (41, 42, 55, 56, 57, 58, 59):
                    f.update(kind='runtime_code_word', value=int.from_bytes(span, 'little'))
                elif op == 26:
                    f.update(kind='bitfield_storage', mask_hex=step.get('bitfield_mask'), unsigned_value=int.from_bytes(span, 'little'))
                elif op == 46 or op == 35:
                    f.update(kind='union_storage', active_member=None)
                else:
                    f.update(kind='layout_bytes')
                fields.append(f)
            cursor += size
            if cursor == limit:
                break
        if cursor < limit:
            fields.append(dict(path=path + '/trailing_layout_bytes', record_relative_offset=relative + cursor, source_address=asdict(self.database.address(address.segment, address.cluster, address.offset + cursor)), size=limit - cursor, raw_hex=raw[cursor:limit].hex(), kind='layout_bytes'))
        return fields

    def _admit_record_bytes(self, allocation, element_index, address, size, maximum):
        if type(size) is not int or size < 0:
            raise FieldError('Logical record size must be a nonnegative integer')
        if size > maximum:
            exc = ResourceLimitError(
                f'Logical record bytes {size} exceed max_record_bytes {maximum}; '
                'raw allocation retained; semantic interpretation UNKNOWN')
            exc.context = dict(phase='decode-limit', address=asdict(address),
                name=allocation.get('name'), native_tag=allocation.get('native_tag'),
                element_index=element_index)
            exc.raw_selector = dict(address=asdict(address), size=size)
            exc.record_bytes = size
            exc.max_record_bytes = maximum
            exc.status = 'RESOURCE_BOUND'
            raise exc

    def decode(self, allocation: AllocationRecord, element_index: int=0, *, max_record_bytes: int | None=None, max_decoded_leaves: int | None=None, max_expansion_work: int | None=None, pointer_policy: str='strict') -> ValueRecord:
        """Interpret one admitted logical record, preserving all retained padding.

        The byte policy bounds the actual requested record, not process RSS.
        A per-call override never changes the constructor policy or its caches.
        Resource refusal preserves an address/size selector without fetching it.
        """
        pointer_policy = validate_pointer_policy(pointer_policy)
        limits = _expansion_limits(
            self.expansion_limits.max_decoded_leaves if max_decoded_leaves is None else max_decoded_leaves,
            self.expansion_limits.max_expansion_work if max_expansion_work is None else max_expansion_work)
        maximum = _record_byte_limit(self.max_record_bytes if max_record_bytes is None else max_record_bytes)
        if type(element_index) is not int or element_index < 0:
            raise FieldError('Invalid element index')
        count = allocation.get('count', 1)
        if element_index >= count:
            raise FieldError('Element index outside allocation')
        if allocation.get('name') == 'inline_char_bytes':
            if element_index:
                raise FieldError('Inline character storage is one scalar record')
            address = self.database.address(allocation['segment'], allocation['cluster'], allocation['logical_offset'])
            self._admit_record_bytes(allocation, element_index, address, allocation['size'], maximum)
            cost = allocation_cost(self, allocation, limits=limits)
            admit_cost(cost, limits, context=dict(address=asdict(address),
                name='inline_char_bytes', native_tag=allocation['native_tag'], element_index=0),
                raw_selector=dict(address=asdict(address), size=allocation['size']))
            raw = self.database.read(address, allocation['size'])
            length = allocation['count']
            if not 0 <= length <= len(raw):
                raise FieldError('Inline character length exceeds allocation')
            return dict(native_tag=allocation['native_tag'], type_name='inline_char_bytes', element_index=0, source_address=asdict(address), size=len(raw), raw_hex=raw.hex(), status='TYPED_INLINE_CHARACTER_BYTES', kind='character_bytes', value=raw[:length].decode('latin1'), encoding='LATIN1_BYTE_VIEW', value_raw_hex=raw[:length].hex(), padding_raw_hex=raw[length:].hex(), character_count=length)
        tag = allocation['native_tag']
        typ = self.types.get(tag)
        if typ is None:
            raise FieldError(f'Unknown native element type {tag:#x}')
        size = allocation.get('element_size', typ['size'])
        stride = allocation.get('element_stride', size)
        header = allocation.get('array_header_size', 0)
        if type(size) is not int or size <= 0 or size != typ['size'] or (stride < size):
            raise FieldError('Native element size/stride disagrees')
        start = allocation['logical_offset'] + header + element_index * stride
        if header + element_index * stride + size > allocation['size']:
            raise FieldError('Native element exceeds allocation')
        address = self.database.address(allocation['segment'], allocation['cluster'], start)
        read_size = size if allocation.get('vector', False) else allocation['size']
        self._admit_record_bytes(allocation, element_index, address, read_size, maximum)
        admission = self.schema_admission(allocation)
        try:
            cost = allocation_cost(self, allocation, limits=limits, typ=typ, admission=admission)
        except ExpansionMetadataError as exc:
            raise FieldError(str(exc)) from exc
        admit_cost(cost, limits, context=dict(address=asdict(address), name=typ['name'],
            native_tag=tag, element_index=element_index),
            raw_selector=dict(address=asdict(address), size=read_size))
        raw_record = self.database.read(address, read_size)
        raw = raw_record[:size]
        common = dict(native_tag=tag, type_name=typ['name'], element_index=element_index, source_address=asdict(address), size=read_size, element_size=size, raw_hex=raw_record.hex())
        if read_size != size:
            common.update(value_raw_hex=raw.hex(), padding_raw_hex=raw_record[size:].hex())
        if admission['schema_name'] is not None:
            common['schema_admission'] = admission
        if admission['admitted']:

            def resolver(relative, width, word):
                return self._resolve(self.database.address(address.segment, address.cluster, address.offset + relative), width, word, pointer_policy, relative)
            result = self.decoder.decode_bytes(typ['name'], raw, asdict(address), resolver, discriminants=allocation.get('discriminant_words', []), max_decoded_leaves=limits.max_decoded_leaves, max_expansion_work=limits.max_expansion_work)
            result.pop('allocation_identity', None)
            result.pop('liveness', None)
            result['schema_declarations'] = [u for u in result.pop('schema_unresolved', []) if u['kind'] in ('non_instance_storage', 'non_variable_member')]
            problems = self._layout_problems(typ['name'])
            bad_fields = [dict(path=field['path'], status=field['status']) for field in self.decoder.source_items(result['fields']) if field.get('status') in ('UNKNOWN_SIZE', 'ARRAY_LIMIT', 'UNSUPPORTED_FLOAT_FORMAT', 'UNSUPPORTED_TYPE')]
            if problems or bad_fields:
                result['status'] = 'UNSUPPORTED_SCHEMA_LAYOUT'
                result['unsupported_reasons'] = problems + bad_fields
            elif result.get('discriminant_status') == 'PRESERVED_UNAPPLIED':
                result['status'] = 'UNSUPPORTED_UNION_DISCRIMINANTS'
            return dict(common, **{k: v for k, v in result.items() if k not in ('source_address', 'size')})
        if tag <= 42:
            result = self._primitive(typ, raw, address, pointer_policy)
            return dict(common, status=result.pop('status', 'TYPED_NATIVE_PRIMITIVE'), **result)
        if 'trace' not in typ:
            return dict(common, status='SOURCE_COMPACT_STORAGE_UNESTABLISHED', fields=[],
                        uninterpreted_regions=[dict(record_relative_offset=0, size=size,
                            raw_hex=raw.hex(), kind='unestablished_native_layout')])
        rejected = cost.rejected_array
        if rejected is not None:
            retained = dict(path='/compact_array_limit_raw', record_relative_offset=0,
                            source_address=asdict(address), size=size, raw_hex=raw.hex(),
                            kind='layout_bytes', status='ARRAY_LIMIT')
            return dict(common, status='UNSUPPORTED_SCHEMA_LAYOUT', fields=[retained],
                        unsupported_reasons=[rejected],
                        member_names_status='COMPACT_LAYOUT_HAS_NO_MEMBER_NAMES')
        fields = self._compact_fields(typ['trace'], raw, address, pointer_policy=pointer_policy)
        covered = bytearray(size)
        for f in fields:
            at = f['record_relative_offset']
            n = f['size']
            if at < 0 or at + n > size or any(covered[at:at + n]):
                raise FieldError('Compact fields overlap or exceed record')
            covered[at:at + n] = b'\x01' * n
            if f['raw_hex'] != raw[at:at + n].hex():
                raise FieldError('Compact field raw bytes disagree')
        if not all(covered):
            raise FieldError('Compact fields leave unreported source bytes')
        return dict(common, status='TYPED_NATIVE_COMPACT_RECORD', fields=fields, member_names_status='COMPACT_LAYOUT_HAS_NO_MEMBER_NAMES')
