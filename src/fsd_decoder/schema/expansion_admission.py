"""Symbolic admission for one decoded record, independent of payload bytes.

Work charges traversal and variable-width representations, never process RSS.
Unknown source shape is not interpreted as a finite successful cost.
"""
from __future__ import annotations
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

DEFAULT_MAX_DECODED_LEAVES = 100000
DEFAULT_MAX_EXPANSION_WORK = 1000000


class ExpansionMetadataError(ValueError):
    """Source metadata cannot establish the requested finite interpretation."""


@dataclass(frozen=True)
class ExpansionLimits:
    max_decoded_leaves: int = DEFAULT_MAX_DECODED_LEAVES
    max_expansion_work: int = DEFAULT_MAX_EXPANSION_WORK

    def __post_init__(self):
        for name in ('max_decoded_leaves', 'max_expansion_work'):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ExpansionMetadataError(name + ' must be a positive integer')


@dataclass(frozen=True)
class ExpansionCost:
    leaves: int | None
    work: int
    established: bool = True
    rejected_array: Mapping | None = None
    analysis_work: int = 0

    def exceeded(self, limits: ExpansionLimits) -> bool:
        return (not self.established or self.leaves is None or
                self.leaves > limits.max_decoded_leaves or
                self.work > limits.max_expansion_work)


class _AnalysisBound(Exception):
    pass


class _Estimator:
    def __init__(self, limits, layout, descriptors, max_depth, max_array_elements):
        self.limits = limits
        self.layout = layout
        self.descriptors = descriptors
        self.max_depth = max_depth
        self.max_array_elements = max_array_elements
        self.nodes = 0
        self.opcode_names = {}

    @staticmethod
    def _add(a, b, cap):
        return cap + 1 if a > cap or b > cap - a else a + b

    @staticmethod
    def _mul(a, b, cap):
        if a == 0 or b == 0:
            return 0
        return cap + 1 if a > cap // b else a * b

    def add(self, a, b):
        if not a.established or not b.established or a.leaves is None or b.leaves is None:
            return ExpansionCost(None, self.limits.max_expansion_work + 1, established=False)
        if a.rejected_array is not None:
            return a
        if b.rejected_array is not None:
            return b
        return ExpansionCost(self._add(a.leaves, b.leaves, self.limits.max_decoded_leaves),
                             self._add(a.work, b.work, self.limits.max_expansion_work))

    def repeat(self, cost, count, path_creation=0):
        if not cost.established or cost.leaves is None:
            return cost
        work = self._add(1, cost.work, self.limits.max_expansion_work)
        work = self._add(work, cost.leaves, self.limits.max_expansion_work)
        work = self._add(work, path_creation, self.limits.max_expansion_work)
        return ExpansionCost(self._mul(count, cost.leaves, self.limits.max_decoded_leaves),
                             self._mul(count, work, self.limits.max_expansion_work))

    def copied(self, cost, overhead=1):
        if not cost.established or cost.leaves is None:
            return cost
        extra = self._add(overhead, cost.leaves, self.limits.max_expansion_work)
        return self.add(cost, ExpansionCost(0, extra))

    @staticmethod
    def text_length(value):
        if value is None:
            return 0
        if not isinstance(value, str):
            raise ExpansionMetadataError('Invalid source text metadata')
        return len(value)

    @staticmethod
    def digits_upper(value):
        # ceil(log10(2)) via an upper rational approximation; never stringify
        # an arbitrary integer or construct an index path during estimation.
        return max(1, (value.bit_length() * 30103) // 100000 + 1)

    def raw_work(self, size, overhead=1):
        if type(size) is not int or size < 0:
            raise ExpansionMetadataError('Invalid source type extent')
        return self._add(overhead, self._mul(2, size, self.limits.max_expansion_work),
                         self.limits.max_expansion_work)

    def unknown_work(self):
        return ExpansionCost(None, self.limits.max_expansion_work + 1, established=False)

    def node(self, depth):
        if depth > self.max_depth:
            raise ExpansionMetadataError('Excessive embedded representation nesting')
        self.nodes += 1
        if self.nodes > self.limits.max_expansion_work:
            raise _AnalysisBound

    @staticmethod
    def enter(key, active):
        if key in active:
            raise ExpansionMetadataError('Cyclic embedded representation; interpretation UNKNOWN')
        return active | {key}

    def typ(self, typ, depth=0, active=frozenset(), path_length=0):
        self.node(depth)
        name_width = self.text_length(typ.get('name'))
        if typ.get('size') is None:
            return ExpansionCost(1, self._add(1, path_length + name_width, self.limits.max_expansion_work))
        common_work = self.raw_work(typ['size'], 1 + name_width)
        kind = typ['kind']
        if kind == 'qualified' and typ.get('unknown_qualifier_flags'):
            return ExpansionCost(1, self._add(common_work, path_length, self.limits.max_expansion_work))
        if common_work > self.limits.max_expansion_work:
            return self.unknown_work()
        if kind in ('alias', 'qualified'):
            seen = self.enter(('wrapper', id(typ)), active)
            child = self.typ(typ['underlying'], depth + 1, seen, path_length)
            if not child.established or child.leaves is None:
                return child
            annotation = name_width if kind == 'alias' else self.text_length(typ.get('qualifier_raw_hex'))
            if kind == 'qualified':
                qualifiers = typ.get('qualifiers', {})
                for key, value in qualifiers.items():
                    self.node(depth)
                    annotation = self._add(annotation, self.text_length(key), self.limits.max_expansion_work)
                    if isinstance(value, str):
                        annotation = self._add(annotation, len(value), self.limits.max_expansion_work)
                    elif value is not None and type(value) not in (bool, int, float):
                        raise ExpansionMetadataError('Unknown qualifier metadata shape')
                    if annotation > self.limits.max_expansion_work:
                        return self.unknown_work()
            extra = self._mul(child.leaves, 1 + annotation, self.limits.max_expansion_work)
            return self.add(child, ExpansionCost(0, self._add(common_work, extra, self.limits.max_expansion_work)))
        if kind == 'array':
            count = typ['count']
            if type(count) is not int or count < 0:
                raise ExpansionMetadataError('Invalid schema array count')
            if count > self.max_array_elements:
                return ExpansionCost(1, self._add(common_work, path_length, self.limits.max_expansion_work))
            if not count:
                return ExpansionCost(0, common_work)
            seen = self.enter(('array', id(typ)), active)
            child_path = path_length + 2 + self.digits_upper(count - 1)
            if child_path > self.limits.max_expansion_work:
                return self.unknown_work()
            child = self.typ(typ['element'], depth + 1, seen, child_path)
            return self.add(ExpansionCost(0, common_work), self.repeat(child, count, child_path))
        if kind == 'class':
            name = typ['name']
            if name.startswith(('os_soft_pointer32<', 'os_hard_pointer32<',
                                'os_soft_pointer64<', 'os_hard_pointer64<')) and typ['size'] in (4, 8):
                return ExpansionCost(1, self._add(common_work, path_length, self.limits.max_expansion_work))
            seen = self.enter(('class', name), active)
            if depth + 1 > self.max_depth:
                raise ExpansionMetadataError('Excessive embedded representation nesting')
            return self.add(ExpansionCost(0, common_work),
                            self.fields(self.layout(name), depth + 1, seen, path_length))
        if kind == 'union':
            seen = self.enter(('union', typ['name']), active)
            layout = self.layout(typ['name'])
            total = ExpansionCost(1, self._add(common_work, path_length, self.limits.max_expansion_work))
            for member in layout['members']:
                self.node(depth)
                member_width = self.text_length(member['name'])
                child_path = path_length + 4 + member_width
                if child_path > self.limits.max_expansion_work:
                    return self.unknown_work()
                if 'bitfield' in member:
                    child = self.fields(dict(bases=(), members=(member,)), depth + 1, seen, child_path)
                else:
                    child = self.typ(member['type'], depth + 1, seen, child_path)
                total = self.add(total, self.add(ExpansionCost(0, 2 + member_width + child_path), child))
                if total.exceeded(self.limits):
                    break
            return total
        enum_work = 0
        if kind == 'enum':
            # Any declared aliases can match before the stored value is read.
            # Charge their scan and retained annotation text conservatively.
            for enumerator in typ.get('enumerators', ()):
                self.node(depth)
                enum_work = self._add(enum_work, 1 + self.text_length(enumerator['name']),
                                      self.limits.max_expansion_work)
                if enum_work > self.limits.max_expansion_work:
                    break
        return ExpansionCost(1, self._add(common_work, path_length + enum_work, self.limits.max_expansion_work))

    def fields(self, layout, depth=0, active=frozenset(), path_length=0):
        self.node(depth)
        key = ('layout', layout.get('name'), layout.get('descriptor_offset'))
        if key[1:] == (None, None):
            key = ('layout-literal', id(layout))
        seen = self.enter(key, active)
        total = ExpansionCost(0, 1)
        for base in layout['bases']:
            self.node(depth)
            child_path = path_length + 4 + self.text_length(base['type']['name'])
            if child_path > self.limits.max_expansion_work:
                return self.unknown_work()
            child = self.fields(base['layout'], depth + 1, seen, child_path)
            total = self.add(total, self.copied(child, 1 + child_path))
            if total.exceeded(self.limits):
                return total
        for member in layout['members']:
            self.node(depth)
            child_path = path_length + 1 + self.text_length(member['name'])
            if child_path > self.limits.max_expansion_work:
                return self.unknown_work()
            if 'bitfield' in member:
                raw_work = self.raw_work(member['bitfield']['storage_size'], 1 + child_path)
                raw_work = self._add(raw_work, self.text_length(member['type'].get('name')),
                                     self.limits.max_expansion_work)
                raw_work = self._add(raw_work, self.text_length(member['bitfield'].get('mask_hex')),
                                     self.limits.max_expansion_work)
                addition = ExpansionCost(1, self._add(raw_work, 1 + child_path, self.limits.max_expansion_work))
            else:
                addition = self.copied(self.typ(member['type'], depth + 1, seen, child_path),
                                       1 + child_path)
            total = self.add(total, addition)
            if total.exceeded(self.limits):
                return total
        return total

    def record(self, layout):
        root_path = self.text_length(layout['name'])
        if root_path > self.limits.max_expansion_work:
            return self.unknown_work()
        if layout.get('class_kind_bits') == 2:
            cost = self.typ(dict(kind='union', name=layout['name'], size=layout['size']),
                            path_length=root_path)
        else:
            cost = self.fields(layout, path_length=root_path)
        # Record raw hex + conservative raw/mask hex of uninterpreted regions.
        # This is a representation-work charge, never a hard byte/RSS ceiling.
        overhead = self._add(self._mul(6, layout['size'], self.limits.max_expansion_work),
                             root_path, self.limits.max_expansion_work)
        return self.add(cost, ExpansionCost(0, overhead))

    def compact(self, trace, limit, depth=0, active=frozenset(), path='', path_length=0):
        self.node(depth)
        if type(limit) is not int or limit < 0:
            raise ExpansionMetadataError('Invalid compact extent')
        total = ExpansionCost(0, 1)
        cursor = 0
        for index, step in enumerate(trace):
            self.node(depth)
            size = step['size']
            if type(size) is not int or size < 0 or cursor + size > limit:
                raise ExpansionMetadataError('Compact field exceeds class base extent')
            op = int(step['opcode'], 16)
            opcode_name = self.opcode_names.get(op, {}).get('name', step['opcode'])
            label_length = path_length + 2 + self.digits_upper(index) + len(opcode_name)
            # Only the compact diagnostic wildcard path is built; source member
            # names and concrete array index paths are accounted symbolically.
            label = path + '/' + str(index) + ':' + opcode_name
            if size == 0:
                total = self.add(total, ExpansionCost(0, 1 + label_length))
            elif 'reference_rd' in step and op != 46:
                if depth + 1 > self.max_depth:
                    raise ExpansionMetadataError('Recursive compact representation exceeds configured max_depth')
                rd = step['reference_rd']
                seen = self.enter(('rd', rd), active)
                child = self.descriptors.get(rd)
                if child is None:
                    raise ExpansionMetadataError('Missing referenced native representation')
                nested = self.compact(child['trace'], size, depth + 1, seen, label, label_length)
                total = self.add(total, self.copied(nested, 1 + label_length))
                cursor += size
            elif 'array_count' in step:
                count = step['array_count']
                if type(count) is not int or count < 0:
                    raise ExpansionMetadataError('Invalid compact array count')
                if count > self.max_array_elements:
                    return ExpansionCost(1, 1, rejected_array=dict(path=label,
                        status='ARRAY_LIMIT', element_count=count,
                        max_array_elements=self.max_array_elements, limit_scope='PER_ARRAY'))
                if count:
                    if depth + 1 > self.max_depth:
                        raise ExpansionMetadataError('Recursive compact representation exceeds configured max_depth')
                    element = step['element_layout']
                    child_length = label_length + 2 + self.digits_upper(count - 1)
                    nested = self.compact(element['trace'], element['size'], depth + 1, active, label + '[*]', child_length)
                    if nested.rejected_array is not None:
                        return nested
                    total = self.add(total, self.add(ExpansionCost(0, 1 + label_length), self.repeat(nested, count, child_length)))
                else:
                    total = self.add(total, ExpansionCost(0, 1 + label_length))
                cursor += size
            else:
                total = self.add(total, ExpansionCost(1, self.raw_work(size, 1 + 2 * label_length)))
                cursor += size
            if total.rejected_array is not None:
                return total
            # Continue bounded metadata analysis so a later per-array refusal
            # still retains the existing single whole-record raw fallback.
            if cursor == limit and size != 0:
                break
        if cursor < limit:
            total = self.add(total, ExpansionCost(1, self.raw_work(limit - cursor,
                1 + 2 * (path_length + len('/trailing_layout_bytes')))))
        return total

    def finish(self, operation):
        try:
            cost = operation()
        except _AnalysisBound:
            return ExpansionCost(None, self.limits.max_expansion_work + 1,
                                 established=False, analysis_work=self.nodes)
        return ExpansionCost(cost.leaves, cost.work, cost.established,
                             cost.rejected_array, self.nodes)


def schema_cost(layout_lookup: Callable, *, limits: ExpansionLimits,
                layout: Mapping | None=None, typ: Mapping | None=None,
                root_record: bool=False, depth: int=0, path_length: int=0, max_depth: int=64,
                max_array_elements: int=1000000) -> ExpansionCost:
    if (layout is None) == (typ is None):
        raise ExpansionMetadataError('Exactly one layout or type is required')
    if type(path_length) is not int or path_length < 0:
        raise ExpansionMetadataError('Invalid symbolic field path length')
    estimator = _Estimator(limits, layout_lookup, {}, max_depth, max_array_elements)
    return estimator.finish(lambda: estimator.typ(typ, depth, path_length=path_length) if typ is not None else
        estimator.record(layout) if root_record else estimator.fields(layout, depth, path_length=path_length))


def compact_cost(trace: Sequence, limit: int, descriptors: Mapping, *,
                 limits: ExpansionLimits, max_depth: int=64,
                 max_array_elements: int=1000000, opcode_names: Mapping | None=None) -> ExpansionCost:
    estimator = _Estimator(limits, None, descriptors, max_depth, max_array_elements)
    estimator.opcode_names = opcode_names or {}
    cost = estimator.finish(lambda: estimator.compact(trace, limit))
    if cost.rejected_array is not None:
        # The legacy compact fallback retains the WHOLE record, including when
        # the first rejected array was nested in a descriptor or another array.
        work = estimator.raw_work(limit, 1 + len('/compact_array_limit_raw'))
        return ExpansionCost(1, work, cost.established, cost.rejected_array, cost.analysis_work)
    return cost


def admit_cost(cost: ExpansionCost, limits: ExpansionLimits, *, context=None, raw_selector=None):
    """Refuse explicitly without reading payload or generating raw_hex."""
    if not cost.exceeded(limits):
        return
    from fsd_decoder.core.diagnostics import ResourceLimitError
    exc = ResourceLimitError('Decoded field/work expansion exceeds resource policy; interpretation UNKNOWN')
    exc.status = 'RESOURCE_BOUND'
    exc.semantic_status = 'UNKNOWN'
    exc.context = dict(context or {}, phase='decode-expansion-limit')
    if raw_selector is not None:
        exc.raw_selector = raw_selector
    exc.expansion = dict(decoded_fields=cost.leaves, work=cost.work,
        cost_established=cost.established, estimate_complete=not cost.exceeded(limits),
        count_semantics='SATURATED_ADMISSION_ESTIMATE', analysis_work=cost.analysis_work,
        max_decoded_leaves=limits.max_decoded_leaves,
        max_expansion_work=limits.max_expansion_work)
    raise exc


def allocation_cost(fields, allocation: Mapping, *, limits: ExpansionLimits,
                    typ: Mapping | None=None, admission: Mapping | None=None) -> ExpansionCost:
    """Follow actual selected-element identity and charge repeated rendering."""
    estimator = _Estimator(limits, None, {}, fields.decoder.max_depth, fields.decoder.max_array_elements)
    if allocation.get('name') == 'inline_char_bytes':
        work = estimator._mul(5, allocation['size'], limits.max_expansion_work)
        return ExpansionCost(1, estimator._add(1 + len('inline_char_bytes'), work, limits.max_expansion_work))
    tag = allocation['native_tag']
    typ = fields.types.get(tag) if typ is None else typ
    if typ is None:
        raise ExpansionMetadataError('Unknown native element type')
    read_size = typ['size'] if allocation.get('vector') else allocation['size']
    native_work = estimator.raw_work(read_size, estimator.text_length(typ['name']))
    if read_size != typ['size']:
        native_work = estimator._add(native_work, estimator._mul(2, read_size, limits.max_expansion_work), limits.max_expansion_work)
    if native_work > limits.max_expansion_work:
        return estimator.unknown_work()
    admission = fields.schema_admission(allocation) if admission is None else admission
    if admission['admitted']:
        cost = schema_cost(fields.decoder.layout, limits=limits,
            layout=fields.decoder.layout(typ['name']), root_record=True,
            max_depth=fields.decoder.max_depth, max_array_elements=fields.decoder.max_array_elements)
    elif tag <= 42:
        cost = ExpansionCost(1, 1)
    elif 'trace' not in typ:
        cost = ExpansionCost(1, estimator.raw_work(typ['size']))
    else:
        cost = compact_cost(typ['trace'], typ['size'], fields.descriptors, limits=limits,
            max_depth=fields.decoder.max_depth, max_array_elements=fields.decoder.max_array_elements,
            opcode_names=getattr(fields, '_expansion_opcode_names', None))
    if cost.rejected_array is not None:
        return ExpansionCost(cost.leaves, estimator._add(cost.work, native_work, limits.max_expansion_work),
                             cost.established, cost.rejected_array, cost.analysis_work)
    result = estimator.add(cost, ExpansionCost(0, native_work))
    return ExpansionCost(result.leaves, result.work, result.established,
                         result.rejected_array, cost.analysis_work)
