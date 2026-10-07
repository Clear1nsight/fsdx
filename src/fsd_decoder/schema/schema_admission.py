"""Bounded storage corroboration; names never witness source-class identity."""
from collections.abc import Mapping, Sequence
from collections import Counter
from fsd_decoder.schema.bootstrap_sizes import Evaluator, Unsupported
from fsd_decoder.resources.loader import load_json

_OPCODES = {row['opcode']: row for row in load_json('bytecode_opcodes.json')}
MAX_ENRICHMENT_PROGRAM_BYTES = 16384
MAX_ENRICHMENT_TOTAL_BYTES = 262144


class _Unestablished(ValueError):
    pass


class _InstructionBudget(Counter):
    def __init__(self, maximum):
        super().__init__()
        self.maximum = maximum
        self.total = 0

    def __setitem__(self, key, value):
        self.total += value - self.get(key, 0)
        if self.total > self.maximum:
            raise _Unestablished('STORAGE_COMPARISON_BOUND')
        super().__setitem__(key, value)


class _BoundedEvaluator(Evaluator):
    """Apply admission budgets around the retained compiler's existing grammar."""
    def __init__(self, descriptors, *, max_nodes, max_depth):
        super().__init__(descriptors)
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.programs = set()
        self.program_bytes = 0
        self.sequence_depth = 0
        self.ops = _InstructionBudget(max_nodes)

    def evaluate(self, rd):
        if len(self.active) >= self.max_depth:
            raise _Unestablished('STORAGE_COMPARISON_BOUND')
        if rd not in self.programs and rd in self.desc:
            raw = self.desc[rd]['instruction_hex']
            if not isinstance(raw, str):
                raise _Unestablished('INVALID_RETAINED_PROGRAM')
            # Count encoded bytes conservatively, including any whitespace.
            # These checks precede bytes.fromhex and all program evaluation.
            size = (len(raw) + 1) // 2
            if size > MAX_ENRICHMENT_PROGRAM_BYTES:
                raise _Unestablished('RETAINED_PROGRAM_BYTE_BOUND')
            if self.program_bytes + size > MAX_ENRICHMENT_TOTAL_BYTES:
                raise _Unestablished('RETAINED_PROGRAM_AGGREGATE_BYTE_BOUND')
            if len(self.programs) >= self.max_nodes:
                raise _Unestablished('STORAGE_COMPARISON_BOUND')
            self.programs.add(rd)
            self.program_bytes += size
        return super().evaluate(rd)

    def sequence(self, b, pos, terminators):
        self.sequence_depth += 1
        try:
            if self.sequence_depth + len(self.active) > self.max_depth:
                raise _Unestablished('STORAGE_COMPARISON_BOUND')
            return super().sequence(b, pos, terminators)
        finally:
            self.sequence_depth -= 1


class _Profiles:
    def __init__(self, schema, descriptors, *, verified_nonvariable=(), max_nodes=4096, max_depth=64):
        self.schema = schema
        self.descriptors = descriptors
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.nodes = 0
        self.evaluator = None
        self.verified_nonvariable = verified_nonvariable

    def budget(self, depth):
        self.nodes += 1
        if depth > self.max_depth or self.nodes > self.max_nodes:
            raise _Unestablished('STORAGE_COMPARISON_BOUND')

    def integer(self, value, label, *, positive=False):
        if type(value) is not int or value < (1 if positive else 0):
            raise _Unestablished('INVALID_' + label)
        return value

    def source_layout(self, layout, depth=0, *, contextual_base=False):
        self.budget(depth)
        size = self.integer(layout.get('size'), 'SOURCE_SIZE', positive=depth == 0)
        if any(issue.get('kind') != 'non_instance_storage' or issue.get('storage_class') not in (1, 2)
               for issue in layout.get('unresolved', ())
               if not (issue.get('kind') == 'non_variable_member' and
                       issue.get('descriptor_offset') in self.verified_nonvariable)):
            raise _Unestablished('UNRESOLVED_SOURCE_LAYOUT')
        result, bases = [], []
        for base in layout.get('bases', ()):
            offset = self.integer(base.get('offset'), 'BASE_OFFSET')
            child = base.get('layout') or self.schema.layout(base['type']['name'])
            profile = self.source_layout(child, depth + 1, contextual_base=True)
            edge = dict(offset=offset, name=base['type']['name'],
                        children=self.contexts(profile))
            if child['size'] and not self.storage(profile):
                # A member-free base contributes no discriminating storage. Its
                # independently declared extent must match the consumed native
                # BASE region, while its enclosing typed profile corroborates.
                declared = self.integer(base['type'].get('size'), 'SOURCE_BASE_SIZE', positive=True)
                if declared != child['size']:
                    raise _Unestablished('SOURCE_BASE_EXTENT')
                self.spans([dict(offset=offset, size=declared)], size)
                edge['opaque_extent'] = declared
            bases.append(edge)
            result.extend(self.shift(self.storage(profile), offset))
        for member in layout.get('members', ()):
            offset = self.integer(member.get('offset'), 'MEMBER_OFFSET')
            if 'bitfield' in member:
                bit = member['bitfield']
                width = self.integer(bit.get('storage_size'), 'BITFIELD_SIZE', positive=True)
                # Masks are little-endian byte strings, not hexadecimal integers.
                mask = int.from_bytes(bytes.fromhex(bit['mask_hex']), 'little')
                result.append(dict(offset=offset, size=width, category='bits', mask=mask))
            else:
                result.extend(self.shift(self.source_type(member['type'], depth + 1), offset))
        if bases:
            result.append(dict(offset=0, size=0, category='bases', edges=bases))
        self.spans(result, size)
        if not self.storage(result) and size and not (contextual_base and not layout.get('members')):
            raise _Unestablished('NO_DISCRIMINATING_SOURCE_STORAGE')
        return self.combine_bits(result)

    @staticmethod
    def shift(nodes, offset):
        return [dict(node, offset=node['offset'] + offset) for node in nodes]

    @staticmethod
    def storage(nodes):
        # Base/class context markers carry no physical bytes. Their hierarchy
        # must stay with its declaration rather than being flattened by shift.
        return [node for node in nodes if node['category'] not in ('bases', 'class_context')]

    @classmethod
    def contexts(cls, nodes):
        result = []
        for node in nodes:
            category = node['category']
            if category in ('bases', 'class_context'):
                result.append(node)
            elif category == 'array':
                children = cls.contexts(node['children'])
                if children:
                    result.append(dict(node, children=children))
            elif category == 'union':
                arms = [cls.contexts(arm) for arm in node['arms']]
                if any(arms):
                    result.append(dict(node, arms=arms))
        return result

    @classmethod
    def embedded(cls, profile, size):
        contexts = cls.contexts(profile)
        if not contexts:
            return profile
        # Keep physical nodes for ordinary storage comparison; the separate
        # context carries relative base offsets through class parent paths.
        return cls.storage(profile) + [dict(offset=0, size=0, extent=size,
            category='class_context', children=contexts)]

    def source_type(self, typ, depth):
        self.budget(depth)
        kind = typ.get('kind')
        if kind in ('alias', 'qualified'):
            if typ.get('unknown_qualifier_flags'):
                raise _Unestablished('UNKNOWN_SOURCE_QUALIFIERS')
            size = self.integer(typ.get('size'), 'SOURCE_TYPE_SIZE', positive=True)
            underlying_size = self.integer(typ['underlying'].get('size'),
                                           'SOURCE_TYPE_SIZE', positive=True)
            if size != underlying_size:
                raise _Unestablished('SOURCE_WRAPPER_EXTENT')
            return self.source_type(typ['underlying'], depth + 1)
        size = self.integer(typ.get('size'), 'SOURCE_TYPE_SIZE', positive=True)
        common = dict(offset=0, size=size)
        if kind == 'primitive':
            name = typ.get('name', '')
            floating = 'float' in name or 'double' in name
            if floating and not (('ieees float' in name and size == 4) or
                                 ('ieeed double' in name and size == 8)):
                raise _Unestablished('UNSUPPORTED_SOURCE_FLOAT')
            return [dict(common, category='floating' if floating else 'ordinal')]
        if kind == 'enum':
            return [dict(common, category='ordinal')]
        if kind == 'pointer':
            if size not in (4, 8):
                raise _Unestablished('UNSUPPORTED_SOURCE_POINTER_WIDTH')
            return [dict(common, category='pointer')]
        if kind == 'class':
            name = typ['name']
            if name.startswith(('os_soft_pointer32<', 'os_hard_pointer32<',
                                'os_soft_pointer64<', 'os_hard_pointer64<')):
                if size != (4 if 'pointer32<' in name else 8):
                    raise _Unestablished('SOURCE_TEMPLATE_POINTER_WIDTH')
                return [dict(common, category='pointer')]
            profile = self.source_layout(self.schema.layout(name), depth + 1)
            return self.embedded(profile, size)
        if kind == 'array':
            count = self.integer(typ.get('count'), 'SOURCE_ARRAY_COUNT')
            stride = self.integer(typ['element'].get('size'), 'SOURCE_ARRAY_STRIDE', positive=True)
            if count * stride != size:
                raise _Unestablished('SOURCE_ARRAY_EXTENT')
            return [dict(common, category='array', count=count, stride=stride,
                         children=self.source_type(typ['element'], depth + 1))]
        if kind == 'union':
            layout = self.schema.layout(typ['name'])
            if layout.get('unresolved') or layout.get('bases'):
                raise _Unestablished('UNSUPPORTED_SOURCE_UNION_DECLARATIONS')
            arms = []
            for member in layout['members']:
                if 'bitfield' in member:
                    arm = self.source_layout(dict(layout, members=[member]), depth + 1)
                else:
                    arm = self.shift(self.source_type(member['type'], depth + 1),
                                     self.integer(member.get('offset'), 'UNION_OFFSET'))
                self.spans(arm, size)
                arms.append(arm)
            if not arms:
                raise _Unestablished('EMPTY_SOURCE_UNION')
            return [dict(common, category='union', arms=arms)]
        raise _Unestablished('UNSUPPORTED_SOURCE_STORAGE_' + str(kind))

    def enrich(self, representation):
        """Recompile only exact retained programs when old union traces lack arms."""
        trace = representation.get('trace')
        if trace is None:
            raise _Unestablished('COMPACT_TRACE_UNAVAILABLE')
        def missing_arms(layout, depth=0):
            self.budget(depth)
            steps = layout.get('trace')
            if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
                raise _Unestablished('INVALID_COMPACT_TRACE')
            for step in steps:
                self.budget(depth)
                if int(step['opcode'], 16) == 35 and 'union_alternatives' not in step:
                    return True
                child = step.get('element_layout')
                if child is not None and missing_arms(child, depth + 1):
                    return True
                if any(missing_arms(arm, depth + 1) for arm in step.get('union_alternatives', ())):
                    return True
            return False
        if not missing_arms(representation):
            return representation
        if self.evaluator is None:
            if len(self.descriptors) > self.max_nodes:
                raise _Unestablished('STORAGE_COMPARISON_BOUND')
            programs = []
            for rd, record in self.descriptors.items():
                raw = record.get('instruction_hex') or record.get('binding', {}).get('layout_hex')
                if raw is not None:
                    alignment = record.get('alignment', record.get('binding', {}).get('alignment', 1))
                    if type(alignment) is not int or alignment <= 0 or alignment & (alignment - 1):
                        raise _Unestablished('INVALID_COMPACT_ALIGNMENT')
                    programs.append(dict(rd_number=rd, name=record['name'], instruction_hex=raw,
                                         alignment_exponent_candidate=alignment.bit_length() - 1))
            if len(programs) > self.max_nodes:
                raise _Unestablished('STORAGE_COMPARISON_BOUND')
            self.evaluator = _BoundedEvaluator(programs, max_nodes=self.max_nodes,
                                               max_depth=self.max_depth)
        rd = representation.get('rd_number')
        try:
            enriched = self.evaluator.evaluate(rd)
        except Unsupported as exc:
            raise _Unestablished('UNION_ARM_TRACE_UNAVAILABLE: ' + str(exc)) from exc
        if enriched['size'] != representation['size']:
            raise _Unestablished('RETAINED_PROGRAM_EXTENT_DISAGREES')
        return enriched

    def native(self, representation, depth=0, *, limit=None):
        self.budget(depth)
        representation = self.enrich(representation)
        extent = self.integer(representation.get('size'), 'COMPACT_SIZE', positive=depth == 0)
        limit = extent if limit is None else limit
        trace = representation['trace']
        if not isinstance(trace, Sequence) or isinstance(trace, (str, bytes)):
            raise _Unestablished('INVALID_COMPACT_TRACE')
        result, bases, cursor = [], [], 0
        for step in trace:
            self.budget(depth)
            size = self.integer(step.get('size'), 'COMPACT_STEP_SIZE')
            op = int(step['opcode'], 16)
            meta = _OPCODES.get(op)
            if meta is None or (meta['size'] >= 0 and size != meta['size']):
                raise _Unestablished('COMPACT_OPCODE_WIDTH_DISAGREES')
            if cursor + size > extent:
                raise _Unestablished('COMPACT_STEP_EXCEEDS_EXTENT')
            if cursor >= limit and size:
                break
            if cursor + size > limit:
                raise _Unestablished('COMPACT_BASE_PARTIAL_FIELD')
            common = dict(offset=cursor, size=size)
            children = []
            if 'reference_rd' in step:
                child = self.descriptors.get(step['reference_rd'])
                if child is None:
                    raise _Unestablished('COMPACT_REFERENCE_UNAVAILABLE')
                if size or op in (44, 47, 48):
                    if op == 46:
                        profile = self.native(child, depth + 1)
                        if len(profile) != 1 or profile[0]['category'] != 'union':
                            raise _Unestablished('COMPACT_UNION_REFERENCE_DISAGREES')
                        children = profile
                    else:
                        children = self.native(child, depth + 1, limit=size)
                if op in (44, 47, 48):
                    bases.append(dict(offset=cursor, name=child['name'], extent=size,
                                      children=self.contexts(children)))
                    children = self.storage(children)
                elif op != 46:
                    children = self.embedded(children, size)
            elif 'array_count' in step:
                count = self.integer(step.get('array_count'), 'COMPACT_ARRAY_COUNT')
                stride = self.integer(step.get('array_stride'), 'COMPACT_ARRAY_STRIDE', positive=True)
                if count * stride != size or step['element_layout']['size'] > stride:
                    raise _Unestablished('COMPACT_ARRAY_EXTENT')
                children = [dict(offset=0, size=size, category='array', count=count, stride=stride,
                                 children=self.native(step['element_layout'], depth + 1))]
            elif op == 35:
                arms = step.get('union_alternatives')
                if arms is None:
                    raise _Unestablished('UNION_ARM_TRACE_UNAVAILABLE')
                children = [dict(offset=0, size=size, category='union',
                                 arms=[self.native(arm, depth + 1) for arm in arms])]
            elif size:
                category = ('ordinal' if op in (1, 2, 3, 4, 5) else
                            'floating' if op in (17, 18) else
                            'pointer' if op in (23, 24, 53, 54) else
                            'bits' if op == 26 else 'padding' if op in (15, 52) else
                            'runtime' if op in (41, 42, 55, 56, 57, 58, 59) else 'unknown')
                node = dict(offset=0, size=size, category=category)
                if op == 26:
                    node['mask'] = int.from_bytes(bytes.fromhex(step['bitfield_mask']), 'little')
                children = [node]
            result.extend(self.shift(children, cursor))
            cursor += size
        if cursor != limit:
            raise _Unestablished('COMPACT_TRACE_EXTENT_UNESTABLISHED')
        if bases:
            result.append(dict(offset=0, size=0, category='bases', edges=bases))
        return self.combine_bits(result)

    @staticmethod
    def spans(nodes, extent):
        for node in nodes:
            if node['offset'] < 0 or node['offset'] + node['size'] > extent:
                raise _Unestablished('SOURCE_STORAGE_EXCEEDS_EXTENT')

    @staticmethod
    def combine_bits(nodes):
        result, groups = [], {}
        for node in nodes:
            if node['category'] != 'bits':
                result.append(node)
                continue
            key = (node['offset'], node['size'])
            if key in groups:
                groups[key]['mask'] |= node['mask']
            else:
                groups[key] = dict(node)
        result.extend(groups.values())
        return sorted(result, key=lambda node: (node['offset'], node['size'], node['category']))

    def match(self, source, native, depth=0):
        self.budget(depth)
        source_contexts = [node for node in source if node['category'] in ('bases', 'class_context')]
        native_contexts = [node for node in native if node['category'] in ('bases', 'class_context')]
        if len(source_contexts) != len(native_contexts):
            return False
        for node in source:
            candidates = [item for item in native if item['offset'] == node['offset'] and
                          item['size'] == node['size'] and item['category'] == node['category']]
            if len(candidates) != 1:
                return False
            actual = candidates[0]
            if node['category'] == 'bases':
                # Declaration order need not be physical subobject order.
                order = lambda edge: (edge['offset'], edge['name'])
                edges = sorted(node['edges'], key=order)
                other_edges = sorted(actual['edges'], key=order)
                if len(edges) != len(other_edges):
                    return False
                for edge, other in zip(edges, other_edges):
                    if 'opaque_extent' in edge and edge['opaque_extent'] != other['extent']:
                        return False
                    if (edge['offset'], edge['name']) != (other['offset'], other['name']) or not self.match(
                            edge['children'], other['children'], depth + 1):
                        return False
            if node['category'] == 'class_context':
                if node['extent'] != actual['extent'] or not self.match(
                        node['children'], actual['children'], depth + 1):
                    return False
            if node['category'] == 'bits' and actual['mask'] != node['mask']:
                return False
            if node['category'] == 'array':
                if (node['count'], node['stride']) != (actual['count'], actual['stride']) or not self.match(
                        node['children'], actual['children'], depth + 1):
                    return False
            if node['category'] == 'union':
                remaining = list(actual['arms'])
                for arm in node['arms']:
                    found = next((index for index, other in enumerate(remaining)
                                  if self.match(arm, other, depth + 1)), None)
                    if found is None:
                        return False
                    remaining.pop(found)
                if remaining:
                    return False
        # Compact storage in source gaps remains raw evidence. It must not
        # overlap any interpreted declaration other than its matching node.
        for actual in self.storage(native):
            overlaps = [node for node in self.storage(source) if actual['offset'] < node['offset'] + node['size']
                        and node['offset'] < actual['offset'] + actual['size']]
            if overlaps and not any(actual['offset'] == node['offset'] and actual['size'] == node['size']
                                    and actual['category'] == node['category'] for node in overlaps):
                return False
        return True


def schema_admission(schema, representations, descriptors, native_tag, *, verified_nonvariable=()):
    """Corroborate exact native storage against a correlated source layout."""
    typ = representations.get(native_tag)
    name = typ.get('name') if typ is not None else None
    result = dict(native_tag=native_tag, type_name=name, schema_name=None, admitted=False,
                  status='NO_SOURCE_CLASS_CORRELATION', reasons=[], association_witnessed=False,
                  evidence_scope='COMPACT_SOURCE_STORAGE_CONCORDANCE')
    if name not in schema.classes:
        return result
    result['schema_name'] = name
    layout = schema.layout(name)
    result['class_descriptor_offset'] = layout.get('descriptor_offset')
    result['representation_rd'] = typ.get('rd_number')
    if layout.get('size') != typ.get('size'):
        return dict(result, status='SOURCE_COMPACT_STORAGE_MISMATCH', reasons=['ELEMENT_EXTENT_MISMATCH'])
    profiles = _Profiles(schema, descriptors, verified_nonvariable=verified_nonvariable)
    try:
        if layout.get('class_kind_bits', 0) & 2:
            source = profiles.source_type(dict(kind='union', name=name, size=layout['size']), 0)
        else:
            source = profiles.source_layout(layout)
        native = profiles.native(typ)
        matched = profiles.match(source, native)
    except (_Unestablished, Unsupported, KeyError, TypeError, ValueError) as exc:
        return dict(result, status='SOURCE_COMPACT_STORAGE_UNESTABLISHED', reasons=[str(exc)])
    return dict(result, admitted=matched,
                status='STRUCTURALLY_CORROBORATED_SOURCE_LAYOUT' if matched else 'SOURCE_COMPACT_STORAGE_MISMATCH',
                reasons=[] if matched else ['TYPED_STORAGE_OFFSETS_WIDTHS_OR_CATEGORIES_DISAGREE'])


def corroborated_member_slots(schema, representations, descriptors, native_tag, slots,
                              *, verified_nonvariable=()):
    """Return matching leaf declarations without admitting the enclosing class.

    Exact class extent and every base/class context must agree first. Conditional
    unions, arrays and ambiguous/overlapping native slots are excluded. Unrelated
    padding/runtime disagreements remain a whole-class rejection.
    """
    typ = representations.get(native_tag)
    if typ is None or typ['name'] not in schema.classes:
        return []
    layout = schema.layout(typ['name'])
    if layout.get('size') != typ.get('size'):
        return []
    profiles = _Profiles(schema, descriptors, verified_nonvariable=verified_nonvariable)
    try:
        source = profiles.source_layout(layout)
        native = profiles.native(typ)
        if not profiles.match(profiles.contexts(source), profiles.contexts(native)):
            return []
        result = []
        for slot in slots:
            if slot['conditional_union'] or slot['arrays']:
                continue
            nodes = [node for node in profiles.storage(source)
                     if node['offset'] == slot['offset'] and node['size'] == slot['size']
                     and node['category'] in ('pointer', 'ordinal', 'floating')]
            overlaps = [node for node in profiles.storage(source)
                        if node['offset'] < slot['offset'] + slot['size']
                        and slot['offset'] < node['offset'] + node['size']]
            if len(nodes) == 1 and len(overlaps) == 1 and profiles.match(nodes, profiles.storage(native)):
                result.append(dict(slot, evidence='PARTIAL_SOURCE_COMPACT_SLOT_CONCORDANCE'))
        return result
    except (_Unestablished, Unsupported, KeyError, TypeError, ValueError):
        return []
