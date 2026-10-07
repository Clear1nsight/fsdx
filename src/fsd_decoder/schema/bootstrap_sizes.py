"""Static size evaluator for the recovered ObjectStore bootstrap bytecode.

Evaluate packaged derived ObjectStore descriptors without vendor file reads,
DLL loading, emulation or native execution. The packaged resource metadata
records the historical vendor binary name and SHA256.
"""
from fsd_decoder.resources.loader import load_json
import collections
from fsd_decoder.core.diagnostics import MalformedSourceError, contextual

class Unsupported(ValueError):
    pass

class Evaluator:

    def __init__(self, descriptors, later_base_full=False, metadata=None):
        self.desc = {r['rd_number']: r for r in descriptors}
        self.meta = metadata if metadata is not None else {r['opcode']: r for r in load_json('bytecode_opcodes.json')}
        self.cache = {}
        self.active = set()
        self.ops = collections.Counter()
        self.later_base_full = later_base_full

    @contextual('representation_descriptor', rd='index')
    def evaluate(self, rd):
        if rd in self.cache:
            return self.cache[rd]
        if rd in self.active:
            raise Unsupported(f'recursive by-value RD {rd}')
        self.active.add(rd)
        try:
            if rd not in self.desc:
                raise Unsupported(f'Missing representation descriptor {rd}')
            row = self.desc[rd]
            try:
                b = bytes.fromhex(row['instruction_hex'])
            except ValueError as exc:
                raise Unsupported('Invalid bytecode hexadecimal representation') from exc
            result, pos = self.sequence(b, 0, {62})
            if pos != len(b) - 1:
                raise Unsupported(f'RD{rd}: trailing bytecode at{pos}')
            result.update(rd_number=rd, name=row['name'], alignment=1 << row['alignment_exponent_candidate'])
            self.cache[rd] = result
            return result
        finally:
            self.active.remove(rd)

    def sequence(self, b, pos, terminators):
        full = base = flags = 0
        firstbase = True
        trace = []

        def get(n):
            nonlocal pos
            if pos + n > len(b):
                raise Unsupported('truncated operand')
            val = int.from_bytes(b[pos:pos + n], 'big')
            pos += n
            return val
        while pos < len(b) and b[pos] not in terminators:
            begin = pos
            op = get(1)
            self.ops[op] += 1
            n = z = f = 0
            extra = {}
            if op in (29, 30, 31):
                width = {29: 1, 30: 2, 31: 4}[op]
                count = get(width)
                stride = get(width)
                child, pos = self.sequence(b, pos, {34})
                if get(1) != 34:
                    raise Unsupported('array missing22')
                if child['size'] != child['base_size'] or child['size'] > count * stride:
                    raise Unsupported('array element extent')
                n = z = count * stride
                f = child['flags'] & 12291
                extra = dict(array_count=count, array_stride=stride, element_layout=child)
            elif op == 35:
                sizes = []
                alternatives = []
                f = 4
                while True:
                    child, pos = self.sequence(b, pos, {36})
                    if get(1) != 36:
                        raise Unsupported('union missing24')
                    if child['size'] != child['base_size']:
                        raise Unsupported('union virtual padding')
                    sizes.append(child['size'])
                    alternatives.append(child)
                    f |= child['flags'] & 12291
                    if pos >= len(b) or b[pos] == 62:
                        break
                n = max(sizes, default=0)
                z = 0
                extra = dict(union_alternative_sizes=sizes, union_alternatives=alternatives)
            elif 43 <= op <= 48:
                ref = get(2)
                child = self.evaluate(ref)
                f = child['flags'] & 12291
                extra = dict(reference_rd=ref, reference_name=child['name'])
                if op in (43, 46):
                    n = z = child['size']
                if op == 44:
                    n = z = child['size'] if self.later_base_full and (not firstbase) else child['base_size']
                    firstbase = False
                if op in (45, 48):
                    extra['virtual_offset'] = get(4)
                    f |= 8192
                if op in (47, 48):
                    if child['base_size'] != 0:
                        raise Unsupported('zero-length base changes child size')
                    firstbase = False
                if op == 46:
                    if not child['flags'] & 4:
                        raise Unsupported('union reference not union')
                    extra['union_control'] = get(1)
                    f |= 4096
            elif op == 26:
                n = z = get(1)
                extra['bitfield_mask'] = b[pos:pos + n].hex()
                get(n)
            elif op == 15:
                n = z = get(2)
            elif op == 52:
                n = get(4)
            elif op in (50, 51):
                n = z = get(1)
                if op == 51:
                    get(1)
            elif op == 60:
                get(1)
                get(2)
                get(get(2))
            else:
                meta = self.meta.get(op)
                if not meta or meta['size'] < 0 or meta['instruction_length'] < 1:
                    raise Unsupported(f'opcode{op:02x}')
                n = z = meta['size']
                get(meta['instruction_length'] - 1)
                if op in (23, 24, 53, 54):
                    f |= 1
                if op in (41, 42, 55, 56, 57, 58):
                    f |= 2
            trace.append(dict(byte_offset=begin, opcode=hex(op), size=n, base_size=z, **extra))
            full += n
            base += z
            flags |= f
        if pos == len(b):
            raise Unsupported('missing terminator')
        return (dict(size=full, base_size=base, flags=flags, needs_discriminants=bool(flags & 4100), trace=trace), pos)

def compile_dynamic_bindings(bindings):
    """Compile recovered persistent dictionary bindings with bootstrap bases.

    Accept flat extended_dictionary() rows or wrapper rows with a ``binding``.
    Return entries/errors; entries include tag, size, binding, discriminant flag.
    Missing, conflicting and version-dependent references remain explicit errors.
    """
    source = load_json('bootstrap_types.json')
    desc = {r['rd_number']: r for r in source['descriptors']}
    flat = []
    for outer in bindings:
        if not isinstance(outer, dict):
            raise MalformedSourceError('Invalid representation binding')
        b = outer.get('binding', outer)
        if (not isinstance(b, dict) or not all(key in b for key in ('dictionary_id', 'alignment', 'name', 'layout_hex', 'native_tag'))
                or type(b['dictionary_id']) is not int or type(b['alignment']) is not int
                or type(b['native_tag']) is not int or not isinstance(b['name'], str)
                or not isinstance(b['layout_hex'], str)):
            raise MalformedSourceError('Invalid representation binding')
        rd = b['dictionary_id']
        align = b['alignment']
        if not align or align & align - 1:
            raise MalformedSourceError('alignment must be power of two')
        row = dict(rd_number=rd, name=b['name'], instruction_hex=b['layout_hex'], alignment_exponent_candidate=align.bit_length() - 1)
        if rd in desc and (desc[rd]['instruction_hex'], desc[rd]['name']) != (row['instruction_hex'], row['name']):
            raise MalformedSourceError(f'Conflicting dictionary ID {rd}')
        desc[rd] = row
        flat.append(b)
    e = Evaluator(list(desc.values()))
    alternate = Evaluator(list(desc.values()), True)
    entries = []
    errors = []
    for b in flat:
        try:
            rd = b['dictionary_id']
            calc = e.evaluate(rd)
            other = alternate.evaluate(rd)
            if calc['size'] != other['size']:
                raise Unsupported('version-dependent base class extent')
            entries.append(dict(calc, tag=b['native_tag'], native_tag=b['native_tag'], binding=b, size_evidence='static persistent descriptor bytecode compiler'))
        except Unsupported as exc:
            errors.append(dict(binding=b, error=str(exc)))
    return dict(entries=entries, errors=errors, opcode_counts={hex(k): v for k, v in sorted(e.ops.items())})
