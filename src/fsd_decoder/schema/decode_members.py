"""Decode schema-owned fields of independently identified FSD allocations.

No object is located from its name or a fixed offset. The caller supplies
allocation identity from native allocation tags and optional supported pointer
links. Every record/leaf retains its exact source bytes. Unknown regions and
unresolved targets are reported explicitly.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
import struct
import tempfile
from pathlib import Path
from fsd_decoder.schema.schema_members import MemberSchema, SchemaError
from fsd_decoder.schema.expansion_admission import (ExpansionLimits, ExpansionMetadataError, schema_cost, admit_cost, DEFAULT_MAX_DECODED_LEAVES, DEFAULT_MAX_EXPANSION_WORK)

class MemberDecoder:

    def __init__(self, data, schema=None, pointer_resolver=None, max_depth=64, max_array_elements=1000000, *, max_decoded_leaves=DEFAULT_MAX_DECODED_LEAVES, max_expansion_work=DEFAULT_MAX_EXPANSION_WORK):
        try:
            self.expansion_limits = ExpansionLimits(max_decoded_leaves, max_expansion_work)
        except ExpansionMetadataError as exc:
            raise SchemaError(str(exc)) from exc
        self.data = data
        self.schema = schema or MemberSchema(data)
        self.pointer_resolver = pointer_resolver
        self.max_depth = max_depth
        self.max_array_elements = max_array_elements
        self.layouts = {}

    def span(self, p, n):
        if p < 0 or n < 0 or p + n > len(self.data):
            raise SchemaError('Object field outside source')
        return self.data[p:p + n]

    def layout(self, name):
        if name not in self.layouts:
            self.layouts[name] = self.schema.layout(name)
        return self.layouts[name]

    def _cost(self, *, typ=None, layout=None, root_record=False, depth=0, limits=None, path_length=0):
        limits = self.expansion_limits if limits is None else limits
        try:
            return schema_cost(self.layout, limits=limits, typ=typ, layout=layout,
                root_record=root_record, depth=depth, path_length=path_length, max_depth=self.max_depth,
                max_array_elements=self.max_array_elements)
        except ExpansionMetadataError as exc:
            raise SchemaError(str(exc)) from exc

    def leaf(self, typ, at, path, root, depth):
        admit_cost(self._cost(typ=typ, depth=depth, path_length=len(path)), self.expansion_limits,
                   context=dict(type=path))
        return self._leaf(typ, at, path, root, depth)

    def fields(self, layout, at, path, root, depth):
        admit_cost(self._cost(layout=layout, depth=depth, path_length=len(path)), self.expansion_limits,
                   context=dict(type=path))
        return self._fields(layout, at, path, root, depth)

    def _leaf(self, typ, at, path, root, depth):
        if depth > self.max_depth:
            raise SchemaError('Excessive embedded type nesting')
        kind = typ['kind']
        size = typ.get('size')
        if size is None:
            return [dict(path=path, kind=kind, type=typ, source_offset=at, status='UNKNOWN_SIZE')]
        raw = self.span(at, size)
        common = dict(path=path, kind=kind, source_offset=at, record_relative_offset=at - root, size=size, raw_hex=raw.hex(), type_name=typ.get('name'), schema_type_descriptor=typ.get('descriptor_offset'), schema_descriptor_address_space='segment0_cluster0_logical' if self.schema.schema_extents else 'physical_file')
        if kind == 'alias':
            leaves = self._leaf(typ['underlying'], at, path, root, depth + 1)
            for leaf in leaves:
                leaf.setdefault('type_aliases', []).insert(0, typ['name'])
            return leaves
        if kind == 'qualified':
            if typ.get('unknown_qualifier_flags'):
                return [dict(common, status='UNKNOWN_QUALIFIERS', type=typ)]
            leaves = self._leaf(typ['underlying'], at, path, root, depth + 1)
            for leaf in leaves:
                leaf.setdefault('type_qualifiers', []).insert(0, dict(descriptor_offset=typ['descriptor_offset'], qualifiers=typ['qualifiers'], qualifier_flags=typ['qualifier_flags'], qualifier_raw_hex=typ['qualifier_raw_hex']))
            return leaves
        if kind == 'class':
            name = typ['name']
            if name.startswith(('os_soft_pointer32<', 'os_hard_pointer32<', 'os_soft_pointer64<', 'os_hard_pointer64<')) and size in (4, 8):
                return [self.pointer(common, raw)]
            return self._fields(self.layout(name), at, path, root, depth + 1)
        if kind == 'array':
            if typ['count'] > self.max_array_elements:
                return [dict(common, status='ARRAY_LIMIT', element_count=typ['count'])]
            result = []
            for i in range(typ['count']):
                result.extend(self._leaf(typ['element'], at + i * typ['element']['size'], f'{path}[{i}]', root, depth + 1))
            return result
        if kind == 'pointer':
            return [self.pointer(dict(common, pointee_type=typ.get('element')), raw)]
        if kind == 'enum':
            value = int.from_bytes(raw, 'little', signed=True)
            names = [e['name'] for e in typ.get('enumerators', []) if e['value'] == value]
            return [dict(common, value=value, enumerator_names=names, enumerator_name_status='KNOWN' if names else 'UNDECLARED_VALUE')]
        if kind == 'union':
            layout = self.layout(typ['name'])
            views = []
            alternate = MemberDecoder(self.data, self.schema, None, self.max_depth, self.max_array_elements, max_decoded_leaves=self.expansion_limits.max_decoded_leaves, max_expansion_work=self.expansion_limits.max_expansion_work)
            alternate.layouts = self.layouts
            for member in layout['members']:
                if 'bitfield' in member:
                    values = alternate._fields(dict(bases=[], members=[member]), at, path + '::<' + member['name'] + '>', root, depth + 1)
                else:
                    values = alternate._leaf(member['type'], at + member['offset'], path + '::<' + member['name'] + '>', root, depth + 1)
                views.append(dict(member=member['name'], offset=member['offset'], fields=values))
            return [dict(common, status='UNION_DECLARED_VIEWS', active_member=None, active_member_status='NOT_ESTABLISHED', declared_views=views)]
        if kind == 'primitive':
            name = typ['name']
            if 'ieees float' in name and size == 4 or ('ieeed double' in name and size == 8):
                value = struct.unpack('<f' if size == 4 else '<d', raw)[0]
                text = repr(value)
                if math.isfinite(value):
                    if struct.pack('<f' if size == 4 else '<d', float(text)) != raw:
                        raise SchemaError('Floating roundtrip failed')
                    return [dict(common, value=value, decimal=text, encoding='IEEE754_LITTLE_ENDIAN')]
                return [dict(common, value=text, encoding='IEEE754_LITTLE_ENDIAN', exact_nan_payload_in_raw_hex=True)]
            if any((t in name for t in ('float', 'double'))):
                return [dict(common, status='UNSUPPORTED_FLOAT_FORMAT')]
            unsigned = 'unsigned' in name or name.endswith(' bool')
            value = int.from_bytes(raw, 'little', signed=not unsigned)
            if name.endswith(' bool'):
                return [dict(common, value=bool(value), stored_integer=value, canonical=value in (0, 1))]
            return [dict(common, value=value, encoding='LITTLE_ENDIAN')]
        return [dict(common, status='UNSUPPORTED_TYPE')]

    def pointer(self, common, raw):
        word = int.from_bytes(raw, 'little')
        r = dict(common, kind='stored_reference', stored_word=word, target_status='ZERO_WORD_UNRESOLVED' if word == 0 else 'UNRESOLVED')
        if self.pointer_resolver:
            evidence = self.pointer_resolver(common['source_offset'], len(raw), word)
            from fsd_decoder.core.contracts import CapturedUnresolvedReference
            if isinstance(evidence, CapturedUnresolvedReference):
                if (evidence.raw != raw or evidence.record_relative_offset != common['source_offset']):
                    raise SchemaError('Captured unresolved reference field bytes/offset disagree')
                from dataclasses import asdict
                from fsd_decoder.schema.native_fields import _plain
                r.update(target_status='UNRESOLVED', target=None,
                    captured_reference=dict(binding_status='UNRESOLVED', width=len(raw), raw_hex=raw.hex(),
                        source_address=asdict(evidence.slot), source_sha256=evidence.source_sha256,
                        resolution_metadata=_plain(evidence.resolution_metadata)))
            elif evidence is not None:
                if not isinstance(evidence, dict):
                    raise SchemaError('Pointer resolver must return dictionary or None')
                r.update(target_status='RESOLVER_SUPPLIED', target=evidence)
            elif word == 0:
                r['target_status'] = 'NULL'
        return r

    def _fields(self, layout, at, path, root, depth):
        if depth > self.max_depth:
            raise SchemaError('Excessive class nesting')
        result = []
        for base in layout['bases']:
            result.extend(self._fields(base['layout'], at + base['offset'], path + '::<' + base['type']['name'] + '>', root, depth + 1))
        for field in layout['members']:
            if 'bitfield' in field:
                b = field['bitfield']
                start = at + field['offset']
                raw = self.span(start, b['storage_size'])
                bit = b['bit_offset']
                width = b['bit_width']
                size = len(raw)
                if not 0 <= bit < 8 or not 0 < width <= size * 8 - bit or size != (bit + width + 7) // 8:
                    raise SchemaError('Invalid bitfield span')
                mask = (1 << width) - 1 << bit
                if mask.to_bytes(size, 'little').hex() != b['mask_hex']:
                    raise SchemaError('Bitfield mask disagrees')
                stored = int.from_bytes(raw, 'little')
                unsigned = stored >> bit & (1 << width) - 1
                value = unsigned - (1 << width) if b['signed'] and unsigned & 1 << width - 1 else unsigned
                result.append(dict(path=path + '.' + field['name'], kind='bitfield', source_offset=start, record_relative_offset=start - root, size=size, raw_hex=raw.hex(), type_name=field['type'].get('name'), schema_type_descriptor=field['type'].get('descriptor_offset'), schema_member_descriptor=field['descriptor_offset'], bit_offset=bit, bit_width=width, mask_hex=b['mask_hex'], signed=b['signed'], stored_unsigned=stored, unsigned_value=unsigned, value=value, encoding='LSB0_LITTLE_ENDIAN'))
            else:
                result.extend(self._leaf(field['type'], at + field['offset'], path + '.' + field['name'], root, depth + 1))
        return result

    @staticmethod
    def source_items(items):
        for item in items:
            yield item
            for view in item.get('declared_views', []):
                yield from MemberDecoder.source_items(view['fields'])

    def decode_bytes(self, name, raw, source_address=None, pointer_resolver=None, include_schema=False, discriminants=None, *, max_decoded_leaves=None, max_expansion_work=None):
        """Decode a complete logical allocation snapshot, including split extents.

        source_address is {database,segment,cluster,offset}; callback receives
        (record_relative_offset,width,stored_word). It can close over the logical
        object address. `discriminants` preserves native uint16 selector words;
        nonempty selectors are marked unapplied until their semantics are proved.
        Numeric unions expose all declared byte views without choosing an arm.
        Returned source addresses are logical, never invented
        physical offsets; callers may attach their independently checked spans.
        """
        if source_address is not None:
            if not isinstance(source_address, dict) or not isinstance(source_address.get('offset'), int) or source_address['offset'] < 0:
                raise SchemaError('Invalid logical source address')
            source_address = dict(source_address)
        try:
            limits = ExpansionLimits(
                self.expansion_limits.max_decoded_leaves if max_decoded_leaves is None else max_decoded_leaves,
                self.expansion_limits.max_expansion_work if max_expansion_work is None else max_expansion_work)
        except ExpansionMetadataError as exc:
            raise SchemaError(str(exc)) from exc
        layout = self.layout(name)
        selector = None
        if source_address is not None and isinstance(raw, (bytes, bytearray, memoryview)):
            size = raw.nbytes if isinstance(raw, memoryview) else len(raw)
            selector = dict(address=source_address, size=size)
        admit_cost(self._cost(layout=layout, root_record=True, limits=limits), limits,
                   context=dict(type=name, address=source_address), raw_selector=selector)
        if not isinstance(raw, bytes):
            raw = bytes(raw)
        child = MemberDecoder(raw, self.schema, pointer_resolver, self.max_depth, self.max_array_elements, max_decoded_leaves=limits.max_decoded_leaves, max_expansion_work=limits.max_expansion_work)
        child.layouts = self.layouts
        r = child._decode(name, 0, len(raw))
        r.pop('source_offset')
        r['source_address'] = source_address
        r['source_address_space'] = 'LOGICAL_DATABASE_OBJECT'
        for item in self.source_items(r['fields'] + r['uninterpreted_regions']):
            relative = item.pop('source_offset')
            if source_address is not None:
                item['source_address'] = {**source_address, 'offset': source_address['offset'] + relative}
                captured = item.get('captured_reference')
                if captured is not None and captured['source_address'] != item['source_address']:
                    raise SchemaError('Captured unresolved reference logical slot disagrees')
            elif item.get('captured_reference') is not None:
                raise SchemaError('Captured unresolved reference requires logical source identity')
            item['record_relative_offset'] = relative
        if discriminants is not None:
            if any((type(v) is not int or not 0 <= v <= 65535 for v in discriminants)):
                raise SchemaError('Invalid native discriminant words')
            r['tag_discriminants'] = list(discriminants)
            r['discriminant_status'] = 'NO_DISCRIMINANTS' if not discriminants else 'PRESERVED_UNAPPLIED'
            if discriminants:
                r['status'] = 'SCHEMA_TYPED_WITH_UNAPPLIED_DISCRIMINANTS'
        if not include_schema:
            layout = r.pop('schema_layout')
            r['schema_class_descriptor'] = layout['descriptor_offset']
            r['schema_unresolved'] = layout['unresolved']
        return r

    def decode(self, name, at, allocation_size=None):
        layout = self.layout(name)
        admit_cost(self._cost(layout=layout, root_record=True), self.expansion_limits,
                   context=dict(type=name))
        return self._decode(name, at, allocation_size)

    def _decode(self, name, at, allocation_size=None):
        layout = self.layout(name)
        size = layout['size']
        if allocation_size is not None and allocation_size != size:
            raise SchemaError('Allocation/class size mismatch')
        raw = self.span(at, size)
        if layout.get('class_kind_bits') == 2:
            # MemberSchema.type uses this same source-derived class-kind value.
            # A root union has conditional declarations just like an embedded
            # union; even a sole pointer arm must not invoke the resolver.
            fields = self._leaf(dict(kind='union', name=name, size=size,
                descriptor_offset=layout['descriptor_offset']), at, name, at, 0)
        else:
            fields = self._fields(layout, at, name, at, 0)
        covered = bytearray(size)
        for f in fields:
            if 'size' not in f:
                continue
            start = f['source_offset'] - at
            if start < 0 or start + f['size'] > size:
                raise SchemaError('Inherited/embedded field outside allocation')
            masks = bytes.fromhex(f['mask_hex']) if f.get('kind') == 'bitfield' else bytes([255]) * f['size']
            for i, mask in enumerate(masks, start):
                if covered[i] & mask:
                    raise SchemaError('Overlapping decoded instance fields')
                covered[i] |= mask
            if bytes.fromhex(f['raw_hex']) != raw[start:start + f['size']]:
                raise SchemaError('Field bytes disagree')
        unknown = []
        p = 0
        while p < size:
            if covered[p] == 255:
                p += 1
                continue
            if covered[p]:
                mask = 255 ^ covered[p]
                unknown.append(dict(record_relative_offset=p, source_offset=at + p, size=1, raw_hex=raw[p:p + 1].hex(), status='UNINTERPRETED_BITS', mask_hex=bytes([mask]).hex(), masked_unsigned_value=raw[p] & mask))
                p += 1
                continue
            start = p
            while p < size and covered[p] == 0:
                p += 1
            unknown.append(dict(record_relative_offset=start, source_offset=at + start, size=p - start, raw_hex=raw[start:p].hex(), status='UNINTERPRETED_VTABLE_PADDING_OR_FIELD'))
        return dict(class_name=name, source_offset=at, size=size, record_hex=raw.hex(), fields=fields, uninterpreted_regions=unknown, schema_layout=layout, status='SCHEMA_OWNED_TYPED_FIELDS', allocation_identity='CALLER_SUPPLIED', liveness='UNRESOLVED')

def write_text(records, stream, source_sha256=None):
    stream.write('SCHEMA-OWNED OBJECT FIELD EXPORT\n')
    if source_sha256:
        stream.write('source_sha256=' + source_sha256 + '\n')
    stream.write('Allocation identities must come from native tags. Pointer words are opaque unless an external resolver supplies evidence. Liveness is unresolved.\n')
    for r in records:
        stream.write(f'\nOBJECT offset=0x{r['source_offset']:x} class={json.dumps(r['class_name'])} size={r['size']}\nraw_hex={r['record_hex']}\n')
        for f in r['fields']:
            stream.write('FIELD ' + json.dumps(f, sort_keys=True, allow_nan=False) + '\n')
        for region in r['uninterpreted_regions']:
            stream.write('UNINTERPRETED ' + json.dumps(region, sort_keys=True) + '\n')

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path)
    ap.add_argument('--allocations', type=Path, required=True, help='JSON array of independently tagged {name,physical_offset,size} records; or {sha256,records:[...]}')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    data = args.source.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    evidence = json.loads(args.allocations.read_text())
    if isinstance(evidence, dict):
        if evidence.get('sha256') != sha:
            raise SchemaError('Allocation evidence hash mismatch')
        allocations = evidence['records']
    else:
        raise SchemaError('Allocation evidence must pin source hash')
    decoder = MemberDecoder(data)
    records = []
    for a in allocations:
        if a['name'] in decoder.schema.classes:
            records.append(decoder.decode(a['name'], a['physical_offset'], a['size']))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=args.output.parent, prefix='.member-export-', delete=False) as f:
            tmp = Path(f.name)
            write_text(records, f, sha)
        if hashlib.sha256(args.source.read_bytes()).hexdigest() != sha:
            raise SchemaError('Source changed')
        os.link(tmp, args.output)
    finally:
        if tmp:
            tmp.unlink(missing_ok=True)
    print(json.dumps(dict(objects=len(records), fields=sum((len(r['fields']) for r in records)), source_unchanged=True)))
