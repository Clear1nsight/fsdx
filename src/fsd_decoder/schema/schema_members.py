"""Schema-owned member recovery without specimen offsets or runtime code recipes.

Logical schema pages are constrained by compact descriptor self references,
corroborated class names and reciprocal class/member-list ownership. Unknown
pages and descriptor types remain explicitly unresolved. Pointer words are
never treated as physical addresses.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from fsd_decoder.schema.object_records import infer_schema, version_layout, occurrences, LOW22, ObjectRecoveryError
from fsd_decoder.schema.probe_types import recover_sizes, compact_dictionary
from fsd_decoder.core.diagnostics import RejectedCandidates, contextual, write_rejection_report, error_category, compact_context, require_source_failure

class SchemaError(ValueError):
    pass

class MemberSchema:

    CLASS_CANDIDATE_EVIDENCE_LIMIT = 4096

    def __init__(self, data, schema_extents=None, native_directory=True):
        self._rejection_diagnostics = RejectedCandidates()
        self.source_size = len(data)
        self.schema_extents = []
        if schema_extents is None and native_directory:
            from fsd_decoder.native.native_directory import parse_database_directory
            directory = parse_database_directory(data)
            schema_extents = [e for e in directory['effective_extents'] if e['segment'] == 0 and e['cluster'] == 0]
        if schema_extents is not None:
            self.schema_extents = sorted(schema_extents, key=lambda e: e['logical_start'])
            if not self.schema_extents:
                raise SchemaError('No native schema extents')
            end = 0
            parts = []
            for e in self.schema_extents:
                if e['logical_start'] != end or e.get('component', 0) != 0 or e['length'] <= 0:
                    raise SchemaError('Schema extent gap/overlap/component')
                p = e['physical_start']
                n = e['length']
                if p < 0 or p + n > len(data):
                    raise SchemaError('Schema extent outside file')
                parts.append(data[p:p + n])
                end += n
            data = b''.join(parts)
        self.data = data
        self.schema = infer_schema(data)
        self.maps = {}
        self.evidence = collections.defaultdict(list)
        self.sizes, self.size_evidence = recover_sizes(data)
        self.dictionary = compact_dictionary(data)
        self.add_map(0, self.schema.origin, 'initial schema anchor')
        if self.schema_extents:
            if self.schema.origin != 0:
                raise SchemaError('Native schema origin disagrees')
            for page in range((len(data) + 4095) // 4096):
                self.add_map(page, page * 4096, 'sequential native directory schema extent')
        for r in self.dictionary:
            logical = r['descriptor_logical_offset']
            physical = r['descriptor_offset']
            low, high = struct.unpack_from('<II', data, physical - 8)
            if high >> 22 and (not high & LOW22) and (low == logical):
                self.add_map(logical // 4096, physical - logical % 4096, 'compact descriptor self reference')
        for r in self.size_evidence['name_pages']:
            self.add_map(r['logical_page'], r['physical_page'], 'three or more unique class names')
        v = version_layout(self.schema)
        for key in ('version_class', 'string_class', 'version_member', 'string_member'):
            r = v[key]
            for k in ('descriptor_offset', 'name_offset'):
                physical = r[k]
                logical = physical - self.schema.origin
                self.add_map(logical // 4096, physical - logical % 4096, 'verified initial Version/String layout')
        for key in ('pointer_type_offset', 'element_type_offset', 'element_name_offset'):
            physical = v[key]
            logical = physical - self.schema.origin
            self.add_map(logical // 4096, physical - logical % 4096, 'verified initial primitive/pointer layout')
        self.member_code = self.u32(v['version_member']['descriptor_offset'])
        self.member_node_code = self.u32(self.schema.local(v['version_class']['name_reference_offset'] + 56))
        self.class_code = self.u32(v['version_class']['descriptor_offset'])
        self.class_body_code = self.u32(v['version_class']['name_reference_offset'] - 8)
        self.pointer_code = self.u32(v['pointer_type_offset'])
        self.primitive_code = self.u32(v['element_type_offset'])
        self.nodes = [p for p in occurrences(data, struct.pack('<I', self.member_node_code)) if p % 8 == 0 and self.schema.code_slot(p)]
        self.classes = {}
        self.by_offset = {}
        self.type_cache = {}
        self.verified_field_members = set()
        self.native_descriptors = {}
        self.native_type_pointer_resolver = None
        self.base_code = self.u32(self.schema.local(v['version_class']['descriptor_offset'] + 88))
        self.base_nodes = [p for p in occurrences(data, struct.pack('<I', self.base_code)) if p % 8 == 0 and self.schema.code_slot(p)]
        self.anchor_primitives()
        self.find_classes()
        for _ in range(12):
            before = len(self.maps)
            for c in list(self.classes.values()):
                self.anchor_bases(c)
                self.anchor_members(c)
            self.find_classes()
            if len(self.maps) == before:
                break
        for c in self.classes.values():
            try:
                p = self.resolve(c['descriptor_offset'] + 88)
                if p and self.ref(p + 48) == self.logical(c['descriptor_offset']):
                    self.base_code = self.u32(p)
                    break
            except SchemaError as exc:
                self.rejection_diagnostics.reject(exc, phase='initial_base_anchor', descriptor_offset=c['descriptor_offset'], name=c['name'])

    @property
    def rejection_diagnostics(self):
        if not hasattr(self, '_rejection_diagnostics'):
            self._rejection_diagnostics = RejectedCandidates()
        return self._rejection_diagnostics

    def write_rejection_diagnostics(self, log_directory=None):
        return write_rejection_report(self.rejection_diagnostics, context=dict(phase='schema_discovery'), log_directory=log_directory)

    def span(self, p, n):
        if p < 0 or n < 0 or p + n > len(self.data):
            raise SchemaError('Out of range schema span')
        return self.data[p:p + n]

    def u32(self, p):
        return struct.unpack('<I', self.span(p, 4))[0]

    def ref(self, p, nullable=False):
        low, high = struct.unpack('<II', self.span(p, 8))
        if low == high == 0:
            if nullable:
                return None
            raise SchemaError('Null schema reference')
        if high & LOW22:
            raise SchemaError('Schema reference requires unknown relocation context')
        return low

    def add_map(self, page, physical, why):
        if physical < 0 or physical % 512 or physical >= len(self.data):
            raise SchemaError('Invalid schema page anchor')
        if page in self.maps and self.maps[page] != physical:
            raise SchemaError('Conflicting schema page anchors')
        self.maps[page] = physical
        if why not in self.evidence[page]:
            self.evidence[page].append(why)

    def physical(self, logical):
        if logical is None:
            return None
        if logical // 4096 not in self.maps:
            raise SchemaError(f'Unmapped schema page {logical // 4096}')
        return self.maps[logical // 4096] + logical % 4096

    def resolve(self, p, nullable=True):
        return self.physical(self.ref(p, nullable))

    def logical(self, physical):
        choices = [page * 4096 + physical - base for page, base in self.maps.items() if base <= physical < base + 4096]
        if len(choices) != 1:
            raise SchemaError('Unknown or ambiguous reverse schema mapping')
        return choices[0]

    def text(self, p, allow_empty=False):
        raw = self.span(p, min(256, len(self.data) - p))
        stop = raw.find(b'\x00')
        if stop < 0:
            raise SchemaError('Unterminated schema text')
        try:
            s = raw[:stop].decode('ascii')
        except UnicodeDecodeError as exc:
            raise SchemaError('Non-ASCII schema text') from exc
        if not s and (not allow_empty) or any((ord(c) < 32 for c in s)):
            raise SchemaError('Invalid schema text')
        return s

    @contextual('primitive_descriptor', p='descriptor_offset')
    def primitive_descriptor(self, p):
        if not self.schema.code_slot(p) or self.ref(p + 8) != 256:
            raise SchemaError('Not primitive type')
        size = self.u32(p + 16)
        if size not in (1, 2, 4, 8, 10, 12, 16):
            raise SchemaError('Not primitive width')
        try:
            name = self.text(self.resolve(p + 40, False))
        except SchemaError as exc:
            self.rejection_diagnostics.reject(exc, phase='primitive_name', descriptor_offset=p)
            if not self.schema.code_slot(p - 16):
                raise SchemaError('No numeric name base')
            name = self.text(self.resolve(p - 8, False))
        match = re.fullmatch('([1248]|10|12|16) byte (?:unsigned |signed )?(?:(?:ieees|ieeed|vaxf|vaxd|vaxg|x87|sparc|ibm|unknown|alpha) )?(?:char|short|int|long|long long|float|double|long double|bool)', name)
        if name in ('__int64', 'unsigned __int64') and size == 8:
            pass
        elif not match or int(match[1]) != size:
            raise SchemaError('Unknown primitive name/width')
        return dict(kind='primitive', descriptor_offset=p, size=size, name=name)

    def anchor_primitives(self):
        primitives = []
        for token in occurrences(self.data, struct.pack('<I', 256)):
            p = token - 8
            if p < 0 or p % 8 or p + 48 > len(self.data):
                continue
            try:
                primitives.append(self.primitive_descriptor(p))
            except (SchemaError, ObjectRecoveryError) as exc:
                self.rejection_diagnostics.reject(exc, phase='primitive_candidate', descriptor_offset=p)
        anchors = collections.defaultdict(set)
        for base in list(self.maps.values()):
            for p in range(base, base + 4096, 8):
                try:
                    low = self.ref(p)
                except SchemaError as exc:
                    self.rejection_diagnostics.reject(exc, phase='primitive_reference', descriptor_offset=p)
                    continue
                if low // 4096 in self.maps:
                    continue
                for d in primitives:
                    physical = d['descriptor_offset']
                    if low % 512 == physical % 512:
                        pagebase = physical - low % 4096
                        if pagebase >= 0 and pagebase % 512 == 0:
                            anchors[low // 4096, pagebase].add((low, d['name']))
        alias_refs = collections.defaultdict(set)
        for base in list(self.maps.values()):
            for p in range(base, base + 4096 - 48, 8):
                try:
                    if not self.schema.code_slot(p) or self.ref(p + 8) != 256:
                        continue
                    name = self.text(self.resolve(p + 24, False))
                    low = self.ref(p + 16)
                    if low // 4096 not in self.maps:
                        alias_refs[low // 4096].add(low)
                except (SchemaError, ObjectRecoveryError) as exc:
                    self.rejection_diagnostics.reject(exc, phase='primitive_alias', descriptor_offset=p)
        bypage = collections.defaultdict(list)
        for (page, base), proof in anchors.items():
            if len(proof) < 3:
                continue
            try:
                if not all((self.schema.code_slot(base + low % 4096) and self.ref(base + low % 4096 + 8) == 256 for low in alias_refs[page])):
                    continue
            except (SchemaError, ObjectRecoveryError) as exc:
                self.rejection_diagnostics.reject(exc, phase='primitive_page_anchor', descriptor_offset=base)
                continue
            bypage[page].append(base)
        for page, bases in bypage.items():
            if len(bases) == 1:
                self.add_map(page, bases[0], 'three named primitive target references')

    def find_classes(self):
        candidates = []
        for token in occurrences(self.data, struct.pack('<I', 256)):
            d = token - 8
            q = d + 24
            pos = d + 16
            if d % 8 or d < 0 or d + 80 > len(self.data):
                continue
            try:
                if not self.schema.code_slot(d) or not self.schema.code_slot(d + 16) or self.u32(d + 8) != 256 or (self.u32(q + 48) not in (0, 1)):
                    continue
                name = self.text(self.resolve(q, False), allow_empty=True)
                size = self.u32(q + 52)
                if not name:
                    name = f'<anonymous_schema_type_0x{d:x}>'
                if not 0 < size <= 1048576:
                    continue
                candidates.append(dict(name=name, descriptor_offset=d, size=size, name_offset=self.resolve(q, False), class_kind_bits=self.u32(d + 140) & 7))
            except (SchemaError, ObjectRecoveryError) as exc:
                self.rejection_diagnostics.reject(exc, phase='class_candidate', descriptor_offset=d)
                continue
        names = collections.defaultdict(list)
        for c in candidates:
            names[c['name']].append(c)
        self.classes = {n: cs[0] for n, cs in names.items() if len(cs) == 1}
        self.by_offset = {c['descriptor_offset']: c for c in self.classes.values()}
        # Final-pass evidence is distinct from class admission. A retention
        # cap must never admit an ambiguous name or omit accepted layouts.
        retained = {}
        limit = self.CLASS_CANDIDATE_EVIDENCE_LIMIT
        for candidate in candidates[:limit]:
            count = len(names[candidate['name']])
            row = dict(candidate, candidate_count_for_name=count,
                status='DUPLICATE_NAME_AMBIGUITY' if count > 1 else 'ACCEPTED_UNIQUE_NAME')
            if count > 1:
                row['reason'] = 'REPEATED_SOURCE_CLASS_NAME'
            retained[str(candidate['descriptor_offset'])] = row
        self.class_candidate_evidence = dict(status='FINAL_PASS',
            scope='STRUCTURALLY_ACCEPTED_CLASS_DESCRIPTORS',
            descriptor_address_space='segment=0 cluster=0 logical bytes' if self.schema_extents else 'physical file bytes',
            candidate_limit=limit, observed_count=len(candidates),
            retained_count=len(retained), truncated_count=len(candidates) - len(retained),
            complete=len(candidates) == len(retained), accepted_count=len(self.classes),
            ambiguous_candidate_count=sum(len(rows) for rows in names.values() if len(rows) > 1),
            ambiguous_name_count=sum(len(rows) > 1 for rows in names.values()), candidates=retained)

    def anchor_bases(self, c):
        d = c['descriptor_offset']
        try:
            low = self.ref(d + 88, True)
        except SchemaError as exc:
            self.rejection_diagnostics.reject(exc, phase='base_reference', descriptor_offset=d, name=c['name'])
            return
        seen = set()
        while low is not None and low not in seen:
            seen.add(low)
            choices = []
            for p in self.base_nodes:
                if p % 512 != low % 512:
                    continue
                try:
                    own = self.ref(p + 48)
                    if d % 512 != own % 512 or self.ref(p + 24) != 256:
                        continue
                    if own // 4096 in self.maps and self.physical(own) != d:
                        continue
                    if low // 4096 in self.maps and self.physical(low) != p:
                        continue
                    off = self.u32(p + 32)
                    size = self.u32(p + 56)
                    if not 0 < size <= c['size'] or off + size > c['size']:
                        continue
                    choices.append((p, own))
                except SchemaError as exc:
                    self.rejection_diagnostics.reject(exc, phase='base_candidate', descriptor_offset=p, name=c['name'])
                    continue
            if len(choices) != 1:
                return
            p, own = choices[0]
            self.add_map(own // 4096, d - own % 4096, 'class/base reciprocal owner')
            self.add_map(low // 4096, p - low % 4096, 'class/base reciprocal list link')
            try:
                low = self.ref(p + 16, True)
            except SchemaError as exc:
                self.rejection_diagnostics.reject(exc, phase='base_list_link', descriptor_offset=p, name=c['name'])
                return

    def anchor_members(self, c):
        owner = c['descriptor_offset'] + 16
        try:
            low = self.ref(c['descriptor_offset'] + 80, True)
        except SchemaError as exc:
            self.rejection_diagnostics.reject(exc, phase='member_reference', descriptor_offset=c['descriptor_offset'], name=c['name'])
            return
        seen = set()
        while low is not None and low not in seen:
            seen.add(low)
            choices = []
            for p in self.nodes:
                if p % 512 != low % 512:
                    continue
                try:
                    own = self.ref(p + 24)
                    if owner % 512 != own % 512:
                        continue
                    if own // 4096 in self.maps and self.physical(own) != owner:
                        continue
                    if low // 4096 in self.maps and self.physical(low) != p:
                        continue
                    name = self.text(self.resolve(p + 40, False))
                    if self.u32(p + 32) != self.member_code or self.ref(p + 56) != 256:
                        continue
                    if self.u32(p + 72) >= c['size']:
                        continue
                    choices.append((p, own, name))
                except SchemaError as exc:
                    self.rejection_diagnostics.reject(exc, phase='member_candidate', descriptor_offset=p, name=c['name'])
                    continue
            if len(choices) != 1:
                return
            p, own, name = choices[0]
            self.add_map(own // 4096, owner - own % 4096, 'class/member reciprocal owner')
            self.add_map(low // 4096, p - low % 4096, 'class/member reciprocal list link')
            try:
                low = self.ref(p + 16, True)
            except SchemaError as exc:
                self.rejection_diagnostics.reject(exc, phase='member_list_link', descriptor_offset=p, name=c['name'])
                return

    def register_native_descriptors(self, allocations, pointer_resolver):
        """Register descriptor owners from the current allocation census.

        The callback resolves a logical schema pointer slot through the current
        native PRM, checking its stored bytes and its schema address space.
        A matching vtable alone never authorizes these additional grammars.
        """
        if not callable(pointer_resolver):
            raise SchemaError('Native descriptor PRM resolver required')
        descriptors = {}
        for a in allocations:
            if a.get('segment') != 0 or a.get('cluster') != 0 or a.get('vector'):
                continue
            name = a.get('name')
            size = a.get('size')
            start = a['logical_offset']
            if (name, size) not in (('_Anonymous_indirect_type', 32), ('_Void_type_', 32), ('_Class_type', 144)):
                continue
            self.span(start, size)
            if name == '_Class_type' and self.u32(start + 76) != 0:
                continue
            p = start + 16 if name == '_Void_type_' else start
            if p in descriptors:
                raise SchemaError('Duplicate native descriptor ownership')
            descriptors[p] = dict(native_type=name, allocation_offset=start, allocation_size=size)
        self.native_descriptors = descriptors
        self.native_type_pointer_resolver = pointer_resolver
        self.type_cache.clear()

    def native_type_target(self, slot):
        target = self.native_type_pointer_resolver(slot)
        if target is None:
            raise SchemaError('Null native type target')
        if target != self.ref(slot):
            raise SchemaError('Native PRM and schema reference disagree')
        self.span(target, 1)
        return target

    def _declaration_reference(self, context, slot, nullable=True):
        """Retain the known slot before resolution; failed targets stay null."""
        context['reference_slot_offset'] = slot
        context['reference_target_offset'] = None
        context['reference_logical_offset'] = None
        try:
            target = self.resolve(slot, nullable)
        except SchemaError:
            try:
                context['reference_logical_offset'] = self.ref(slot, nullable)
            except SchemaError:
                pass
            raise
        context['reference_target_offset'] = target
        return target

    def _declaration_failure(self, exc, phase, context, *, prefix_count=0):
        """Serialize fixed-size declaration context plus bounded diagnostics."""
        require_source_failure(exc)
        owner = context['owner_descriptor_offset']
        slot = context['reference_slot_offset']
        selector = f'{phase}:{owner}:{slot}'
        self.rejection_diagnostics.reject(
            exc, phase=phase, descriptor_offset=owner,
            offset=context.get('node_offset'), name=context.get('name'),
            address=dict(offset=slot), type=selector)
        return dict(reason=str(exc)[:1024], error_type=type(exc).__name__,
                    error_category=error_category(exc), diagnostic_selector=selector,
                    failure_context=dict(context), error_context=compact_context(exc=exc),
                    resolved_prefix_count=prefix_count)

    @contextual('schema_type', p='descriptor_offset')
    def type(self, p, stack=()):
        if p is None:
            return dict(kind='unknown', reason='null type')
        if p in stack:
            return dict(kind='recursive', descriptor_offset=p)
        if p in self.type_cache:
            return self.type_cache[p]
        result = dict(kind='unknown', descriptor_offset=p, raw_hex=self.span(p, min(80, len(self.data) - p)).hex())
        context = dict(owner_descriptor_offset=p, reference_slot_offset=None,
                       reference_target_offset=None, target_descriptor_offset=None,
                       type_status='UNSUPPORTED_DESCRIPTOR')
        element = None
        try:
            if p in self.native_descriptors:
                owner = self.native_descriptors[p]
                start = owner['allocation_offset']
                common = dict(descriptor_offset=p, native_ownership=owner, raw_hex=self.span(start, owner['allocation_size']).hex(), evidence='CURRENT_NATIVE_ALLOCATION')
                if owner['native_type'] == '_Anonymous_indirect_type':
                    context['reference_slot_offset'] = p + 16
                    target = self.native_type_target(p + 16)
                    context.update(reference_target_offset=target, target_descriptor_offset=target)
                    flags = int.from_bytes(self.span(p + 24, 2), 'little')
                    underlying = self.type(target, stack + (p,))
                    unknown = flags & ~3
                    result = dict(common, kind='qualified', target_reference_evidence='CURRENT_NATIVE_PRM', size=underlying.get('size') if not unknown else None, underlying=underlying, qualifiers=dict(const=bool(flags & 1), volatile=bool(flags & 2)), qualifier_flags=flags, unknown_qualifier_flags=unknown, qualifier_raw_hex=self.span(p + 24, 2).hex(), target_pointer_raw_hex=self.span(p + 16, 8).hex(), target_descriptor_offset=target, qualifier_status='UNKNOWN_FLAGS' if unknown else 'KNOWN')
                elif owner['native_type'] == '_Void_type_':
                    result = dict(common, kind='void', name='void', size=None, instance_layout_status='UNSIZED_TYPE')
                else:
                    context['reference_slot_offset'] = p + 24
                    name_target = self.native_type_target(p + 24)
                    context['reference_target_offset'] = name_target
                    name = self.text(name_target, allow_empty=True)
                    result = dict(common, kind='incomplete_class', name_reference_evidence='CURRENT_NATIVE_PRM', name=name or f'<anonymous_schema_type_0x{p:x}>', size=None, stored_size=0, class_flags=self.u32(p + 140), instance_layout_status='NO_STORED_INSTANCE_SIZE')
            elif p in self.by_offset:
                c = self.by_offset[p]
                result = dict(kind='union' if c['class_kind_bits'] == 2 else 'class', descriptor_offset=p, name=c['name'], size=c['size'])
            elif self.u32(p) == self.pointer_code and self.ref(p + 8) == 256:
                size = self.u32(p + 16)
                if size not in (4, 8):
                    raise SchemaError('Unsupported pointer width')
                target = self._declaration_reference(context, p + 32, False)
                context['target_descriptor_offset'] = target
                result = dict(kind='pointer', descriptor_offset=p, size=size, element=self.type(target, stack + (p,)))
            elif self.u32(p + 16) == 0 and 0 < self.u32(p + 20) <= 10000000 and (self.ref(p + 8) == 256):
                target = self._declaration_reference(context, p + 24, False)
                context['target_descriptor_offset'] = target
                element = self.type(target, stack + (p,))
                count = self.u32(p + 20)
                if not element.get('size'):
                    context['type_status'] = 'UNKNOWN_ARRAY_ELEMENT_SIZE'
                    raise SchemaError('Unknown array element size')
                result = dict(kind='array', descriptor_offset=p, size=count * element['size'], count=count, element=element)
            elif self.u32(p + 16) in (1, 2, 4, 8, 10, 12, 16) and self.ref(p + 8) == 256:
                try:
                    result = self.primitive_descriptor(p)
                except SchemaError as exc:
                    require_source_failure(exc)
                    self.rejection_diagnostics.reject(exc, phase='primitive_type_candidate', descriptor_offset=p)
                    name = self.text(self._declaration_reference(context, p + 32, False))
                    result = dict(kind='enum', descriptor_offset=p, size=self.u32(p + 16), name=name, enumerators=self.enum_literals(p))
            elif self.schema.code_slot(p) and self.ref(p + 8) == 256:
                name = self.text(self._declaration_reference(context, p + 24, False))
                target = self._declaration_reference(context, p + 16, False)
                context['target_descriptor_offset'] = target
                if not re.fullmatch('[\\w :<>,*&]+', name):
                    raise SchemaError('Invalid alias name')
                underlying = self.type(target, stack + (p,))
                if underlying['kind'] in ('unknown', 'recursive'):
                    raise SchemaError('Unknown alias underlying type')
                result = dict(kind='alias', descriptor_offset=p, name=name, size=underlying.get('size'), underlying=underlying)
        except (SchemaError, ObjectRecoveryError) as exc:
            result.update(self._declaration_failure(exc, 'type_candidate', context))
            result['type_status'] = context['type_status']
            if element is not None:
                result['element'] = element
            if p in self.native_descriptors:
                owner = self.native_descriptors[p]
                result.update(native_ownership=owner, raw_hex=self.span(owner['allocation_offset'], owner['allocation_size']).hex())
        self.type_cache[p] = result
        return result

    def enum_literals(self, p):
        q = self.resolve(p + 56)
        seen = set()
        result = []
        while q is not None:
            if q in seen or len(seen) >= 65536:
                raise SchemaError('Cyclic/excessive enum literals')
            seen.add(q)
            if self.resolve(q + 40, False) != p or self.ref(q + 8) != 256:
                raise SchemaError('Enumerator owner mismatch')
            result.append(dict(name=self.text(self.resolve(q + 16, False)), value=struct.unpack('<i', self.span(q + 32, 4))[0], descriptor_offset=q))
            q = self.resolve(q + 24)
        return result

    @contextual('schema_layout', name='name')
    def layout(self, name, stack=()):
        if name not in self.classes:
            raise SchemaError('Unknown class')
        if name in stack:
            raise SchemaError('Cyclic inheritance')
        c = self.classes[name]
        d = c['descriptor_offset']
        result = dict(c, members=[], bases=[], unresolved=[])
        context = dict(owner_descriptor_offset=d, name=name, node_offset=None,
                       member_descriptor_offset=None, target_descriptor_offset=None,
                       reference_slot_offset=d + 80, reference_target_offset=None)
        try:
            p = self._declaration_reference(context, d + 80)
            seen = set()
            while p is not None:
                context.update(node_offset=p, target_descriptor_offset=None)
                if 'member_descriptor_offset' in context:
                    context['member_descriptor_offset'] = None
                else:
                    context['base_descriptor_offset'] = p
                if p in seen:
                    raise SchemaError('Cyclic member list')
                seen.add(p)
                if self._declaration_reference(context, p + 24, False) != d + 16:
                    raise SchemaError('Member owner mismatch')
                if p in self.verified_field_members:
                    context['member_descriptor_offset'] = p + 32
                    storage = self.u32(p + 76) & 3
                    mname = self.text(self._declaration_reference(context, p + 40, False))
                    if storage:
                        result['unresolved'].append(dict(kind='non_instance_storage', name=mname, storage_class=storage, descriptor_offset=p + 32))
                        p = self._declaration_reference(context, p + 16)
                        continue
                    off = self.u32(p + 80)
                    bit = self.span(p + 84, 1)[0]
                    width = self.span(p + 88, 1)[0]
                    off += bit // 8
                    bit %= 8
                    target = self._declaration_reference(context, p + 64, False)
                    context['target_descriptor_offset'] = target
                    typ = self.type(target)
                    base = typ
                    while base['kind'] in ('alias', 'qualified'):
                        if base.get('unknown_qualifier_flags'):
                            raise SchemaError('Unknown bitfield qualifiers')
                        base = base['underlying']
                    if base['kind'] not in ('primitive', 'enum') or not base.get('size') or any((t in base.get('name', '') for t in ('float', 'double'))):
                        raise SchemaError('Unsupported bitfield type')
                    if not 0 < width <= base['size'] * 8:
                        raise SchemaError('Invalid bitfield width')
                    size = (bit + width + 7) // 8
                    if off + size > c['size']:
                        raise SchemaError('Bitfield extent outside class')
                    signed = base['kind'] == 'enum' or ('unsigned' not in base.get('name', '') and (not base.get('name', '').endswith(' bool')))
                    mask = (1 << width) - 1 << bit
                    result['members'].append(dict(name=mname, offset=off, descriptor_offset=p + 32, type=typ, bitfield=dict(bit_offset=bit, bit_width=width, storage_size=size, signed=signed, mask_hex=mask.to_bytes(size, 'little').hex()), native_descriptor_type='_Field_member_variable'))
                elif self.u32(p) == self.member_node_code and self.u32(p + 32) == self.member_code:
                    context['member_descriptor_offset'] = p + 32
                    off = self.u32(p + 72)
                    mname = self.text(self._declaration_reference(context, p + 40, False))
                    storage = self.u32(p + 76) & 3
                    if storage:
                        result['unresolved'].append(dict(kind='non_instance_storage', name=mname, storage_class=storage, descriptor_offset=p + 32))
                        p = self._declaration_reference(context, p + 16)
                        continue
                    if off >= c['size']:
                        raise SchemaError('Member outside class')
                    target = self._declaration_reference(context, p + 64, False)
                    context['target_descriptor_offset'] = target
                    typ = self.type(target)
                    if typ.get('size') and off + typ['size'] > c['size']:
                        raise SchemaError('Member extent outside class')
                    result['members'].append(dict(name=mname, offset=off, descriptor_offset=p + 32, type=typ))
                else:
                    result['unresolved'].append(dict(kind='non_variable_member', descriptor_offset=p, raw_hex=self.span(p, 48).hex()))
                p = self._declaration_reference(context, p + 16)
        except SchemaError as exc:
            result['unresolved'].append(dict(kind='member_list', **self._declaration_failure(exc, 'member_list', context, prefix_count=len(result['members']))))
        context = dict(owner_descriptor_offset=d, name=name, node_offset=None,
                       base_descriptor_offset=None, target_descriptor_offset=None,
                       reference_slot_offset=d + 88, reference_target_offset=None)
        try:
            p = self._declaration_reference(context, d + 88)
            seen = set()
            while p is not None:
                context.update(node_offset=p, target_descriptor_offset=None)
                if 'member_descriptor_offset' in context:
                    context['member_descriptor_offset'] = None
                else:
                    context['base_descriptor_offset'] = p
                if p in seen:
                    raise SchemaError('Cyclic base list')
                seen.add(p)
                if self.base_code is None or self.u32(p) != self.base_code or self._declaration_reference(context, p + 48, False) != d:
                    raise SchemaError('Base owner mismatch')
                off = self.u32(p + 32)
                target = self._declaration_reference(context, p + 40, False)
                context['target_descriptor_offset'] = target
                typ = self.type(target)
                size = self.u32(p + 56)
                if typ['kind'] != 'class' or typ['size'] != size or off + size > c['size']:
                    raise SchemaError('Base extent mismatch')
                result['bases'].append(dict(offset=off, type=typ, descriptor_offset=p, layout=self.layout(typ['name'], stack + (name,))))
                p = self._declaration_reference(context, p + 16)
        except SchemaError as exc:
            result['unresolved'].append(dict(kind='base_list', **self._declaration_failure(exc, 'base_list', context, prefix_count=len(result['bases']))))
        return result

    def report(self):
        layouts = {}
        for name in sorted(self.classes):
            try:
                layouts[name] = self.layout(name)
            except SchemaError as exc:
                layouts[name] = dict(name=name, error=str(exc))
        return dict(status='NATIVE_DIRECTORY_SCHEMA_OWNED_GENERIC_MEMBERS' if self.schema_extents else 'BOOTSTRAP_SCHEMA_OWNED_GENERIC_MEMBERS', descriptor_address_space='segment=0 cluster=0 logical bytes' if self.schema_extents else 'physical file bytes', schema_extents=self.schema_extents, classes=layouts, native_type_declarations=[self.type(p) for p in sorted(self.native_descriptors)], native_tags={k: dict(name=v['name'], size=v['size']) for k, v in self.sizes.items()}, schema_pages=[dict(logical_page=k, physical_offset=v, evidence=self.evidence[k]) for k, v in sorted(self.maps.items())], limitations=['Recovered schema fields do not establish runtime allocation identity or liveness.', 'Unknown schema pages, descriptor kinds and pointer targets remain explicit.'])

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    data = args.source.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    s = MemberSchema(data)
    r = s.report()
    r.update(source=str(args.source.resolve()), sha256=sha)
    if hashlib.sha256(args.source.read_bytes()).hexdigest() != sha:
        raise SchemaError('Source changed')
    with args.output.open('x') as f:
        json.dump(r, f, indent=2)
        f.write('\n')
    sidecar = s.write_rejection_diagnostics()
    print(json.dumps(dict(phase='schema_diagnostics', diagnostics_path=str(sidecar), rejected_count=s.rejection_diagnostics.total)), file=sys.stderr)
    print(json.dumps(dict(classes=len(r['classes']), schema_pages=len(r['schema_pages']), direct_members=sum((len(c.get('members', [])) for c in r['classes'].values())))))
