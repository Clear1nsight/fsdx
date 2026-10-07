"""Experimental schema-guided recovery of the small Fs::Version record.

This reads database bytes, not vendor code. Physical file positions, vtable
addresses, application versions and file hashes are never recovery recipes.
The initial schema extent and local pointer representation are inferred and
cross-checked. General extent/PRM decoding and root identity remain unresolved.
"""
from __future__ import annotations
import re
import struct
LOW22 = (1 << 22) - 1
PAGE_BYTES = 4096
MAX_STRING_BYTES = 256

class ObjectRecoveryError(ValueError):
    """Unsupported, inconsistent or ambiguous structure; do not guess."""

def occurrences(data, value):
    return (m.start() for m in re.finditer(re.escape(value), data))

class Schema:

    def __init__(self, data, origin):
        self.data, self.origin = (data, origin)

    def span(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ObjectRecoveryError('Schema/reference span is outside the file')
        return self.data[offset:offset + size]

    def u32(self, offset):
        return struct.unpack('<I', self.span(offset, 4))[0]

    def local(self, offset):
        """Observed 8-byte schema reference, only within its inferred extent.

        The upper word links pointer locations; a nonzero low-22-bit component
        requires a relocation mapping that this implementation cannot resolve.
        """
        low, thread = struct.unpack('<2I', self.span(offset, 8))
        if thread & LOW22 or not thread >> 22:
            raise ObjectRecoveryError('Schema pointer needs unsupported relocation')
        target = self.origin + low
        self.span(target, 1)
        return target

    def cstring(self, offset):
        raw = self.span(offset, min(MAX_STRING_BYTES, len(self.data) - offset))
        stop = raw.find(b'\x00')
        if stop < 0:
            raise ObjectRecoveryError('Unterminated schema string')
        try:
            return raw[:stop].decode('ascii')
        except UnicodeDecodeError as exc:
            raise ObjectRecoveryError('Unsupported schema text encoding') from exc

    def code_slot(self, offset):
        low, high = struct.unpack('<2I', self.span(offset, 8))
        return low != 0 and high in (0, low)

    def named_references(self, name):
        for text_offset in occurrences(self.data, name.encode('ascii') + b'\x00'):
            logical = text_offset - self.origin
            if not 0 <= logical <= LOW22:
                continue
            for offset in occurrences(self.data, struct.pack('<I', logical)):
                if offset % 8 or offset < self.origin:
                    continue
                try:
                    if self.local(offset) == text_offset:
                        yield (offset, text_offset)
                except ObjectRecoveryError:
                    continue

    def named_descriptor(self, name, kind):
        candidates = []
        for ref, text_offset in self.named_references(name):
            try:
                if not self.code_slot(ref - 8):
                    continue
                if kind == 'class':
                    if not self.code_slot(ref - 24) or self.u32(ref - 16) != 256 or self.u32(ref + 48) != 1:
                        continue
                    value = self.u32(ref + 52)
                    if not 1 <= value <= 4096:
                        continue
                else:
                    if self.u32(ref + 16) != 256:
                        continue
                    self.local(ref + 16)
                    self.local(ref + 24)
                    value = self.u32(ref + 32)
                    if value > 4096:
                        continue
                candidates.append({'name': name, 'name_offset': text_offset, 'name_reference_offset': ref, 'descriptor_offset': ref - (24 if kind == 'class' else 8), 'value_offset': ref + (52 if kind == 'class' else 32), 'size_bytes' if kind == 'class' else 'member_offset': value})
            except ObjectRecoveryError:
                continue
        if len(candidates) != 1:
            raise ObjectRecoveryError(f'Expected one {kind} descriptor for {name}; found {len(candidates)}')
        return candidates[0]

    def check_member(self, cls, field):
        """Check the observed member-list links and owner, not just the name."""
        ref = cls['name_reference_offset']
        current = self.local(ref + 56)
        seen = set()
        for _ in range(16):
            if current in seen:
                break
            seen.add(current)
            if not self.code_slot(current) or self.local(current + 24) != ref - 8:
                break
            if current + 32 == field['descriptor_offset']:
                return
            current = self.local(current + 16)
        raise ObjectRecoveryError(f'Cannot establish {cls['name']}.{field['name']} membership')

def infer_schema(data):
    candidates = set()
    for name_offset in occurrences(data, b'Fs::Version\x00'):
        ref = name_offset - 16
        if ref < 0 or ref % 8:
            continue
        low, thread = struct.unpack_from('<2I', data, ref)
        origin = name_offset - low
        if origin >= 0 and origin % PAGE_BYTES == 0 and (thread & LOW22 == 0) and ((thread >> 22) * 4 == (name_offset + 16) % PAGE_BYTES) and (data[ref + 8:ref + 16] == bytes(8)):
            candidates.add(origin)
    if len(candidates) != 1:
        raise ObjectRecoveryError(f'Expected one initial schema translation; found {len(candidates)}')
    return Schema(data, candidates.pop())

def version_layout(schema):
    version = schema.named_descriptor('Fs::Version', 'class')
    string = schema.named_descriptor('Fs::String', 'class')
    member = schema.named_descriptor('m_versionString', 'field')
    chars = schema.named_descriptor('_strRep', 'field')
    schema.check_member(version, member)
    schema.check_member(string, chars)
    if schema.local(member['name_reference_offset'] + 24) != string['descriptor_offset']:
        raise ObjectRecoveryError('m_versionString type does not resolve to Fs::String')
    pointer_type = schema.local(chars['name_reference_offset'] + 24)
    pointer_bytes = schema.u32(pointer_type + 16)
    element_type = schema.local(pointer_type + 32)
    element_bytes = schema.u32(element_type + 16)
    element_name_offset = schema.local(element_type + 40)
    element_name = schema.cstring(element_name_offset)
    if pointer_bytes != 4 or element_bytes != 1 or element_name != '1 byte char' or (chars['member_offset'] + pointer_bytes != string['size_bytes']) or (member['member_offset'] + string['size_bytes'] != version['size_bytes']) or (member['member_offset'] != pointer_bytes) or (chars['member_offset'] != pointer_bytes):
        raise ObjectRecoveryError('Unsupported Version/String layout')
    return {'schema_origin': schema.origin, 'version_class': version, 'string_class': string, 'version_member': member, 'string_member': chars, 'pointer_type_offset': pointer_type, 'pointer_size_bytes': pointer_bytes, 'element_type_offset': element_type, 'element_name_offset': element_name_offset, 'element_type': element_name, 'element_size_bytes': element_bytes}

def recover_version(data):
    schema = infer_schema(data)
    layout = version_layout(schema)
    size = layout['version_class']['size_bytes']
    field_offset = layout['version_member']['member_offset']
    chars_offset = layout['string_member']['member_offset']
    pointer_offset = field_offset + chars_offset
    expected_word = pointer_offset // 4 << 22 | size
    candidates = []
    for position in occurrences(data, struct.pack('<I', expected_word)):
        start = position - pointer_offset
        if start < 0 or start % 512:
            continue
        if struct.unpack_from('<I', data, start)[0] == 0 or struct.unpack_from('<I', data, start + field_offset)[0] == 0:
            continue
        array_start = start + (expected_word & LOW22)
        end = data.find(b'\x00', array_start, min(len(data), array_start + MAX_STRING_BYTES))
        if end < 0 or end == array_start:
            continue
        raw = data[array_start:end]
        if any((c < 32 or c >= 127 for c in raw)):
            continue
        candidates.append({'class': 'Fs::Version', 'source_offset': start, 'size_bytes': size, 'record_hex': data[start:start + size].hex(), 'fields': {'m_versionString': {'class': 'Fs::String', 'source_offset': start + field_offset, 'size_bytes': layout['string_class']['size_bytes'], '_strRep': {'source_pointer_offset': position, 'encoded_word': expected_word, 'next_pointer_page_offset': pointer_offset, 'target_local_offset': size, 'source_offset': array_start, 'end_offset': end + 1, 'element_type': 'char', 'count_including_nul': len(raw) + 1, 'hex': data[array_start:end + 1].hex(), 'text': raw.decode('ascii')}}}})
    if len(candidates) != 1:
        raise ObjectRecoveryError(f'Expected one Version record candidate; found {len(candidates)}')
    return {'status': 'EXPERIMENTAL_SCHEMA_GUIDED_RECOVERY', 'schema': layout, 'objects': candidates, 'checks': ['named class and field descriptors', 'member ownership links', 'nested member type', 'record/member sizes and offsets', 'pointer and character element types', 'unique self-threaded local record', 'bounded terminated character array'], 'unresolved': ['full file extent and persistent relocation maps', 'native root/object identity and allocation liveness', 'general object and array references', 'native osdump equivalence']}
