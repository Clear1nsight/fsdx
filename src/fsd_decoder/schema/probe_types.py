"""Experimental native type binding to schema sizes, no fixed specimen offsets."""
from fsd_decoder.resources.loader import load_json
import struct
import collections
from dataclasses import asdict
from fsd_decoder.schema.object_records import infer_schema, version_layout, occurrences, LOW22, ObjectRecoveryError
from fsd_decoder.native.native_tag_probe import compact_dictionary, MAGIC

def current_dictionary(data, database, schema_identity=(0, 0)):
    """Read live representation objects and follow their current native pointers.

    The bootstrap _Rep_desc_persist layout is pointer8, u16 ID, u16 tag,
    u32 active flag, pointer8. Its final pointer owns the compact descriptor
    stored in a live native char array. Adjacency has no semantic significance.
    ``data`` is the complete logical schema snapshot used by MemberSchema.
    """
    from fsd_decoder.native.native_allocations import NativeAllocationReader
    bootstrap = load_json('bootstrap_sizes.json')
    types = {r['tag']: r for r in bootstrap['entries']}
    allocations = [a for a in NativeAllocationReader(database, types).iter_allocations(segments=[schema_identity[0]]) if a['cluster'] == schema_identity[1]]
    characters = {a['logical_offset'] + a['array_header_size']: a for a in allocations if a['native_tag'] == 1 and a['vector']}
    result = []
    ids = set()
    active_tags = set()
    for allocation in allocations:
        if allocation['native_tag'] != 140:
            continue
        if allocation['element_size'] != 24:
            raise ValueError('Unsupported representation binding size')
        for index in range(allocation['count']):
            owner = allocation['logical_offset'] + allocation['array_header_size'] + index * allocation['element_stride']
            raw = database.read_at(*schema_identity, owner, 24)
            ident, native, active = struct.unpack_from('<HHI', raw, 8)
            if not 1000 <= ident < 10000 or native >= 2048 or active not in (0, 1):
                raise ValueError('Invalid current representation binding')
            field = database.address(*schema_identity, owner + 16)
            target = database.resolve(field, width=8)
            if target is None or (target.segment, target.cluster) != schema_identity:
                raise ValueError('Representation descriptor target outside schema')
            if target.offset not in characters:
                raise ValueError('Representation descriptor is not a current character allocation')
            character = characters[target.offset]
            pos = target.offset
            limit = pos + character['count']
            if not 0 <= pos < limit <= len(data):
                raise ValueError('Representation descriptor exceeds schema snapshot')
            payload = database.read(target, character['count'])
            if payload != data[pos:limit]:
                raise ValueError('Schema snapshot differs from current descriptor bytes')
            if len(payload) < 9 or payload[:2] != b'\xbd\x06':
                raise ValueError('Unsupported persistent descriptor header')
            flags = struct.unpack_from('<I', payload, 2)[0]
            length = payload[6]
            name_at = 7 + length
            if flags not in (0, 1, 2, 3, 4) or not length or name_at >= len(payload) or (payload[name_at - 1] != 62):
                raise ValueError('Invalid persistent descriptor layout')
            end = payload.find(b'\x00', name_at)
            if end <= name_at or not all((32 <= x < 127 for x in payload[name_at:end])):
                raise ValueError('Invalid persistent descriptor name')
            if ident in ids:
                raise ValueError('Duplicate current dictionary ID')
            if active and native and (native in active_tags):
                raise ValueError('Duplicate current native type binding')
            ids.add(ident)
            if active and native:
                active_tags.add(native)
            result.append(dict(descriptor_offset=pos, name=payload[name_at:end].decode('ascii'), layout_hex=payload[7:name_at].hex(), persistent_flags=flags, alignment=1 << flags, binding_offset=owner + 8, dictionary_id=ident, native_tag=native, binding_active=active, descriptor_logical_offset=pos, binding_evidence='current _Rep_desc_persist allocation and native PRM descriptor reference', binding_allocation_address=asdict(database.address(*schema_identity, owner)), descriptor_reference_address=asdict(field), descriptor_address=asdict(target), descriptor_allocation_count=character['count']))
    return result

def extended_dictionary(data, database=None, schema_identity=(0, 0)):
    """Read current owned bindings when ``database`` is supplied.

    Without a database this retains the historical candidate-only scanner,
    including 8-byte aligned types. It cannot establish allocation liveness.
    bd06 identifies this observed persistent descriptor representation. Its
    following four bytes carry alignment/flags; fixing those bytes to02000000
    incorrectly excludes double-aligned classes. Nonadjacent bindings resolve
    only through descriptor pages already corroborated by adjacent bindings.
    """
    if database is not None:
        return current_dictionary(data, database, schema_identity)
    descriptors = []
    result = []
    for pos in occurrences(data, b'\xbd\x06'):
        if pos + 7 > len(data):
            continue
        flags = struct.unpack_from('<I', data, pos + 2)[0]
        if flags not in (0, 1, 2, 3, 4):
            continue
        length = data[pos + 6]
        name_at = pos + 7 + length
        end = data.find(b'\x00', name_at, name_at + 180)
        if not length or name_at >= len(data) or data[name_at - 1] != 62 or (not name_at < end) or (not all((32 <= x < 127 for x in data[name_at:end]))):
            continue
        descriptor = dict(descriptor_offset=pos, name=data[name_at:end].decode(), layout_hex=data[pos + 7:name_at].hex(), persistent_flags=flags, alignment=1 << flags)
        descriptors.append(descriptor)
        if pos < 16:
            continue
        ident, native, active, low, high = struct.unpack_from('<HHIII', data, pos - 16)
        if 1000 <= ident < 10000 and native < 2048 and (active in (0, 1)) and (high & LOW22 == 0):
            result.append(dict(descriptor, binding_offset=pos - 16, dictionary_id=ident, native_tag=native, binding_active=active, descriptor_logical_offset=low))
    page_maps = {(r['descriptor_offset'] - r['descriptor_logical_offset'] % 4096, r['descriptor_logical_offset'] // 4096) for r in result}
    seen = {r['descriptor_offset'] for r in result}
    for descriptor in descriptors:
        pos = descriptor['descriptor_offset']
        if pos in seen:
            continue
        logicals = {lp * 4096 + pos - pp for pp, lp in page_maps if pp <= pos < pp + 4096}
        if len(logicals) != 1:
            continue
        low = logicals.pop()
        bindings = []
        for ref in occurrences(data, struct.pack('<I', low)):
            if ref % 8 or ref < 8 or ref + 8 > len(data):
                continue
            ident, native, active = struct.unpack_from('<HHI', data, ref - 8)
            high = struct.unpack_from('<I', data, ref + 4)[0]
            if 1000 <= ident < 10000 and native < 2048 and (active in (0, 1)) and (high & LOW22 == 0):
                bindings.append(dict(descriptor, binding_offset=ref - 8, dictionary_id=ident, native_tag=native, binding_active=active, descriptor_logical_offset=low, binding_evidence='unique descriptor reference through corroborated descriptor page'))
        if len(bindings) == 1:
            result.extend(bindings)
    return result

def corroborate_local_members(schema, candidate, binding, version):
    """Corroborate a sparse name page through reciprocal class/member links.

    A compact descriptor self-reference supplies a candidate local translation.
    Require that same translation to resolve the class name, first/member-next
    links, and every reciprocal member-owner pointer. This is deliberately
    limited to classes with at least two members wholly inside that extent.
    """
    origin = binding['descriptor_offset'] - binding['descriptor_logical_offset']
    q = candidate['name_reference_offset']

    def ref(at):
        low, high = struct.unpack('<II', schema.span(at, 8))
        if high & LOW22 or not high >> 22:
            raise ObjectRecoveryError('Unsupported local reference')
        physical = origin + low
        schema.span(physical, 1)
        return physical
    if origin < 0 or origin % 512 or ref(q) != candidate['name_offset']:
        return None
    field_code = schema.u32(version['version_member']['descriptor_offset'])
    list_code = schema.u32(schema.local(version['version_class']['name_reference_offset'] + 56))
    at = ref(q + 56)
    seen = set()
    fields = []
    while True:
        if at in seen or len(seen) > 256:
            raise ObjectRecoveryError('Member-list cycle or excessive count')
        seen.add(at)
        if not schema.code_slot(at) or ref(at + 24) != q - 8:
            raise ObjectRecoveryError('Member ownership/layout disagrees')
        member = dict(list_node_offset=at, owner_reference_offset=at + 24, subtype_opaque=True)
        if schema.u32(at) == list_code and schema.u32(at + 32) == field_code and schema.code_slot(at + 32):
            name = schema.cstring(ref(at + 40))
            offset = schema.u32(at + 72)
            if not name or offset >= candidate['size']:
                raise ObjectRecoveryError('Member outside class')
            member.update(name=name, offset=offset, descriptor_offset=at + 32, subtype_opaque=False)
        fields.append(member)
        if schema.span(at + 16, 8) == bytes(8):
            break
        at = ref(at + 16)
    if len(fields) < 2:
        return None
    return dict(translation_origin=origin, member_owner_checks=len(fields), members=fields)

def recover_sizes(data):
    schema = infer_schema(data)
    v = version_layout(schema)
    dictionary = extended_dictionary(data)
    descriptor_names = {r['descriptor_offset'] + 7 + len(bytes.fromhex(r['layout_hex'])) for r in dictionary}
    texts = collections.defaultdict(list)
    for name in set((r['name'] for r in dictionary)):
        for pos in occurrences(data, name.encode() + b'\x00'):
            if pos not in descriptor_names:
                texts[pos % 512].append((name, pos))
    possible = []
    for pos in occurrences(data, struct.pack('<I', 256)):
        q = pos + 16
        if q % 8 or q < 24 or q + 56 > len(data):
            continue
        if not schema.code_slot(q - 24) or not schema.code_slot(q - 8) or schema.u32(q - 16) != 256 or (schema.u32(q + 48) != 1):
            continue
        low, high = struct.unpack_from('<II', data, q)
        size = schema.u32(q + 52)
        if high & LOW22 or not high >> 22 or (not 0 < size <= 4096):
            continue
        for name, text in texts[low % 512]:
            physical = text - low % 4096
            if physical < 0 or physical % 512:
                continue
            possible.append(dict(name=name, name_offset=text, name_reference_offset=q, schema_size_field=q + 52, size=size, logical_name_page=low // 4096, physical_name_page=physical))
    maps = collections.defaultdict(set)
    for r in possible:
        maps[r['logical_name_page'], r['physical_name_page']].add(r['name'])
    acceptable = {k for k, n in maps.items() if len(n) >= 3}
    bypage = collections.defaultdict(list)
    for k in acceptable:
        bypage[k[0]].append(k[1])
    accepted = [r for r in possible if (r['logical_name_page'], r['physical_name_page']) in acceptable and len(bypage[r['logical_name_page']]) == 1]
    byname = collections.defaultdict(list)
    for r in accepted:
        byname[r['name']].append(r)
    result = {}
    reject = []
    for r in dictionary:
        if not r['native_tag'] or not r['binding_active']:
            continue
        candidates = byname[r['name']]
        if not candidates and r['name'] == 'Fs::Version':
            c = v['version_class']
            candidates = [dict(name=r['name'], name_offset=c['name_offset'], name_reference_offset=c['name_reference_offset'], schema_size_field=c['value_offset'], size=c['size_bytes'], version_member_ownership_checked=True)]
        if not candidates:
            candidates = []
            for candidate in possible:
                if candidate['name'] != r['name']:
                    continue
                try:
                    corroboration = corroborate_local_members(schema, candidate, r, v)
                except ObjectRecoveryError:
                    continue
                if corroboration:
                    candidates.append(dict(candidate, reciprocal_member_evidence=corroboration))
        if len(candidates) != 1:
            reject.append(dict(binding=r, reason='schema class absent or ambiguous', candidate_count=len(candidates)))
            continue
        if r['native_tag'] in result:
            raise ValueError('Duplicate native tag')
        result[r['native_tag']] = dict(binding=r, **candidates[0])
    return (result, dict(name_pages=[dict(logical_page=k[0], physical_page=k[1], distinct_class_names=len(maps[k])) for k in sorted(acceptable) if len(bypage[k[0]]) == 1], rejected=reject, dictionary_candidates=len(dictionary)))
