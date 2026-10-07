"""Generic compact dictionary scanner for supported native metadata layouts."""
import struct

MAGIC = bytes.fromhex('bd0602000000')

def compact_dictionary(data):
    result = []
    pos = 0
    while (pos := data.find(MAGIC, pos)) >= 0:
        if pos + 7 > len(data):
            break
        length = data[pos + 6]
        name_at = pos + 7 + length
        end = data.find(b'\x00', name_at, name_at + 180)
        if end > name_at and all((32 <= x < 127 for x in data[name_at:end])):
            binding = pos - 16
            if binding >= 0:
                ident, native, active = struct.unpack_from('<HHI', data, binding)
                low, high = struct.unpack_from('<II', data, pos - 8)
                if 1000 <= ident < 10000 and native < 2048 and (active in (0, 1)) and (not high & 4194303):
                    result.append(dict(descriptor_offset=pos, binding_offset=binding, dictionary_id=ident, native_tag=native, binding_active=active, descriptor_logical_offset=low, name=data[name_at:end].decode('ascii'), layout_hex=data[pos + 7:name_at].hex()))
        pos += 1
    return result
