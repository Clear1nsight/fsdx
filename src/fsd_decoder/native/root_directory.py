"""Read native root records through caller-verified logical address resolution.

No physical offsets or source hashes are built in. The caller owns directory
replay and PRM decoding; this module refuses unresolved directory/name pointers.
"""
import struct

def read_native_roots(read, resolve, *, max_roots=100000, max_name=4096):
    """read((segment,cluster,offset),size)->bytes; resolve(address,8bytes)->tuple|None.

 Value/type pointers may remain unresolved and are reported. Directory and name
 pointers must resolve. The source must use the statically corroborated native
 database-header version 2, 8-byte internal-pointer layout.
 """

    def span(addr, size):
        result = read(addr, size)
        if len(result) != size:
            raise ValueError('short logical read')
        return result

    def ptr(addr, raw, required=False):
        target = resolve(addr, raw)
        if target is None:
            if required:
                raise ValueError('unresolved root directory pointer')
            return None
        if len(target) != 3 or any((type(x) is not int or x < 0 for x in target)):
            raise ValueError('invalid resolved logical address')
        return tuple(target)

    def plus(addr, n):
        return (addr[0], addr[1], addr[2] + n)

    def cstring(addr):
        out = bytearray()
        for n in range(max_name):
            b = span(plus(addr, n), 1)
            if b == b'\x00':
                return bytes(out)
            out += b
        raise ValueError('unterminated native root/type name')
    header_addr = (0, 0, 0)
    h = span(header_addr, 112)
    version, flags = struct.unpack_from('<2I', h)
    if version != 2:
        raise ValueError('unsupported native database header version')
    count, capacity = struct.unpack_from('<2I', h, 48)
    if count > capacity or count > max_roots or capacity > max_roots:
        raise ValueError('invalid root array count/capacity')
    array = ptr((0, 0, 56), h[56:64], required=bool(count))
    roots = []
    seen = set()
    names = set()
    for i in range(count):
        slot = plus(array, i * 8)
        raw = span(slot, 8)
        addr = ptr(slot, raw, True)
        if addr in seen:
            raise ValueError('duplicate native root record')
        seen.add(addr)
        record = span(addr, 24)
        name_addr = ptr(addr, record[:8], True)
        name = cstring(name_addr)
        type_target = ptr(plus(addr, 16), record[16:24])
        type_name = None
        type_name_address = None
        if type_target is not None:
            type_name_address = ptr(type_target, span(type_target, 8))
            if type_name_address is not None:
                type_name = cstring(type_name_address)
        if bytes(name) in names:
            raise ValueError('duplicate native root name')
        names.add(bytes(name))
        roots.append({'index': i, 'address': addr, 'record_raw_hex': record.hex(), 'name_address': name_addr, 'name_raw_hex': name.hex(), 'name': name.decode('utf-8', errors='backslashreplace'), 'value_pointer_raw_hex': record[8:16].hex(), 'value_target': ptr(plus(addr, 8), record[8:16]), 'type_pointer_raw_hex': record[16:24].hex(), 'type_target': type_target, 'type_name_address': type_name_address, 'type_name_raw_hex': type_name.hex() if type_name is not None else None, 'type_name': type_name.decode('utf-8', errors='backslashreplace') if type_name is not None else None})
    return {'header_address': header_addr, 'header_raw_hex': h.hex(), 'version': version, 'flags': flags, 'root_count': count, 'root_capacity': capacity, 'array_address': array, 'roots': roots, 'limits': ['Caller must establish current directory and PRM mappings.', 'Root value and type targets may remain unresolved.', 'Header layout follows the recovered ObjectStore 6.1 SP1 native implementation.']}
