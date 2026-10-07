"""Static-derived ObjectStore OSFS metadata hash-directory accessors.

These expose current leaf references only; leaf records and overflow chains are
handled by sibling decoders. No scan of unreferenced historical bytes is used.
Source: o6satmgr 118f2ce0, 118f2fc0, 118f3910, 118f5350, 118f5410.
"""
from dataclasses import dataclass

class TableError(ValueError):
    pass

@dataclass(frozen=True)
class LeafReference:
    direct_sectors: int
    total_sectors: int
    component: int
    sector: int

    @property
    def is_null(self):
        return self.direct_sectors == 0

def decode_entry(raw):
    if len(raw) != 8:
        raise TableError('directory entry must contain eight bytes')
    total, direct = raw[:2]
    if direct > total:
        raise TableError('direct leaf sectors exceed total sectors')
    return LeafReference(direct, total, int.from_bytes(raw[2:4], 'big'), int.from_bytes(raw[4:8], 'big'))

def dimensions(table):
    depth, shift = table['kinds']
    if not 0 <= depth <= 31 or not 0 <= shift <= 32 or depth + shift > 32:
        raise TableError('unsupported directory depth or shift')
    return (depth, shift, 1 << depth, (1 << depth + shift) - 1)

def _read_extents(read, extents, start, size):
    """read(component, physical_byte_offset, size) must return exact bytes."""
    if start < 0 or size < 0:
        raise TableError('negative directory read')
    chunks = []
    for extent in extents:
        length = extent['sector_count'] * 512
        if start >= length:
            start -= length
            continue
        take = min(size, length - start)
        raw = read(extent['component'], extent['sector'] * 512 + start, take)
        if len(raw) != take:
            raise TableError('truncated physical directory extent')
        chunks.append(raw)
        size -= take
        start = 0
        if not size:
            return b''.join(chunks)
    raise TableError('directory entry exceeds current extent allocation')

def lookup(read, table, key):
    depth, shift, count, max_key = dimensions(table)
    if type(key) is not int or key < 0 or key > 4294967295:
        raise TableError('key must be unsigned 32-bit integer')
    if key > max_key:
        return None
    extents = table['extents']
    if depth == 0:
        if not extents:
            return None
        first = extents[0]
        return LeafReference(first['sector_count'], sum((e['sector_count'] for e in extents)), first['component'], first['sector'])
    return decode_entry(_read_extents(read, extents, (key >> shift) * 8, 8))

def ranges(read, table):
    """Yield adjacent runs (min_key, max_key, LeafReference or None).

    Corresponds to native iterator coalescing equal count/address/total fields.
    Zero-count entries retain opaque address bytes; caller must skip is_null.
    """
    depth, shift, count, max_key = dimensions(table)
    if depth == 0:
        yield (0, max_key, lookup(read, table, 0))
        return
    start = 0
    previous = decode_entry(_read_extents(read, table['extents'], 0, 8))
    for index in range(1, count):
        current = decode_entry(_read_extents(read, table['extents'], index * 8, 8))
        if current != previous:
            yield (start << shift, (index << shift) - 1, previous)
            start, previous = (index, current)
    yield (start << shift, max_key, previous)
