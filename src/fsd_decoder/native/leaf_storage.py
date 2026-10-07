"""Bounded reconstruction of statically established ObjectStore leaf storage.

The caller must supply an authoritative table entry. This does not find tables,
select committed copies, or establish liveness. Only component zero is supported.
"""
import struct

class LeafError(ValueError):
    pass

def entry(data):
    if len(data) != 8:
        raise LeafError('Directory entry must contain exactly eight bytes')
    total, direct, component, sector = struct.unpack('>BBHI', data)
    return dict(total_sectors=total, direct_sectors=direct, component=component, sector=sector)

def validate_allocation(allocation):
    total, direct = (allocation['total_sectors'], allocation['direct_sectors'])
    if not 1 <= direct <= total <= 255:
        raise LeafError('Invalid leaf sector counts')
    if allocation['component'] != 0:
        raise LeafError('External file component is unsupported')

def reconstruct(data, allocation):
    validate_allocation(allocation)
    spans = []

    def append_run(component, sector, sectors):
        if component != 0 or sector < 0 or (not 1 <= sectors <= 255):
            raise LeafError('Invalid or external leaf run')
        start, end = (sector * 512, (sector + sectors) * 512)
        if end > len(data):
            raise LeafError('Leaf run exceeds input file')
        if any((start < s['physical_end'] and s['physical_start'] < end for s in spans)):
            raise LeafError('Overlapping physical leaf runs')
        spans.append(dict(physical_start=start, physical_end=end, sectors=sectors))
        return data[start:end]
    raw = append_run(allocation['component'], allocation['sector'], allocation['direct_sectors'])
    n = raw[8]
    if 20 + 7 * n > len(raw):
        raise LeafError('Extent descriptors exceed direct run')
    runs = []
    for i in range(n):
        count, component, sector = struct.unpack_from('>BHI', raw, 20 + 7 * i)
        runs.append((count, component, sector))
    if allocation['direct_sectors'] + sum((r[0] for r in runs)) != allocation['total_sectors']:
        raise LeafError('Fragmented leaf run totals disagree')
    for count, component, sector in runs:
        raw += append_run(component, sector, count)
    slots = int.from_bytes(raw[2:4], 'big')
    slot_start = 20 + (7 * n + 7) // 8 * 8
    payload_start = slot_start + 8 * slots
    if payload_start > len(raw):
        raise LeafError('Slot directory exceeds leaf allocation')
    following = dict(total_sectors=raw[9], direct_sectors=raw[10], component=int.from_bytes(raw[11:13], 'big'), sector=int.from_bytes(raw[13:17], 'big'))
    if following['direct_sectors']:
        validate_allocation(following)
    elif following['total_sectors']:
        raise LeafError('Nonempty overflow link without direct sectors')
    return {'bytes': raw, 'physical_spans': spans, 'extent_count': n, 'slot_count': slots, 'slot_start': slot_start, 'payload_start': payload_start, 'next_overflow': following if following['direct_sectors'] else None}

def lookup(parsed, key):
    """Reproduce the read-only exact-key hash probe, including empty-slot stop.

    A zero-length found value returns None as in the table overflow search.
    This does not choose between authoritative global overflow and primary tables.
    """
    if not 0 <= key < 4294967295:
        raise LeafError('Unsupported lookup key')
    data, n = (parsed['bytes'], parsed['slot_count'])
    if not n:
        raise LeafError('Empty hash directory')
    probe = key
    for attempt in range(min(n, 9999) + 1):
        offset = parsed['slot_start'] + probe % n * 8
        stored, payload_offset, length = struct.unpack_from('>IHH', data, offset)
        if stored == key:
            start = parsed['payload_start'] + payload_offset
            if start + length > len(data):
                raise LeafError('Blob exceeds reconstructed leaf')
            return {'slot_offset': offset, 'payload_offset': start, 'bytes': data[start:start + length]} if length else None
        if stored == 4294967295 and payload_offset == 0:
            return None
        probe = key // n + n // 2 if attempt == 0 else probe + 1
    return None
