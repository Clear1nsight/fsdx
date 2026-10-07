"""32-bit PRM fields reconstructed from static ObjectStore6.1SP1 x86 code.

No vendor code is loaded or executed. Physical extent mapping is separate.
Sources: o6clien1.dll 1125cf9a..1125d104 (head iteration),
1125d110..1125d190 (32-bit pointer),1125d230..1125d3e1 (named debug print).
"""
import struct

def decode_heads(blob, source_segment=None, source_cluster=None):
    if not blob or len(blob) % 4:
        raise ValueError('PRM must contain complete nonempty words')
    at = 0
    heads = []
    database = {'source_database': True}
    segment = source_segment
    cluster = source_cluster
    cluster_delta = 0
    granularity = 16

    def word():
        nonlocal at
        if at + 4 > len(blob):
            raise ValueError('Truncated PRM optional word')
        value = struct.unpack_from('<I', blob, at)[0]
        at += 4
        return value
    while at < len(blob):
        start = at
        head = word()
        num = head >> 10 & 63
        flags = {'new_database': bool(head & 2147483648), 'new_segment': bool(head & 1073741824), 'new_cluster': bool(head & 536870912), 'new_mapping_granularity': bool(head & 268435456)}
        fields = {}
        if flags['new_database']:
            fields['database_word'] = word()
            database = {'database_word': fields['database_word']}
            segment = num
            cluster = num
            cluster_delta = 0
            granularity = 16
        if flags['new_segment']:
            fields['segment_word'] = word()
            segment = fields['segment_word']
            cluster = num
            cluster_delta = 0
            granularity = 16
        if flags['new_cluster']:
            fields['cluster_word'] = word()
            cluster = fields['cluster_word']
            cluster_delta = 0
        elif not flags['new_database'] and (not flags['new_segment']):
            if cluster is None:
                cluster_delta += num
            else:
                cluster = cluster + num & 4294967295
        if flags['new_mapping_granularity']:
            fields['mapping_granularity_word'] = word()
            granularity = fields['mapping_granularity_word']
        heads.append(dict(head=head, byte_offset=start, raw_hex=blob[start:at].hex(), index=head & 1023, num=num, high_offset_units=head >> 16 & 1023, zero_offset=bool(head & 67108864), pointer_width=64 if head & 134217728 else 32, flags=flags, optional_fields=fields, database_context=dict(database), segment=segment, cluster=cluster, source_cluster_delta=cluster_delta if cluster is None else None, mapping_granularity_pages=granularity))
    if len({h['index'] for h in heads}) != len(heads):
        raise ValueError('Duplicate PRM head index')
    return heads

def decode_pointer(head, word):
    if head['pointer_width'] != 32:
        raise ValueError('64-bit pointer decoding not implemented')
    if not 0 <= word <= 4294967295:
        raise ValueError('Pointer must fit one u32')
    combined = head['high_offset_units'] << 22 | word & 4194303
    cluster = combined if head['zero_offset'] else head['cluster']
    return dict(next_pointer_index=word >> 22, database_context=head['database_context'], segment=head['segment'], cluster=cluster, source_cluster_delta=None if head['zero_offset'] else head['source_cluster_delta'], offset=0 if head['zero_offset'] else combined, mapping_granularity_pages=head['mapping_granularity_pages'])

def decode_pointer64(head, low_word, high_word):
    """Native little-endian 64-bit pointer step, statically observed1125d193..225."""
    if head['pointer_width'] != 64:
        raise ValueError('Expected64-bit PRM head')
    if not all((0 <= w <= 4294967295 for w in (low_word, high_word))):
        raise ValueError('Pointer words must fit u32')
    combined = head['high_offset_units'] << 22 | high_word & 4194303
    return dict(next_pointer_index=high_word >> 22, database_context=head['database_context'], segment=combined if head['zero_offset'] else head['segment'], cluster=low_word if head['zero_offset'] else combined, source_cluster_delta=None, offset=0 if head['zero_offset'] else low_word, mapping_granularity_pages=head['mapping_granularity_pages'])

def walk_decoded_threads(data, page, heads):
    """Walk 32/64-bit PRM chains with exact available-byte bounds.

    A final logical page may contain fewer than 4096 allocated bytes. Every
    referenced field must fit both its native page and the supplied buffer;
    no padding is invented for unallocated bytes.
    """
    if page < 0 or page >= len(data):
        raise ValueError('Missing source page bytes')
    available_end = min(page + 4096, len(data))
    occupied = set()
    chains = []
    for h in heads:
        seen = set()
        pointers = []
        index = h['index']
        while index not in seen:
            width = h['pointer_width'] // 8
            if index * 4 + width > 4096:
                raise ValueError('Cross-page64-bit pointer is not supported')
            slots = set(range(index, index + width // 4))
            if slots & occupied:
                raise ValueError('PRM pointer storage overlaps')
            occupied.update(slots)
            seen.add(index)
            at = page + index * 4
            if at + width > available_end:
                raise ValueError('Pointer field exceeds available source page bytes')
            words = struct.unpack_from('<' + 'I' * (width // 4), data, at)
            target = decode_pointer(h, words[0]) if width == 4 else decode_pointer64(h, *words)
            pointers.append(dict(index=index, physical_offset=at, raw_hex=data[at:at + width].hex(), words=list(words), target=target))
            index = target['next_pointer_index']
        if index != h['index']:
            raise ValueError('Cycle does not close at head')
        chains.append(dict(head=h, pointers=pointers))
    return chains
