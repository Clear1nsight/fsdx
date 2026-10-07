"""Native ObjectStore allocation tag grammar corroborated by static client code.

This decodes allocation boundaries only, independent of physical page selection.
Caller supplies dynamic schema sizes. It does not prove source liveness, map
cluster offsets, or decode stored pointer targets.
"""
from fsd_decoder.resources.loader import load_json
BOOTSTRAP = load_json('bootstrap_sizes.json')
BOOTSTRAP_TYPES = {r['tag']: r for r in BOOTSTRAP['entries']}
PRIMITIVES = {k: v for k, v in BOOTSTRAP_TYPES.items() if k <= 42}

class TagError(ValueError):
    pass

def regions(payload):
    if len(payload) < 2 or len(payload) % 2:
        raise TagError('Incomplete tag words')
    flags, architecture = payload[:2]
    if architecture != 17:
        raise TagError(f'Unsupported architecture {architecture:#x}')
    order = 'big' if flags & 128 else 'little'
    huge = bool(flags & 4)
    header = 4 if flags & 64 else 2
    if len(payload) < header:
        raise TagError('Truncated displaced header')
    initial = -int.from_bytes(payload[2:4], order) if header == 4 else 0
    words = (len(payload) - header) // 2
    tagwords = words if huge or words <= 8 else (words * 8 + 8) // 9
    indexwords = 0 if huge or words <= 8 else (tagwords - 1) // 8
    if tagwords + indexwords != words:
        raise TagError('Invalid tag/index partition')
    return dict(flags=flags, architecture=architecture, huge=huge, byte_order=order, header_bytes=header, tag_word_count=tagwords, index_word_count=indexwords, tag_end=header + tagwords * 2, initial_offset=initial)

def decode_tags(payload, sizes, validate_index=True, max_records=1000000, range_start=0):
    sizes = {**BOOTSTRAP_TYPES, **sizes}
    framing = regions(payload)
    cursor = framing['header_bytes']
    end = framing['tag_end']
    offset = framing['initial_offset'] + range_start
    out = []
    if not 0 <= range_start <= 4096 or range_start % 4:
        raise TagError('Invalid beginning free-space byte count')

    def word():
        nonlocal cursor
        if cursor + 2 > end:
            raise TagError('Truncated tag argument')
        val = int.from_bytes(payload[cursor:cursor + 2], framing['byte_order'])
        cursor += 2
        return val

    def wide():
        return word() << 16 | word()
    while cursor < end:
        begin = cursor
        raw = word()
        tag = raw & ~16384
        exported = bool(raw & 16384)
        repeat = 1
        count = 1
        if 15104 <= tag <= 15359:
            repeat = tag - 15102
            rawtype = word()
            if rawtype & 49152:
                raise TagError('Unsupported flagged repeated type')
            tag = rawtype
        vector = bool(tag & 32768)
        base = tag & 32767
        if vector:
            count = wide() if framing['huge'] else word() + 1
        detail = {}
        prefix = 0
        typ = {}
        if not vector and 15360 <= base <= 16383:
            size = (base & 1023) * 4
            name = 'free_space_candidate'
            stride = size
            detail['placeholder'] = size == 0
        elif not vector and 14848 <= base <= 15103:
            count = base & 255
            size = count + 3 & ~3
            stride = 1
            name = 'inline_char_bytes'
            detail['element_size'] = 1
        else:
            if base in PRIMITIVES:
                typ = PRIMITIVES[base]
                esize = typ['size']
                align = typ['alignment']
                name = typ['name']
            elif base in sizes:
                typ = sizes[base]
                esize = typ['size']
                align = typ.get('binding', {}).get('alignment', 4)
                name = typ['name']
                if vector:
                    prefix = 16
                if esize % 4:
                    raise TagError('Unsupported class size alignment')
            else:
                raise TagError(f'Unknown native type {base:#x}')
            if count == 0:
                raise TagError('Zero array element count')
            stride = (esize + align - 1) // align * align
            size = (count - 1) * stride + esize + prefix + 3 & ~3
            detail.update(element_size=esize, element_stride=stride, array_header_size=prefix)
            if vector:
                name += '[]'
        if typ.get('needs_discriminants', False):
            if framing['huge']:
                detail['discriminant_state'] = 'not_stored_in_huge_descriptor'
            else:
                discriminants = word()
                detail['discriminant_words'] = [word() for _ in range(discriminants)]
        export_id = wide() if exported else None
        if len(out) + repeat > max_records:
            raise TagError('Allocation count limit')
        for instance in range(repeat):
            out.append(dict(native_tag=base, name=name, page_offset=offset, size=size, count=count, vector=vector, tag_relative_offset=begin, tag_word_index=(begin - framing['header_bytes']) // 2, tag_bytes=payload[begin:cursor].hex(), repeat_count=repeat, instance_index=instance, export_id=export_id, **detail))
            offset += size
    first_by_block = {}
    for record in out:
        first_by_block.setdefault(record['tag_word_index'] // 8, record)
    indexes = []
    for i in range(1, framing['index_word_count'] + 1):
        val = int.from_bytes(payload[-2 * i:len(payload) - 2 * i + 2 if i > 1 else None], framing['byte_order'])
        position = val >> 11 & 15
        expected = (val & 2047) * 4
        first = first_by_block.get(i)
        if position == 8:
            valid = first is None
            observed = None
        else:
            observed = first
            valid = bool(observed and observed['tag_word_index'] % 8 == position and (observed['page_offset'] == expected))
            if first is None and i * 8 + position == framing['tag_word_count']:
                valid = expected == min(offset, 4096)
        check = dict(block=i, raw_word=val, tag_position=position, object_offset=expected, valid=valid)
        indexes.append(check)
        if validate_index and (not valid):
            raise TagError(f'Tag index disagrees in block {i}')
    return dict(framing=framing, initial_offset=framing['initial_offset'] + range_start, begin_free_bytes=range_start, final_offset=offset, covered_bytes=offset - framing['initial_offset'] - range_start, records=out, indexes=indexes, all_indexes_valid=all((x['valid'] for x in indexes)))
parse_tag_payload = decode_tags

def infer_begin_free_from_indexes(payload, sizes):
    """Diagnostic corroboration of external beginning free-space bytes.

    This is not a free-space metadata reader. It requires at least two native
    seek entries to agree independently on the same omitted positive prefix,
    then reparses and validates every index. Production callers should supply
    the page-free-space record's first field directly.
    """
    trace = decode_tags(payload, sizes, validate_index=False)
    deltas = []
    for index in trace['indexes']:
        if index['tag_position'] >= 8 or index['object_offset'] >= 4096:
            continue
        target = index['block'] * 8 + index['tag_position']
        records = [r for r in trace['records'] if r['tag_word_index'] == target]
        if records:
            deltas.append(index['object_offset'] - records[0]['page_offset'])
    if len(deltas) < 2 or len(set(deltas)) != 1:
        raise TagError('No unique multiply corroborated beginning-free offset')
    start = deltas[0]
    if not 0 <= start <= 4096 or start % 4:
        raise TagError('Inferred beginning-free offset invalid')
    result = decode_tags(payload, sizes, range_start=start)
    result['begin_free_evidence'] = dict(kind='native_seek_index_inference', agreeing_index_entries=len(deltas), metadata_record_decoded=False)
    return result
