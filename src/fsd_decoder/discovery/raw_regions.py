"""Evidence overlay for retained bytes; never infer semantics from byte values.

Uses already compiled ObjectStore representation traces. The caller must retain
their native opcode-table provenance and source binding evidence. These helpers
do not change decoded values, resolve pointers, or discard filler bytes.
"""
from __future__ import annotations

class RawRegionError(ValueError):
    pass
FILLER_OPS = frozenset(range(8, 16)) | {52}
RUNTIME_OPS = frozenset({41, 42, 55, 56, 57, 58, 59})
REFERENCE_OPS = frozenset({23, 24, 53, 54})

def representation_spans(typ, descriptors, *, max_spans=100000, max_depth=64):
    """Flatten exact trace extents, including truncated bases and array stride.

    A union remains one opaque span. Missing trace tails remain unexplained;
    neither a size match nor zero bytes can promote them to proven padding.
    """
    spans = []

    def append(at, size, path, step=None, descriptor=None):
        if not size:
            return
        if len(spans) >= max_spans:
            raise RawRegionError('Representation span limit exceeded')
        row = dict(record_relative_offset=at, size=size, representation_path=path)
        if step is not None:
            row.update(opcode=step['opcode'], bytecode_offset=step['byte_offset'])
            if 'bitfield_mask' in step:
                row['bitfield_mask'] = step['bitfield_mask']
        if descriptor is not None:
            row.update(rd_number=descriptor.get('rd_number'), representation_name=descriptor.get('name'))
        spans.append(row)

    def walk(trace, at, extent, path, owner, depth):
        if depth > max_depth:
            raise RawRegionError('Representation nesting limit exceeded')
        cursor = 0
        for i, step in enumerate(trace):
            size = step['size']
            if type(size) is not int or size < 0 or cursor + size > extent:
                raise RawRegionError('Representation exceeds supplied extent')
            op = int(step['opcode'], 16)
            label = f'{path}/{i}:{step['opcode']}'
            if size:
                if 'reference_rd' in step and op != 46:
                    child = descriptors.get(step['reference_rd'])
                    if child is None:
                        raise RawRegionError('Referenced descriptor missing')
                    walk(child['trace'], at + cursor, size, label, child, depth + 1)
                elif 'array_count' in step:
                    count, stride, child = (step['array_count'], step['array_stride'], step['element_layout'])
                    if count * stride != size or child['size'] > stride:
                        raise RawRegionError('Array stride or extent disagrees')
                    for index in range(count):
                        element_at = at + cursor + index * stride
                        walk(child['trace'], element_at, child['size'], label + f'[{index}]', owner, depth + 1)
                        append(element_at + child['size'], stride - child['size'], label + f'[{index}]/unexplained_stride', descriptor=owner)
                else:
                    append(at + cursor, size, label, step, owner)
            cursor += size
            if cursor == extent:
                break
        append(at + cursor, extent - cursor, path + '/unexplained_tail', descriptor=owner)
    walk(typ['trace'], 0, typ['size'], '', typ, 0)
    return spans

def classify_region(region, spans):
    """Return preserved subregions with explicit representation evidence.

    Counts can grow when one schema gap crosses multiple representation spans.
    Bitfield mask operands are retained without asserting their native polarity
    or encoding. Schema-uncovered bits remain unknown even when their values are
    zero or an apparent compact mask would exclude them.
    """
    start, size = (region['record_relative_offset'], region['size'])
    raw = bytes.fromhex(region['raw_hex'])
    if type(start) is not int or start < 0 or type(size) is not int or (size <= 0) or (len(raw) != size):
        raise RawRegionError('Retained region extent or bytes invalid')
    matches = sorted((s for s in spans if s['record_relative_offset'] < start + size and s['record_relative_offset'] + s['size'] > start), key=lambda s: s['record_relative_offset'])
    result, cursor = ([], start)
    for span in matches:
        lo = max(start, span['record_relative_offset'])
        hi = min(start + size, span['record_relative_offset'] + span['size'])
        if lo != cursor:
            raise RawRegionError('Representation overlap or uncovered retained bytes')
        op = int(span['opcode'], 16) if 'opcode' in span else None
        classification = 'UNEXPLAINED_REPRESENTATION_BYTES'
        if op in FILLER_OPS:
            classification = 'PROVEN_REPRESENTATION_FILLER'
        elif op in RUNTIME_OPS:
            classification = 'PROVEN_RUNTIME_WORD'
        elif op in REFERENCE_OPS:
            classification = 'UNNAMED_REFERENCE_STORAGE'
        elif op == 26:
            classification = 'UNINTERPRETED_BITFIELD_STORAGE'
        elif op is not None:
            classification = 'UNNAMED_REPRESENTATION_STORAGE'
        row = dict(record_relative_offset=lo, size=hi - lo, raw_hex=raw[lo - start:hi - start].hex(), classification=classification, original_status=region.get('status', region.get('kind')), representation_evidence=dict(span))
        if 'mask_hex' in region:
            mask = bytes.fromhex(region['mask_hex'])
            if len(mask) != size:
                raise RawRegionError('Retained mask extent disagrees')
            row['mask_hex'] = mask[lo - start:hi - start].hex()
            if op == 26 and 'bitfield_mask' in span:
                native_mask = bytes.fromhex(span['bitfield_mask'])
                if len(native_mask) != span['size']:
                    raise RawRegionError('Native bitfield mask extent disagrees')
        if 'source_address' in region:
            row['source_address'] = dict(region['source_address'], offset=region['source_address']['offset'] + lo - start)
        result.append(row)
        cursor = hi
    if cursor != start + size:
        raise RawRegionError('Representation leaves retained bytes uncovered')
    return result
