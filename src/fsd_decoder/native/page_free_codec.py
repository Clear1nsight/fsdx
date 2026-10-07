"""Pure Python _SUTL_page_free_space packer decoder from static O6LOW code.

Booleans reserve one flag byte for eight LSB-first flags; scalar bytes are read
from the same forward byte cursor without consuming the pending flag reservoir.
"""

class PackedFreeError(ValueError):
    pass

class Reader:

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.bits = 0
        self.flags = 0

    def raw(self, n):
        if self.pos + n > len(self.data):
            raise PackedFreeError('truncated packed free-space record')
        value = int.from_bytes(self.data[self.pos:self.pos + n], 'big')
        self.pos += n
        return value

    def boolean(self):
        if not self.bits:
            self.flags = self.raw(1)
            self.bits = 8
        self.bits -= 1
        return bool(self.flags & 1 << 7 - self.bits)

    def units4(self):
        value = self.raw(2 if self.boolean() else 1)
        if value >= 1024:
            raise PackedFreeError('packed size exceeds page')
        return value * 4

    def page(self):
        start = self.pos
        begin = end = middle = middle_at = 0
        if not self.boolean():
            kind = 'all_used'
        elif not self.boolean():
            kind = 'end_free'
            end = self.units4()
        elif not self.boolean():
            kind = 'all_free'
            begin = 4096
        else:
            kind = 'general'
            if self.boolean():
                begin = self.units4()
            end = self.units4()
            middle = self.units4()
            middle_at = self.units4()
            if middle and middle_at <= begin and (middle_at < 2048):
                middle_at += 2048
            if begin + end >= 4096:
                raise PackedFreeError('begin plus end free extent invalid')
            if middle and (begin + end + middle >= 4096 or middle_at <= begin or middle_at + middle >= 4096 - end):
                raise PackedFreeError('middle free extent invalid')
        return dict(begin_free_bytes=begin, end_free_bytes=end, middle_free_bytes=middle, middle_free_offset=middle_at, encoding_kind=kind, byte_cursor_before=start, byte_cursor_after=self.pos)

def decode_group(data, count=16, require_end=True, extended=False):
    """Decode one native 16-page block, with optional network-only prefix.

    Disk kind1 metadata passes extended=False. The initial bitmap suppresses
    stored records for all-free pages, scanning least-significant bit first.
    """
    if count != 16:
        raise PackedFreeError('native block must contain16 pages')
    reader = Reader(data)

    def os2u():
        return reader.raw(2 if reader.boolean() else 1)
    extra = [os2u(), os2u()] if extended else []
    bitmap = os2u()
    rows = []
    for i in range(16):
        if bitmap & 1 << i:
            row = dict(begin_free_bytes=4096, end_free_bytes=0, middle_free_bytes=0, middle_free_offset=0, encoding_kind='all_free_bitmap', byte_cursor_before=reader.pos, byte_cursor_after=reader.pos)
        else:
            row = reader.page()
        row['page_within_group'] = i
        rows.append(row)
    if require_end and reader.pos != len(data):
        raise PackedFreeError('trailing packed bytes')
    if reader.bits and reader.flags >> 8 - reader.bits:
        raise PackedFreeError('nonzero unused boolean bits')
    return dict(pages=rows, all_free_bitmap=bitmap, consumed_bytes=reader.pos, unused_boolean_bits=reader.bits, extended_fields=extra)
