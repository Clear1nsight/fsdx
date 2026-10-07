"""Independent Python implementation of statically observed ObjectStore packing.

The implementation derives from retained static packing observations; supporting
research evidence is private and is not a packaged runtime dependency. No vendor
DLL is executed. This implements scalar packing only, not the ObjectStore
directory event grammar.
"""

class PackingError(ValueError):
    pass

class Reader:

    def __init__(self, data, *, control=0, used=8, canonical=False):
        if not 0 <= control <= 255 or not 0 <= used <= 8:
            raise ValueError('invalid control state')
        self.data = bytes(data)
        self.pos = 0
        self.control = control
        self.used = used
        self.control_pos = None
        self.canonical = canonical
        self.trace = []

    def raw(self, count=1):
        if count < 0 or self.pos + count > len(self.data):
            raise PackingError('truncated data')
        pos = self.pos
        self.pos += count
        out = self.data[pos:self.pos]
        self.trace.append({'kind': 'data', 'start': pos, 'end': self.pos, 'hex': out.hex()})
        return out

    def boolean(self):
        if self.used == 8:
            self.control_pos = self.pos
            self.control = self.raw()[0]
            self.trace[-1]['kind'] = 'control'
            self.used = 0
        bit = self.used
        self.used += 1
        value = self.control >> bit & 1
        self.trace.append({'kind': 'bit', 'control_offset': self.control_pos, 'bit': bit, 'value': value})
        return value

    def unsigned(self, bits):
        if bits == 8:
            width = 1
        elif bits == 16:
            width = 1 + self.boolean()
        elif bits == 32:
            width = 1 + 2 * self.boolean() + self.boolean()
        elif bits == 64:
            if self.boolean():
                raise PackingError('unsupported native os8u high-width branch')
            return self.unsigned(32)
        else:
            raise ValueError('only 8,16,32,64 bit fields supported')
        value = int.from_bytes(self.raw(width), 'big')
        if self.canonical and width != max(1, (value.bit_length() + 7) // 8):
            raise PackingError('nonminimal numeric width')
        return value

    def signed(self, bits):
        if bits == 16:
            width = 1 + self.boolean()
        elif bits == 32:
            width = 1 + 2 * self.boolean() + self.boolean()
        else:
            raise ValueError('only signed16/32 supported')
        return int.from_bytes(self.raw(width), 'big', signed=True)

class Writer:
    """Canonical encoder used for roundtrip tests, independently mirroring widths."""

    def __init__(self):
        self.data = bytearray()
        self.control_pos = None
        self.used = 8

    def boolean(self, value):
        if value not in (0, 1):
            raise ValueError('boolean out of range')
        if self.used == 8:
            self.control_pos = len(self.data)
            self.data.append(0)
            self.used = 0
        self.data[self.control_pos] |= value << self.used
        self.used += 1

    def unsigned(self, value, bits):
        if not 0 <= value < 1 << min(bits, 32):
            raise ValueError('unsigned field out of supported range')
        width = max(1, (value.bit_length() + 7) // 8)
        if bits == 16:
            self.boolean(width == 2)
        elif bits in (32, 64):
            if bits == 64:
                self.boolean(0)
            self.boolean(width >= 3)
            self.boolean(width % 2 == 0)
        elif bits != 8:
            raise ValueError('unsupported field width')
        self.data.extend(value.to_bytes(width, 'big'))

class SectorReader(Reader):
    """Packed sector reader; raw buffer transitions discard unused control bits.

    Static o6low 1152aa30/1152abe2 clears control pointer/count when loading the
    next sector. Bits from the old reservoir remain usable until a raw read
    actually requests bytes beyond its sector, even at an exact boundary.
    """

    def __init__(self, data, sector_lengths, **kwargs):
        super().__init__(data, **kwargs)
        self.boundaries = []
        total = 0
        for n in sector_lengths:
            if not 0 < n <= 505:
                raise ValueError('invalid sector payload length')
            total += n
            self.boundaries.append(total)
        if total != len(data):
            raise ValueError('sector lengths do not cover payload')
        self.sector_index = 0

    def raw(self, count=1):
        if count < 0 or self.pos + count > len(self.data):
            raise PackingError('truncated data')
        out = bytearray()
        while count:
            if self.pos == self.boundaries[self.sector_index]:
                self.sector_index += 1
                self.used = 8
                self.control = 0
                self.control_pos = None
                self.trace.append({'kind': 'sector_transition', 'start': self.pos, 'discarded_control': True})
            n = min(count, self.boundaries[self.sector_index] - self.pos)
            out.extend(super().raw(n))
            count -= n
        return bytes(out)
