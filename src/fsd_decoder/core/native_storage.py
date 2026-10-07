"""Checked logical-address reads over explicit physical extent mappings.

The directory reader must supply the effective extent map. This module does not
select historical events, infer ownership, or turn carving candidates into live
mappings. Logical and physical lengths are measured in bytes.
"""
from bisect import bisect_right
from dataclasses import dataclass

class MappingError(ValueError):
    pass

@dataclass(frozen=True)
class Address:
    database: str
    segment: int
    cluster: int
    offset: int

    def __post_init__(self):
        if type(self.database) is not str or not self.database or any((type(x) is not int or x < 0 for x in (self.segment, self.cluster, self.offset))):
            raise MappingError('Address needs explicit database, segment, cluster and nonnegative offset')

    @property
    def owner(self):
        return (self.database, self.segment, self.cluster)

@dataclass(frozen=True)
class Extent:
    database: str
    segment: int
    cluster: int
    logical_start: int
    physical_start: int
    length: int
    provenance: str

    def __post_init__(self):
        Address(self.database, self.segment, self.cluster, self.logical_start)
        if type(self.physical_start) is not int or self.physical_start < 0 or type(self.length) is not int or (self.length <= 0) or (type(self.provenance) is not str) or (not self.provenance):
            raise MappingError('Extent needs a positive length, physical offset and provenance')

    @property
    def owner(self):
        return (self.database, self.segment, self.cluster)

    @property
    def logical_end(self):
        return self.logical_start + self.length

@dataclass(frozen=True)
class PhysicalSpan:
    logical_start: int
    physical_start: int
    length: int
    provenance: str

class AddressMap:

    def __init__(self, source, extents):
        self.source = memoryview(source)
        if not self.source.readonly or not isinstance(self.source.obj, bytes):
            raise MappingError('AddressMap requires an immutable source snapshot')
        if self.source.ndim != 1 or self.source.itemsize != 1:
            raise MappingError('Source must be a one-dimensional byte buffer')
        self.extents = {}
        for extent in extents:
            if not isinstance(extent, Extent):
                raise MappingError('AddressMap requires explicit Extent records')
            if extent.physical_start + extent.length > len(self.source):
                raise MappingError('Extent lies beyond the source snapshot')
            self.extents.setdefault(extent.owner, []).append(extent)
        self.starts = {}
        for owner, ranges in self.extents.items():
            ranges.sort(key=lambda e: e.logical_start)
            if any((a.logical_end > b.logical_start for a, b in zip(ranges, ranges[1:]))):
                raise MappingError('Overlapping logical extents require directory-state resolution')
            self.extents[owner] = tuple(ranges)
            self.starts[owner] = tuple((e.logical_start for e in ranges))

    def spans(self, address, length):
        if type(length) is not int or length < 0:
            raise MappingError('Read length must be a nonnegative integer')
        if length == 0:
            return ()
        ranges = self.extents.get(address.owner)
        if ranges is None:
            raise MappingError('Address owner is unmapped')
        position, end = (address.offset, address.offset + length)
        index = bisect_right(self.starts[address.owner], position) - 1
        if index < 0:
            raise MappingError('Read begins in an unmapped logical range')
        spans = []
        while position < end:
            if index >= len(ranges):
                raise MappingError('Read extends beyond mapped logical ranges')
            extent = ranges[index]
            if not extent.logical_start <= position < extent.logical_end:
                raise MappingError('Read crosses an unmapped logical gap')
            size = min(end, extent.logical_end) - position
            spans.append(PhysicalSpan(position, extent.physical_start + position - extent.logical_start, size, extent.provenance))
            position += size
            index += 1
        return tuple(spans)

    def read(self, address, length):
        return b''.join((self.source[s.physical_start:s.physical_start + s.length] for s in self.spans(address, length)))
