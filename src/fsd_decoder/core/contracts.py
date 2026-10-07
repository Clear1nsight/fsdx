"""Public typing contracts; record spellings and runtime checks remain authoritative.

Addresses and raw bytes describe source evidence. A typed field or declared union
view does not establish application meaning, liveness, or an active union arm.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Protocol, Sequence, TypedDict
from fsd_decoder.core.native_storage import Address, PhysicalSpan
ValueStatus = Literal['TYPED_INLINE_CHARACTER_BYTES', 'TYPED_NATIVE_PRIMITIVE', 'TYPED_NATIVE_COMPACT_RECORD', 'SCHEMA_OWNED_TYPED_FIELDS', 'SCHEMA_TYPED_WITH_UNAPPLIED_DISCRIMINANTS', 'UNSUPPORTED_SCHEMA_LAYOUT', 'UNSUPPORTED_UNION_DISCRIMINANTS', 'UNSUPPORTED_FLOAT_ENCODING', 'UNKNOWN_SIZE', 'UNKNOWN_QUALIFIERS', 'ARRAY_LIMIT', 'UNSUPPORTED_FLOAT_FORMAT', 'UNSUPPORTED_TYPE', 'UNION_DECLARED_VIEWS', 'UNINTERPRETED_BITS', 'UNINTERPRETED_VTABLE_PADDING_OR_FIELD']
ReferenceStatus = Literal['NULL', 'CURRENT_NATIVE_PRM', 'ZERO_WORD_UNRESOLVED', 'UNRESOLVED', 'RESOLVER_SUPPLIED']
DiscriminantStatus = Literal['NO_DISCRIMINANTS', 'PRESERVED_UNAPPLIED']

@dataclass(frozen=True)
class CapturedUnresolvedReference:
    """Exact unavailable captured binding; carries no target address."""
    slot: Address
    raw: bytes
    source_sha256: str
    resolution_metadata: Mapping[str, Any]
    record_relative_offset: int | None = None

    def __post_init__(self):
        if (not isinstance(self.slot, Address) or type(self.raw) is not bytes
                or len(self.raw) not in (4, 8)
                or not isinstance(self.source_sha256, str)
                or len(self.source_sha256) != 64
                or any(c not in '0123456789abcdef' for c in self.source_sha256)
                or not isinstance(self.resolution_metadata, Mapping)
                or (self.record_relative_offset is not None and
                    (type(self.record_relative_offset) is not int or self.record_relative_offset < 0))):
            raise ValueError('Invalid captured unresolved reference evidence')

class CapturedReferenceDatabase(Protocol):
    def captured_unresolved_reference(self, address: Address, width: int = 4,
            raw: bytes | None = None) -> Mapping[str, Any] | None:
        """Validate the current binding; return evidence only for explicit UNRESOLVED."""
        ...

class AddressRecord(TypedDict):
    database: str
    segment: int
    cluster: int
    offset: int

class AllocationRecord(TypedDict, total=False):
    segment: int
    cluster: int
    logical_offset: int
    size: int
    native_tag: int
    name: str
    count: int
    vector: bool
    element_size: int
    element_stride: int
    array_header_size: int
    discriminant_words: list[int]
    address: Address
    physical_spans: tuple[PhysicalSpan, ...]
    source_metadata: dict[str, Any]

class LayoutRecord(TypedDict):
    name: str
    size: int
    descriptor_offset: int
    members: list[dict[str, Any]]
    bases: list[dict[str, Any]]
    unresolved: list[dict[str, Any]]

class ValueRecord(TypedDict, total=False):
    native_tag: int
    type_name: str
    element_index: int
    source_address: AddressRecord
    source_address_space: Literal['LOGICAL_DATABASE_OBJECT']
    size: int
    element_size: int
    raw_hex: str
    value_raw_hex: str
    padding_raw_hex: str
    status: ValueStatus
    kind: str
    value: int | float | str | bool
    fields: list[dict[str, Any]]
    uninterpreted_regions: list[dict[str, Any]]
    target: AddressRecord | dict[str, Any] | None
    target_status: ReferenceStatus
    tag_discriminants: list[int]
    discriminant_status: DiscriminantStatus
    active_member: None

class LogicalDatabase(Protocol):
    sha256: str
    database_id: str

    def address(self, segment: int, cluster: int, offset: int) -> Address:
        ...

    def read(self, address: Address, size: int) -> bytes:
        ...

    def resolve(self, address: Address, width: int=4, raw: bytes | None=None) -> Address | None:
        ...

    def spans(self, address: Address, size: int) -> tuple[PhysicalSpan, ...]:
        ...

class SchemaLayouts(Protocol):
    classes: Mapping[str, LayoutRecord]
    schema_extents: Sequence[Mapping[str, Any]]

    def layout(self, name: str) -> LayoutRecord:
        ...

    def report(self) -> Mapping[str, Any]:
        ...
