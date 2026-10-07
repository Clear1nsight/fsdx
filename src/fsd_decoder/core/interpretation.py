"""Interpretation facets for retained typed records; no application semantics implied.

Outer typed statuses describe the decoder used. They do not establish that every
byte or bit has an interpretation, or that a declared union arm is active.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

_TYPED = frozenset(('SCHEMA_OWNED_TYPED_FIELDS', 'TYPED_NATIVE_PRIMITIVE',
    'TYPED_NATIVE_COMPACT_RECORD', 'TYPED_INLINE_CHARACTER_BYTES'))
_RAW_KINDS = frozenset(('layout_bytes', 'runtime_code_word', 'floating_storage', 'bitfield_storage'))
_UNRESOLVED_PREFIXES = ('UNSUPPORTED', 'UNKNOWN', 'UNRESOLVED', 'UNINTERPRETED', 'ARRAY_LIMIT')


def interpretation_facets(value: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize existing evidence without choosing union views or re-decoding.

    Counts include nested declared alternatives, which remain evidence rather
    than independently interpreted active fields. Raw retention means this
    record exposes its original byte view, not that those bytes have semantics.
    """
    counts: Counter[str] = Counter()
    statuses: Counter[str] = Counter()

    def walk(item: Mapping[str, Any]) -> None:
        status = item.get('status', '')
        if isinstance(status, str) and status.startswith(_UNRESOLVED_PREFIXES):
            statuses[status] += 1
        kind = item.get('kind')
        if kind in ('union', 'union_storage') or status == 'UNION_DECLARED_VIEWS':
            counts['unresolved_union_count'] += 1
        if kind in _RAW_KINDS:
            counts['uninterpreted_field_count'] += 1
        if item.get('target_status') in ('UNRESOLVED', 'ZERO_WORD_UNRESOLVED'):
            counts['unresolved_reference_count'] += 1
        if item.get('discriminant_status') == 'PRESERVED_UNAPPLIED':
            counts['unapplied_discriminant_count'] += len(item.get('tag_discriminants', ())) or 1
        for region in item.get('uninterpreted_regions', ()):
            counts['uninterpreted_region_count'] += 1
            counts['uninterpreted_bit_region_count'] += region.get('status') == 'UNINTERPRETED_BITS'
            walk(region)
        for field in item.get('fields', ()):
            walk(field)
        for view in item.get('declared_views', ()):
            counts['declared_union_view_count'] += 1
            walk(view)
        for key in ('padding_raw_hex', 'stride_padding_raw_hex'):
            if item.get(key):
                counts['uninterpreted_padding_region_count'] += 1

    walk(value)
    return dict(
        typed_fields_complete=value.get('status') in _TYPED and not statuses and not any(counts[k] for k in (
            'unresolved_union_count', 'uninterpreted_field_count', 'uninterpreted_region_count',
            'unresolved_reference_count', 'unapplied_discriminant_count', 'uninterpreted_padding_region_count')),
        raw_evidence_retained=isinstance(value.get('raw_hex', value.get('record_hex')), str),
        unresolved_union_count=counts['unresolved_union_count'],
        declared_union_view_count=counts['declared_union_view_count'],
        uninterpreted_field_count=counts['uninterpreted_field_count'],
        uninterpreted_region_count=counts['uninterpreted_region_count'],
        uninterpreted_bit_region_count=counts['uninterpreted_bit_region_count'],
        uninterpreted_padding_region_count=counts['uninterpreted_padding_region_count'],
        unresolved_reference_count=counts['unresolved_reference_count'],
        unapplied_discriminant_count=counts['unapplied_discriminant_count'],
        unresolved_status_counts=dict(statuses),
        application_semantics_complete=False)
