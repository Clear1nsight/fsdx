"""Exact source-declared reference pointees shared by discovery consumers."""
from __future__ import annotations

from collections.abc import Mapping
import re

from fsd_decoder.core.contracts import SchemaLayouts


def declared_pointee(schema: SchemaLayouts, native_types: Mapping,
                     field: Mapping, slot: Mapping) -> Mapping | None:
    if field.get('pointee_type') is not None:
        return field['pointee_type']
    # NativeFields already recognizes these exact source template families and
    # widths as stored references. Their literal T is a source declaration, not
    # a role inferred from an instance label or the target allocation name.
    match = re.fullmatch(r'os_(?:soft|hard)_pointer(32|64)<(.+)>', slot.get('type_name') or '')
    if not match or field.get('size') != int(match[1]) // 8:
        return None
    name = match[2].strip()
    stars = len(name) - len(name.rstrip('*'))
    base = name.rstrip('*').strip()
    if base in schema.classes:
        layout = schema.layout(base)
        pointee = dict(kind='class', name=base, size=layout['size'],
            descriptor_offset=layout.get('descriptor_offset'))
    else:
        # Only retained native primitive declarations can resolve a literal
        # template primitive name; no application name dictionary is supplied.
        candidates = [t for tag,t in native_types.items() if tag < 30
            and t.get('name') == base and tag not in (8,14)]
        if len(candidates) != 1:
            return None
        pointee = dict(kind='primitive',name=base,size=candidates[0]['size'])
    for _ in range(stars):
        pointee = dict(kind='pointer',size=int(match[1])//8,element=pointee)
    return dict(pointee, declaration_evidence='SOURCE_SOFT_HARD_POINTER_TEMPLATE',
        source_template=slot['type_name'])

