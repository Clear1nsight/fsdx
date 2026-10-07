"""JSON output for ordinary and read-only indexed documents.

Containers are traversed one member at a time, without aggregate conversion to
``dict`` or ``list``. Scalar spelling and default conversion remain delegated
to the standard-library encoder. Retained traversal state is bounded by nesting
depth, apart from the current scalar and the caller's document/cache policy.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
import json
from typing import Any, TextIO


def iter_json(value: Any, *, default: Callable[[Any], Any] | None = None,
              ensure_ascii: bool = True, allow_nan: bool = False,
              indent: int | str | None = None,
              separators: tuple[str, str] | None = None) -> Iterator[str]:
    """Yield JSON with ``json.dump`` spelling, including lazy container views.

Key order is the mapping's iteration order. Bytes and other non-JSON values
continue through the caller's existing ``default`` converter. Circular values
raise ``ValueError``, just as the standard-library encoder does.
    """
    encoder = json.JSONEncoder(default=default, ensure_ascii=ensure_ascii,
                               allow_nan=allow_nan, indent=indent,
                               separators=separators)
    indentation = (' ' * indent if isinstance(indent, int) else indent)
    markers: set[int] = set()

    def key_text(key: Any) -> str:
        if isinstance(key, str):
            return encoder.encode(key)
        if key is None or isinstance(key, (int, float, bool)):
            return encoder.encode(encoder.encode(key))
        raise TypeError('keys must be str, int, float, bool or None, '
                        f'not {type(key).__name__}')

    def walk(item: Any, level: int) -> Iterator[str]:
        if item is None or isinstance(item, (str, int, float, bool)):
            yield encoder.encode(item)
            return
        identity = id(item)
        if identity in markers:
            raise ValueError('Circular reference detected')
        markers.add(identity)
        try:
            mapping = isinstance(item, Mapping)
            sequence = isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray))
            if not mapping and not sequence:
                yield from walk(encoder.default(item), level)
                return
            opening, closing = ('{', '}') if mapping else ('[', ']')
            yield opening
            # Iterate keys rather than items() so lazy mappings never need an
            # aggregate items representation, even for very large documents.
            entries = iter(item)
            first = True
            next_level = level + 1
            newline = '' if indentation is None else '\n' + indentation * next_level
            for entry in entries:
                if first:
                    first = False
                else:
                    yield encoder.item_separator
                if newline:
                    yield newline
                if mapping:
                    yield key_text(entry)
                    yield encoder.key_separator
                    child = item[entry]
                else:
                    child = entry
                yield from walk(child, next_level)
            if not first and indentation is not None:
                yield '\n' + indentation * level
            yield closing
        finally:
            markers.remove(identity)

    return walk(value, 0)


def dump_json(value: Any, stream: TextIO, **options: Any) -> None:
    """Write an ordinary or indexed JSON document without aggregate copying."""
    for chunk in iter_json(value, **options):
        stream.write(chunk)
