"""Lossless page-local factoring of pointer-evidence JSON, not pointer decoding.

Object key layouts and long immutable strings are shared within one page.
Unknown members and JSON scalar types survive; native addresses are not inferred.
"""
import hashlib
import json

from .format import StoreError, ResourcePolicy, encode_json, decode_json

FORMAT = 'fsdx-pointer-page'
VERSION = 1
CAPABILITY = 'compact_pointer_pages_v1'


def pack_pointer_page(raw: bytes, policy: ResourcePolicy | None = None) -> bytes | None:
    """Return bounded factored JSON, or None when ordinary JSON is preferable."""
    policy = policy or ResourcePolicy()
    page = decode_json(raw, policy)
    if not isinstance(page, dict) or len(raw) < 1024:
        return None
    schemas, strings, schema_ids, string_ids = [], [], {}, {}

    def encode(value):
        if isinstance(value, dict):
            keys = tuple(value)
            if keys not in schema_ids:
                schema_ids[keys] = len(schemas)
                schemas.append(list(keys))
            return [0, schema_ids[keys], [encode(value[key]) for key in keys]]
        if isinstance(value, list):
            return [1, [encode(child) for child in value]]
        if isinstance(value, str) and len(value) >= 64:
            if value not in string_ids:
                string_ids[value] = len(strings)
                strings.append(value)
            return [2, string_ids[value]]
        return value

    entries = [[key, encode(value)] for key, value in page.items()]
    packed = encode_json(dict(format=FORMAT, version=VERSION, schemas=schemas,
        strings=strings, entries=entries, json_bytes=len(raw),
        json_sha256=hashlib.sha256(raw).hexdigest()))
    if len(packed) >= len(raw) or len(packed) > policy.max_json_bytes:
        return None
    # Factoring adds container levels; deep valid ordinary pages keep their
    # original representation instead of exceeding the encoded parser policy.
    try:
        decode_json(packed, policy)
    except StoreError:
        return None
    return packed


def unpack_pointer_page(value: dict, policy: ResourcePolicy | None = None) -> dict:
    """Restore exact canonical JSON with independent expansion/depth budgets."""
    policy = policy or ResourcePolicy()
    fields = {'format', 'version', 'schemas', 'strings', 'entries', 'json_bytes', 'json_sha256'}
    if (type(value) is not dict or set(value) != fields or value['format'] != FORMAT
            or type(value['version']) is not int or value['version'] != VERSION
            or type(value['json_bytes']) is not int
            or not 2 <= value['json_bytes'] <= policy.max_json_bytes
            or not isinstance(value['json_sha256'], str) or len(value['json_sha256']) != 64):
        raise StoreError('Invalid compact pointer-page declaration')
    schemas, strings, entries = value['schemas'], value['strings'], value['entries']
    if any(type(part) is not list for part in (schemas, strings, entries)):
        raise StoreError('Invalid compact pointer-page tables')
    for keys in schemas:
        if (type(keys) is not list or any(type(key) is not str for key in keys)
                or len(set(keys)) != len(keys)):
            raise StoreError('Invalid compact pointer-page object keys')
    if any(type(text) is not str for text in strings):
        raise StoreError('Invalid compact pointer-page string table')
    string_sizes = [len(encode_json(text)) for text in strings]
    schema_sizes = [2 + max(0, len(keys)-1) + sum(len(encode_json(key))+1 for key in keys)
                    for keys in schemas]
    budget = 0

    def charge(size):
        nonlocal budget
        budget += size
        if budget > value['json_bytes'] or budget > policy.max_json_bytes:
            raise StoreError('Compact pointer-page expansion exceeds resource policy')

    def index(number, table):
        if type(number) is not int or not 0 <= number < len(table):
            raise StoreError('Invalid compact pointer-page table reference')
        return table[number]

    def decode(node, depth):
        if type(node) is not list:
            if type(node) not in (str, int, float, bool, type(None)):
                raise StoreError('Invalid compact pointer-page scalar')
            if node is None or node is True:
                size = 4
            elif node is False:
                size = 5
            elif type(node) is int:
                size = len(str(node))
            else:
                size = len(json.dumps(node, ensure_ascii=False, allow_nan=False).encode('utf-8'))
            charge(size)
            return node
        if not node or type(node[0]) is not int:
            raise StoreError('Invalid compact pointer-page node')
        tag = node[0]
        if tag == 2 and len(node) == 2:
            text = index(node[1], strings)
            charge(string_sizes[node[1]])
            return text
        if depth > policy.max_json_depth:
            raise StoreError('Compact pointer-page nesting exceeds resource policy')
        if tag == 0 and len(node) == 3 and type(node[2]) is list:
            keys = index(node[1], schemas)
            if len(keys) != len(node[2]):
                raise StoreError('Compact pointer-page row width disagrees with layout')
            charge(schema_sizes[node[1]])
            return {key: decode(child, depth+1) for key, child in zip(keys, node[2])}
        if tag == 1 and len(node) == 2 and type(node[1]) is list:
            charge(2 + max(0, len(node[1])-1))
            return [decode(child, depth+1) for child in node[1]]
        raise StoreError('Unsupported compact pointer-page node')

    charge(2 + max(0, len(entries)-1))
    page = {}
    for entry in entries:
        if (type(entry) is not list or len(entry) != 2 or type(entry[0]) is not str
                or entry[0] in page):
            raise StoreError('Invalid or duplicate compact pointer-page entry')
        charge(len(encode_json(entry[0]))+1)
        page[entry[0]] = decode(entry[1], 2)
    # Native page keys are integer offsets before serialization. Their numeric
    # order differs from string sorting after JSON decoding (8 before 16).
    # Retain each object's stored key order when reconstructing evidence bytes.
    raw = json.dumps(page, ensure_ascii=False, allow_nan=False,
        separators=(',', ':')).encode('utf-8')
    if (len(raw) != value['json_bytes'] or budget != len(raw)
            or hashlib.sha256(raw).hexdigest() != value['json_sha256']):
        raise StoreError('Compact pointer-page canonical evidence hash disagrees')
    return page
