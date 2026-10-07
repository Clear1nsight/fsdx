"""Dataset/geometry ownership evidence from native or restored logical readers.

Entity/shape discovery enumerates the supplied allocation population. Restored
catalogs use captured bytes and compiled fields without reopening the native FSD.
Semantic edges are restricted to
schema-named ownership fields; coordinate maps and numeric arrays are not treated
as geometry ownership. Rendering and coordinate transformations are separate.
"""
from __future__ import annotations
import argparse
import collections
import functools
import json
import sqlite3
import sys
import zlib
from dataclasses import asdict
from pathlib import Path
from fsd_decoder.native.native_database import NativeDatabase
from fsd_decoder.schema.native_fields import NativeFields
from fsd_decoder.native.native_allocations import NativeAllocationReader
from fsd_decoder.core.native_storage import Address
from fsd_decoder.exports.fsd_mesh import members
from fsd_decoder.core.diagnostics import require_source_failure, failure_record

# Catalog labels are interpretation views, never the raw-byte authority.
# Default per-label policy is 64 KiB; callers may select 1..1 MiB. This bounds
# fetched/materialized label bytes, not total report memory or process RSS.
DEFAULT_MAX_STRING_BYTES = 64 * 1024
MAX_STRING_BYTES = 1024 * 1024
STRING_DIAGNOSTIC_LIMIT = 100


def _string_byte_limit(value):
    if type(value) is not int or not 1 <= value <= MAX_STRING_BYTES:
        raise CatalogError('max_string_bytes must be between 1 and 1048576')
    return value


class CatalogError(ValueError):
    def __init__(self, message, *, collection_evidence=None):
        super().__init__(message)
        self.collection_evidence = collection_evidence


def _clear_value_cache(reader):
    """Release decoded field trees between report phases, retaining the report."""
    clear = getattr(getattr(reader, 'decode', None), 'cache_clear', None)
    if clear is not None:
        clear()

def ident(a):
    return f's{a['segment']}_c{a['cluster']}_o{a['offset']:x}'

def addrkey(a):
    return (a['segment'], a['cluster'], a['offset'])

def target(f):
    t = f.get('target')
    return t.get('address', t) if t else None

def member_match(path, name):
    return path.endswith('.' + name) or '.' + name + '.' in path or '.' + name + '::' in path

def _admitted_layout(reader, allocation, kind):
    """Use source declarations only after exact native storage admission."""
    admission = reader.fields.schema_admission(allocation)
    if not admission['admitted'] or admission.get('schema_name') != kind:
        raise CatalogError('Source class lacks native storage admission: ' +
                           str(admission['status']))
    return reader.fields.schema.layout(kind)


def _schema_value(reader, address):
    """Guard catalog schema roles without changing general value inspection."""
    allocation = reader.allocation(*addrkey(address))
    _admitted_layout(reader, allocation, allocation['name'].removesuffix('[]'))
    return reader.value(address)


def _navigation_root(reader, root):
    """Recognise a declared navigation root without relying on its display name."""
    declared = root.get('type_name')
    if not reader.inherits(declared, 'Fs__NavigationTree'):
        return None
    location = root.get('value_target')
    if location is None:
        raise CatalogError('Navigation root value target is unresolved')
    address = dict(database=reader.db.database_id,
                   **dict(zip(('segment', 'cluster', 'offset'), location)))
    value = _schema_value(reader, address)
    actual = value['type_name']
    if not reader.inherits(actual, declared):
        raise CatalogError('Navigation root declaration disagrees with current allocation')
    allocation = reader.allocation(*addrkey(address))
    declaration = members(_admitted_layout(reader, allocation, actual)).get('m_pRootGroup')
    if declaration is None:
        raise CatalogError('Navigation root lacks declared root-group member')
    offset, kind = declaration
    pointee = kind.get('element', {})
    if kind.get('kind') != 'pointer' or not reader.inherits(pointee.get('name'), 'Fs__NavigationTree__Group'):
        raise CatalogError('Navigation root-group member is not a declared Group pointer')
    fields = [field for field in value.get('fields', [])
              if field.get('path', '').endswith('.m_pRootGroup')]
    if len(fields) != 1 or fields[0].get('kind') != 'stored_reference' or fields[0].get('record_relative_offset') != offset:
        raise CatalogError('Navigation root-group field is missing or ambiguous')
    field = fields[0]
    group = target(field)
    group_type = None
    if group is None:
        if field.get('target_status') != 'NULL':
            raise CatalogError('Navigation root-group reference is unresolved')
    else:
        if group.get('database') != reader.db.database_id:
            raise CatalogError('Navigation root-group reference belongs to another database')
        group_type = _schema_value(reader, group)['type_name']
        if not reader.inherits(group_type, pointee['name']):
            raise CatalogError('Navigation root-group target disagrees with declared Group type')
    return dict(root_index=root.get('index'), root_name=root.get('name'),
                declared_type=declared, allocation_type=actual, address=address,
                member='m_pRootGroup', member_offset=offset,
                declared_group_type=pointee['name'], group_address=group,
                group_type=group_type, status='RESOLVED' if group else 'NULL',
                evidence='SOURCE_ROOT_TYPE_SCHEMA_MEMBER_AND_CURRENT_REFERENCE')

def assign_owners(entities, geometries):
    diagnostics = []
    for e in entities.values():
        pending = [e['shape_id']] if e['shape_id'] else []
        visited = set()
        while pending:
            gid = pending.pop()
            if gid in visited:
                continue
            visited.add(gid)
            if gid not in geometries:
                diagnostics.append(dict(where=e['id'], error='Shape reference absent from current Shape census', geometry_id=gid))
                continue
            geometries[gid]['owner_entity_ids'].append(e['id'])
            pending.extend(geometries[gid]['child_ids'])
        e['geometry_ids'] = sorted(visited)
    return diagnostics

class CatalogReader:

    def __init__(self, bundle, *, max_string_bytes=DEFAULT_MAX_STRING_BYTES):
        self.max_string_bytes = _string_byte_limit(max_string_bytes)
        self.string_bound_count = 0
        self.bundle = Path(bundle).resolve()
        info = json.loads((self.bundle / 'file_information.json').read_text())
        self.inventory = json.loads((self.bundle / 'inventory/manifest.json').read_text())
        self.db = NativeDatabase.from_path(info['source']['path'])
        if self.db.sha256 != info['source']['sha256'] or self.db.sha256 != self.inventory['source_sha256']:
            raise CatalogError('Source/inventory identity mismatch')
        if not self.inventory['complete']:
            raise CatalogError('Inventory allocation census incomplete')
        self.fields = NativeFields(self.db)
        self.index = sqlite3.connect('file:' + str(self.bundle / 'inventory/index.sqlite') + '?mode=ro', uri=True)
        self.source_metadata = dict(path=str(self.db.source_path), sha256=self.db.sha256, database_id=self.db.database_id, bytes=len(self.db.data))
        self.exports = {}
        for kind, path in (('mesh', self.bundle / 'meshes/manifest.json'), ('geometry', self.bundle / 'geometry/manifest.json')):
            if path.exists():
                m = json.loads(path.read_text())
                sha = m.get('source_sha256', m.get('source', {}).get('sha256'))
                if sha != self.db.sha256:
                    raise CatalogError('Geometry manifest source mismatch')
                for entry in m.get('meshes', m.get('objects', [])):
                    self.exports[entry['id']] = dict(kind=kind, entry=entry)
        self.errors = []
        self.collection_checks = []
        self.allocation = functools.lru_cache(maxsize=8192)(self.allocation)
        self.decode = functools.lru_cache(maxsize=128)(self.decode)
        self.inherits = functools.lru_cache(maxsize=None)(self.inherits)

    def iter_allocations(self):
        return NativeAllocationReader(self.db, self.fields.types).iter_allocations()

    def close(self):
        self.index.close()

    def allocation(self, s, c, o):
        row = self.index.execute('select start,end,record from allocations where segment=? and cluster=? and start<=? order by start desc limit 1', (s, c, o)).fetchone()
        if not row or not row[0] <= o < row[1]:
            raise CatalogError('Address is outside current allocation')
        a = json.loads(zlib.decompress(row[2]))
        return a

    def decode(self, s, c, o):
        a = self.allocation(s, c, o)
        relative = o - a['logical_offset'] - a['array_header_size']
        stride = a['element_stride']
        if relative < 0 or relative % stride:
            raise CatalogError('Pointer is not at a native element start')
        return self.fields.decode(a, relative // stride)

    def value(self, a):
        return self.decode(*addrkey(a))

    def inherits(self, name, base):
        if name == base:
            return True
        if name not in self.fields.schema.classes:
            return False
        return any((self.inherits(b['type']['name'], base) for b in self.fields.schema.layout(name)['bases']))

    def pointer(self, value, name):
        return next((target(f) for f in value.get('fields', []) if member_match(f.get('path', ''), name) and target(f)), None)

    def string(self, value, name):
        p = self.pointer(value, name)
        if not p:
            return None
        a = self.allocation(*addrkey(p))
        if a['native_tag'] != 1 and a['name'] != 'inline_char_bytes':
            raise CatalogError('String pointer lacks character allocation ownership')
        address = Address(**p)
        if address.database != getattr(self.db, 'database_id', address.database):
            raise CatalogError('String pointer belongs to another database')
        start, size = a['logical_offset'], a['size']
        if (type(start) is not int or type(size) is not int or start < 0
                or size <= 0 or not start <= address.offset < start + size):
            raise CatalogError('String pointer is outside its character allocation')
        limit = _string_byte_limit(getattr(self, 'max_string_bytes', DEFAULT_MAX_STRING_BYTES))
        remaining = start + size - address.offset
        read_bytes = min(remaining, limit)
        raw = self.db.read(address, read_bytes)
        terminator = raw.find(b'\x00')
        if terminator >= 0:
            return raw[:terminator].decode('latin1')
        if remaining <= limit:
            # Preserve the existing fully inspected, non-NUL allocation view.
            return raw.decode('latin1')
        # A bounded prefix is never an accepted shortened label. Raw bytes stay
        # accessible through this exact continuation; catalog traversal can
        # continue, but its label completeness must remain false.
        evidence = dict(where=ident(p) + '/' + name, status='RESOURCE_BOUND',
            error_category='RESOURCE_LIMIT', error='Catalog string resource limit reached before terminator',
            member=name, type=value.get('type_name'), address=dict(p),
            allocation_logical_offset=start, allocation_bytes=size,
            max_string_bytes=limit, inspected_bytes=read_bytes,
            remaining_raw_bytes=remaining - read_bytes,
            continuation_address=dict(p, offset=address.offset + read_bytes),
            value_status='UNRESOLVED_STRING', raw_bytes_preserved=True)
        self.string_bound_count = getattr(self, 'string_bound_count', 0) + 1
        errors = getattr(self, 'errors', None)
        if errors is None:
            self.errors = errors = []
        if len(errors) < STRING_DIAGNOSTIC_LIMIT and evidence not in errors:
            errors.append(evidence)
        return None

    def scalar(self, value, name):
        return next((f.get('value') for f in value.get('fields', []) if f.get('path', '').endswith('.' + name)), None)

    def collection(self, address, predicate):
        """Apply semantic selection only after independent membership validation."""
        if address is None:
            return []
        from fsd_decoder.discovery.collections import inspect_collection
        membership = inspect_collection(self, address)
        items = [row['address'] for row in membership['members']
                 if row['address'] is not None and predicate(row['target_type'])]
        expected = membership['declared_count']
        check = dict(address=address, representation=membership['representation'],
            declared_count=expected, observed_count=len(items),
            equal=membership['status'] == 'VERIFIED_CARDINALITY' and expected == len(items),
            membership_observed_count=membership['observed_count'],
            membership_status=membership['status'], diagnostics=membership['diagnostics'])
        self.collection_checks.append(check)
        if not check['equal']:
            # Keep the independent membership adapter's exact observed slots.
            # They are investigation evidence, never verified ownership edges.
            compact = dict(check)
            check.update(complete=False, observed_members=membership['members'],
                ownership='NOT_INFERRED')
            raise CatalogError('Collection cardinality unresolved ' + str(compact),
                               collection_evidence=check)
        return items

    def geometry_target(self, address):
        a = self.allocation(*addrkey(address))
        base = dict(address, offset=a['logical_offset'])
        delta = address['offset'] - a['logical_offset']
        layout = _admitted_layout(self, a, a['name'])
        if not self.inherits(a['name'], 'Fs::Spatial::Shape'):
            raise CatalogError('Geometry target does not belong to Shape')

        def views(layout, at=0):
            result = [(at, layout['name'])]
            for b in layout['bases']:
                result.extend(views(b['layout'], at + b['offset']))
            return result
        allowed = [name for offset, name in views(layout) if offset == delta and self.inherits(name, 'Fs::Spatial::Shape')]
        if not allowed:
            raise CatalogError('Geometry reference is not an exact Shape base subobject')
        return (base, dict(reference_address=address, allocation_address=base, base_displacement=delta, matching_base_types=allowed))

    def frame(self, address):
        v = _schema_value(self, address)
        units = []
        if not self.inherits(v['type_name'], 'Fs::Spatial::CoordinateSystem'):
            raise CatalogError('Coordinate-system pointer does not target a CoordinateSystem-derived allocation')
        for f in v.get('fields', []):
            p = target(f)
            path = f.get('path', '')
            if p and any((member_match(path, n) for n in ('m_pEastingUnit', 'm_pNorthingUnit', 'm_pHeightUnit', 'm_pLongitudeUnit', 'm_pLatitudeUnit', 'm_pUnit', 'm_pUnitX', 'm_pUnitY', 'm_pUnitZ'))):
                u = _schema_value(self, p)
                units.append(dict(axis_field=path.rsplit('.', 1)[-1], unit_address=p, name=self.string(u, 'm_name'), abbreviation=self.string(u, 'm_abbreviation'), numerator=self.scalar(u, 'm_numerator'), denominator=self.scalar(u, 'm_denominator')))
        return dict(id=ident(address), address=address, type=v['type_name'], code=self.string(v, 'm_code'), description=self.string(v, 'm_description'), units=units, transform_parameters_address=self.pointer(v, 'm_pTransformParameters'), transform_policy='NOT_APPLIED')

class PortableCatalogReader(CatalogReader):
    """Dependency-injected semantic reader; never opens an FSD or old export path.

 allocation_lookup returns the containing allocation; iter_allocations is a
 zero-argument iterator factory. Both provide the native allocation dictionaries.
 The facade must expose read/resolve/roots/address/verify_source and database_id.
 """

    def __init__(self, db, fields, *, iter_allocations, allocation_lookup, source_metadata, expected_allocations, exports=None, iter_named_allocations=None, allocation_counts_by_name=None, decode_cache_size=128, max_string_bytes=DEFAULT_MAX_STRING_BYTES):
        self.max_string_bytes = _string_byte_limit(max_string_bytes)
        self.string_bound_count = 0
        if type(decode_cache_size) is not int or not 1 <= decode_cache_size <= 8192:
            raise CatalogError('decode_cache_size must be between 1 and 8192')
        self.db = db
        self.fields = fields
        self.bundle = None
        self.source_metadata = dict(source_metadata)
        self.inventory = dict(allocations=expected_allocations, complete=True)
        self.exports = exports or {}
        self.collection_checks = []
        self.errors = []
        self.iter_named_allocations = iter_named_allocations
        self.allocation_counts_by_name = allocation_counts_by_name

        def checked_lookup(segment, cluster, offset):
            result = allocation_lookup(segment, cluster, offset)
            if result is None:
                raise CatalogError('Address is outside current allocation')
            return result
        self.iter_allocations = iter_allocations
        self.allocation = functools.lru_cache(maxsize=8192)(checked_lookup)
        self.decode = functools.lru_cache(maxsize=decode_cache_size)(self.decode)
        self.inherits = functools.lru_cache(maxsize=None)(self.inherits)

    def close(self):
        pass

def build_portable_catalog(db, *, progress=None, max_string_bytes=DEFAULT_MAX_STRING_BYTES):
    """Build a catalog only from the self-contained store and compiled metadata.

 The covering allocation-type index is counted without loading unrelated
 allocation payloads. This verifies the filtered iterator against actual stored
 rows while preserving the complete ingest allocation total separately.
 """
    max_string_bytes = _string_byte_limit(max_string_bytes)
    store = db.store
    total = store.manifest.get('counts', {}).get('allocations')
    if store.manifest.get('state') != 'COMPLETE' or type(total) is not int or total < 0:
        raise CatalogError('Portable store has no complete allocation census')
    by_name = {row[0]: row[1] for row in store.connection.execute('SELECT n.name,count(*) FROM allocations a JOIN names n ON n.id=a.name_id GROUP BY a.name_id')}
    if sum(by_name.values()) != total:
        raise CatalogError('Portable store total differs from allocation index counts')
    reader = PortableCatalogReader(db, db.fields, iter_allocations=db.iter_allocations, iter_named_allocations=lambda names: db.iter_allocations(names=names), allocation_counts_by_name=by_name, allocation_lookup=db.allocation, source_metadata=db.source_info, expected_allocations=total, exports={}, max_string_bytes=max_string_bytes)
    return build_catalog_from_reader(reader, progress=progress)

def build_catalog(bundle_path, *, max_navigation_nodes=None, progress=None, max_string_bytes=DEFAULT_MAX_STRING_BYTES):
    return build_catalog_from_reader(CatalogReader(bundle_path, max_string_bytes=max_string_bytes), max_navigation_nodes=max_navigation_nodes, progress=progress)

def build_catalog_from_reader(r, *, max_navigation_nodes=None, progress=None):
    db = r.db
    entity_allocations = {}
    geometry_allocations = {}
    scanned = 0
    named_iterator = getattr(r, 'iter_named_allocations', None)
    indexed = named_iterator is not None
    selected_names = []
    if indexed:
        candidates = set(r.fields.schema.classes) | {t['name'] for t in r.fields.types.values()}
        selected_names = sorted({variant for name in candidates if r.inherits(name, 'Fs::Entity') or r.inherits(name, 'Fs::Spatial::Shape') for variant in (name, name + '[]')})
        iterator = named_iterator(tuple(selected_names))
        census_basis = 'COMPLETE_INGEST_INVENTORY_PLUS_INDEXED_SCHEMA_DERIVED_TYPES'
    else:
        iterator = r.iter_allocations()
        census_basis = 'EXHAUSTIVE_ALLOCATION_ITERATION'
    selected_set = set(selected_names)
    observed_names = collections.Counter()
    seen_allocations = set()
    for a in iterator:
        scanned += 1
        name = a['name']
        base = name[:-2] if name.endswith('[]') else name
        ad = asdict(a['address'])
        key = ident(ad)
        if indexed and name not in selected_set:
            raise CatalogError('Indexed name query returned unselected type ' + name)
        if indexed and key in seen_allocations:
            raise CatalogError('Indexed name query duplicated current allocation ' + key)
        if indexed:
            seen_allocations.add(key)
        observed_names[name] += 1
        # Allocation template/context metadata and physical spans are not part
        # of this census. Retain only the fields consumed by later phases;
        # typed access still uses the normal validated allocation lookup.
        descriptor = (a['address'], name, a['vector'])
        if r.inherits(base, 'Fs::Entity'):
            entity_allocations[key] = descriptor
        if r.inherits(base, 'Fs::Spatial::Shape'):
            geometry_allocations[key] = descriptor
        if progress and scanned % 250000 == 0:
            progress(dict(phase='indexed_relevant_allocations' if indexed else 'allocation_census', allocations=scanned))
    if not indexed and scanned != r.inventory['allocations']:
        raise CatalogError('Current native census differs from inventory')
    expected_relevant = None
    if indexed and getattr(r, 'allocation_counts_by_name', None) is not None:
        expected_counts = {name: r.allocation_counts_by_name.get(name, 0) for name in selected_names}
        if any((type(n) is not int or n < 0 for n in expected_counts.values())):
            raise CatalogError('Invalid stored per-type allocation count')
        if any((observed_names[name] != n for name, n in expected_counts.items())):
            raise CatalogError('Indexed relevant allocation counts differ from stored ingest statistics')
        expected_relevant = sum(expected_counts.values())
    entity_allocation_count = len(entity_allocations)
    geometry_allocation_count = len(geometry_allocations)
    seen_allocations.clear()
    entities = {}
    geometries = {}
    frames = {}
    navgroups = {}
    navitem_entities = {}
    navparent = {}
    diagnostics = []

    def attempt(where, fn, *, partial_collection=None, **context):
        try:
            return fn()
        except Exception as e:
            context = dict(phase='catalog_value', name=where, **context)
            require_source_failure(e, context)
            diagnostics.append(dict(where=where, error_type=type(e).__name__, error=str(e)))
            if len(diagnostics) <= 100:
                detail = failure_record(e, status='CATALOG_VALUE_FAILED', context=context)
                diagnostics[-1].update({k: detail[k] for k in ('error_category', 'context', 'developer_log', 'developer_log_error') if k in detail})
            if (partial_collection is not None and isinstance(e, CatalogError)
                    and e.collection_evidence is not None):
                partial_collection(e.collection_evidence)
            return None
    for eid, (address, name, vector) in entity_allocations.items():
        ad = asdict(address)
        if vector:
            diagnostics.append(dict(where=eid, error='Vector entity allocation requires explicit element catalog'))
            continue
        v = attempt(eid, lambda: _schema_value(r, ad), address=ad)
        if v is None:
            allocation = r.allocation(*addrkey(ad))
            entities[eid] = dict(id=eid, name=None, address=ad, type=name,
                native_tag=allocation['native_tag'], group_paths=[], navigation_item_ids=[],
                shape_address=None, shape_id=None, attributes=[],
                composite_children_collection=None, cached_shape_references=[],
                status='SOURCE_SCHEMA_VALUE_UNRESOLVED')
            continue
        entity = dict(id=eid, name=r.string(v, 'm_name'), address=ad, type=name, group_paths=[], navigation_item_ids=[], shape_address=r.pointer(v, 'm_pShape'), shape_id=None, attributes=[], status='CATALOGED')
        if entity['shape_address']:
            view = attempt(eid + '/shape', lambda: r.geometry_target(entity['shape_address']))
            if view is None:
                entity['status'] = 'SHAPE_TARGET_UNRESOLVED'
            else:
                canonical, proof = view
                entity['shape_id'] = ident(canonical)
                entity['shape_reference_view'] = proof
        attr = r.pointer(v, 'm_attributes')
        owned = attempt(eid + '/attributes', lambda: r.collection(attr, lambda n: r.inherits(n, 'Fs::Attribute')))
        if owned is None:
            entity['status'] = 'PARTIAL_ATTRIBUTES'
        for p in owned or []:
            av = attempt(eid + '/attribute:' + ident(p), lambda: _schema_value(r, p), address=p)
            if av is None:
                allocation = r.allocation(*addrkey(p))
                entity['attributes'].append(dict(address=p, native_tag=allocation['native_tag'],
                    type=allocation['name'], purpose=None, display_name=None,
                    value_address=None, value_type=None, status='SOURCE_SCHEMA_VALUE_UNRESOLVED'))
                entity['status'] = 'PARTIAL_ATTRIBUTES'
                continue
            value_address = r.pointer(av, 'm_pValue')
            value_type = r.allocation(*addrkey(value_address))['name'] if value_address else None
            entity['attributes'].append(dict(address=p, purpose=r.string(av, 'm_purpose'), display_name=r.string(av, 'm_displayName'), value_address=value_address, value_type=value_type))
        entity['composite_children_collection'] = r.pointer(v, 'm_children')
        entity['cached_shape_references'] = [dict(field=f['path'], address=target(f)) for f in v.get('fields', []) if target(f) and 'm_cached_' in f.get('path', '')]
        entities[eid] = entity
    entity_allocations.clear()
    _clear_value_cache(r)
    q = collections.deque()
    seen = set()
    navigation_roots = []
    unresolved_navigation = []
    unresolved_roots = []
    for root in db.roots()['roots']:
        discovered = attempt('navigation_root:' + str(root.get('index')),
                             lambda root=root: _navigation_root(r, root))
        if discovered is not None:
            navigation_roots.append(discovered)
            if discovered['group_address']:
                q.append(discovered['group_address'])
        elif r.inherits(root.get('type_name'), 'Fs__NavigationTree'):
            unresolved_roots.append(dict(root=root,
                status='SOURCE_ROOT_SCHEMA_ROLE_UNRESOLVED'))
    while q and (max_navigation_nodes is None or len(seen) < max_navigation_nodes):
        ad = q.popleft()
        nid = ident(ad)
        if nid in seen:
            continue
        seen.add(nid)
        v = attempt(nid, lambda: _schema_value(r, ad), address=ad)
        if v is None:
            allocation = r.allocation(*addrkey(ad))
            unresolved_navigation.append(dict(id=nid, address=ad,
                type=allocation['name'], native_tag=allocation['native_tag'],
                status='SOURCE_SCHEMA_VALUE_UNRESOLVED'))
            continue
        parent = r.pointer(v, 'm_pParent')
        navparent[nid] = ident(parent) if parent else None
        if r.inherits(v['type_name'], 'Fs__NavigationTree__Group'):
            navgroups[nid] = dict(id=nid, address=ad, name=r.string(v, 'm_name'), parent_id=navparent[nid])
            child = r.pointer(v, 'm_children')
            items = attempt(nid + '/children', lambda: r.collection(child, lambda n: r.inherits(n, 'Fs__NavigationTree__Group') or r.inherits(n, 'Fs__EntityNavTreeItem')))
            for p in items or []:
                cv = attempt(nid + '/child:' + ident(p), lambda: _schema_value(r, p), address=p)
                if cv is None:
                    allocation = r.allocation(*addrkey(p))
                    unresolved_navigation.append(dict(id=ident(p), address=p,
                        type=allocation['name'], native_tag=allocation['native_tag'],
                        status='SOURCE_SCHEMA_VALUE_UNRESOLVED'))
                    continue
                if r.pointer(cv, 'm_pParent') != ad:
                    diagnostics.append(dict(where=nid, error='Navigation child parent disagrees', child=p))
                q.append(p)
        elif r.inherits(v['type_name'], 'Fs__EntityNavTreeItem'):
            p = r.pointer(v, 'm_pEntity')
            if p:
                navitem_entities[nid] = ident(p)
        else:
            diagnostics.append(dict(where=nid, error='Unrecognized navigation node', type=v['type_name']))
    for nid, eid in navitem_entities.items():
        if eid not in entities:
            diagnostics.append(dict(where=nid, error='Navigation entity absent from allocation census', entity=eid))
            continue
        chain = []
        p = navparent[nid]
        visited = set()
        while p and p not in visited:
            visited.add(p)
            if p not in navgroups:
                diagnostics.append(dict(where=nid, error='Missing parent group', parent=p))
                break
            chain.append(navgroups[p]['name'])
            p = navparent.get(p)
        if p in visited and p is not None:
            diagnostics.append(dict(where=nid, error='Navigation parent cycle'))
        entities[eid]['group_paths'].append(list(reversed(chain)))
        entities[eid]['navigation_item_ids'].append(nid)
    _clear_value_cache(r)
    exports = r.exports
    for gid, (address, name, vector) in geometry_allocations.items():
        ad = asdict(address)
        g = dict(id=gid, address=ad, type=name, coordinate_system_id=None, coordinate_system_address=None, coordinate_system_status='NULL_OR_UNSPECIFIED', owner_entity_ids=[], child_ids=[], source_export=exports.get(gid), status='CATALOGED')
        geometries[gid] = g
        category = next((label for base, label in [('Fs::Spatial::Geom::TriSurface', 'triangles'), ('Fs::Spatial::Geom::LineString', 'lines'), ('Fs::Spatial::Geom::PointSet', 'points'), ('Fs::Spatial::Geom::RegularGrid2', 'grid2'), ('Fs::Spatial::Geom::RegularGrid3', 'grid3'), ('Fs::Spatial::Geom::ImagePlane', 'image_plane'), ('Fs::Spatial::Geom::GeometryCollection', 'collection'), ('Fs::Spatial::Geom::LinearPolygon', 'polygon_boundaries')] if r.inherits(name, base)), 'unsupported_shape_type')
        g['render_class'] = category
        if vector:
            g['status'] = 'UNSUPPORTED_VECTOR_SHAPE'
            diagnostics.append(dict(where=gid, error='Vector Shape requires element geometry ownership'))
            continue
        declared = attempt(gid + '/schema_admission',
            lambda: _admitted_layout(r, r.allocation(*addrkey(ad)), name), address=ad)
        if declared is None:
            g['native_tag'] = r.allocation(*addrkey(ad))['native_tag']
            g['status'] = 'SOURCE_SCHEMA_ADMISSION_UNRESOLVED'
            continue
        layout = members(declared)
        csdef = layout.get('m_pCoordinateSystem')
        if csdef:
            cs = db.resolve(db.address(ad['segment'], ad['cluster'], ad['offset'] + csdef[0]))
            cs = asdict(cs) if cs else None
            g['coordinate_system_address'] = cs
            g['coordinate_system_id'] = ident(cs) if cs else None
            if cs and ident(cs) not in frames:
                frame = attempt(gid + '/frame', lambda: r.frame(cs))
                if frame:
                    frames[ident(cs)] = frame
            g['coordinate_system_status'] = 'DECODED_CURRENT_COORDINATE_SYSTEM' if cs and ident(cs) in frames else 'UNRESOLVED_CURRENT_COORDINATE_SYSTEM' if cs else 'NULL_OR_UNSPECIFIED'
        if 'm_geometryList' in layout or 'm_pExteriorRing' in layout:
            v = _schema_value(r, ad)
            children = []
            if 'm_geometryList' in layout:
                def retain_partial(check):
                    g['observed_child_references'] = [row for row in check['observed_members']
                        if row['address'] is not None and r.inherits(row['target_type'], 'Fs::Spatial::Shape')]
                    g['child_membership_status'] = check['membership_status']
                    g['observed_child_ownership'] = 'NOT_INFERRED; COLLECTION_CARDINALITY_UNVERIFIED'
                members_ = attempt(gid + '/geometryList', lambda: r.collection(r.pointer(v, 'm_geometryList'), lambda n: r.inherits(n, 'Fs::Spatial::Shape')),
                                   partial_collection=retain_partial)
                if members_ is None:
                    g['status'] = 'PARTIAL_CHILDREN'
                children.extend(members_ or [])
            for field in ('m_pExteriorRing', 'm_pInteriorRings'):
                if field in layout:
                    p = r.pointer(v, field)
                    if p:
                        children.append(p)
            g['child_reference_views'] = []
            for p in children:
                view = attempt(gid + '/child:' + ident(p), lambda: r.geometry_target(p), address=p)
                if view is None:
                    g.setdefault('unresolved_child_references', []).append(p)
                    g['status'] = 'PARTIAL_CHILDREN'
                    continue
                canonical, proof = view
                g['child_ids'].append(ident(canonical))
                g['child_reference_views'].append(proof)
    geometry_allocations.clear()
    _clear_value_cache(r)
    diagnostics.extend(assign_owners(entities, geometries))
    unassigned = [gid for gid, g in geometries.items() if not g['owner_entity_ids']]
    orphans = [eid for eid, e in entities.items() if not e['navigation_item_ids']]
    string_diagnostics = list(getattr(r, 'errors', ()))
    diagnostics.extend(string_diagnostics)
    string_bound_count = getattr(r, 'string_bound_count', 0)
    db.verify_source()
    result = dict(format='FSD_DATASET_RENDER_CATALOG', format_version=1, source=r.source_metadata, bundle_path=str(r.bundle) if r.bundle else None, entities=list(entities.values()), geometries=geometries, coordinate_systems=frames, navigation_groups=list(navgroups.values()), coverage=dict(census_basis=census_basis, ingest_allocation_count=r.inventory['allocations'], allocation_scan_complete=not indexed, allocation_inventory_complete=r.inventory['complete'], allocations_scanned=scanned, relevant_type_query_complete=indexed, queried_native_names=selected_names, relevant_counts_verified=expected_relevant is not None, expected_relevant_allocations=expected_relevant, entity_allocations=entity_allocation_count, cataloged_entities=len(entities), shape_allocations=geometry_allocation_count, cataloged_geometries=len(geometries), navigation_nodes=len(seen), navigation_pending=len(q), unassigned_geometry_ids=unassigned, entities_not_in_navigation=orphans, render_class_counts=dict(collections.Counter((g['render_class'] for g in geometries.values()))), shared_geometry_count=sum((len(g['owner_entity_ids']) > 1 for g in geometries.values()))), unhandled_objects=[dict(id=g['id'], address=g['address'], type=g['type'], reason='No verified rendering adapter for this Shape type') for g in geometries.values() if g['render_class'] == 'unsupported_shape_type'], collection_checks=r.collection_checks, diagnostics=diagnostics, source_unchanged=True, complete=not diagnostics and (not q), limitations=['Current allocated geometry includes objects not reachable from an entity shape.', 'Dataset owners propagate only along explicit geometry collection/ring relationships.', 'Composite entities and cached geometry references are retained separately; unknown ownership stays unassigned.', 'Coordinate-system transformations are not applied.'])
    if isinstance(r, PortableCatalogReader):
        result.pop('source_unchanged', None)
        result.update(store_verified=False, integrity_scope='QUICK_CHECKED',
                      full_store_verification_performed=False,
                      original_source_reopened=False, source_snapshot_sha256=r.source_metadata.get('sha256'))
    result['string_checks'] = dict(max_string_bytes=getattr(r, 'max_string_bytes', DEFAULT_MAX_STRING_BYTES),
        unresolved_calls=string_bound_count, diagnostic_preview_count=len(string_diagnostics),
        diagnostic_preview_omitted_calls=string_bound_count - len(string_diagnostics))
    result['labels_complete'] = not string_bound_count
    result['navigation_roots'] = navigation_roots
    result['unresolved_navigation_objects'] = unresolved_navigation
    result['unresolved_navigation_roots'] = unresolved_roots
    # Legacy complete describes successful traversal/catalog construction.
    # Rendering adapters and application interpretation have separate scopes.
    result.update(traversal_complete=not diagnostics and not q,
        adapters_complete=not result['unhandled_objects']
            and all(g['status'] == 'CATALOGED' for g in geometries.values())
            and all(e['status'] == 'CATALOGED' for e in entities.values()),
        application_semantics_complete=False)
    r.close()
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bundle', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    result = build_catalog(a.bundle, progress=lambda p: print(json.dumps(p), file=sys.stderr, flush=True))
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(complete=result['complete'], coverage={k: len(v) if isinstance(v, list) else v for k, v in result['coverage'].items()}, diagnostic_count=len(result['diagnostics']))))
if __name__ == '__main__':
    main()
