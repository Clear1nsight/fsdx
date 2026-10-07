"""Versioned, paginated discovery from current schema and allocation evidence.

Every allocated type is counted. Objects are inspected in structural priority
order; unknown types, unresolved references and resource bounds remain visible.
Candidate classification never assigns geological meaning or arbitrary owners.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from types import SimpleNamespace
import sqlite3

from fsd_decoder.core.diagnostics import require_source_failure, error_category
from fsd_decoder.discovery.relationship_discovery import RelationshipError, inspect_element
from fsd_decoder.discovery.source_declarations import declared_pointee
from fsd_decoder.exports.catalog import PortableCatalogReader
from fsd_decoder.portable.format import MAX_BLOB_BYTES, decode_json

VERSION = 3
DEFAULT_OBJECTS = 2000


def _typed(status):
    return status in ('SCHEMA_OWNED_TYPED_FIELDS', 'TYPED_NATIVE_PRIMITIVE',
                      'TYPED_NATIVE_COMPACT_RECORD', 'TYPED_INLINE_CHARACTER_BYTES')


def _limit(value, name, ceiling):
    if type(value) is not int or not 1 <= value <= ceiling:
        raise RelationshipError(f'{name} must be an integer from 1 to {ceiling}')
    return value


def _slots(schema, name, *, maximum=4096):
    """Flatten declarations, keeping arrays symbolic and union arms conditional."""
    result = []

    def emit(kind, at, path, arrays, conditional):
        if len(result) >= maximum:
            raise RelationshipError('Schema slot count exceeds resource limit')
        result.append(dict(path=path, offset=at, kind=kind['kind'], size=kind.get('size'),
            type_name=kind.get('name'), descriptor_offset=kind.get('descriptor_offset'),
            pointee_type=kind.get('element') if kind['kind'] == 'pointer' else None,
            arrays=arrays, conditional_union=conditional))

    def walk(kind, at, path, arrays=(), conditional=False, depth=0):
        if depth > 64:
            raise RelationshipError('Excessive embedded schema nesting')
        tag = kind['kind']
        if tag in ('alias', 'qualified'):
            if kind.get('unknown_qualifier_flags'):
                emit(kind, at, path, arrays, conditional)
            else:
                walk(kind['underlying'], at, path, arrays, conditional, depth + 1)
        elif tag == 'array':
            walk(kind['element'], at, path + '[]',
                 (*arrays, dict(count=kind['count'], stride=kind['element'].get('size'))),
                 conditional, depth + 1)
        elif tag in ('class', 'union') and kind.get('name') in schema.classes:
            layout = schema.layout(kind['name'])
            # The same verified soft/hard pointer representations used by the
            # value interpreter are leaves, rather than invented object links.
            if kind['name'].startswith(('os_soft_pointer32<', 'os_hard_pointer32<',
                                        'os_soft_pointer64<', 'os_hard_pointer64<')):
                emit(kind, at, path, arrays, conditional)
                return
            for base in layout.get('bases', ()):
                walk(base['type'], at + base['offset'], path + '::<' + base['type']['name'] + '>',
                     arrays, conditional, depth + 1)
            for member in layout.get('members', ()):
                walk(member['type'], at + member['offset'], path + '.' + member['name'],
                     arrays, conditional or tag == 'union', depth + 1)
        else:
            emit(kind, at, path, arrays, conditional)

    layout = schema.layout(name)
    walk(dict(kind='union' if layout.get('class_kind_bits') == 2 else 'class', name=name), 0, name)
    return result


def _character(kind):
    while kind and kind.get('kind') in ('alias', 'qualified'):
        if kind.get('unknown_qualifier_flags'):
            return False
        kind = kind.get('underlying')
    return bool(kind and kind.get('kind') == 'primitive' and kind.get('size') == 1
                and kind.get('name') in ('1 byte char', '1 byte signed char', '1 byte unsigned char'))


def _numeric(kind):
    """Recognize a primitive storage declaration through bounded known wrappers."""
    seen = set()
    wrappers = 0
    while isinstance(kind, dict) and kind.get('kind') in ('alias', 'qualified'):
        if id(kind) in seen or wrappers == 64 or kind.get('unknown_qualifier_flags'):
            return False
        if kind.get('kind') == 'qualified':
            flags = kind.get('qualifier_flags', 0)
            if (type(flags) is not int or flags < 0 or flags & ~3
                    or kind.get('qualifier_status', 'KNOWN') != 'KNOWN'):
                return False
        seen.add(id(kind))
        wrappers += 1
        kind = kind.get('underlying')
    return bool(isinstance(kind, dict) and kind.get('kind') == 'primitive'
                and not _character(kind))


def _type_census(db, reader):
    rows = db.store.connection.execute('''SELECT n.name,count(*),sum(a.element_count),sum(a.size)
        FROM allocations a JOIN names n ON n.id=a.name_id GROUP BY a.name_id''')
    census = []
    for name, allocations, elements, size in rows:
        base = name.removesuffix('[]')
        groups = []
        for tag, template_id, metadata, tag_allocations, tag_elements in db.store.connection.execute('''SELECT a.native_tag,
                a.template_id,CASE WHEN length(CAST(t.metadata AS BLOB))<=? THEN t.metadata END,
                count(*),sum(a.element_count) FROM allocations a JOIN names n ON n.id=a.name_id
                JOIN allocation_templates t ON t.id=a.template_id
                WHERE n.name=? GROUP BY a.native_tag,a.template_id''', (MAX_BLOB_BYTES, name)):
            template = decode_json(metadata) if metadata is not None else {}
            admission = reader.fields.schema_admission(dict(template, native_tag=tag, name=name))
            if metadata is None:
                admission.update(admitted=False, status='SOURCE_COMPACT_STORAGE_UNESTABLISHED',
                                 reasons=['ALLOCATION_TEMPLATE_BOUND'])
            groups.append(dict(native_tag=tag, template_id=template_id, allocations=tag_allocations, elements=tag_elements,
                               schema_admission=admission))
        row = dict(type=name, allocations=allocations, elements=elements, bytes=size,
                   schema_class=any(g['schema_admission']['admitted'] for g in groups),
                   native_tag_groups=groups,
                   inspection_objects=sum(g['elements'] if g['schema_admission']['admitted'] else
                                          g['allocations'] for g in groups), slots=[], diagnostics=[])
        if row['schema_class']:
            try:
                row['slots'] = _slots(reader.fields.schema, base)
                for slot in row['slots']:
                    if slot['kind'] == 'class':
                        slot['pointee_type'] = declared_pointee(
                            reader.fields.schema, reader.fields.types, slot, slot)
                layout = reader.fields.schema.layout(base)
                row['unresolved_declarations'] = list(layout.get('unresolved', ()))
                row['bases'] = [b['type']['name'] for b in layout.get('bases', ())]
                row['entity_family'] = reader.inherits(base, 'Fs::Entity')
            except Exception as exc:
                require_source_failure(exc, dict(phase='discovery_schema', name=name))
                row['diagnostics'].append(dict(category=error_category(exc), error=str(exc)))
        char_slots = [s for s in row['slots'] if not s['conditional_union'] and _character(s['pointee_type'])]
        if not row['schema_class'] and base in reader.fields.schema.classes and reader.inherits(base, 'Fs::Entity'):
            from fsd_decoder.schema.schema_admission import corroborated_member_slots
            slots = _slots(reader.fields.schema, base)
            row['partial_entity_slots'] = {str(group['native_tag']): corroborated_member_slots(
                reader.fields.schema, reader.fields.types, reader.fields.descriptors,
                group['native_tag'], slots,
                verified_nonvariable=reader.fields._verified_nonvariable) for group in groups}
            row['source_entity_candidate'] = any(row['partial_entity_slots'].values())
        # Priority affects only pagination order, never inclusion in the census.
        row['priority'] = 0 if row.get('entity_family') else 1 if char_slots else 2 if row['schema_class'] else 3
        census.append(row)
    return sorted(census, key=lambda row: (row['priority'], row['type']))


def _allocation_rows(db, name, after_id):
    return db.store.connection.execute('''SELECT a.id,a.segment,a.cluster,a.logical_offset
        FROM allocations a JOIN names n ON n.id=a.name_id
        WHERE n.name=? AND a.id>=? ORDER BY a.id''', (name, after_id))


def _recorded_bindings(db, address, size, maximum):
    rows = db.store.connection.execute('''SELECT logical_offset,width,raw,status,
        target_segment,target_cluster,target_offset,metadata FROM pointers
        WHERE segment=? AND cluster=? AND logical_offset>=? AND logical_offset<?
        ORDER BY logical_offset LIMIT ?''', (address['segment'], address['cluster'],
        address['offset'], address['offset'] + size, maximum + 1))
    bindings = []
    for at, width, raw, status, s, c, o, metadata in rows:
        if len(bindings) == maximum:
            return bindings, True
        bindings.append(dict(slot_offset=at, width=width, raw_hex=raw.hex(), status=status,
            target=None if s is None else dict(database=db.database_id, segment=s, cluster=c, offset=o),
            resolution_metadata=decode_json(metadata),
            span_status='WITHIN_ELEMENT' if at + width <= address['offset'] + size else 'CROSSES_ELEMENT_BOUNDARY',
            meaning='CURRENT_RECORDED_BINDING; OWNERSHIP_NOT_INFERRED'))
    return bindings, False


def _object(db, reader, allocation, index, declaration, *, max_element_bytes, max_text_bytes, max_references):
    admission = reader.fields.schema_admission(allocation)
    partial_slots = declaration.get('partial_entity_slots', {}).get(str(allocation['native_tag']), [])
    if not admission['admitted']:
        declaration = dict(declaration, schema_class=False, slots=[], entity_family=False)
    header = allocation.get('array_header_size', 0)
    stride = allocation.get('element_stride', allocation.get('element_size', allocation['size']))
    offset = allocation['logical_offset'] + header + index * stride
    address = asdict(db.address(allocation['segment'], allocation['cluster'], offset))
    size = allocation.get('element_size', allocation['size']) if allocation.get('vector') else allocation['size']
    obj = dict(id=f"a{allocation['store_allocation_id']}:e{index}", address=address,
        allocation_id=allocation['store_allocation_id'], type=allocation['name'], element_index=index,
        allocation_address=asdict(db.address(allocation['segment'], allocation['cluster'], allocation['logical_offset'])),
        element_count=allocation.get('count', 1), allocation_bytes=allocation['size'],
        text_fields=[], classification='CURRENT_OBJECT', candidate_reasons=[], ownership='NOT_INFERRED')
    obj['schema_admission'] = admission
    if not declaration['schema_class'] and allocation.get('vector'):
        size = allocation['size'] - header
        obj.update(status='ARRAY_METADATA_ONLY', references=[], scalars=[],
                   inspection='Array payload is retained; values can be exported separately')
        # A raw native vector is data evidence, never a confirmed application dataset.
        obj['candidate_reasons'].append('CURRENT_NATIVE_ARRAY')
    else:
        leaf_count = 0
        for slot in declaration['slots']:
            multiplicity = 1
            for array in slot['arrays']:
                multiplicity *= array['count']
            leaf_count += multiplicity
        if leaf_count > 4096 or declaration['diagnostics']:
            obj.update(status='SCHEMA_INSPECTION_BOUND', references=[], scalars=[],
                       inspection='Schema slots are incomplete or expand beyond 4096 leaves')
        else:
            inspected = inspect_element(db, address['segment'], address['cluster'], offset,
                max_element_bytes=max_element_bytes, include_scalars=True)
            obj.update({key: inspected[key] for key in ('status', 'references', 'scalars', 'unsupported_reasons', 'error', 'error_category',
                'interpretation', 'fields', 'raw_hex', 'record_hex', 'value_raw_hex', 'padding_raw_hex',
                'uninterpreted_regions', 'tag_discriminants', 'discriminant_status',
                'schema_declarations', 'member_names_status') if key in inspected})
            refs = obj.get('references', [])
            if len(refs) > max_references:
                obj['references'] = refs[:max_references]
                obj['typed_references_truncated'] = True
    bindings, truncated = _recorded_bindings(db, address, size, max_references)
    obj['recorded_bindings'] = bindings
    obj['recorded_bindings_truncated'] = truncated
    # Partial views keep the native opcode paths and whole-class rejection intact.
    # Only exact corroborated slots acquire a source-member interpretation view.
    views = []
    for slot in partial_slots:
        for field in obj.get('references', []) + obj.get('scalars', []):
            if field.get('record_relative_offset') == slot['offset'] and len(bytes.fromhex(field.get('raw_hex', ''))) == slot['size']:
                views.append(dict(field, path=slot['path'], pointee_type=slot['pointee_type'],
                                  evidence=slot['evidence']))
    if views:
        obj['source_member_views'] = views
    for field in obj.get('references', []) + [v for v in views if v.get('kind') == 'stored_reference']:
        if not _character(field.get('pointee_type')) or not field.get('target'):
            continue
        target = field['target'].get('address', field['target'])
        a = db.allocation(target['segment'], target['cluster'], target['offset'])
        if a is None:
            continue
        # Schema char pointee alone does not validate the target allocation tag.
        if a.get('native_tag') != 1 and a['name'] != 'inline_char_bytes':
            continue
        remaining = a['logical_offset'] + a['size'] - target['offset']
        raw = db.read(db.address(target['segment'], target['cluster'], target['offset']), min(remaining, max_text_bytes))
        ended = b'\0' in raw
        text = raw.split(b'\0', 1)[0]
        obj['text_fields'].append(dict(path=field['path'], address=target,
            text=text.decode('latin1'), raw_hex=text.hex(), encoding='LATIN1_BYTE_VIEW',
            status='TERMINATED' if ended else 'TEXT_BOUND' if remaining > max_text_bytes else 'ALLOCATION_END',
            role='SOURCE_TEXT; NAME_ROLE_NOT_ASSUMED'))
    if declaration.get('entity_family'):
        obj['classification'] = 'ENTITY_DATASET'
        obj['candidate_reasons'].append('SOURCE_SCHEMA_DERIVES_FROM_VERIFIED_ENTITY_FAMILY')
        obj['name_fields'] = [f for f in obj['text_fields'] if '.m_name.' in f['path'] or f['path'].endswith('.m_name')]
    elif partial_slots:
        obj['classification'] = 'SOURCE_ENTITY_NAME_CANDIDATE'
        obj['name_fields'] = [f for f in obj['text_fields'] if '.m_name.' in f['path'] or f['path'].endswith('.m_name')]
        obj['candidate_reasons'].append('PARTIAL_SOURCE_COMPACT_SLOT_CONCORDANCE; WHOLE_CLASS_NOT_ADMITTED')
    else:
        numeric = any(not s['conditional_union'] and _numeric(s['pointee_type'])
                      for s in declaration['slots'])
        if numeric:
            obj['candidate_reasons'].append('SCHEMA_NUMERIC_STORAGE_REFERENCE')
        if obj['text_fields'] and obj.get('references'):
            obj['candidate_reasons'].append('TEXT_AND_TYPED_REFERENCES')
        if obj['candidate_reasons']:
            obj['classification'] = 'DATASET_CANDIDATE'
    obj['creation_time_fields'] = [dict(field, interpretation='RAW_SOURCE_TIME_VALUE; EPOCH_AND_TIMEZONE_UNESTABLISHED')
        for field in obj.get('scalars', []) + views if '.m_createTime' in field.get('path', '')]
    from .roles import storage_role, supported_collection_family
    base = allocation['name'].removesuffix('[]')
    if declaration['schema_class'] and supported_collection_family(reader, base):
        obj['collection_representation'] = dict(type=base,
            declared_cardinality_fields=[f for f in obj.get('scalars', ()) if f.get('path', '').endswith('.card')],
            membership_policy='RECORDED_REFERENCE_SLOTS; CARDINALITY_NOT_VERIFIED_BY_GENERIC_DISCOVERY')
    role_declaration = dict(declaration, collection_family='collection_representation' in obj)
    obj['storage_role'] = storage_role(role_declaration, vector=allocation.get('vector', False))
    return obj


@contextmanager
def session_operation(session: DiscoverySession) -> Iterator[None]:
    """Protect real discovery sessions; preserve existing reader protocols."""
    if isinstance(session, DiscoverySession):
        with session.operation():
            yield
    else:
        yield


class DiscoverySession:
    """Reuse one source census while consuming successive bounded pages."""
    def __init__(self, db):
        self.db = db
        self._failed = False
        self.reader = PortableCatalogReader(db, db.fields, iter_allocations=lambda: (),
            allocation_lookup=db.allocation, source_metadata=db.source_info, expected_allocations=0,
            decode_cache_size=512)
        with self.operation():
            self.census = _type_census(db, self.reader)
            self.total = sum(row['allocations'] for row in self.census)
            if self.total != db.store.manifest.get('counts', {}).get('allocations'):
                raise RelationshipError('Discovery census differs from complete allocation inventory')
            path = getattr(db, 'path', None)
            self._path = path
            self._identity = self._stat() if path is not None else None

    def _stat(self):
        info = self._path.stat()
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def _ensure_usable(self) -> None:
        if self._failed:
            raise RelationshipError('Discovery session is invalid after a failed operation')

    @contextmanager
    def operation(self) -> Iterator[None]:
        """Keep completed work reusable; release caches when a stream is closed."""
        self._ensure_usable()
        try:
            yield
        except GeneratorExit:
            # Closing a partially consumed public iterator cancels its work;
            # it does not establish a failed store or complete verification.
            try:
                self.close()
            except BaseException:
                self._failed = True
                raise
            raise
        except BaseException:
            self.abort()
            raise

    def _clear_caches(self) -> None:
        # These wrappers belong to this session's reader. Shared database,
        # store and NativeFields caches remain the caller's responsibility.
        self.reader.decode.cache_clear()
        self.reader.allocation.cache_clear()
        self.reader.inherits.cache_clear()

    def close(self) -> None:
        """Release owned caches without checking or re-reading the source."""
        self._clear_caches()

    def abort(self) -> None:
        """Invalidate failed work without reading or verifying its source."""
        self._failed = True
        self._clear_caches()

    def check_identity(self):
        self._ensure_usable()
        try:
            source_guard = getattr(self.db.store, 'check_identity', None)
            if source_guard is not None:
                source_guard()
            if self._path is not None and self._stat() != self._identity:
                raise RelationshipError('Store changed during discovery session')
        except BaseException:
            self.abort()
            raise

    def finish(self):
        try:
            self.check_identity()
            self.db.verify_source()
            self.check_identity()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._clear_caches()

    def page(self, **options):
        with self.operation():
            return build_discovery(self.db, _session=self, **options)

    def iter_objects(self, *, progress=None):
        """Stream the complete existing page population, verifying once at end.

        Class arrays expand to every declared element. Primitive/unknown arrays
        remain one payload record with their element count and retained bytes.
        One SQL cursor per type avoids sorting that type again on every page.
        """
        with self.operation():
            inspected = 0
            expected = sum(row['inspection_objects']
                           for row in self.census)
            for declaration in self.census:
                name = declaration['type']
                for aid, segment, cluster, offset in _allocation_rows(self.db, name, 0):
                    allocation = self.db.allocation(segment, cluster, offset)
                    if allocation is None or allocation['store_allocation_id'] != aid:
                        raise RelationshipError('Discovery index does not resolve to its current allocation')
                    count = allocation.get('count', 1) if self.reader.fields.schema_admission(allocation)['admitted'] else 1
                    for index in range(count):
                        yield _object(self.db, self.reader, allocation, index, declaration,
                            max_element_bytes=65536, max_text_bytes=4096, max_references=128)
                        inspected += 1
                        if inspected % 10000 == 0:
                            self.check_identity()
                            if progress:
                                progress(dict(phase='discovery_objects', objects_inspected=inspected,
                                    expected_objects=expected, type=name))
            if inspected != expected:
                raise RelationshipError('Discovery object stream differs from census population')
            self.finish()


def build_discovery(db, *, max_objects=DEFAULT_OBJECTS, cursor=None, type_name=None,
                    max_element_bytes=65536, max_text_bytes=4096, max_references=128,
                    progress=None, _session=None, include_collections=True) -> dict:
    """Inspect one stable page; census includes every current allocated type.

    Cursor pins source identity and ordering. Class arrays enumerate each element;
    primitive/unknown vectors are one data-array record, never millions of bytes
    materialised as unrelated dataset objects. Bounds are explicit in the output.
    """
    session = _session
    try:
        _limit(max_objects, 'max_objects', 10000)
        _limit(max_element_bytes, 'max_element_bytes', 1048576)
        _limit(max_text_bytes, 'max_text_bytes', 65536)
        _limit(max_references, 'max_references', 1000)
        if type(include_collections) is not bool:
            raise RelationshipError('include_collections must be a boolean')
        session = _session or DiscoverySession(db)
        session._ensure_usable()
        if session.db is not db:
            raise RelationshipError('Discovery session belongs to another store')
        reader, census, total = session.reader, session.census, session.total
        names = [r['type'] for r in census]
        if type_name is not None and type_name not in names:
            raise RelationshipError('Requested type is absent from current allocation inventory')
        if cursor is not None:
            if (not isinstance(cursor, dict) or set(cursor) != {'version', 'source_sha256', 'type', 'allocation_id', 'element_index', 'type_filter'}
                    or type(cursor['version']) is not int or cursor['version'] != VERSION or cursor['source_sha256'] != db.sha256
                    or cursor['type'] not in names or cursor['type_filter'] != type_name
                    or type(cursor['allocation_id']) is not int or cursor['allocation_id'] < 1
                    or type(cursor['element_index']) is not int or cursor['element_index'] < 0):
                raise RelationshipError('Invalid discovery cursor or incompatible source/type filter')
            row = db.store.connection.execute('SELECT n.name,a.element_count,a.segment,a.cluster,a.logical_offset FROM allocations a JOIN names n ON n.id=a.name_id WHERE a.id=?', (cursor['allocation_id'],)).fetchone()
            current = db.allocation(row[2],row[3],row[4]) if row else None
            count = row[1] if current and reader.fields.schema_admission(current)['admitted'] else 1
            if not row or row[0] != cursor['type'] or cursor['element_index'] >= count:
                raise RelationshipError('Discovery cursor is outside its current allocation')
        start_type = names.index(cursor['type']) if cursor else 0
        objects = []
        next_cursor = None
        last = None
        for declaration in census[start_type:]:
            name = declaration['type']
            if type_name is not None and name != type_name:
                continue
            after = cursor['allocation_id'] if cursor and cursor['type'] == name else 0
            for aid, segment, cluster, offset in _allocation_rows(db, name, after):
                allocation = db.allocation(segment, cluster, offset)
                if allocation is None or allocation['store_allocation_id'] != aid:
                    raise RelationshipError('Discovery index does not resolve to its current allocation')
                count = allocation.get('count', 1) if reader.fields.schema_admission(allocation)['admitted'] else 1
                first = cursor['element_index'] + 1 if cursor and cursor['type'] == name and aid == cursor['allocation_id'] else 0
                for index in range(first, count):
                    if len(objects) == max_objects:
                        next_cursor = last
                        break
                    obj = _object(db, reader, allocation, index, declaration,
                        max_element_bytes=max_element_bytes, max_text_bytes=max_text_bytes,
                        max_references=max_references)
                    objects.append(obj)
                    last = dict(version=VERSION, source_sha256=db.sha256, type=name,
                        allocation_id=aid, element_index=index, type_filter=type_name)
                    if progress and len(objects) % 500 == 0:
                        progress(dict(phase='dataset_discovery', objects_inspected=len(objects), max_objects=max_objects, type=name))
                if next_cursor:
                    break
            if next_cursor:
                break
        candidates = [dict(object_id=o['id'], address=o['address'], type=o['type'],
            classification=o['classification'], reasons=o['candidate_reasons'])
            for o in objects if o['candidate_reasons']]
        session.check_identity()
        result = dict(format='FSD_DATASET_DISCOVERY', version=VERSION, source=dict(db.source_info),
            policy='SOURCE_SCHEMA_CURRENT_ALLOCATIONS_AND_REFERENCES; NO_INSTANCE_NAME_ALLOWLIST',
            ownership_policy='GENERIC_REFERENCES_DO_NOT_ESTABLISH_OWNERSHIP',
            type_census=census, census_complete=True, allocations_counted=total,
            objects=objects, dataset_candidates=candidates,
            inspection=dict(objects_inspected=len(objects), classification_counts=dict(Counter(o['classification'] for o in objects)),
                status_counts=dict(Counter(o['status'] for o in objects)), cursor=cursor, next_cursor=next_cursor,
                enumeration_complete=next_cursor is None, type_filter=type_name,
                max_objects=max_objects, max_element_bytes=max_element_bytes, max_text_bytes=max_text_bytes,
                max_references=max_references,
                typed_values_complete=all(o.get('interpretation', {}).get('typed_fields_complete', False) for o in objects),
                reference_views_complete=all(o.get('interpretation', {}).get('typed_fields_complete', False) and not o.get('typed_references_truncated') and not o['recorded_bindings_truncated'] for o in objects)),
            original_source_required=False, application_semantics_complete=False,
            limitations=['Candidates require application-role evidence before being accepted as datasets.',
                'Union alternatives are declarations, not active reference edges.',
                'The census covers all allocated types; object inspection is paginated and size bounded.',
                'Character text roles and geological meanings are not inferred.'])
        if include_collections:
            from .membership import discover_membership, reconcile_entities
            result['collection_evidence'] = discover_membership(session, objects=objects, progress=progress)
            result['entity_reconciliation'] = reconcile_entities(result, result['collection_evidence'])
        if _session is None:
            session.finish()
        return result
    except BaseException:
        if session is not None:
            session.abort()
        raise


class _CaptureDatabase:
    """Read uncommitted private capture rows against the native immutable snapshot."""
    def __init__(self, native, fields, writer):
        self.native = native
        self.fields = fields
        self.source_info = writer.source
        self.sha256 = native.sha256
        self.database_id = native.database_id
        self.header = native.directory.get('header', {})
        count = writer.connection.execute('SELECT count(*) FROM allocations').fetchone()[0]
        self.store = SimpleNamespace(connection=writer.connection,
            manifest=dict(counts=dict(allocations=count), pointer_resolution_complete=True))

    def address(self, *args):
        return self.native.address(*args)

    def roots(self):
        return self.native.roots()

    def read(self, *args):
        return self.native.read(*args)

    def resolve(self, *args, **kwargs):
        return self.native.resolve(*args, **kwargs)

    def verify_source(self):
        # Encoder streams the original source hash before publishing. Here the
        # same immutable snapshot is used; there is no second physical read.
        return True

    def allocation(self, segment, cluster, offset):
        row = self.store.connection.execute('''SELECT a.id,a.logical_offset,a.size,a.native_tag,
            a.element_count,a.vector,n.name,
            CASE WHEN length(CAST(t.metadata AS BLOB))<=? THEN t.metadata END,
            CASE WHEN length(CAST(c.metadata AS BLOB))<=? THEN c.metadata END
            FROM allocations a JOIN names n ON n.id=a.name_id
            JOIN allocation_templates t ON t.id=a.template_id
            JOIN allocation_contexts c ON c.id=a.context_id
            WHERE a.segment=? AND a.cluster=? AND a.logical_offset<=?
            ORDER BY a.logical_offset DESC LIMIT 1''', (MAX_BLOB_BYTES, MAX_BLOB_BYTES, segment, cluster, offset)).fetchone()
        if row is None or offset >= row[1] + row[2]:
            return None
        if row[7] is None or row[8] is None:
            raise RelationshipError('Capture allocation metadata exceeds resource policy')
        allocation = decode_json(row[7])
        allocation.update(store_allocation_id=row[0], logical_offset=row[1], size=row[2],
            native_tag=row[3], count=row[4], vector=bool(row[5]), name=row[6],
            segment=segment, cluster=cluster, source_metadata=decode_json(row[8]),
            address=self.address(segment, cluster, row[1]))
        return allocation


def capture_discovery(native, fields, writer, *, progress=None) -> dict:
    """Build complete indexed discovery before capture integrity is sealed."""
    previous = writer.connection.row_factory
    try:
        # Typed inspection names pointer columns. Keep the private writer's
        # ordinary tuple-row contract before and after this synchronous phase.
        writer.connection.row_factory = sqlite3.Row
        from fsd_decoder.discovery.complete import build_complete_discovery
        result = build_complete_discovery(_CaptureDatabase(native, fields, writer), progress=progress)
    finally:
        writer.connection.row_factory = previous
    result['original_source_accessed_during_generation'] = True
    result['operation'] = 'NATIVE_CAPTURE_DISCOVERY'
    return result
