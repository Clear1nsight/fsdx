"""Sequential native directory reader developed from static ObjectStore handlers.

Checkpoint implementation. Unsupported branches fail with source/control state;
there is no phase guessing or row carving in this module.
"""
from fsd_decoder.native.packed_stream import Reader, SectorReader, PackingError

class DirectoryReader:

    def __init__(self, r, *, max_string_bytes=1048576):
        if not isinstance(max_string_bytes, int) or isinstance(max_string_bytes, bool) or max_string_bytes < 0:
            raise ValueError('max_string_bytes must be a nonnegative integer')
        self.r = r
        self.version = None
        self.segments = {}
        self.events = []
        self.max_string_bytes = max_string_bytes

    def address(self):
        r = self.r
        component = r.unsigned(16) if r.boolean() else 0
        sector = r.unsigned(64)
        if component >= 500 or sector > 2147483647:
            raise PackingError('invalid native physical address')
        return {'component': component, 'sector': sector}

    def extent(self):
        start = self.r.pos
        size = self.r.unsigned(64)
        address = self.address()
        if not size or size > 2147483647 or address['sector'] + size > 2147483647:
            raise PackingError('invalid native extent size')
        return {'sector_count': size, **address, 'provenance': {'payload_start': start, 'payload_end': self.r.pos, 'native_handler': '118e91d0'}}

    def extent_snapshot(self):
        r = self.r
        end = r.unsigned(64)
        unknown = r.unsigned(64)
        n = r.unsigned(64)
        if n > 100000:
            raise PackingError('implausible snapshot extent count')
        extents = [self.extent() for _ in range(n)]
        if unknown > end * 512:
            raise PackingError('snapshot used bytes exceed allocation')
        if sum((e['sector_count'] for e in extents)) != end:
            raise PackingError('extent lengths do not sum to logical end')
        begin = 0
        for e in extents:
            e['logical_start_sector'] = begin
            begin += e['sector_count']
        return {'logical_end_sector': end, 'used_bytes': unknown, 'extents': extents}

    def table_snapshot(self, previous=None):
        r = self.r
        if not r.boolean():
            if previous is None:
                return None
            return {**previous, 'kinds': [0, 32], 'extents': [], 'snapshot_present': False}
        kinds = list(r.raw(2))
        n = r.unsigned(32)
        if n > 100000:
            raise PackingError('table snapshot count too large')
        extents = [self.extent() for _ in range(n)]
        tableflag = r.unsigned(8)
        address = self.address()
        kind = r.unsigned(8)
        a = r.unsigned(32)
        b = r.unsigned(32)
        tail = {'table_flag': tableflag, 'address': address, 'kind': kind, 'a': a, 'b': b}
        if tableflag == 0 and previous is not None:
            effective = {k: previous[k] for k in ('table_flag', 'address', 'kind', 'a', 'b')}
            return {'kinds': kinds, 'extents': extents, **effective, 'serialized_tail': tail}
        return {'kinds': kinds, 'extents': extents, **tail}

    def cluster_snapshot(self):
        tables = [self.table_snapshot(), self.table_snapshot()]
        extents = self.extent_snapshot() if self.version >= 3 else None
        return {'tables': tables, 'allocation': extents}

    def string(self):
        """Read native get_string's raw NUL-terminated bytes without encoding guesses.

  Static o6low 11529540 reads bytes directly, with no length/control field.
  raw(1) also preserves the sector reader's native refill/control reset rules.
  The configurable limit counts content bytes; one additional NUL is required.
  """
        r = self.r
        start = r.pos
        value = bytearray()
        while True:
            if r.pos >= len(r.data):
                raise PackingError(f'unterminated native string at payload {start:#x}: input ended after {len(value)} bytes')
            byte = r.raw(1)[0]
            if byte == 0:
                break
            if len(value) >= self.max_string_bytes:
                raise PackingError(f'native string exceeds max_string_bytes={self.max_string_bytes} at payload {start:#x}')
            value.append(byte)
        return {'raw_hex': value.hex(), 'byte_length': len(value), 'terminator_hex': '00', 'byte_view': ''.join((chr(b) if 32 <= b < 127 and b != 92 else f'\\x{b:02x}' for b in value)), 'byte_view_format': 'ASCII_ESCAPED_BYTES', 'encoding': 'UNDETERMINED', 'provenance': {'payload_start': start, 'payload_end': r.pos, 'native_handler': '11529540'}}

    def segment_snapshot(self, seg):
        r = self.r
        seg['snapshot_flag'] = r.boolean()
        flags = seg['flags']
        if self.version < 3:
            if not r.boolean():
                return
        elif flags & 32:
            seg['next_even'] = r.unsigned(32)
            seg['next_odd'] = r.unsigned(32)
        if flags & 2:
            seg['mode'] = r.signed(32)
            seg['native_normalized_mode'] = seg['mode'] & 63 | 448
            seg['owner'] = self.string()
        if flags & 4:
            seg['comment'] = self.string()
        if flags & 16:
            seg['pair'] = [r.unsigned(32), r.unsigned(32)]
        seg['clusters'] = {}
        if flags & 8:
            n = r.unsigned(32)
            if n > 100000:
                raise PackingError('too many snapshot clusters')
            for _ in range(n):
                cluster = r.unsigned(32)
                clflags = r.unsigned(16)
                timestamp = r.unsigned(64)
                seg['clusters'][cluster] = {'flags': clflags, 'timestamp': timestamp, **self.cluster_snapshot()}
        if self.version < 3:
            seg['legacy_allocation'] = self.extent_snapshot()

    def snapshot(self, has_outer=True):
        r = self.r
        if has_outer:
            self.outer = r.unsigned(8)
            if self.outer > 8:
                raise PackingError('unsupported outer directory format')
        self.version = r.unsigned(16)
        if not 1 <= self.version <= 3:
            raise PackingError('invalid snapshot version')
        limit = r.unsigned(64) if self.version > 1 else None
        self.limit = limit
        count = r.unsigned(64)
        if count > 10000:
            raise PackingError('snapshot segment count too large')
        for _ in range(count):
            sid = r.signed(32)
            bits = [r.unsigned(32), r.unsigned(32)]
            flags = r.unsigned(16) if self.version > 1 else 0
            timestamp = r.unsigned(64) if self.version > 1 else limit
            seg = {'id': sid, 'segbits': bits, 'flags': flags, 'timestamp': timestamp}
            self.segments[sid] = seg
            self.segment_snapshot(seg)
        self.next_segment = r.signed(32)
        return {'version': self.version, 'limit': limit, 'next_segment': self.next_segment, 'segments': self.segments, 'end': r.pos, 'control_used': r.used, 'control': r.control}

    def event(self):
        r = self.r
        start = r.pos
        top = r.unsigned(8)
        if top in (3, 5, 8):
            value = r.signed(32) if top == 3 else r.unsigned(64 if top == 5 else 32)
            if top == 3:
                self.next_segment = value
            elif top == 5:
                self.limit = value
            else:
                self.field8 = value
            record = {'start': start, 'end': r.pos, 'top': top, 'value': value, 'control': r.control, 'used': r.used}
            self.events.append(record)
            return record
        if top != 1:
            raise PackingError(f'unsupported segment event {top} at {start:x}')
        op = r.unsigned(8)
        sid = r.signed(32)
        if sid not in self.segments:
            raise PackingError(f'unknown segment {sid}')
        seg = self.segments[sid]
        record = {'start': start, 'top': top, 'op': op, 'segment': sid}
        if op in (13, 14):
            value = r.unsigned(32)
            record['next_cluster'] = value
            seg['next_even' if op == 13 else 'next_odd'] = value
        elif op == 12:
            cid = r.unsigned(32)
            flags = r.unsigned(16)
            stamp = r.unsigned(64)
            if cid in seg['clusters']:
                raise PackingError('duplicate cluster creation')
            seg['clusters'][cid] = {'flags': flags, 'timestamp': stamp, **self.cluster_snapshot()}
            record.update(cluster=cid, flags=flags, timestamp=stamp)
        elif op == 11:
            cop = r.unsigned(8)
            cid = r.unsigned(32)
            record.update(cluster_op=cop, cluster=cid)
            if cid not in seg['clusters']:
                raise PackingError(f'unknown cluster {sid}:{cid}')
            cl = seg['clusters'][cid]
            if cop == 4:
                kind = r.unsigned(8)
                if kind not in (4, 5):
                    raise PackingError(f'unsupported table kind {kind}')
                table = self.table_snapshot(cl['tables'][kind - 4])
                cl['tables'][kind - 4] = table
                record.update(table_kind=kind, table=table)
            elif cop == 5:
                cl['timestamp'] = r.unsigned(64)
                record['timestamp'] = cl['timestamp']
            elif cop in (6, 7):
                size = r.unsigned(64)
                record['size'] = size
                allocation = cl['allocation']
                if cop == 6:
                    if size > allocation['logical_end_sector'] * 512:
                        raise PackingError('used byte count exceeds allocation')
                    allocation['used_bytes'] = size
                else:
                    if not size < allocation['logical_end_sector'] or allocation['used_bytes'] > size * 512:
                        raise PackingError('invalid allocation truncation')
                    allocation['extents'] = [{**e, 'sector_count': min(e['sector_count'], size - e['logical_start_sector'])} for e in allocation['extents'] if e['logical_start_sector'] < size]
                    allocation['logical_end_sector'] = size
            elif cop in (8, 9):
                end = r.unsigned(64)
                extent = self.extent()
                extent['logical_start_sector'] = end - extent['sector_count']
                if extent['logical_start_sector'] < 0:
                    raise PackingError('negative extent start')
                record.update(logical_end_sector=end, extent=extent)
                allocation = cl['allocation']
                extents = allocation['extents']
                if cop == 9:
                    if end != allocation['logical_end_sector'] + extent['sector_count']:
                        raise PackingError('append end mismatch')
                    extents.append(extent.copy())
                else:
                    if not extents:
                        raise PackingError('grow last on empty allocation')
                    old = extents[-1]
                    if old['component'] != extent['component'] or old['sector'] != extent['sector'] or old['sector_count'] >= extent['sector_count'] or (old['logical_start_sector'] != extent['logical_start_sector']):
                        raise PackingError('invalid last extent growth')
                    extents[-1] = extent.copy()
                allocation['logical_end_sector'] = end
                extents[-1]['provenance'].update(event_start=start, event_end=r.pos, event_op=cop)
                cl.setdefault('extent_updates', []).append({'op': cop, 'end': end, **extent})
            elif cop == 10:
                kind = r.unsigned(8)
                if kind not in (4, 5):
                    raise PackingError('unsupported table delta kind')
                flag = r.unsigned(8)
                address = self.address()
                mode = r.unsigned(8)
                a = r.unsigned(32)
                b = r.unsigned(32)
                delta = {'table_flag': flag, 'address': address, 'kind': mode, 'a': a, 'b': b}
                old = cl['tables'][kind - 4]
                cl['tables'][kind - 4] = {**(old or {'kinds': [0, 32], 'extents': []}), **delta, 'descriptor_provenance': {'event_start': start, 'event_end': r.pos, 'native_handler': '118f45d0'}}
                record.update(table_kind=kind, table_update=delta)
            else:
                raise PackingError(f'unsupported cluster operation {cop}')
        elif op == 8:
            record['timestamp'] = r.unsigned(64)
            seg['timestamp'] = record['timestamp']
        elif op == 2:
            record['segbits'] = [r.unsigned(32), r.unsigned(32)]
            seg['segbits'] = record['segbits']
        elif op == 15:
            cid = r.unsigned(32)
            record['deleted_cluster'] = cid
            if cid not in seg['clusters']:
                raise PackingError('delete unknown cluster')
            del seg['clusters'][cid]
        else:
            raise PackingError(f'unsupported segment operation {op}')
        record.update(end=r.pos, control=r.control, used=r.used)
        self.events.append(record)
        return record

def source_spans(positions, start=0, end=None):
    """Losslessly compact payload-offset to source-offset correspondence."""
    if end is None:
        end = len(positions)
    spans = []
    for i in range(start, end):
        physical = positions[i]
        if spans and physical == spans[-1]['physical_start'] + spans[-1]['length']:
            spans[-1]['length'] += 1
        else:
            spans.append({'payload_start': i, 'physical_start': physical, 'length': 1})
    return spans

def read_packed_sectors(data, allocation):
    """Follow explicit outer-directory extents; stop at native partial footer."""
    pieces = []
    positions = []
    sectors = []
    stamp = None
    stopped = False
    for extent in allocation['extents']:
        if extent['component'] != 0:
            raise PackingError('external directory address component')
        for sector in range(extent['sector'], extent['sector'] + extent['sector_count']):
            p = sector * 512
            if p + 512 > len(data):
                raise PackingError('directory sector outside source')
            footer = data[p + 505:p + 512]
            n = int.from_bytes(footer[4:6], 'big')
            if n > 505 or footer[6] != 1:
                raise PackingError('unsupported packed sector footer')
            if stamp is None:
                stamp = footer[:4]
            if footer[:4] != stamp:
                raise PackingError('packed sector stamp mismatch')
            pieces.append(data[p:p + n])
            positions.extend(range(p, p + n))
            sectors.append({'physical_start': p, 'payload_length': n, 'stamp': int.from_bytes(stamp, 'big'), 'footer_hex': footer.hex()})
            if n < 505:
                stopped = True
                break
        if stopped:
            break
    if not stopped:
        raise PackingError('no final partial packed sector in allocation')
    payload = b''.join(pieces)
    if not payload:
        raise PackingError('empty packed stream')
    return (payload, positions, sectors)

def parse_database_directory(data, *, max_string_bytes=1048576):
    """Parse header-selected native directory and replay effective allocations.

 Pure read-only function. All offsets and lengths in effective_extents are bytes.
 Internal snapshot/event fields retain their explicitly named native units.
 Native pair selector118c2540 requires adjacent sequences and selects the lower.
 Unsupported grammar and corrupt streams raise PackingError; no candidate maps
 or scanned fallback are returned. This API supports tested native formats
 (header5/condition1 and directory3), not every historical ObjectStore grammar.
 max_string_bytes limits content bytes per owner/comment field (excluding NUL);
 callers may explicitly raise it for unusually long native directory strings.
 """
    import hashlib
    import copy
    data = bytes(data)
    if len(data) < 512 or data[:15] != b'eXc\r\nelon\rdb\n!\x00':
        raise PackingError('ObjectStore magic mismatch')
    if data[15:17] != b'\x05\x01':
        raise PackingError('unsupported file type/condition')
    footer = data[505:512]
    n = int.from_bytes(footer[4:6], 'big')
    if not 17 < n <= 505 or footer[6] != 1:
        raise PackingError('unsupported header footer')
    r = SectorReader(data[:n], [n])
    r.raw(17)
    header = {'magic_hex': data[:15].hex(), 'file_type': data[15], 'condition': data[16], 'dbid': [r.unsigned(32) for _ in range(3)], 'timestamp': r.unsigned(32), 'footer_hex': footer.hex(), 'payload_bytes': n}
    outer = DirectoryReader(r, max_string_bytes=max_string_bytes)
    outer.snapshot()
    if outer.outer != 1:
        raise PackingError('unsupported outer nesting depth')
    while r.pos < len(r.data):
        outer.event()
    if set(outer.segments) != {0, 1}:
        raise PackingError('unsupported outer directory pair')
    streams = []
    readers = []
    for sid in (0, 1):
        allocation = outer.segments[sid].get('legacy_allocation')
        if allocation is None:
            raise PackingError('unsupported outer directory allocation')
        payload, positions, sectors = read_packed_sectors(data, allocation)
        reader = SectorReader(payload, [s['payload_length'] for s in sectors])
        sequence = reader.unsigned(64)
        streams.append({'outer_segment': sid, 'sequence': sequence, 'payload_bytes': len(payload), 'sectors': sectors, 'source_spans': source_spans(positions), 'positions': positions})
        readers.append(reader)
    a, b = (s['sequence'] for s in streams)
    if abs(a - b) != 1:
        raise PackingError('native directory pair sequence difference must be1')
    selected = 0 if a < b else 1
    dr = DirectoryReader(readers[selected], max_string_bytes=max_string_bytes)
    snapshot = copy.deepcopy(dr.snapshot())
    if dr.outer != 0:
        raise PackingError('selected directory nesting mismatch')
    while dr.r.pos < len(dr.r.data):
        dr.event()
    positions = streams[selected]['positions']
    flat = []
    clusters = []
    for segments, string_positions in ((outer.segments, list(range(n))), (snapshot['segments'], positions), (dr.segments, positions)):
        for seg in segments.values():
            for key in ('owner', 'comment'):
                if key in seg:
                    provenance = seg[key]['provenance']
                    provenance['source_spans'] = source_spans(string_positions, provenance['payload_start'], provenance['payload_end'])
    for sid, seg in dr.segments.items():
        for cid, cl in seg['clusters'].items():
            allocation = cl['allocation']
            cursor = 0
            for e in allocation['extents']:
                if e['logical_start_sector'] != cursor:
                    raise PackingError('effective allocation gap/overlap')
                cursor += e['sector_count']
                physical = e['sector'] * 512
                length = e['sector_count'] * 512
                if e['component'] == 0 and physical + length > len(data):
                    raise PackingError('effective extent outside source')
                provenance = copy.deepcopy(e['provenance'])
                provenance['source_spans'] = source_spans(positions, provenance['payload_start'], provenance['payload_end'])
                flat.append({'segment': sid, 'cluster': cid, 'logical_start': e['logical_start_sector'] * 512, 'physical_start': physical, 'length': length, 'component': e['component'], 'address_scope': 'local' if e['component'] == 0 else 'external_component', 'provenance': provenance})
            if cursor != allocation['logical_end_sector']:
                raise PackingError('effective extent size mismatch')
            clusters.append({'segment': sid, 'cluster': cid, 'flags': cl['flags'], 'timestamp': cl['timestamp'], 'allocated_bytes': cursor * 512, 'used_bytes': allocation['used_bytes'], 'used_bytes_within_allocation': 0 <= allocation['used_bytes'] <= cursor * 512, 'metadata_tables': cl['tables']})
    for event in dr.events:
        event['source_spans'] = source_spans(positions, event['start'], event['end'])
    covered = [0] * len(dr.r.data)
    for t in dr.r.trace:
        if t['kind'] in ('data', 'control'):
            for i in range(t['start'], t['end']):
                covered[i] += 1
    if any((n != 1 for n in covered)):
        raise PackingError('selected stream byte coverage mismatch')
    for stream in streams:
        stream.pop('positions')
    return {'complete': True, 'sha256': hashlib.sha256(data).hexdigest(), 'header': header, 'outer_segments': outer.segments, 'directory_streams': streams, 'selected_outer_segment': selected, 'snapshot': snapshot, 'segments': dr.segments, 'clusters': clusters, 'effective_extents': flat, 'events': dr.events, 'event_count': len(dr.events), 'directory_timestamp': dr.limit, 'consumed_payload_bytes': dr.r.pos, 'consumed_source_spans': source_spans(positions), 'unsupported_tails': [], 'byte_accounting': {'payload_bytes': len(covered), 'exactly_once': True}, 'trace': dr.r.trace}
