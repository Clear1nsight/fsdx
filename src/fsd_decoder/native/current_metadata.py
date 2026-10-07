"""Current metadata via authoritative table directory and native hash probing.

With table_flag==0, primary-leaf next links are deliberately NOT followed: they
can retain historical overflow links. Global auxiliary table selection is not
yet supported, and is rejected before reading either a value or an iterator.
"""
from dataclasses import asdict
import struct
from fsd_decoder.native.table_directory import lookup as table_lookup, ranges as table_ranges
from fsd_decoder.native.leaf_storage import reconstruct, lookup as leaf_lookup

def indexed(mapping, key):
    if key in mapping:
        return mapping[key]
    return mapping[str(key)]

class CurrentMetadata:

    def __init__(self, data, effective):
        self.data = data
        self.effective = effective
        self.cache = {}
        self.leaves = {}

    def physical(self, component, offset, size):
        if component != 0:
            raise ValueError('External physical component unsupported')
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError('Truncated physical range')
        return self.data[offset:offset + size]

    def table(self, segment, cluster, table_index):
        if table_index not in (0, 1):
            raise ValueError('Unknown metadata table index')
        item = indexed(indexed(self.effective['segments'], segment)['clusters'], cluster)
        tables = item.get('tables', item.get('metadata_tables'))
        if tables is None:
            raise ValueError('Metadata table descriptors missing')
        table = tables[table_index]
        if table is not None and table.get('table_flag', 0):
            raise ValueError('Global overflow table selection unsupported')
        return table

    def leaf(self, reference):
        allocation = asdict(reference)
        ident = (allocation['component'], allocation['sector'], allocation['direct_sectors'], allocation['total_sectors'])
        leaf = self.leaves.get(ident)
        if leaf is None:
            leaf = reconstruct(self.data, allocation)
            if leaf['bytes'][0] != 2:
                raise ValueError('Unsupported native metadata leaf version')
            self.leaves[ident] = leaf
        return (leaf, allocation)

    def entry(self, segment, cluster, key, table_index=1):
        token = (segment, cluster, table_index, key)
        if token in self.cache:
            return self.cache[token]
        table = self.table(segment, cluster, table_index)
        if table is None:
            self.cache[token] = None
            return None
        reference = table_lookup(self.physical, table, key)
        if reference is None or reference.is_null:
            self.cache[token] = None
            return None
        leaf, allocation = self.leaf(reference)
        found = leaf_lookup(leaf, key)
        if found is None:
            self.cache[token] = None
            return None
        begin = found['payload_offset']
        end = begin + len(found['bytes'])
        spans = []
        run_base = 0
        for s in leaf['physical_spans']:
            run_length = s['physical_end'] - s['physical_start']
            lo = max(begin, run_base)
            hi = min(end, run_base + run_length)
            if lo < hi:
                spans.append(dict(physical_offset=s['physical_start'] + lo - run_base, length=hi - lo))
            run_base += run_length
        result = dict(key=key, raw=found['bytes'], leaf_reference=allocation, leaf_chain=[allocation], payload_spans=spans, table_index=table_index, slot_offset=found['slot_offset'], primary_next_link_followed=False)
        self.cache[token] = result
        return result

    def iter_entries(self, segment, cluster, table_index=1):
        """Yield current native-probe-visible values, each with key/raw/provenance."""
        table = self.table(segment, cluster, table_index)
        if table is None:
            return
        seen = set()
        for minimum, maximum, reference in table_ranges(self.physical, table):
            if reference is None or reference.is_null:
                continue
            leaf, _ = self.leaf(reference)
            for n in range(leaf['slot_count']):
                key = struct.unpack_from('>I', leaf['bytes'], leaf['slot_start'] + n * 8)[0]
                if key == 4294967295 or key in seen or (not minimum <= key <= maximum):
                    continue
                seen.add(key)
                value = self.entry(segment, cluster, key, table_index)
                if value is not None:
                    yield value
