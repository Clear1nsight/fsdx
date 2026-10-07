"""Exact source raster and scalar-index slice views, without inferred world geometry.

Uses native schema, current PRMs and current allocation boundaries. Caller supplies
catalog-proven shape/value ownership; reports retain the complete supplied context.
"""
from dataclasses import asdict
from pathlib import Path
import hashlib
import json
import math
import sqlite3
import struct
import zlib
from fsd_decoder.native.native_database import NativeDatabase
from fsd_decoder.schema.native_fields import NativeFields
from fsd_decoder.core.native_storage import Address
from fsd_decoder.exports.fsd_mesh import members
from fsd_decoder.exports.fsd_render_light import _png_bytes, _publish

class ExtraGeometryError(ValueError):
    pass

def rgba_png(raw, width, height, text):
    if len(raw) != width * height * 4 or min(width, height) <= 0:
        raise ExtraGeometryError('RGBA dimensions/storage disagree')

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 4294967295)
    compressor = zlib.compressobj(6)
    compressed = []
    for y in range(height):
        compressed.append(compressor.compress(b'\x00' + raw[y * width * 4:(y + 1) * width * 4]))
    compressed.append(compressor.flush())
    result = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
    for key, value in sorted(text.items()):
        result += chunk(b'tEXt', key.encode('latin1') + b'\x00' + str(value).encode('latin1', 'replace'))
    return result + chunk(b'IDAT', b''.join(compressed)) + chunk(b'IEND', b'')

def decode_png_rgba(png):
    """Independently inflate our lossless RGBA output for source-pixel comparison."""
    if png[:8] != b'\x89PNG\r\n\x1a\n':
        raise ExtraGeometryError('Invalid PNG signature')
    cursor = 8
    compressed = []
    dims = None
    while cursor < len(png):
        size = struct.unpack_from('>I', png, cursor)[0]
        kind = png[cursor + 4:cursor + 8]
        data = png[cursor + 8:cursor + 8 + size]
        if len(data) != size or struct.unpack_from('>I', png, cursor + 8 + size)[0] != zlib.crc32(kind + data) & 4294967295:
            raise ExtraGeometryError('PNG chunk CRC mismatch')
        if kind == b'IHDR':
            width, height, depth, colour, compression, filter_, interlace = struct.unpack('>IIBBBBB', data)
            if (depth, colour, compression, filter_, interlace) != (8, 6, 0, 0, 0):
                raise ExtraGeometryError('Unsupported PNG encoding')
            dims = (width, height)
        if kind == b'IDAT':
            compressed.append(data)
        cursor += size + 12
    if dims is None:
        raise ExtraGeometryError('Missing PNG dimensions')
    width, height = dims
    scan = zlib.decompress(b''.join(compressed))
    stride = width * 4 + 1
    if len(scan) != height * stride:
        raise ExtraGeometryError('PNG row extent mismatch')
    if any((scan[y * stride] != 0 for y in range(height))):
        raise ExtraGeometryError('Unsupported PNG filter')
    return (width, height, b''.join((scan[y * stride + 1:(y + 1) * stride] for y in range(height))))

def scalar_colour(value, low, high):
    """Documented blue-to-red index legend; all finite values participate."""
    if not math.isfinite(value):
        return (180, 180, 180)
    t = 0.5 if high == low else max(0.0, min(1.0, (value - low) / (high - low)))
    return (round(255 * t), round(200 * (1 - abs(2 * t - 1))), round(255 * (1 - t)))

class ExtraGeometry:

    def __init__(self, bundle=None, db=None, *, fields=None, schema_classes=None, allocation_lookup=None, max_pixels=25000000):
        """Read either a validated legacy bundle or injected portable-store APIs.

        Portable callers pass db, schema_classes and allocation_lookup(address).
        No source FSD or bundle path is opened in that mode.
        """
        self.bundle = Path(bundle) if bundle is not None else None
        self.index = None
        self._allocation_lookup = allocation_lookup
        if self.bundle is not None:
            info = json.loads((self.bundle / 'file_information.json').read_text())
            db = db or NativeDatabase.from_path(info['source']['path'])
            expected = info['source'].get('sha256')
            if expected and db.sha256 != expected:
                raise ExtraGeometryError('Bundle/source hash mismatch')
            self.index = sqlite3.connect('file:' + str(self.bundle / 'inventory/index.sqlite') + '?mode=ro', uri=True)
            manifest = json.loads((self.bundle / 'inventory/manifest.json').read_text())
            if manifest['source_sha256'] != db.sha256 or not manifest['complete']:
                raise ExtraGeometryError('Inventory/source mismatch or incomplete inventory')
        elif db is None or allocation_lookup is None or (fields is None and schema_classes is None):
            raise ExtraGeometryError('Portable mode requires db, schema and allocation lookup')
        self.db = db
        self.fields = fields if fields is not None else NativeFields(db) if schema_classes is None else None
        self.schema_classes = schema_classes
        self.class_names = set(self.fields.schema.classes) if self.fields is not None else set(schema_classes)
        if type(max_pixels) is not int or max_pixels <= 0:
            raise ExtraGeometryError('Invalid pixel bound')
        self.max_pixels = max_pixels

    def close(self):
        if self.index is not None:
            self.index.close()

    def layout(self, name):
        return self.fields.schema.layout(name) if self.fields is not None else self.schema_classes[name]

    def layout_problems(self, name):
        if self.fields is not None:
            return self.fields._layout_problems(name)

        def problems(layout):
            return layout.get('unresolved', []) + [issue for base in layout['bases'] for issue in problems(base['layout'])]
        return problems(self.layout(name))

    def address(self, value):
        address = value if isinstance(value, Address) else Address(**value)
        if address.database != self.db.database_id:
            raise ExtraGeometryError('Address belongs to another source')
        return address

    def allocation(self, address, *, exact=False):
        address = self.address(address)
        if self._allocation_lookup is not None:
            value = self._allocation_lookup(address)
            if value is None or not value['logical_offset'] <= address.offset < value['logical_offset'] + value['size']:
                raise ExtraGeometryError('Address outside portable allocation')
        else:
            row = self.index.execute('SELECT start,end,record FROM allocations WHERE segment=? AND cluster=? AND start<=? ORDER BY start DESC LIMIT 1', (address.segment, address.cluster, address.offset)).fetchone()
            if row is None or not row[0] <= address.offset < row[1]:
                raise ExtraGeometryError('Address outside current allocation')
            value = json.loads(zlib.decompress(row[2]))
        if exact and address.offset != value['logical_offset']:
            raise ExtraGeometryError('Expected exact owner allocation start')
        return value

    def owner(self, address, name=None, *, allow_value_base=False):
        address = self.address(address)
        a = self.allocation(address)
        if self.fields is None or not self.fields.schema_admission(a)['admitted']:
            raise ExtraGeometryError('Owner native storage does not corroborate source layout')
        displacement = address.offset - a['logical_offset']
        if displacement:

            def bases(layout, offset=0):
                found = []
                for base in layout['bases']:
                    at = offset + base['offset']
                    if base['type']['name'] == 'Fs::Value':
                        found.append(at)
                    found.extend(bases(base['layout'], at))
                return found
            if not allow_value_base or a['name'] not in self.class_names or displacement not in bases(self.layout(a['name'])):
                raise ExtraGeometryError('Interior owner reference is not a schema-proven Fs::Value base')
            address = self.db.address(address.segment, address.cluster, a['logical_offset'])
        if a['vector'] or (name is not None and a['name'] != name):
            raise ExtraGeometryError('Unexpected owner type')
        if a['name'] not in self.class_names or self.layout_problems(a['name']):
            raise ExtraGeometryError('Incomplete schema for owner')
        return (address, a, members(self.layout(a['name'])))

    def field(self, address, definition, name):
        offset, typ = definition[name]
        return (self.db.address(address.segment, address.cluster, address.offset + offset), typ)

    def uint(self, address, definition, name):
        source, typ = self.field(address, definition, name)
        while typ['kind'] in ('alias', 'qualified'):
            typ = typ['underlying']
        if typ['kind'] != 'primitive' or typ['size'] not in (2, 4) or 'unsigned' not in typ['name']:
            raise ExtraGeometryError('Invalid unsigned dimension member')
        return int.from_bytes(self.db.read(source, typ['size']), 'little')

    def pointer(self, address, definition, name):
        source, typ = self.field(address, definition, name)
        if typ['size'] != 4:
            raise ExtraGeometryError('Unsupported reference width')
        return self.db.resolve(source)

    def double(self, address, definition, name):
        source, typ = self.field(address, definition, name)
        if typ['size'] != 8 or typ.get('name') != '8 byte ieeed double':
            raise ExtraGeometryError('Unsupported scalar encoding')
        raw = self.db.read(source, 8)
        value = struct.unpack('<d', raw)[0]
        return dict(source_address=asdict(source), raw_hex=raw.hex(), decimal=repr(value))

    def array(self, address, name, count, stride):
        if address is None:
            if count == 0:
                return None
            raise ExtraGeometryError('Positive array has null pointer')
        a = self.allocation(address)
        accepted = {'double[]', '8 byte ieeed double[]'} if name == 'double[]' else {name}
        if a['name'].removesuffix('[]') in self.class_names and (
                self.fields is None or not self.fields.schema_admission(a)['admitted']):
            raise ExtraGeometryError('Array native storage does not corroborate source layout')
        if a['name'] not in accepted or not a['vector'] or a['count'] != count or (a['element_stride'] != stride) or (a['element_size'] != stride):
            raise ExtraGeometryError('Native array type/count/stride mismatch')
        data_start = a['logical_offset'] + a['array_header_size']
        if self.address(address).offset != data_start or a['array_header_size'] + count * stride > a['size']:
            raise ExtraGeometryError('Pointer is not array data start or exceeds allocation')
        return a

    def coordinate(self, target):
        address, a, definition = self.owner(target)

        def inherits(layout):
            return layout['name'] == 'Fs::Spatial::Coordinate' or any((inherits(b['layout']) for b in layout['bases']))
        if not inherits(self.layout(a['name'])):
            raise ExtraGeometryError('Reference does not target Coordinate-derived class')
        dimension = self.uint(address, definition, 'm_dimension')
        values = self.pointer(address, definition, 'm_pValues')
        self.array(values, 'double[]', dimension, 8)
        raw = self.db.read(values, dimension * 8) if dimension else b''
        components = []
        for i, (value,) in enumerate(struct.iter_unpack('<d', raw)):
            bits = raw[i * 8:i * 8 + 8]
            decimal = repr(value)
            finite = math.isfinite(value)
            if finite and struct.pack('<d', float(decimal)) != bits:
                raise ExtraGeometryError('Coordinate decimal failed roundtrip')
            components.append(dict(decimal=decimal, raw_hex=bits.hex(), finite=finite))
        return dict(type=a['name'], source_address=asdict(address), dimension=dimension, values_address=asdict(values) if values else None, values=components)

    def shape_metadata(self, shape_address, context=None):
        address, a, definition = self.owner(shape_address)
        frame = self.pointer(address, definition, 'm_pCoordinateSystem')
        context = context or {}
        supplied = context.get('coordinate_system_address')
        if supplied is None and isinstance(context.get('frame'), dict):
            supplied = context['frame'].get('coordinate_system_address')
        if supplied is not None and self.address(supplied) != frame:
            raise ExtraGeometryError('Shape and context coordinate frames disagree')
        report = dict(shape_address=asdict(address), shape_type=a['name'], coordinate_system_address=asdict(frame) if frame else None, source=dict(sha256=self.db.sha256, database_id=self.db.database_id), context=context, coordinate_policy='Stored row/column index image; source geometry coordinates recorded without transformation')
        names = ('m_pTopLeftCoordinate', 'm_pTopRightCoordinate', 'm_pBottomLeftCoordinate', 'm_pBottomRightCoordinate') if a['name'] == 'Fs::Spatial::Geom::ImagePlane' else ('m_pOriginPoint', 'm_pBasisVector1', 'm_pBasisVector2', 'm_pBasisVector3')
        report['stored_coordinates'] = {n: self.coordinate(self.pointer(address, definition, n)) for n in names if n in definition}
        report['stored_extents'] = {n: self.uint(address, definition, n) for n in ('m_extent1', 'm_extent2', 'm_extent3') if n in definition}
        return report

    def write_ring_coordinates(self, shape_address, jsonl_path, context=None):
        report = self.shape_metadata(shape_address, context)
        address, a, definition = self.owner(shape_address)
        layout = self.layout(a['name'])

        def inherits(node, name):
            return node['name'] == name or any((inherits(b['layout'], name) for b in node['bases']))
        if not inherits(layout, 'Fs::Spatial::Geom::LineString'):
            raise ExtraGeometryError('Unsupported line/ring class')
        count = self.uint(address, definition, 'm_numPoints')
        target = self.pointer(address, definition, 'm_ppPointArray')
        self.array(target, '4 byte void*[]', count, 4)
        first = last = None
        dimensions = set()
        raw_hash = hashlib.sha256()
        with Path(jsonl_path).open('x', encoding='utf-8') as stream:
            for i in range(count):
                slot = self.db.address(target.segment, target.cluster, target.offset + 4 * i)
                coordinate = self.coordinate(self.db.resolve(slot))
                dimensions.add(coordinate['dimension'])
                raw = b''.join((bytes.fromhex(v['raw_hex']) for v in coordinate['values']))
                raw_hash.update(raw)
                if first is None:
                    first = raw
                last = raw
                entry = dict(index=i, reference_source=asdict(slot), reference_raw_hex=self.db.read(slot, 4).hex(), **coordinate)
                stream.write(json.dumps(entry, allow_nan=False) + '\n')
        self.db.verify_source()
        report.update(kind='lines', point_count=count, dimensions=sorted(dimensions), source_coordinates_sha256=raw_hash.hexdigest(), closed_endpoint_equal=count > 1 and first == last, source_unchanged=True, sequence_policy='Consecutive stored source edges only; no new closing edge or polygon fill')
        return report

    def render_image(self, shape_address, value_address, png_path, report_path, context=None):
        report = self.shape_metadata(shape_address, context)
        if report['shape_type'] != 'Fs::Spatial::Geom::ImagePlane':
            raise ExtraGeometryError('ImageData requires exact ImagePlane owner association')
        address, a, definition = self.owner(value_address, 'Fs::ImageData', allow_value_base=True)
        rows = self.uint(address, definition, 'm_rows')
        columns = self.uint(address, definition, 'm_cols')
        if not 0 < rows * columns <= self.max_pixels:
            raise ExtraGeometryError('Empty image or explicit pixel limit exceeded')
        pixel_type = self.layout('Fs::RGBAPixelValue')
        pixel_members = members(pixel_type)
        if pixel_type['size'] != 4 or set(pixel_members) != {'red', 'green', 'blue', 'alpha'}:
            raise ExtraGeometryError('Unsupported RGBA pixel schema')
        for offset, name in enumerate(('red', 'green', 'blue', 'alpha')):
            member_offset, typ = pixel_members[name]
            if member_offset != offset or typ['size'] != 1 or typ.get('name') != '1 byte unsigned char':
                raise ExtraGeometryError('Unsupported RGBA channel layout')
        target = self.pointer(address, definition, 'm_pPixelData')
        array = self.array(target, 'Fs::RGBAPixelValue[]', rows * columns, 4)
        raw = self.db.read(target, rows * columns * 4)
        report.update(kind='native_rgba_raster', status='COMPLETE_SOURCE_PIXEL_RASTER', value_address=asdict(address), value_reference_address=asdict(self.address(value_address)), width=columns, height=rows, source_pixel_address=asdict(target), source_pixel_sha256=hashlib.sha256(raw).hexdigest(), pixel_count=rows * columns, channel_order='RGBA8 from embedded red/green/blue/alpha member offsets', pixel_order='row * columns + column; row 0 shown at top', pixel_order_evidence='Static ImageData accessor 0x10032af0 uses (row*m_cols+column)*4; embedded dimensions and current array count agree', alpha_policy='Exact stored alpha retained; no opacity replacement or background compositing', source_allocation=dict(start=array['logical_offset'], size=array['size'], count=array['count'], header_size=array['array_header_size']), alpha_zero_count=raw[3::4].count(0), alpha_opaque_count=raw[3::4].count(255), world_plane_projection_applied=False)
        png = rgba_png(raw, columns, rows, {'Source SHA256': self.db.sha256, 'View': 'Original stored RGBA raster; row 0 at top'})
        w, h, decoded = decode_png_rgba(png)
        if (w, h) != (columns, rows) or decoded != raw:
            raise ExtraGeometryError('PNG pixel/source validation failed')
        report.update(png_sha256=hashlib.sha256(png).hexdigest(), all_pixels_source_verified=True, source_unchanged=True)
        self.db.verify_source()
        _publish(png, report, Path(png_path), Path(report_path))
        return report

    def grid_rows(self, address, definition, layers, rows, columns, three):
        root = self.pointer(address, definition, 'm_pppValues' if three else 'm_ppValues')
        self.array(root, '4 byte void*[]', layers if three else rows, 4)
        for layer in range(layers):
            row_array = self.db.resolve(self.db.address(root.segment, root.cluster, root.offset + 4 * layer)) if three else root
            self.array(row_array, '4 byte void*[]', rows, 4)
            for row in range(rows):
                slot = self.db.address(row_array.segment, row_array.cluster, row_array.offset + row * 4)
                target = self.db.resolve(slot)
                self.array(target, 'double[]', columns, 8)
                yield (layer, row, target, self.db.read(target, columns * 8))

    def render_grid(self, shape_address, value_address, output_directory, context=None):
        report = self.shape_metadata(shape_address, context)
        address, a, definition = self.owner(value_address, allow_value_base=True)
        if a['name'] not in ('Fs::Grid2ScalarData', 'Fs::Grid3ScalarData'):
            raise ExtraGeometryError('Unsupported scalar grid owner')
        three = a['name'] == 'Fs::Grid3ScalarData'
        expected = 'Fs::Spatial::Geom::RegularGrid3' if three else 'Fs::Spatial::Geom::RegularGrid2'
        if report['shape_type'] != expected:
            raise ExtraGeometryError('Grid scalar and geometry dimensionality disagree')
        rows = self.uint(address, definition, 'm_numRows')
        columns = self.uint(address, definition, 'm_numColumns')
        layers = self.uint(address, definition, 'm_numLayers') if three else 1
        if min(rows, columns, layers) <= 0 or rows * columns > self.max_pixels:
            raise ExtraGeometryError('Empty grid or explicit per-slice pixel limit exceeded')
        extents = report['stored_extents']
        if extents.get('m_extent1') != columns or extents.get('m_extent2') != rows or (three and extents.get('m_extent3') != layers):
            raise ExtraGeometryError('Owned grid/scalar dimensions disagree')
        low = math.inf
        high = -math.inf
        finite = nonfinite = marker_count = 0
        whole = hashlib.sha256()
        layer_hashes = [hashlib.sha256() for _ in range(layers)]
        marker = self.double(address, definition, 'm_missingDataIdentifier')
        marker_raw = bytes.fromhex(marker['raw_hex'])
        for layer, row, target, raw in self.grid_rows(address, definition, layers, rows, columns, three):
            whole.update(raw)
            layer_hashes[layer].update(raw)
            for i, (value,) in enumerate(struct.iter_unpack('<d', raw)):
                marker_count += raw[i * 8:(i + 1) * 8] == marker_raw
                if math.isfinite(value):
                    low = min(low, value)
                    high = max(high, value)
                    finite += 1
                else:
                    nonfinite += 1
        report.update(kind='scalar_grid_index_slices', value_address=asdict(address), value_reference_address=asdict(self.address(value_address)), value_type=a['name'], width=columns, height=rows, layers=layers, total_source_values=layers * rows * columns, finite_values=finite, nonfinite_values=nonfinite, source_scalar_f64le_sha256=whole.hexdigest(), stored_missing_data_identifier=marker, stored_identifier_match_count=marker_count, stored_range_min=self.double(address, definition, 'm_rangeMin'), stored_range_max=self.double(address, definition, 'm_rangeMax'), legend=dict(finite_min=low if finite else None, finite_max=high if finite else None, low_rgb=[0, 0, 255], high_rgb=[255, 0, 0], constant_rgb=[128, 200, 128], nonfinite_rgb=[180, 180, 180], rule='Linear blue-green-red scale over all finite values across all layers; stored sentinel values included; no values silently removed'), pixel_order='column index to the right; row index downward; one separate image per stored layer', topology_policy='Scalar storage index views only; no interpolated geometry, cell/node spatial assignment, axis mapping, or isosurface inferred')
        directory = Path(output_directory)
        directory.mkdir(parents=True, exist_ok=False)
        reports = []
        pixels = bytearray(rows * columns * 3)
        checked = hashlib.sha256()
        for layer, row, target, raw in self.grid_rows(address, definition, layers, rows, columns, three):
            checked.update(raw)
            for col, (value,) in enumerate(struct.iter_unpack('<d', raw)):
                k = (row * columns + col) * 3
                pixels[k:k + 3] = bytes(scalar_colour(value, low, high))
            if row == rows - 1:
                entry = dict(report, status='COMPLETE_STORED_LAYER', layer_index=layer, layer_source_values=rows * columns, layer_source_f64le_sha256=layer_hashes[layer].hexdigest(), source_unchanged=True, png_path=f'layer_{layer:04d}.png', report_path=f'layer_{layer:04d}.json')
                png = _png_bytes(pixels, columns, rows, {'Source SHA256': self.db.sha256, 'View': f'Scalar index slice {layer}; source row 0 at top', 'Legend': json.dumps(report['legend'])})
                entry['png_sha256'] = hashlib.sha256(png).hexdigest()
                self.db.verify_source()
                _publish(png, entry, directory / entry['png_path'], directory / entry['report_path'])
                reports.append(entry)
        if checked.hexdigest() != whole.hexdigest():
            raise ExtraGeometryError('Grid changed between range and rendering reads')
        self.db.verify_source()
        return reports
