# Recovering FracSIS/ObjectStore databases

### Encoded file anatomy, recovery architecture, and design evolution

<p class="paper-repository"><small>GitHub repository: <a href="https://github.com/Clear1nsight/fsdx">https://github.com/Clear1nsight/fsdx</a></small></p>

**Living technical paper.** Software baseline 0.1.51. Document revision 15.

<details>
<summary>Contents</summary>

[1. Purpose and scope](#1-purpose-and-scope)  
[2. The architectural model](#2-the-architectural-model)  
[3. Anatomical overview of the encoded FSD](#3-anatomical-overview-of-the-encoded-fsd)  
[4. Packed directories and current logical storage](#4-packed-directories-and-current-logical-storage)  
[5. Metadata tables and leaf storage](#5-metadata-tables-and-leaf-storage)  
[6. Allocation anatomy](#6-allocation-anatomy)  
[7. Persistent pointer anatomy](#7-persistent-pointer-anatomy)  
[8. Schemas, roots, and typed interpretation](#8-schemas-roots-and-typed-interpretation)  
[9. Software architecture and FSDX](#9-software-architecture-and-fsdx)  
[10. Capture, verification, and operational workflows](#10-capture-verification-and-operational-workflows)  
[11. Recovery prototypes and the decisions they produced](#11-recovery-prototypes-and-the-decisions-they-produced)  
[12. Storage and compression experiments](#12-storage-and-compression-experiments)  
[13. Performance and resource-management prototypes](#13-performance-and-resource-management-prototypes)  
[14. Testing the architecture](#14-testing-the-architecture)  

</details>

## Abstract

This paper explains how the FSD recovery system reconstructs observed FracSIS/ObjectStore databases, why its architecture takes its present form, and how earlier prototypes informed the implementation. The native file is approached as a structured persistent object database rather than a collection of recognisable strings or numerical arrays. Recovery begins with an immutable source snapshot, follows the header-selected directory streams, reconstructs current logical storage, and interprets allocation tags, persistent pointer metadata, and source-derived schemas. The resulting logical database is captured in FSDX, a purpose-built SQLite archive that supports subsequent inspection without reopening the original FSD. Structural interpretation remains separate from application meaning, allowing unknown fields and unresolved relationships to remain available for later investigation. The development account follows the progression from specimen-specific extraction and independent binary-layout checks to directory-driven recovery, portable capture, bounded parallelism, and selective native acceleration. It also explains alternatives that were tested but not adopted, including storage projections, numeric compression, pointer batching, and verifier-cache changes. Historical measurements are retained to explain engineering decisions rather than presented as universal performance claims. The document is intended to evolve with the software and to provide a coherent account of both its mechanisms and their rationale.

## 1. Purpose and scope

The immediate problem was practical. Legacy FracSIS databases contained information that could no longer be inspected through the available application environment. An initial request to recover readable text developed into a broader requirement to identify current objects, reconstruct their relationships, and retain enough of the underlying representation to support further interpretation. A successful extraction therefore needed to explain where a value came from and how it had been interpreted, rather than merely produce plausible output.

This is a living technical paper, not a journal submission or a complete vendor-format specification. Its purpose is to explain the implemented system, its principal workflows, and the decisions that shaped it. It retains an academic style through explicit terminology, architectural explanation, and careful distinctions between observations and conclusions, without organising the narrative around publication claims or a separate evidence ledger.

The present-tense architectural description follows the 0.1.49 source, including the indexed chunk-admission change in section 13.12, page-context encoding reuse in section 13.14 and reusable JSON encoder configuration in section 13.15, and bounded pointer-proof framing in section 13.17. Development history combines the earlier manuscript with the author-supplied architecture research log, comprising of 104 records. Historical version identities remain attached to the activities they describe; a candidate version is not assumed to have been released. The log summarises prior work rather than providing a newly executed experiment. The historical tests were not rerun for the history integration; the later local algorithm experiments and their fresh validation are reported separately in sections 13.11–13.17. The later source review and constructed byte-example checks are described separately. Earlier experiments explain decisions, while the current source determines which mechanisms are implemented.

The scope is the observed FracSIS/ObjectStore layouts supported by this reader. The `.fsd` extension alone does not establish compatibility. Similarly, successful preservation of current logical storage does not establish complete recovery of the originating application's behaviour, geological meaning, coordinate reference systems, units, or ownership rules.

## 2. The architectural model

### 2.1. Four distinct representations

The system separates the physical file, the logical database, the interpreted object structures, and the application view. This separation is central to both its implementation and its limitations.

| Representation | What it contains | What it does not establish |
| --- | --- | --- |
| Physical FSD | The original file bytes, including directory storage, mapped extents, and other physical regions. | Which recognisable bytes belong to the effective current database. |
| Logical database | Current segment and cluster address spaces reconstructed from the selected directory and extent mappings. | The type or application meaning of every stored byte. |
| Structural object view | Allocations, element counts, compiled layouts, fields, roots, and pointer bindings. | Dataset ownership, geological roles, units, or complete application behaviour. |
| Application and export view | Selected catalogues, relationships, text, geometry, and other derived interpretations. | Completeness outside the particular selection and interpretation contract. |

FSDX preserves the logical database together with the structural descriptions needed to inspect it. It is not a physical clone of the native file. Current cluster allocations can contain bytes that are not interpreted as live object payload, and capture retains those mapped bytes too. Conversely, physical storage outside the reconstructed current map is not made part of FSDX simply because it remains present in the original file. The original FSD must therefore remain available for later investigation of historical or otherwise unmapped regions.

### 2.2. Native storage is a dependency structure

The relationships below describe how structures are reached. They are not a claim that those structures occupy consecutive regions in the physical file.

```text
Physical header sector
    |
    +--> Outer directory description
             |
             +--> Paired packed directory streams
                       |
                       +--> Selected snapshot and sequential updates
                                 |
                                 +--> Current segments and clusters
                                           |
                                           +--> Physical extent mappings
                                           |       |
                                           |       +--> Logical cluster bytes
                                           |
                                           +--> Current metadata tables
                                                   |
                                                   +--> Free-space groups
                                                   +--> Allocation tags
                                                   +--> PRM pointer chains

Logical bytes + allocation metadata + pointer mappings + schema
    |
    +--> Structural objects and roots
             |
             +--> FSDX capture and subsequent interpretation
```

The directory tells the reader which storage is current and how to address it. Allocation metadata explains how parts of that storage are divided into typed allocations. Pointer metadata explains how stored words refer to other logical addresses. Schema information explains how supported objects can be read as fields. Skipping one of these dependencies can turn a recognisable byte pattern into an incorrect object interpretation.

*Implementation basis.* The dependency structure is implemented across [native directory reconstruction](../../src/fsd_decoder/native/native_directory.py), [logical addressing](../../src/fsd_decoder/core/native_storage.py), [allocation iteration](../../src/fsd_decoder/native/native_allocations.py), and [typed interpretation](../../src/fsd_decoder/schema/native_fields.py).

### 2.3. How the architecture emerged

The present layers were not designed independently of the recovery work. They address limitations exposed by successive prototypes, with several alternatives remaining outside the maintained implementation.

| Investigative stage | Limitation encountered | Resulting architectural decision |
| --- | --- | --- |
| Initial byte extraction and array carving | Readable output and specimen-specific offsets did not establish current object identity. | Follow directory state, reconstruct logical storage, and retain exact source spans. |
| Schema and independent layout prototypes | Local layout agreement did not settle liveness, relocation, or ownership. | Combine admitted schema descriptions with allocations and PRM before interpreting relationships. |
| Repeated exports and language experiments | Native reconstruction was repeated, while crossing a language bridge could add object-conversion costs. | Separate Python native capture from reusable FSDX inspection and optimise bounded work before attempting a rewrite. |
| Dynamic discovery and collection work | More names, members, or exported records did not necessarily produce new usable datasets. | Separate structural populations, membership, partial interpretation, and application-level conclusions. |
| Worker and native-helper experiments | A faster component could still regress whole-capture time or memory. | Keep one ordered capture owner, use bounded optional workers, and admit narrow acceleration against complete operations. |
| Public-source preparation | Private inputs and historical results could be mistaken for installed resources or new validation. | Keep the runtime self-contained and distinguish present implementation from historical experiments. |

Sections 11 through 13 develop these decisions, including unsuccessful and incomplete routes. The dependency structure described above remains the organising model; the experiments explain why those boundaries matter.

## 3. Anatomical overview of the encoded FSD

### 3.1. What encoded means here

The reader encounters several representations within one file. Directory values use variable-width packing. Metadata tables contain fixed-width directory entries and hash slots. Allocation descriptions use tag words and compact counts. Persistent pointers combine target information with chain links. Object payloads use their own primitive and class layouts. Encoded therefore does not mean that the entire file is encrypted or that one decompressor can turn it into a flat object stream.

There is also no single byte order for every structure. The following distinctions are part of the implemented grammar.

| Structure | Implemented representation |
| --- | --- |
| Header and directory scalar values | Packed values with big-endian numeric payload bytes and least-significant-bit-first control flags. |
| Directory-sector footers | Fixed fields, including a big-endian payload length. |
| Metadata leaf references and hash slots | Fixed-width big-endian fields. |
| Allocation tag words | Byte order selected by the tag header. |
| PRM heads and stored pointer words | Little-endian 32-bit words, with either four-byte or eight-byte pointer fields. |
| Supported native root header | Little-endian integers and eight-byte internal pointer fields. |

The physical sector size is 512 bytes. Allocation and PRM operations are organised around logical pages of 4,096 bytes. These units must not be confused with FSDX's default 1 MiB logical chunks or its selected 16 MiB BLOB and document-leaf limits, which are archive policies rather than native disk-format units.

### 3.2. The physical header sector

`parse_database_directory` first requires at least one complete 512-byte sector. It recognises the following header prefix and footer. Offsets in this table are physical byte offsets from the beginning of the file.

| Offset | Length | Interpretation in the supported reader |
| --- | --- | --- |
| `0x000` through `0x00E` | 15 bytes | Signature `65 58 63 0d 0a 65 6c 6f 6e 0d 64 62 0a 21 00`, represented as `eXc\r\nelon\rdb\n!\x00`. |
| `0x00F` | 1 byte | Supported file-type value `0x05`. |
| `0x010` | 1 byte | Supported condition value `0x01`. |
| From `0x011` | Variable | Packed database identity, timestamp, and outer-directory content. |
| `0x1F9` through `0x1FC` | 4 bytes | Footer stamp bytes. |
| `0x1FD` through `0x1FE` | 2 bytes | Big-endian valid payload length. |
| `0x1FF` | 1 byte | Supported footer marker `0x01`. |

The valid payload length must be greater than 17 and no greater than 505. Bytes after that payload and before the footer are not treated as additional packed header fields. After the fixed prefix, the reader extracts three packed unsigned 32-bit values for the database identity and another for the recorded timestamp. It formats the identity words as a 24-character hexadecimal identifier. The timestamp is retained as a raw field; this reader does not establish its epoch or application meaning merely by decoding it.

Offsets after the prefix cannot be listed as one universal fixed-layout structure because numeric widths depend on control bits. A byte map that assumes three ordinary four-byte identity fields would misdescribe the implementation.

*Implementation basis.* See `parse_database_directory` in [native_directory.py](../../src/fsd_decoder/native/native_directory.py) and the database identity construction in [native_database.py](../../src/fsd_decoder/native/native_database.py).

## 4. Packed directories and current logical storage

### 4.1. Interleaved control bits and numeric bytes

The packed reader maintains a byte cursor and a separate reservoir of control bits. When the reservoir is empty, it reads a control byte and consumes its flags from least significant to most significant bit. Numeric payload bytes advance the byte cursor without consuming the remaining control flags. A control byte can therefore govern several values separated by their payload bytes.

For an unsigned 32-bit value, two successive control bits select the number of payload bytes. If the bits in consumption order are `b0` and `b1`, the implemented width is `1 + 2*b0 + b1`.

| First flag | Second flag | Payload width |
| --- | --- | --- |
| 0 | 0 | 1 byte |
| 0 | 1 | 2 bytes |
| 1 | 0 | 3 bytes |
| 1 | 1 | 4 bytes |

Unsigned 16-bit values use one flag to select one or two bytes. Signed 16-bit and 32-bit values use the corresponding width selection with signed big-endian interpretation. The nominal unsigned 64-bit reader accepts the observed low-width branch and then reads an unsigned 32-bit value. It rejects the high-width branch. Its method name should not be read as a promise to support arbitrary 64-bit packed values.

A constructed example encodes `0x1234` followed by `0x05` as `02 12 34 05`. The control byte `02` supplies flags `0,1` for the first value and `0,0` for the second. The numeric payloads are therefore `12 34` and `05`. This example demonstrates the interleaving rule, not the complete grammar of a database directory.

### 4.2. Sector boundaries are parser state

Packed directory sectors reserve their final seven bytes for a stamp, a valid-byte count, and a marker. At most 505 bytes contribute to the packed stream. The directory reader follows explicit extents, checks the sector marker and matching stamps within a stream, and stops at a final partial sector. An allocation without that terminating partial sector is rejected by the supported reader.

Sector boundaries remain significant after payload bytes are concatenated. `SectorReader` tracks each sector's payload length. Loading raw bytes from the next sector discards unused flags from the previous control reservoir. Merely arriving at a boundary does not itself discard them. Remaining flags can still be consumed until a raw read actually crosses into the next sector. A parser that strips the footers and then treats all control bytes as one uninterrupted bit stream would miss this behaviour.

### 4.3. Paired streams and sequential replay

The outer directory must describe the supported pair of segments numbered 0 and 1. Each identifies a packed directory stream through its recorded allocation. The first packed value of each stream is its sequence number. The implementation requires the two sequence numbers to differ by exactly one and selects the lower sequence. It does not choose the numerically highest value under a generic assumption that the highest number must be newest.

The selected stream is interpreted as a snapshot followed by supported events. The parser handles operations such as cluster creation and deletion, metadata-table replacement or update, extent append or growth, allocation truncation, and used-byte changes. Events change the effective state in sequence. An old snapshot or recognisable table found elsewhere in the file is not interchangeable with that state.

The scalar snapshot parser contains version branches, but the complete database path is narrower than those branches considered individually. Its stated support is the observed header-type-5, condition-1 path and directory-3 layout. Supporting an isolated scalar or older snapshot branch does not establish end-to-end support for every historical file version.

### 4.4. From extents to logical addresses

A logical address has four components, comprising database identity, segment, cluster, and byte offset. A physical file position is a different quantity. For an extent beginning at logical byte `L` and physical byte `P`, a logical position `x` within the extent maps to `P + (x - L)`. Physical sector numbers are converted into byte positions by multiplying by 512.

The effective directory must provide contiguous logical coverage for each admitted cluster allocation. Physical storage may be fragmented. A read can therefore span multiple nonadjacent physical ranges while remaining contiguous in logical space. The address map validates each span and joins the corresponding bytes in logical order. Unsupported external storage components, out-of-file physical ranges, and unmapped logical gaps are not filled with invented bytes.

Consider a constructed cluster whose first 4,096 logical bytes occupy physical offset `0x4000` and whose next 4,096 bytes occupy physical offset `0xA000`. Reading 12 bytes at logical offset 4,090 requires six bytes from `0x4FFA` and six from `0xA000`. Reading 12 adjacent physical bytes from the first location would be wrong.

Each logical cluster also carries both allocated and used byte counts. They are not synonyms. FSDX capture copies the admitted allocated logical range, rather than treating the used-byte count as an instruction to discard everything beyond it.

*Implementation basis.* See [packed_stream.py](../../src/fsd_decoder/native/packed_stream.py), [native_directory.py](../../src/fsd_decoder/native/native_directory.py), and [native_storage.py](../../src/fsd_decoder/core/native_storage.py).

## 5. Metadata tables and leaf storage

### 5.1. Current table lookup

Each admitted cluster carries two metadata-table descriptors. Table selection comes from the effective directory. `CurrentMetadata` then uses the selected descriptor to locate the appropriate leaf and reproduce its exact-key lookup. This path does not scan every physical page for a plausible matching key.

A table descriptor contains a depth and a shift. The depth determines the number of directory entries, while the shift determines how many adjacent keys share an entry. In the directory form, a key selects its eight-byte reference at index `key >> shift`. The depth-zero form instead uses the descriptor's extents directly. These are supported representation branches, not alternative recovery guesses.

An eight-byte leaf reference has the following structure.

| Relative offset | Length | Meaning |
| --- | --- | --- |
| 0 | 1 byte | Total number of sectors belonging to the leaf. |
| 1 | 1 byte | Number of directly contiguous sectors. |
| 2 | 2 bytes | Big-endian storage component. |
| 4 | 4 bytes | Big-endian starting physical sector. |

For example, `03 01 00 00 00 00 00 20` describes three sectors in total, one direct sector, component zero, and starting sector 32. The first direct byte is consequently at physical offset 16,384. The additional two sectors are located through the leaf's own extension descriptors rather than assumed to follow that first sector.

### 5.2. Reconstructing a leaf

A leaf begins with a fixed header region and may describe additional physical runs. The implemented reconstruction uses the following fields. Offsets are relative to the reconstructed leaf, not to the file header.

| Relative offset | Length | Role |
| --- | --- | --- |
| 0 | 1 byte | Leaf version, required to be 2 by current-metadata access. |
| 2 | 2 bytes | Big-endian hash-slot count. |
| 8 | 1 byte | Number of additional extent descriptors. |
| 9 through 16 | 8 bytes | Following-leaf reference, retained and validated structurally. |
| 20 onwards | 7 bytes per descriptor | Additional run length, component, and starting sector. |
| After descriptor padding | 8 bytes per slot | Key, relative payload offset, and payload length. |

If the leaf has `n` extension descriptors, its slot array starts at `20 + 8*ceil(7*n/8)`. The payload region follows the slot array. Each slot contains a four-byte key, a two-byte offset relative to the payload region, and a two-byte length, all big-endian. The decoder checks that the direct and additional runs sum to the declared total and that reconstructed runs do not overlap physically.

These metadata leaves are reconstructed from full sector runs. They must not be confused with packed directory-stream sectors, whose last seven bytes have the separate footer contract described earlier.

The lookup procedure preserves the native probe behaviour, including an empty-slot stopping condition. It begins with the key-derived slot and follows the implemented secondary and subsequent probes. A linear scan for an equal key would not reproduce all of these conditions, particularly around empty or historical slots.

### 5.3. Why a retained link is not automatically followed

The leaf header can retain a following-leaf link. For the supported table selection with `table_flag == 0`, `CurrentMetadata` deliberately does not follow that primary-leaf link. The implementation treats it as potentially historical rather than sufficient authority for current lookup. A nonzero table flag selects an unsupported global-overflow case and is rejected.

This is an important recovery decision. Retaining a pointer-like structure and using it to expand the current database are separate acts. Following every recognisable link could merge historical storage into the current interpretation.

### 5.4. Page keys connect metadata to logical storage

Let `p` be a logical page number, calculated as the logical byte offset divided by 4,096. The reader uses the following metadata keys.

| Purpose | Table | Key |
| --- | --- | --- |
| Free-space information for a group of 16 pages | 0 | `((p & ~15) << 5) + 1` |
| Ordinary allocation tags | 1 | `(p << 5) + 16` |
| Huge-allocation descriptor | 1 | `(p << 5) + 17` |
| Pointer-resolution metadata | 1 | `(p << 5) + 18` |

The low five key bits identify the metadata kind. The higher bits associate the record with its page or page group. These keys explain how allocation and pointer readers reach the appropriate encoded metadata without performing specimen-specific physical searches.

*Implementation basis.* See [table_directory.py](../../src/fsd_decoder/native/table_directory.py), [leaf_storage.py](../../src/fsd_decoder/native/leaf_storage.py), [current_metadata.py](../../src/fsd_decoder/native/current_metadata.py), and the metadata accessors in [native_database.py](../../src/fsd_decoder/native/native_database.py).

## 6. Allocation anatomy

### 6.1. Free space establishes the starting position

The free-space codec decodes groups of 16 logical pages. An initial bitmap identifies pages that are entirely free and therefore need no individual stored page record. Other pages use packed cases for fully used, end-free, all-free, or more general free-space arrangements. Sizes are expressed in units of four bytes and converted to byte counts by the reader.

Ordinary allocation tags begin relative to the page's decoded beginning-free count. The allocation reader does not simply assume that every page begins with an object at byte zero. A page identified as entirely free is skipped when enumerating live allocations. A constructed all-free group is encoded as `01 ff ff`, where the control flag selects a two-byte bitmap and all 16 bitmap positions are set.

### 6.2. The allocation-tag header

Allocation tag payloads begin with a flags byte and an architecture byte. The current parser requires architecture value `0x11`. Flag `0x80` selects big-endian tag words, while an unset flag selects little-endian words. Flag `0x04` identifies the huge form. Flag `0x40` adds a displacement word, interpreted as a negative initial offset relative to the normal page position.

That displacement supports descriptions of allocations which began before the current page. Such a description is not automatically a new allocation. The ordered allocation iterator compares repeated cross-page descriptions and yields an admitted allocation once. Conflicting descriptions or overlapping live allocations are rejected.

For ordinary sufficiently long payloads, the trailing words form seek indexes associated with blocks of tag words. The parser derives the split between tags and indexes and checks the index values against the positions calculated from the tags. Huge payloads use a different framing branch without that ordinary index partition. The index is therefore a cross-check on the interpreted layout, not a substitute for decoding the tags.

### 6.3. Tags describe more than a type number

A tag can encode an ordinary scalar, a vector, repeated instances, inline character bytes, or a free-space span. The following fields and ranges are relevant to the implemented decoder.

| Tag feature | Implemented interpretation |
| --- | --- |
| `0x4000` | An export flag with an accompanying identifier. |
| `0x8000` | A vector flag on the type description. |
| `0x3B00` through `0x3BFF` | A repetition form followed by the repeated type. |
| `0x3A00` through `0x3AFF`, in the scalar branch | Inline character bytes with a compact count. |
| `0x3C00` through `0x3FFF`, in the scalar branch | A free-space candidate sized in four-byte units. |
| Ordinary vector count | The stored word plus one. |
| Huge vector count | A wider count assembled from two tag words. |

Primitive type sizes come from the retained bootstrap descriptions. Application type sizes are recovered from source bindings and supported representations. An unknown type cannot be assigned a size merely because nearby bytes resemble a familiar object. Some representations also carry discriminant words. Capturing those words is not the same as determining the active union alternative or applying every discriminant semantically.

### 6.4. Element size, stride, and allocation size

An allocation's byte size is not always its element count multiplied by its nominal element size. The calculation can include alignment, a class-array prefix, and terminal padding. For a supported vector with element size `E`, alignment `A`, element count `N`, and prefix `H`, the implementation calculates the stride as `ceil(E/A)*A` and rounds `H + (N-1)*stride + E` up to a multiple of four bytes.

The dynamic class-vector branch adds a 16-byte prefix. Primitive vectors do not automatically acquire that prefix. For example, a constructed class with size 12 and alignment 4, stored as a three-element vector, occupies `16 + 2*12 + 12`, or 52 bytes. Its little-endian tag payload can be represented as `00 11 64 80 02 00` when the illustrative dynamic native tag is 100. This is a codec example using an invented class, not an extracted FracSIS object.

Materialisation records the array-header bytes, inter-element padding size, and terminal-padding bytes alongside the logical allocation. Retaining this distinction prevents padding or array-management bytes from being exported as additional application values. It also permits exact logical-byte preservation without requiring every byte to have a known field meaning.

### 6.5. Allocation admission

The allocation iterator operates in current cluster and metadata order. It checks the relationship between metadata-key kind and huge flag, requires the huge form to describe one allocation, validates cluster bounds, and rejects inconsistent cross-page repetitions. Free-space records are excluded by default. Zero-sized nonfree allocations are invalid.

The resulting record preserves a native tag, logical location, size, element count, vector state, and physical spans. It also retains the metadata context and original tag bytes. These are structural records. A million allocations do not imply a million independently meaningful datasets, and a class name does not by itself establish an application object identity.

*Implementation basis.* See [page_free_codec.py](../../src/fsd_decoder/native/page_free_codec.py), [native_tags.py](../../src/fsd_decoder/native/native_tags.py), and [native_allocations.py](../../src/fsd_decoder/native/native_allocations.py).

## 7. Persistent pointer anatomy

### 7.1. Why stored words are not direct file offsets

PRM is the term used here for the persistent pointer-resolution metadata associated with a logical page. A PRM entry contains little-endian head words and optional context words. The heads identify pointer positions within the logical page and carry information used to reconstruct their targets. The stored pointer words also carry links to the next pointer position in a chain.

The reader therefore needs both the PRM head and the pointer bytes. Interpreting a four-byte word as a direct physical offset would confuse the chain link, the encoded target, and the distinction between logical and physical addressing.

### 7.2. PRM head fields

Bit positions below are numbered from zero at the least significant bit of the decoded 32-bit head word.

| Bits | Field or behaviour |
| --- | --- |
| 0 through 9 | Starting pointer index in four-byte units within the page. |
| 10 through 15 | A context-dependent compact number used in segment or cluster handling. |
| 16 through 25 | High target units combined with part of the pointer word. |
| 26 | The alternative zero-offset target mode. |
| 27 | Pointer width, with an unset bit selecting 32 bits and a set bit selecting 64 bits. |
| 28 | An additional mapping-granularity word follows. |
| 29 | An additional cluster-context word follows. |
| 30 | An additional segment-context word follows. |
| 31 | An additional database-context word follows. |

Optional words are consumed in the implemented database, segment, cluster, and granularity order. Context carries between heads. A head without an explicit new context is therefore not an independent self-contained target description. The parser retains mapping granularity and external context even where the higher-level reader cannot support the resulting address.

### 7.3. Ordinary 32-bit pointers

For a 32-bit pointer word `W`, the next pointer index is `W >> 22`. The low 22 bits contribute to the target. If `H` is the head's high-offset field, the combined value is `(H << 22) | (W & 0x3FFFFF)`.

In the ordinary mode, that combined value is the target's cluster-relative byte offset. The database, segment, and cluster are supplied by the decoded context. In zero-offset mode, the combined value instead identifies the target cluster and the byte offset is zero. Zero-offset mode is not a null-pointer flag.

For a constructed example, use source segment 3, cluster 7, a head with index 2 and high-offset units 1, and pointer word `0x00801234`. The head bytes are `02 00 01 00`, and the pointer bytes are `34 12 80 00`. The pointer resides at page byte offset 8, points to logical offset `0x00401234` in the current context, and links back to index 2. This forms a one-pointer closed chain. The example decodes a target expression; a real database must additionally map that target before resolution succeeds.

### 7.4. Ordinary 64-bit pointers

A 64-bit pointer consists of two little-endian words, called the low word and high word in the implementation. The high word supplies the next pointer index and participates in a combined context value. In the ordinary mode, the low word is the target offset, the combined value is the target cluster, and the segment comes from the head context. In zero-offset mode, the combined value supplies the segment, the low word supplies the cluster, and the offset is zero.

This is a separate decoding rule, not simply the 32-bit rule applied to a larger integer. The distinction also explains why metadata and internal-root pointers can be eight bytes wide while selected application fields use four-byte pointers.

### 7.5. Chain validation and unresolved states

`walk_decoded_threads` checks that pointer fields fit within both the native page and the bytes actually available. Eight-byte fields occupy two four-byte positions, and overlapping pointer storage is rejected. Chains must close at their own head. Reaching some other previously visited position is an invalid cycle rather than a successful termination.

After decoding a chain, `NativeDatabase.resolve` checks the stored raw bytes, width, target database context, target cluster, and mapped target address. Unsupported external databases and incomplete target contexts remain unresolved at the capture layer. A mapped target is still not proof that it is the beginning of an allocated element, a compatible base subobject, or a member of the expected application collection.

A zero stored field is not immediately treated as null. Native resolution consults current PRM first. In the restored archive, an absent all-zero binding is accepted as null only under the archive's recorded binding-completeness policy. The manifest field `pointer_resolution_complete` concerns that enumeration policy. It does not assert that every captured pointer has a resolved target.

The writer records the caller's assertion that supported binding enumeration is complete; `StoreWriter.finish` does not independently compare that enumeration with the native source. Explicit captured bindings take precedence over the absent-zero rule. An explicit `UNRESOLVED` record remains unresolved even when the flag is true, and an absent nonzero binding is an error. The serialized field name is retained for compatibility.

*Implementation basis.* See [prm_fields.py](../../src/fsd_decoder/native/prm_fields.py), [native_database.py](../../src/fsd_decoder/native/native_database.py), and the restored pointer operations in [format.py](../../src/fsd_decoder/portable/format.py).

## 8. Schemas, roots, and typed interpretation

### 8.1. The retained schema-bootstrap approach

Schema recovery must break an initial dependency. Object layouts help interpret schema objects, but the reader must first find enough schema structure to establish those layouts. The current implementation retains a constrained bootstrap based on `Fs::Version`, followed by structural checks and directory corroboration.

The main capture path supplies the current segment-0, cluster-0 extents to `MemberSchema`. It first reconstructs those extents as one logical schema buffer, checking bounds, continuity, and local storage. Within that buffer, `infer_schema` searches for the `Fs::Version` name and checks the nearby reference pattern, page-aligned candidate origin, thread relationship, and reserved bytes. The inferred origin must be zero in the reconstructed schema. Version/String layout checks then establish further anchors.

A related `recover_directory_types` helper supports the allocation reader's type-building interface. That helper begins with an inferred physical origin, requires a unique matching current-directory extent, and then reconstructs and checks the logical schema. It should not be substituted for the actual `NativeFields` constructor sequence when describing capture. Both paths retain constrained schema inference, but they reach it through different orchestration.

The correct architectural description is therefore more precise than saying the decoder performs no scanning. Current allocation and metadata selection are directory-driven. Schema construction still includes constrained name-and-layout and descriptor-candidate searches within the reconstructed schema. That bootstrap is a retained design dependency, not an arbitrary specimen offset, and a file without the expected schema relationship can remain unsupported even when its outer storage is recognisable.

### 8.2. Source declarations and compact representations

Source schema content describes classes, unions, members, inheritance, aliases, primitive types, pointers, and arrays. Representation bindings associate native tags with supported compact layouts. The bundled bootstrap resources supply known storage descriptions and opcode information needed to interpret that machinery; they do not constitute a hard-coded inventory of application datasets for each source file.

Where both source class information and a compiled compact representation are available, the reader cross-checks their sizes. Application tags that collide with bootstrap tags or duplicate active bindings are rejected. A supported compact representation can sometimes provide allocation size even when a complete source class declaration is not admitted. That preserves structural access without pretending that every named field is established.

Schema descriptor addresses identify declarations. They are not automatically the addresses of instances of the class being described. Similarly, matching a name, offset, and size is insufficient to establish an application relationship. Admission checks distinguish a whole-class layout from partial source-name candidates and reject inconsistent storage descriptions rather than silently widening support.

### 8.3. Compact representation descriptors

The current dictionary path reaches compact descriptors through live representation-binding allocations and PRM-resolved references. It does not assume that a descriptor must be physically adjacent to its binding. The supported `_Rep_desc_persist` binding is a 24-byte structure, identified through its bootstrap allocation type.

| Relative binding offset | Length | Role |
| --- | --- | --- |
| 0 | 8 bytes | Leading internal pointer field in the retained bootstrap layout. |
| 8 | 2 bytes | Little-endian dictionary identifier. |
| 10 | 2 bytes | Little-endian native tag. |
| 12 | 4 bytes | Little-endian active flag. |
| 16 | 8 bytes | PRM-resolved pointer to the compact descriptor. |

The descriptor target must belong to a current character-vector allocation in the schema address space. Its payload starts with `bd 06`, followed by a four-byte little-endian flags value, a one-byte compact-layout length, the compact-layout bytes, and a terminated printable name. The accepted flags are 0 through 4 and imply alignment `1 << flags`. The layout must have the supported terminal marker. Dictionary identifiers, native tags, active flags, duplicate bindings, and payload bounds are all checked.

This separation explains how a name, a native allocation tag, and a compiled layout become associated without treating every nearby printable string as a class name. The historical candidate scanner remains available in a separate path, while `extended_dictionary(..., database=...)` selects the current-allocation and PRM-based implementation.

### 8.4. The logical database header and roots

The logical root header is distinct from the physical file header described earlier. The root reader accesses a 112-byte structure at logical segment 0, cluster 0, offset 0. The supported layout has version 2, a root count and capacity at offsets 48 and 52, and an eight-byte pointer to the root array at offset 56.

The root array contains eight-byte pointers to 24-byte root records. Each root record contains three eight-byte pointer fields, identifying the name, value, and type. Name and directory pointers must resolve. Value and type pointers may be null, but this native root reader does not generically suppress unsupported resolution errors. Those errors can still stop the operation. Names are read with explicit termination and length checks, and duplicate names or duplicate root records are rejected.

These roots provide a structurally justified starting point for traversal. They do not guarantee that every application collection is reachable through a fully understood path. A correct root export can still omit objects or values outside its admitted traversal.

### 8.5. Typed fields and bounded expansion

`NativeFields` brings together logical reads, supported source declarations, compact representations, and pointer resolution. It can decode selected allocation elements while applying limits to depth, expanded arrays, decoded leaves, and work. Unsupported representations and uncertain alternatives remain explicit rather than acquiring guessed values.

The archive restoration path uses `NativeFields.from_compiled`. It restores captured layouts and bindings against a compatible logical database interface, checking source identity and structural contracts. It does not rerun native directory reconstruction. Field decoding and later discovery still occur, however, so source-independent inspection must not be described as merely printing every interpretation already completed during capture.

### 8.6. A complete structural read

A typical supported read begins with a logical address or selected allocation. The reader locates its current cluster mapping, obtains bytes through one or more physical spans or FSDX chunks, admits the relevant allocation and layout, and decodes the requested element. A pointer-valued field is interpreted through its recorded PRM binding before the target is followed. The target must then pass its own allocation and type checks before further expansion.

This sequence explains both the system's extra work and its refusal rules. The pipeline carries context between layers because no single byte pattern establishes current storage, pointer identity, field layout, and application meaning simultaneously.

*Implementation basis.* See [object_records.py](../../src/fsd_decoder/schema/object_records.py), [directory_types.py](../../src/fsd_decoder/schema/directory_types.py), [schema_members.py](../../src/fsd_decoder/schema/schema_members.py), [probe_types.py](../../src/fsd_decoder/schema/probe_types.py), [schema_admission.py](../../src/fsd_decoder/schema/schema_admission.py), [root_directory.py](../../src/fsd_decoder/native/root_directory.py), and [native_fields.py](../../src/fsd_decoder/schema/native_fields.py).

## 9. Software architecture and FSDX

### 9.1. Runtime responsibilities

The source is divided into layers that follow the distinction between native storage, interpretation, portable capture, and downstream work.

| Layer | Responsibility | Principal modules |
| --- | --- | --- |
| Core | Addresses, physical spans, diagnostics, resource policies, JSON handling, and runtime identity. | `core/native_storage.py`, `core/provenance.py`, `core/json_io.py` |
| Native | Header and directory parsing, immutable source access, current metadata, allocations, roots, and PRM. | `native/native_database.py`, `native/native_directory.py`, `native/native_allocations.py` |
| Schema | Source declarations, compact representations, layout admission, and field interpretation. | `schema/directory_types.py`, `schema/schema_admission.py`, `schema/native_fields.py` |
| Portable | FSDX storage, capture orchestration, restored interfaces, and verification. | `portable/format.py`, `portable/writer.py`, `portable/facade.py` |
| Discovery | Names, collections, membership, relationships, payload accounting, and roles. | `discovery/datasets.py`, `discovery/membership.py`, `discovery/payload_census.py` |
| Exports | Text, catalogues, mesh, packed points, and other derived views. | `exports/dataset_text.py`, `exports/catalog.py`, `exports/fsd_mesh.py` |
| Interfaces | Installed commands and the separate terminal interface. | `cli/encode.py`, `cli/output.py`, `tools/fsd_tui.py` |

The capture writer orchestrates these components. It does not contain all ObjectStore interpretation. That interpretation is distributed across native and schema modules, and selected interpretation also takes place during restored inspection.

### 9.2. The portable database model

FSDX is a standalone SQLite logical archive. Its main relationships preserve current byte ranges and allow structural records to be addressed without reopening the source.

| Table or table family | Stored role | Architectural reason |
| --- | --- | --- |
| `manifest` | Format identity, completion state, capabilities, source and runtime descriptions, and verification declarations. | Makes the archive's interpretation and compatibility requirements explicit. |
| `blobs` | Content-addressed uncompressed identities and raw or compressed payloads. | Retains unknown bytes and permits deduplication. |
| `clusters` and `chunks` | Logical cluster bounds and byte intervals referencing BLOBs. | Supports direct logical reads independently of native physical placement. |
| `extents` | Original logical-to-physical span descriptions. | Preserves where logical bytes came from without reopening the source. |
| `allocations` | Address, size, type association, count, vector state, and selected metadata coordinates. | Supports address and type lookup over captured storage. |
| `names`, `allocation_templates`, and `allocation_contexts` | Shared descriptions factored out of repeated allocation rows. | Avoids repeating identical metadata for large populations. |
| `pointers` | Source location, width, raw words, resolution state, and supported target. | Separates stored pointer bytes from their interpreted destination. |
| `documents` and optional `document_nodes` | Schema reports, compiled layouts, roots, directory descriptions, and other structured documents. | Retains interpretation context, including documents too large for one bounded leaf. |

Default logical chunks contain up to 1 MiB. Their SHA-256 identity is calculated from the uncompressed bytes. The implemented payload codecs are zlib at level 3 and raw storage, with raw used when compression is not beneficial. Chunk compression does not decide field semantics and does not replace the original FSD's encoding rules.

Chunk admission requires positive lengths, known cluster bounds, and disjoint intervals. Given those invariants, the writer can determine overlap by querying the stored interval with the greatest start below the proposed end, then comparing its end with the proposed start. If that interval ends before or at the proposed start, every earlier disjoint interval also does. The existing `(segment, cluster, logical_start)` primary key supports this lookup even when chunks arrive out of order. The change avoids scanning earlier intervals to evaluate each end boundary for a valid insertion; final logical-coverage and interval verification remain separate checks.

During native capture, the allocation iterator encodes the page's source-derived provenance on its first admitted record. The capture owner passes those immutable bytes through a transient channel to private batch admission. Each allocation still undergoes bounds/count validation and receives its own template encoding. The conservative metadata budget continues to count the context size for each row even when bytes are shared. Public native iteration defaults to no encoding callback; public allocation writes encode supplied metadata afresh. Consequently, mutation of caller dictionaries is not hidden by a cache. This is an internal preparation change, with no additional archive field or capability.

The ordinary document representation uses format version 1. Oversized aggregate documents can use indexed trees associated with version 2 and the `indexed_documents_v1` capability. Optional pointer-page factoring has its own `compact_pointer_pages_v1` capability. It shares repeated page-local JSON structure while retaining the logical document content. It does not change native PRM decoding. Readers reject unsupported capabilities rather than silently interpreting a newer archive as an older format.

### 9.3. Why capture and inspection are separated

Native capture requires the original snapshot, directory reconstruction, and native schema work. Repeating those steps for every catalogue, export, or hypothesis about a collection would couple all later investigation to the original file and its expensive initial interpretation. FSDX creates a stable logical interface between those activities.

```text
Native capture
    FSD snapshot
        -> directory, address map, allocations, PRM, and schemas
        -> logical bytes and structural records
        -> verified staged FSDX
        -> published standalone FSDX

Restored inspection
    FSDX
        -> Store and PortableDatabase
        -> compiled layouts and logical byte access
        -> selected fields, discovery, catalogues, and exports
```

The recorded native source path is descriptive metadata, not an instruction to reopen that path. Restored inspection uses captured logical bytes, pointer records, and compiled descriptions. New interpretation remains possible, but it is constrained by what the archive preserved and what the current reader can establish.

### 9.4. Immutable archives and mutable progress ledgers

The same database technology serves two different roles. A completed FSDX is the source-independent logical archive, while membership and census ledgers record evolving analysis progress. A checkpoint must associate committed results with the cursor and source or configuration identity that produced them. It must not mark work complete merely because an in-memory traversal reached its limit.

The collection-progress layer creates and updates records under caller-owned transactions and does not commit on its own. Its stored phases, processed ranges, and resource states permit a caller to continue a bounded traversal without materialising every completed member again. This separation keeps transactional progress distinct from native ingestion and from the semantic completeness of an object or dataset. Deleting a checkpoint removes that resume state even when an earlier summary of its results survives.

*Implementation basis.* See [format.py](../../src/fsd_decoder/portable/format.py), [facade.py](../../src/fsd_decoder/portable/facade.py), [pointer_evidence.py](../../src/fsd_decoder/portable/pointer_evidence.py), [writer.py](../../src/fsd_decoder/portable/writer.py), and [collection_progress.py](../../src/fsd_decoder/discovery/collection_progress.py).

## 10. Capture, verification, and operational workflows

### 10.1. Capture and publication

Capture starts by recording the runtime identity and constructing an immutable `bytes` snapshot of the native source. The full source remains resident during native interpretation. Bounded caches, worker messages, and row batches reduce selected working sets, but they do not provide a source-size-independent process-memory ceiling.

The encoder compiles supported schemas, obtains roots, and creates a unique adjacent staging file. It stores source-derived documents, cluster descriptions, physical extent descriptions, and the full admitted logical cluster ranges. It then writes allocation rows and pointer records while preparing normalised source comparisons. Pointer preparation checks the raw field bytes against the native logical snapshot and retains unresolved target descriptions where necessary.

After allocation and pointer preparation, the encoder closes its preparation workers and performs capture-time discovery using the native interfaces and the writer's current records. It completes the staged SQLite store, opens it through the restored reader, and runs archive verification. It then compares restored allocations, pointer rows, and logical bytes against the native capture view. Finally, it rechecks the original source digest and runtime identity before publishing by a non-overwriting hard link, removing the staging name, and synchronising the destination directory.

Existing destinations, including dangling symbolic links, are refused. Verification cannot be disabled for native publication. `StoreWriter.finish` completes a SQLite representation, while the higher-level encoder controls publication. These are separate responsibilities, and an exception after a local commit is not equivalent to proving that no completed staging file exists.

The store's `COMPLETE` state is committed before its final close and file synchronization. The encoder's destination publication also precedes directory synchronization and result reporting, so a later exception can leave a verified destination present. Capture state, verification, publication and successful synchronization must therefore be distinguished when interpreting a result or failure.

### 10.2. What each verification stage checks

There are several different checks in this workflow. SQLite checks concern the container and its relational constraints. BLOB checks compare decompressed payloads with their recorded lengths and digests. Ordered relational checks hash canonical row representations. Logical coverage checks inspect intervals and declared cluster coverage. Capture-time comparison additionally checks correspondence with the immutable native view.

For ordered relational hashing, each canonical row is preceded by its encoded length as an eight-byte big-endian integer. Table-specific ordering is retained. This makes record boundaries and order part of the comparison and permits optional accelerated framing without changing the logical hash contract.

These proofs include all columns of the selected supported tables. They do not include manifest entries or BLOB payloads; payload lengths and hashes are checked separately. A selection of tables must not be described as a proof over every field in the database.

The current standalone verifier has narrower coverage than the entire capture workflow. `Store.verify(full=True)` does not exhaustively compare each pointer record's raw field bytes with the corresponding logical chunk bytes. Resolution performs that comparison when a pointer is used, and capture performs additional source comparisons before publication. The manifest is not itself included among the relationally hashed tables. The verifier also permits an archive without recorded relational proofs and reports this through component fields, even when its aggregate mode is `FULL_VERIFIED`.

Consumers that require recorded relational proofs must inspect `relational_hashes_verified` and `relational_integrity_status`. These distinctions are part of the current implementation contract. They should neither be omitted from the architectural account nor mistaken for a claim that ordinary capture is necessarily producing incorrect archives. Internal hashes also do not authenticate the archive producer or prove the semantic correctness of the initial native interpretation.

### 10.3. Two forms of parallel work

Optional capture preparation uses fork-based workers on the supported Linux path. The pool is created before the SQLite writer is opened. Workers prepare bounded native page batches, while an ordered owner retains cross-page admission and writes the archive. Oversized groups can be split in source order; an oversized individual page can retain serial parsing under the same grammar and bounds. The default remains serial.

Relational proof verification uses a different model. Optional spawned workers open separate read-only readers and hash independent tables. The table results are then compared with the declared proofs. This is not a second writable capture path, and it does not remove the deterministic row ordering within each table.

The optional C++17 helper accelerates UTF-8 and depth screening, supported canonical row and bounded normalized allocation-proof framing, and row-size estimation. Python retains FSD interpretation, JSON syntax decisions, integrity policy, and publication control. Unsupported accelerated values retain Python handling. The helper is therefore a narrow acceleration boundary rather than a replacement native FSD parser.

### 10.4. Inspection, discovery, and resumable work

Installed entry points cover native capture, archive inspection, decoding coverage, relationships, packed-point export, and corpus orchestration. The terminal interface is a separate tool that presents source selection, progress, saved-store information, and resource observations. A saved preview is not a fresh verification result.

Single-file native capture is not driven by a historical source-name manifest. Corpus orchestration is different. `fsd-corpus` requires an explicit source manifest and uses declared source size with deterministic label ties when ordering work. The manifest coordinates a workload and its expected identities; it does not supply object layouts in place of decoding.

The corpus manifest is a list of `label`, `path`, `bytes` and `sha256` records supplied through `--sources`; its validation phase also requires `--baseline-root`. Those labels and expected identities serve orchestration and admission, rather than discovery of application project names or datasets. Terminal intake enumerates only filenames and filesystem sizes before processing and uses no such manifest. Corpus reuse accepts completed project boundaries, rather than resuming a partially captured native database.

Census, membership, and selected text-export workflows maintain mutable progress ledgers separate from immutable FSDX archives. Their records distinguish committed progress from work not yet durably recorded and apply source, runtime, environment, and configuration checks to reuse. They do not make an interrupted native capture transaction resumable.

Discovery also retains separate denominators for allocations, elements, pointer bindings, collection tasks, interpreted values, and raw byte ranges. A terminal collection queue does not automatically mean every schema or payload is understood. A renderable mesh is useful inspection output, but it does not alone establish its owner, units, topology semantics, or coordinate reference system.

### 10.5. The terminal interface as an orchestration layer

The separate Rich terminal interface launches the canonical encoder as a subprocess and consumes structured progress and discovery events. Source selection lists filesystem facts without opening the native database or consulting preassigned source identities. Source names, schema families, and metadata are discovered during processing. This prevents a convenient interface from becoming a second implementation with its own decoding rules.

The interface developed from file selection and cancellation into live name display, scrollable discovery details, and separate presentation of capture progress and application meaning. Raw date fields, tentative names, and unconfirmed families remain qualified. A name displayed in the interface does not prove that its payload has been decoded, and an apparently complete capture does not establish complete dataset recovery.

Saved FSDX detection is a separate convenience. Filename association lets a user inspect a retained export, but its displayed metadata is not a fresh verification of the current source and does not seed a new decode. The historical interface checks covered dispatch, terminal behaviour, and selected viewports; those tests did not add new native-format interpretation. An earlier full-decode wrapper draft had only intercepted-dispatch checks at its own stage and must not be counted as a completed capture.

Resource monitoring samples the encoder and its descendants, rather than unrelated workstation processes. Resident set size can count shared pages more than once when summed across workers; proportional set size apportions those pages. Sequential samples can also miss short-lived peaks. The counters are useful observations for worker and lifecycle investigations, not hard guarantees about total memory use or proof that adding workers will accelerate a serial phase.

*Implementation basis.* See [writer.py](../../src/fsd_decoder/portable/writer.py), [format.py](../../src/fsd_decoder/portable/format.py), [allocation_workers.py](../../src/fsd_decoder/portable/allocation_workers.py), [verification_workers.py](../../src/fsd_decoder/portable/verification_workers.py), [run_corpus.py](../../src/fsd_decoder/portable/run_corpus.py), and [collection_progress.py](../../src/fsd_decoder/discovery/collection_progress.py), and the separate [terminal interface](../../tools/fsd_tui.py).

## 11. Recovery prototypes and the decisions they produced

### 11.1. Initial extraction and the first comparison sources

The first approach sought useful content before attempting a general database reader. Byte inspection located readable strings, paths, schema clues, and selected geometric regions in the initial test database. The early text command retained offsets, while a mesh extraction recipe was restricted to an exact source hash. SHA-256 fingerprints established which input a recipe applied to and supported before-and-after source checks. They did not make its physical offsets transferable to another file.

Public examples were acquired to challenge that dependence. The early search identified 13 downloadable databases and initially downloaded three; the maintained corpus subsequently reached 15 original files. Those are different acquisition stages, rather than conflicting corpus totals. The progression established a practical rule for the later reader. A recognisable output from one specimen was a starting point, while support for another specimen required its own structural interpretation.

The initial extraction approach was superseded as the main architecture. Its useful contributions were source identity, byte provenance, and small outputs that could be compared directly with source spans. Its limitation was that printable strings and exact-file mesh offsets did not identify all current objects or their relationships.

### 11.2. The vendor-tool route

A native ObjectStore `osdump` route was investigated as a potential authoritative dump or comparison baseline. Extracted Reader distributions contained runtime libraries and schemas, but the required executable was absent. No native dump ran. The investigation therefore remained blocked rather than becoming an implemented competing decoder or an independent semantic oracle.

The current package does not require those vendor libraries to execute. Retained static descriptions and provenance from that investigation must not be confused with runtime loading or execution of vendor code. The blocked route also explains why the subsequent work relied on independent structural checks and source-byte comparisons rather than claiming agreement with a successful vendor export.

### 11.3. Independent binary-layout prototypes

Several tools were used to express inferred layouts independently of the main decoder. Their purpose was to check particular structures, not to find a ready-made FracSIS parser. The development history records the following bounded results.

| Prototype | Recorded experiment | Architectural consequence |
| --- | --- | --- |
| Construct | 649 candidate structures parsed and rebuilt byte-identically. | Demonstrated a second executable description of selected metadata; not adopted as the maintained parser. |
| Headless ImHex 1.38.1 | 48 metadata tables and 1,358 slots agreed with Python `struct` interpretations; 13 damaged fixtures were rejected. | Supported the inferred table and slot grammar without establishing a general object decoder. |
| Kaitai 0.11 generated Python parser | 4,989 candidate tables agreed with the probe; 15 malformed controls were rejected. | Broadened metadata-layout corroboration without proving current-state selection or complete ObjectStore semantics. |
| Dynamically generated ImHex object patterns | 175 selected values, 987 field views, and 247 edges were checked across three test databases, including 18 bitfield assertions in one database. | Cross-checked selected source-derived fields and relationships against original bytes. |
| Binwalk 3.1.0 signature and compression screening | Valid controls were used, but all 477 final candidate zlib hits failed independent decoding. | Discouraged a compressed-payload carving architecture for the observed files. |

The dynamic ImHex prototype used Python to discover objects and targets before generated patterns reread their bytes. It therefore offered a separate interpretation of selected byte layouts, but not wholly independent object discovery. Similarly, candidate-table agreement did not establish that every candidate belonged to current database state. These distinctions explain why executable patterns remained investigative tools while directory selection, liveness, and pointer resolution became responsibilities of the maintained reader.

The ImHex account concerns custom headless patterns, not a verified interactive GUI workflow or an existing FSD decoder. The failed Binwalk hits do not prove that no possible compression scheme occurs anywhere in an FSD. They show that those particular signatures did not supply the missing object-storage model.

### 11.4. The schema-guided local-object prototype

The next prototype followed source declarations from `Fs::Version` through `m_versionString` to the character array. It checked class and field descriptors, member links, offsets, sizes, pointer representation, and source spans. Five FSDs yielded version strings, with 38 tests and exact-span comparisons reported in that stage. This established a small typed field tree rather than merely finding text that resembled a version.

The experiment did not settle arbitrary object recovery, allocation liveness, or relocation. Its constrained Version/String checks survived as schema-bootstrap components, while the general capture path moved towards directory and PRM reconstruction. The retained `recover_version` experiment in `object_records.py` is consequently part of the developmental background, not the main archive-capture workflow.

### 11.5. Arrays, native tags, and geometry witnesses

Array carving and allocation-tag walks explored whether structured numerical data could be recovered alongside text. Early reports describe exact array-row exports and a bounded native coordinate and double-array walk, with some targets unresolved. The early native-tag exporter remained exact-specimen restricted. Stored pointer words could not be treated as XYZ coordinates simply because they formed regular numerical patterns.

Geometry experiments then exported source-verified coordinates and topology as plain text and rendered selected results without requiring Blender or adjusting coordinates to obtain a visually plausible fit. Five-file geometry exports were reported for the tested scope, followed by mesh CSV and independent per-entity images. These outputs were useful witnesses of particular decoded structures. They did not establish every dataset, its owner, units, or coordinate reference system.

A later packed-point experiment compared candidate bit-lane interpretations with a separately stored PointSet. It recovered 16,030 owner-selected points from one test database while preserving quantised integers and raw words. Unknown high bits and physical quantisation remained explicit. The lasting method was to use a separate stored representation as corroboration and retain the undecoded representation, rather than infer correctness from the appearance of a rendered cloud.

### 11.6. Cross-database failures and directory-driven reconstruction

A previously unseen database was first checked with unchanged file-information and schema scripts. A later acquisition supplied nine additional databases for the same kind of test. Seven passed both outputs, one produced incomplete schema output, and another failed schema export. The requested tenth additional database was not acquired. These were failures and limits of that early stage, preceding later fixes, rather than claims that 0.1.45 currently fails on those inputs.

The results made the limitations of local offsets and familiar declarations visible. Directory extents, global pointer chains, and native allocation walks became the route to current objects across fragmented pages. Cross-page entity, name, and attribute links could then be investigated within a reconstructed logical address space. The reader's checks on paired directory sequences, metadata ownership, class sizes, and pointer-chain closure address those earlier weaknesses.

A separate, later search sought ten more unseen native FSDs through additional public sources. It acquired none before that search stopped at the user's request. That later zero-of-ten result must not erase the earlier nine acquisitions or be presented as ten successful generalisation tests. The retained corpus provided useful diversity, but not universal format coverage.

### 11.7. Tolerant recovery and uninterpreted regions

An early tolerant-recovery prototype retained diagnostics and raw bytes within verified boundaries. If initialisation could not proceed, it could fall back to physical hexadecimal output, with a source-hash reconstruction check reported. That physical-file fallback was a historical prototype. It does not describe current FSDX, which preserves the admitted logical map rather than every physical byte of the original.

A later unknown-region review explained 7,020 bounded regions using schema and representation information. It also examined 65 unique unavailable targets represented by 130 fields and found current free-space indications, without a missed live allocation in those cases. The result supported caution around unresolved references. An unavailable target need not indicate a decoder failure to find a live object, and a free-space observation does not reveal why the application deallocated it.

The retained principle is local rather than indiscriminate tolerance. Independently supported values can be exposed, while unresolved interpretation stays attached to its original bytes and scope. Unsupported directory grammar is not repaired by quietly substituting a speculative physical scan.

### 11.8. From repeated decoding to a portable archive

Repeated exports and renders made repeated native reconstruction costly. The two-stage Python architecture captured logical bytes, schema descriptions, allocations, and pointers once into SQLite, then inspected an isolated FSDX copy separately. All 15 historical captures and isolated-copy checks were reported passing. This was the decisive change from a collection of extraction scripts to a reusable recovery system.

The historical inventory reported 47,837,587 allocations, 65,794,233 bindings, and 2,038,533,120 captured logical bytes across the 15 test databases. Original source files totalled 2,441,084,928 bytes. The recorded canonical archives occupied 12,689,833,984 bytes, reflecting relational indexes and overlapping structural descriptions as well as payloads. Those totals are retained from the earlier development account. The original archive files were subsequently removed during an explicitly authorised cleanup, so the inventory is not a statement that those historical stores accompany the public source.

Consolidation also introduced a maintained Python package and reviewed overlap admission, checkpoints, report recovery, and derivative publication. That stage reported 173 retained regressions and allocation structural checks. The architecture retained source-independent logical access; it did not convert those structural counts into a claim of complete application recovery.

### 11.9. Dynamic roots, inheritance, and discovery populations

Discovery originally risked depending on a navigation-root display label. Version 0.1.3 removed the fixed `Navigation Tree Root` text as the selection rule, using compatible source roots and their declared layouts instead. Renamed-root controls passed, and root bindings across the 15 retained stores were preserved. This distinguished a useful structural anchor from a changeable application label.

Version 0.1.4 expanded discovery through embedded inheritance, layouts, and recorded references. Version 0.1.5 added allocation-based accounting, streamed object records, and reusable discovery sessions, while 0.1.7 grouped runtime storage roles into Entities, arrays, collections, and other structural families. The recorded accounting retained 414 Entity names in one test database and 1,297 in another. Unfamiliar families became inspectable without being promoted automatically to confirmed geological datasets.

Version 0.1.6 corrected completion flags when typed decoding remained unresolved. Enumeration completion and typed interpretation therefore became distinct reported states. Earlier 0.1.5 timing and capture results retain that original identity; they are not retrospectively measurements of the corrected flag behaviour. Source-guided discovery also still depends on recognised storage and field-role anchors, rather than being unrestricted interpretation of any embedded class.

### 11.10. Collection adapters and the meaning of membership

The list adapter introduced in 0.1.8 used observed layout, member slots, cardinality, and exact reference targets to separate collection elements from bookkeeping links. The recorded tests covered 4,912 lists in one test database and 247,125 in another. Sets remained unsupported at that revision, and the largest list required larger explicit traversal budgets.

The pointer-key set and hash adapter followed in 0.1.9. It inferred member types from referring fields and checked shared tables against source cardinality. Twenty-four set instances across two test databases were inspected, with Entity addresses matching the retained census. Some flag and bitmap meanings remained unknown. Membership consistency did not establish collection ownership or a new geological family.

Version 0.1.11 brought supported adapters into normal discovery and reconciled Entity and catalogue sets across all 15 test databases. Later work addressed `os_array` roles, direct collection context, repeated-member ranges, and plaintext omissions. The progression explains why the current architecture keeps adapters, source declarations, graph traversal, and application roles separate. A recorded reference, a collection member, and an application-owned dataset are different conclusions.

### 11.11. Resumable censuses and their denominators

The census and membership workflows developed source-pinned SQLite checkpoints so larger populations could be processed in bounded batches. Progress ranges and the records supporting them were retained together. Subsequent corrections addressed identity checks involving SQLite write-ahead logging, pending-task indexes, repeated path construction, and profiling retention. These were improvements to resumable analysis, not resumable native capture.

A census of one test database at 0.1.18 reconciled 165,161 allocations, 1,362,417 elements, 230,900 bindings, and 9,506,816 retained logical bytes. Its element count comprised 751,515 individual interpretations and 610,902 primitive block checks. A second census on a different test database at 0.1.22 reconciled 646,985 allocations, 3,151,035 elements, 888,335 bindings, and 39,458,816 logical bytes, with 51,364 elements retaining unknown source-slot cardinality. The historical audit closed two retained-logical censuses out of 15.

A separate eligible collection-adapter queue reached terminal states for 765,541 referrers and 1,102,296 tasks. Its recorded snapshot contained 1,102,295 verified-cardinality states and one unconfirmed state. A later bounded investigation in the associated test database reported 218 matching ordered members. These belong to different stages of the work; the later result does not retroactively change the earlier queue snapshot or close every excluded population.

A read-only 0.1.22 cost audit found that warm tokens avoided deep source-prefix admission but did not eliminate repeated accumulated-history aggregates. Three larger census calls on another test database were subsequently approved, each planned around 10,000 allocations and 100,000 values with the existing limits. Closeout retained only partial work and did not establish a controlled speed benefit. This remains an inconclusive batch-size trial, not an adopted performance result.

### 11.12. Type admission, reference widths, and bounded failure

Corrective work around 0.1.24 through 0.1.29 separated native tag identity from display names and retained ambiguity between repeated declarations. Additional checks concerned empty and nested base layouts, pointer widths, compiled-wrapper extents, and incoming-reference consistency. The purpose was to prevent a plausible name or size match from admitting an incompatible object view.

The historical controls included synthetic conflicting `Sample` tags, but no controlled occurrence of that exact conflict in the native corpus was established. Source-level, installed, and independent-control checks also differed between the individual fixes. The history supports scoped corrections, not a universal claim that every source ABI or wrapper form is admitted correctly.

Resource review similarly separated specific faults from broader diagnoses. Six safeguards were reported at 0.1.27, including checks before expanding labels, scalar reads, array counts, and compact structures. An increased working set during one database investigation was associated with larger report volume rather than demonstrated as a leak, while checkpoint capacity concerned disk space rather than RAM. These observations motivated bounded expansion and explicit lifecycle management without promising that every future file fits within a fixed memory budget.

### 11.13. Root exports and partial-field recovery

Source-root traversal attempted to reach records missed by navigation catalogues, following source-declared links, pointer arrays, and nested numerical payloads. Generated root-to-array-to-child paths agreed between API and command-line controls. The later 0.1.29 export from one test database produced 128 of 14,293 declared records, retained 83 support fields, and yielded identical 2,456,092-byte API and command-line outputs. It omitted 14,165 records and did not recover `m_nodes` child values through that chain.

Earlier direct-class selection at 0.1.27 recovered 24 indices in three scalars, but used a fixed selector rather than independently establishing application discovery. Three tag-selected double-precision values from another test database and a later metadata-only operation were likewise different scoped outcomes. These were informative partial recoveries, not interchangeable demonstrations of a complete recovered graph.

A further 0.1.30 source candidate sought to retain independently readable sibling fields beside a captured unresolved pointer. Focused fixtures supported the approach, but installed public-export integration remained incomplete at historical closeout. The present source contains a `captured_unresolved_partial` policy alongside strict handling, with checks against the stored binding, width, address, and raw bytes. Its existence does not retrospectively turn the earlier incomplete integration into a completed native export. A partial field view must retain its failed link and partial status.

### 11.14. The real-data gain gate and the recovery pause

The recovery programme explicitly prioritised usable object and data identification over optimisation alone. A final review compared the later semantic-recovery work with the retained 0.1.18 baseline across the 15 test databases. No qualifying new application dataset or controlled recovery gain was established. Some numerical and support fields had been recovered, but incomplete baseline material also prevented a conclusion of unchanged-output parity. Failure to establish a gain is not proof that every later result was identical.

Semantic recovery was paused at that gate. The subsequent resource, interface, C++, and packaging work addressed separately authorised engineering goals. Those changes can improve processing or maintainability without proving additional application meaning. The pause therefore remains part of the design history rather than being overwritten by later successful captures or lower timings.

An earlier metadata-processing child ended with `SIGKILL` before saving its result. Its cause remained unknown, and that attempt lacked post-run source-preservation checks. It must not be labelled an out-of-memory event or confused with the separately diagnosed loaded-library inspection crash described in Section 13.10. Recording unresolved failures without supplying a convenient cause is part of keeping the development account technically useful.

*Implementation connections.* The retained mechanisms are visible in [object_records.py](../../src/fsd_decoder/schema/object_records.py), [directory_types.py](../../src/fsd_decoder/schema/directory_types.py), [schema_admission.py](../../src/fsd_decoder/schema/schema_admission.py), [native_fields.py](../../src/fsd_decoder/schema/native_fields.py), [decoding_coverage.py](../../src/fsd_decoder/discovery/decoding_coverage.py), [membership.py](../../src/fsd_decoder/discovery/membership.py), and [dataset_text.py](../../src/fsd_decoder/exports/dataset_text.py).

## 12. Storage and compression experiments

### 12.1. Evaluating the archive rather than one projection

A synthetic database experiment used 20,000 allocations, 80,000 pointers, and 12 MiB of chunk data to compare SQLite variants and checkpoint batches. The observed trade-offs depended on the workload. The tests did not establish a complete replacement archive implementation. In that synthetic model, 16 KiB pages used 2.65% more space than 4 KiB pages, and a rowid BLOB-table variant added one 4 KiB page. Those observations did not justify a production-format migration or establish a corpus-wide page-size optimum.

A Parquet experiment preserved a matching 15-column allocation projection. It did not include logical chunks, pointer relationships, the complete archive metadata, or equivalent integrity and publication behaviour. Its smaller output could therefore support the use of analytical projections without establishing that it could replace FSDX. DuckDB, HDF5, and LMDB were considered but were not benchmarked in the recorded experiment.

SQLite was retained because the implementation already needed indexed relationships, logical address lookup, a standalone file, and transactional progress in related workflows. This was a decision about the whole implemented contract rather than a claim that SQLite must outperform every other engine. A future alternative would need to reproduce source-independent reads, structural lookup, unknown-byte retention, compatibility rules, and publication behaviour as well as improve selected measurements.

A separate set of 16 bounded lookup trials on one test database tested a 64 MiB SQLite cache. The recorded median lookup time fell by 19.7% and read calls by 76.6%, at higher peak memory. The default change was deferred because a bounded lookup result did not establish full-catalogue or concurrent-worker behaviour. This is distinct from the later private-verifier cache experiments in Section 13.

### 12.2. Byte-codec experiments

Codec microprobes used seven patterns totalling 7,339,968 bytes, with three repeated calls per byte-codec and filter variant. The tested byte-oriented paths retained exact bytes and suggested Zstandard and LZ4 as candidates. These were small pattern experiments, not integrated replacements exercised across complete FSDX captures.

The retained implementation uses zlib/raw. Introducing another codec would require explicit reader capability handling, bounded expansion, self-contained decoding requirements, malformed-input behaviour, and complete-operation measurements. Compression of BLOBs would also leave substantial relational and index storage untouched. One historical verifier profile attributed 40.62% of the profiled archive's pages to BLOB storage, illustrating why a codec-only improvement could not be applied indiscriminately to the whole file.

### 12.3. Numeric fidelity and raw-bit fidelity

The LERC experiment provided a particularly useful distinction. Direct LERC 4.0.0 float64 encoding with zero numerical error changed 256 of 512 alternating signed-zero words and substituted zero bytes for 512 tested NaN words under the tested invalid-mask treatment. That route did not meet the archive's raw-bit preservation requirement, even though a numerical-error setting might suggest losslessness in another sense.

A later opaque-uint8 treatment restored exact bytes and hashes for three 16 KiB samples, totalling 49,152 bytes. It demonstrated that the failing numerical route did not rule out every possible wrapper. It did not establish arbitrary-tail handling, malformed-input safety, integrated archive compatibility, or an end-to-end benefit.

The design decision was to keep unknown and numerical payloads under an exact-byte preservation contract. Derived analytical outputs can choose numerical conventions, but the primary archive must not silently normalise distinctions present in the source representation.

### 12.4. Reducing repeated pointer descriptions

Storage layout was tested before changing implementation language. An early factoring of repeated pointer descriptions reportedly reduced one test archive from roughly 277 MB to 44 MB, with a verified conversion taking 52.2 seconds. That was one pre-package representation experiment, not a current-release or whole-corpus compression ratio.

The later compact pointer-page representation at 0.1.7 retained reconstructable page content, including unknown fields, scalar types, key order, and original content hashes. Reconstruction and full-verification checks on two test databases were reported passing. The representation remained opt-in and concerns repeated document storage, not new PRM interpretation or dataset discovery. Its rationale is to remove structural repetition without making the archive depend on a guessed semantic simplification.

### 12.5. Incremental JSON without a new representation

A bounded JSON-writer prototype addressed large metadata aggregates. Five store fixtures remained byte-identical, while a 50.35 MB synthetic aggregate's peak memory fell from 215.35 to 39.46 MiB with similar write time. Initial differences in failed-write promotion and error ordering required repair. The result concerned that writer workload, not an approximately 82% reduction in whole-decoder memory.

The 0.1.1 integration retained canonical representation and custom conversion behaviour. Its recorded checks included 4,010 helper comparisons, 32 writer comparisons, 2,800 property examples, and a fresh preservation comparison on one test database. The current bounded encoder keeps the retained prefix within a ceiling and continues validation after that prefix overflows, so a later invalid value is not silently admitted through an indexed-document path. Individual encoder chunks, key sorting, compression, and final copying remain outside that prefix bound.

A separate writer audit identified partial failed-write staging and different spellings for Boolean and `None` keys in the tested paths. It recommended broader write-sequence checks. Those historical findings should not be converted into an assertion that every recommendation was integrated, or dismissed merely because valid single-document outputs matched. Transactional behaviour and canonical successful output are separate parts of compatibility.

### 12.6. Library reviews that did not become dependencies

The library review considered `orjson`, `simdjson`, APSW, asynchronous processing, GPU use, and broader rewrites against the measured workload. It did not establish local adoption benchmarks or drop-in compatibility for those replacements. Canonical byte spelling, numerical handling, error order, and buffer lifetimes would need to remain compatible with the archive's verification contracts. Narrow batching and elimination of repeated work were selected first.

Base64++ was reviewed separately and not adopted. Converting binary to text would not discover object layouts or pointer relationships, and the reviewed route introduced full-buffer handling, binding work, and a larger textual representation. This was a source and suitability review, not a C++ malformed-input runtime experiment. Dictionary compression, byte shuffling, delta transforms, and custom mixtures likewise remained candidate designs requiring explicit framing, reader identity, resource bounds, and complete-operation measurements.

*Implementation connection.* The retained raw/zlib BLOB contract, capability declarations, and resource policies are defined in [format.py](../../src/fsd_decoder/portable/format.py).

## 13. Performance and resource-management prototypes

### 13.1. How the measurements should be read

The optimisation work progressed through component probes, installed integration checks, and complete captures. These measurements answer different questions. A faster table-hashing pass can identify an implementation opportunity without proving that complete capture is faster. A sampled memory peak can reject a candidate under an admission rule without diagnosing the cause of that peak.

The results below distinguish the principal benchmark workload, smaller validation workloads, and separate capacity trials by their experimental role. Worker counts, CPU affinity, software stage, and shared-host conditions varied between experiment families. Results should be compared within their stated trial rather than assembled into one universal speedup sequence. The original narrative reports no confidence intervals for these small paired experiments.

### 13.2. Eliminating Python work before adding a native core

An early large-data review reported text exports at 103.16 times the native source size and identified full-source buffers, repeated metadata, and growing caches. Streaming source hashing, staged geometry publication, and cancellation repairs were reported. Independent-file subprocesses and resource budgets were recommendations at that stage; asynchronous execution had not been measured as a complete replacement. Streaming hashing also did not mean that later native interpretation stopped retaining its complete source snapshot.

A separate `hashlib.file_digest` experiment preserved digests and source-change checks but showed no consistent speed advantage in repeated 64 MiB blocking-file trials. It remained a simplification investigation rather than a demonstrated performance adoption. The more productive 0.1.2 work removed 33 unused bindings and avoided repeated schema, coordinate, tag-lookup, and scheduler work. Four paired operations improved by 25.5% to 38.4% with matching outputs, and 397 installed checks plus selected corpus comparisons were reported. Those were operation-specific shared-host observations, not a whole-conversion multiplier.

The associated test-policy review favoured proportionate tests around changed contracts. It did not establish that an existing test was obsolete. Both the performance and maintenance conclusions were bounded by what had actually been inspected or measured.

### 13.3. The Rust bridge and the retained Python boundary

Rust was initially recommended as a possible checked-ownership core for allocation-tag and pointer batches. A bounded bridge prototype then compared native output, malformed-input behaviour, and Python dictionary reconstruction. Reported parity covered 563,576 raw tag records and 600,786 pointers. Prepared 128-page tag batches were 1.32 times faster, while pointer batches were 31.8% slower through the bridge.

The mixed result showed that native execution cost was only one part of the proposed boundary. Converting and transporting results into Python could absorb or reverse a local gain. No whole-capture or memory benefit was established, and the Rust bridge was not adopted. The history therefore does not support a claim that Rust was either a completed alternative decoder or intrinsically unsuitable for the problem.

Python remained the orchestration and interpretation language. Later C++ work targeted small, measured byte-screening and row-processing operations with explicit fallback, rather than reviving a whole-decoder rewrite. This was a change in the scope of native acceleration, informed by the earlier bridge experiment and subsequent profiling.

### 13.4. Whole-cluster work versus bounded page preparation

Early one-, two-, and four-worker whole-cluster trials exposed task imbalance. In the principal benchmark database, one cluster held 88.74% of allocations, so it dominated one worker while others completed their work; four workers did not beat two for that workload. A smaller validation workload showed more benefit in its allocation phase. These were allocation and proof-preparation trials that produced no FSDX archive, so their timings did not establish a complete-capture improvement.

The adopted direction was bounded page preparation from an immutable snapshot. Workers prepared page groups, and one owner retained deterministic admission and writes. Twelve page-size and queue trials were followed by three complete captures of the principal benchmark workload. The workload contained 1,832,298 allocations and 1,966,325 pointers.

| Trial stage | Serial elapsed | Two-worker elapsed | Four-worker elapsed | Sampled process-tree PSS |
| --- | --- | --- | --- | --- |
| Initial bounded allocation preparation | 815.84 s | 771.66 s | 764.81 s | 380.4, 385.4, and 384.4 MiB respectively. |
| Subsequent pointer-pipeline revision | 741.78 s | 560.01 s | 542.06 s | 384.1, 567.6, and 892.9 MiB respectively. |
| Final cache and depth-scanner revision in that experiment | Not remeasured | 514.99 s | Not remeasured | 300.0 MiB for two workers. |

The first experiment reduced allocation writing from 150.82 seconds serially to 94.73 seconds with two workers. Four workers achieved 94.19 seconds for that component, illustrating diminishing returns. Four oversized-batch trials were rejected. The later pipeline moved pointer preparation into bounded page work as well, but its initial four-worker memory cost showed why worker count could not be treated as a free performance setting.

The final two-worker observation included 128.91 seconds for pointer preparation and writing and 227.62 seconds for store and graph verification. Reported structural comparisons matched, apart from two discovery-duration fields. These single complete runs justified the mechanism and further investigation rather than a repeatable corpus-wide speedup claim. Serial operation remained the default.

### 13.5. Garbage collection and reader lifetime

A separate experiment compared default cyclic garbage-collection settings with a tenfold generation-zero threshold. Complete captures of the principal benchmark workload took 521.08 and 496.81 seconds. Measured GC CPU across owner and workers fell from 16.78 to 5.72 seconds, while sampled tree PSS changed from 292.28 to 296.25 MiB. Concurrent workstation activity and overlapping probes prevented attribution of the whole elapsed difference to GC.

The work did identify a more concrete lifecycle issue. A closed reader's connection guard retained a reference cycle that delayed cache release. Later lifecycle changes released 5.22 MiB of raw cache immediately on close. Two read-only helpers that had accumulated 24 descriptors without automatic GC accumulated none after explicit closure changes. A repeated 240-operation Store test reached a small traced-heap plateau after warm-up.

Explicit lifecycle repair was retained. The implementation did not adopt global GC tuning or allocator trimming as a substitute. The distinction matters because delayed object release, allocator-retained pages, and an operating-system resident-memory measurement are different mechanisms.

### 13.6. The C++ preflight prototype and integration

The first native helper accelerated UTF-8 validation and JSON depth screening. An isolated comparison exercised 8,056 value and error cases. A reported two-worker comparison on the principal benchmark workload took 501.08 seconds with Python and 436.25 seconds with the helper, with sampled PSS of 286.35 and 292.69 MiB. Structural parity and independent Python verification were retained, while application discovery outcomes were unchanged.

The integration at 0.1.34 recorded 86 selected regression checks and three fresh-process fallback probes. Installed captures completed in 431.87 seconds for the principal benchmark workload and 62.96 seconds for a smaller validation workload, with mandatory capture comparisons. A fresh Python-only process verified the benchmark archive without native-source access.

The helper was retained as an optional, narrow acceleration layer. Its stable-ABI declaration did not itself establish execution across all declared interpreter versions. Python remained responsible for JSON syntax, native recovery, policies, and integrity. Loss or replacement of a loaded helper remained a runtime-identity concern rather than a reason to continue silently with a different implementation.

### 13.7. Row framing, bounded batches, and exception safety

The preceding architecture profile identified verification and repeated BLOB decoding, encoding, SQL-row processing, and worker-result transport as substantial costs. Intrusive cumulative timings overlapped and could not be treated as a partition of production runtime. They directed attention towards bounded work elimination rather than providing a percentage budget for every phase.

Version 0.1.35 extended the acceleration boundary to supported canonical SQL-row framing. Related changes included bounded allocation writes, smaller worker messages, a combined BLOB and ordinary-document verification pass, and optional independent table-verification workers. The parent retained ordered capture and publication control. Canonical framing bounded batches at 256 rows and a conservative 1 MiB estimate, retaining Python handling for unsupported values. A Python-only batching variant regressed and was rejected. Allocation writes deferred the secondary nonunique type index until before discovery and publication, while independent hashing workers retained complete table order rather than combining hashes of arbitrary partitions.

For the principal benchmark workload, the reported capture time changed from 431.87 to 395.99 seconds against 0.1.34, while sampled tree PSS increased from 298.94 to 312.56 MiB. The smaller validation workload was effectively unchanged at 62.96 versus 63.18 seconds. A separate capacity-limited workload completed in 718.58 seconds with two split retries and no fallback pages after an earlier capacity rejection. Capacity-driven splitting did not turn parser or programming errors into recoverable input. These results supported integration but did not isolate the contribution of each simultaneous change.

A subsequent review found an owned-reference leak on a C++ allocation-failure path. Deterministic test-only injection changed the observed reference count from 3 to 4 in the original helper and kept it at 3 in the corrected version. Both paths raised `MemoryError`, and normal framing remained identical. The correction in 0.1.36 was retained. It addressed a demonstrated exceptional path rather than proving that successful captures had been leaking references. Initial helper read or load failures also gained Python fallback, while replacement of a helper already loaded into a running process remained a rejection condition.

### 13.8. Integer conversion and batch admission

Further experiments separated integer conversion, buffer reuse, and direct framing. Five paired table runs reported median times of 23.06 seconds for the baseline and 20.46 seconds for integer conversion, with unchanged canonical bytes and ordered-table hashes. Buffer reuse reduced counted string allocations, and direct framing removed copies, but neither showed a repeated complete-operation benefit in that study.

The signed 64-bit `std::to_chars` conversion was adopted in 0.1.37. The next study compared batch-size estimation over every relational table of the archive retained from the principal benchmark. Five fresh-process runs per alternative produced median times of 20.22 seconds for the original estimator, 19.09 seconds for an inline Python loop, and 13.04 seconds for the native estimator. Table hashes and batch-length hashes matched in every run, with peak process RSS around 27.5 to 27.9 MiB.

The native estimator was adopted in 0.1.38. It retained exact-type admission and continued examining later fields even after an estimate became oversized, so a late unsupported value would still invoke Python handling. Subsequent validation captures took 372.88 seconds for the principal benchmark workload and 53.84 seconds for the smaller workload, but these were not new paired end-to-end performance comparisons. Their process-tree PSS was also a different measurement from the isolated table-pass RSS.

### 13.9. Pointer and allocation verification candidates

The next experiments targeted source-to-store graph comparison. Their experimental version labels should not be read as a sequence in which every candidate became canonical.

| Candidate | Change tested | Main result recorded | Decision |
| --- | --- | --- | --- |
| 0.1.39 | Bounded restored-pointer framing. | The pointer component improved, but one of two full-capture pairs reversed the whole-operation result. | Not adopted. |
| 0.1.40 | Private allocation-proof projection using validated cached children. | Both timed pairs improved, but one sampled memory peak exceeded the 3% admission screen. | Not adopted at that gate. |
| 0.1.41 | Late verifier-cache clearing. | Clearing late did not remove the resident peak in the diagnostic trials. | Rejected. |
| 0.1.42 | Zero BLOB cache in the private verifier combined with allocation projection. | Memory improved, but complete-time results were inconsistent under the unchanged gate. | Not adopted. |
| 0.1.43 | Zero-cache change alone. | Complete-time results were again inconsistent. | Not adopted. |
| 0.1.44 | Allocation-proof projection alone, with normal BLOB caching. | Both full-capture pairs passed the recorded time and sampled-memory screens. | Adopted. |

The pointer candidate processed 1,966,325 rows across 10,634 pages, using five fresh processes per alternative. Bounded framing recorded a 58.98% median paired reduction in the pointer component, with matching page hashes. Its two alternating complete pairs were 383.33 versus 366.63 seconds and 352.64 versus 354.20 seconds, baseline versus candidate. The second whole-capture result failed the promotion requirement despite faster verification. A smaller serial capture and affected tests retained the structural comparisons, but correctness alone did not make the performance candidate a winner.

The allocation study initially sampled every 32nd identifier. Profiling the complete 1,832,298-record stream corrected a misleading cache-locality impression from that sparse sample and identified encoding, normalisation, and copying as significant work. A private projection recorded a 16.38% median paired reduction in its allocation component. Complete fixed-three-CPU pairs were 359.51 versus 352.70 seconds and 355.54 versus 342.31 seconds. The second candidate's sampled tree PSS rose from 307.36 to 324.07 MiB, or 5.44%, exceeding the predefined 3% screen. The candidate remained unpromoted at that stage.

The important lesson was to test the full operation and retain a declared regression rule. A plausible micro-optimisation could be correct and locally faster without meeting the operational acceptance criteria.

### 13.10. Cache controls, mapped binaries, and the adopted projection

Verifier diagnostics found a peak during table hashing, with 31.98 MiB of retained BLOB payloads at worker entry and approximately 2.3 MiB of live SQLite allocations. Six read-only policy trials observed roughly 109 MiB peak tree PSS with normal or late-cleared caching, compared with 71 MiB for zero caching. A post-close glibc diagnostic reduced owner PSS from approximately 61 to 17 MiB after collection and trimming. That supported allocator retention in that run, not a general leak diagnosis or a deployed trimming policy.

The combined 0.1.42 candidate changed full-capture time by +4.82% and -0.33%, where positive means slower. Its paired memory changes were -6.36% and -6.19%. Cache-only 0.1.43 changed time by +1.98% and -2.51%, with memory changes of -1.27% and -4.53%. Neither produced the required repeatable time improvement, so both remained unpromoted.

During the cache-only investigation, an in-place rewrite performed by a concurrent inspection process damaged a loaded native library mapping. The development account records a disposable-library reproduction and a safe distinct-output control. This led to separating binary inspection from tests against a loaded helper. File hashes alone cannot describe every transient state of a live mapped image, and loaded shared libraries must not be casually rewritten during a test.

The later projection-only 0.1.44 retained the default BLOB cache and excluded the rejected pointer and cache changes. The two reported whole-run time changes were -20.36% and -3.81%, with sampled tree PSS changes of +0.05% and -2.20%. The first baseline experienced high host I/O pressure, so the larger elapsed gain cannot be attributed entirely to projection. Same-phase graph CPU fell by 11.72% and 12.06%, approximately ten CPU seconds in each pair. All five captures in the experiment retained structural comparisons, and 71 affected tests and independent smaller-store checks passed.

This projection was adopted. In the current source, the writer uses `Store._allocation_record(..., for_proof=True)` for immediate internal hashing. The private path borrows validated cached children while constructing the required top-level representation. Public allocation access still returns detached metadata. The private verifier is still opened with `Store(stage)`, so the rejected zero-cache policy is not silently part of the present design.

Version 0.1.45 subsequently cleaned portability and references, including machine-specific bootstrap provenance paths and a historical source-name scheduling preference. It did not introduce a new native decoding method or a new benchmark result.

*Implementation connections.* The adopted design is visible in [allocation_workers.py](../../src/fsd_decoder/portable/allocation_workers.py), [verification_workers.py](../../src/fsd_decoder/portable/verification_workers.py), [format.py](../../src/fsd_decoder/portable/format.py), [writer.py](../../src/fsd_decoder/portable/writer.py), [json_scan.py](../../src/fsd_decoder/core/json_scan.py), and [_json_scan.cpp](../../src/fsd_decoder/core/_json_scan.cpp).

### 13.11. Review-driven algorithm experiments

A subsequent review motivated three isolated candidates on baseline 0.1.45: replacing the broad chunk overlap scan with an indexed predecessor check, replacing per-byte directory positions with indexed sector runs, and returning copied bytes directly for reads contained in one physical extent. The selected-stream coverage algorithm, archive format, native helper and verification policies were unchanged. These remained experimental copies rather than production changes (claims EXP-20261007-COMP and EXP-20261007-PARITY).

| Experiment | Baseline median | Candidate median | Component speedup |
| --- | ---: | ---: | ---: |
| 4,000 chunk overlap checks + insertions | 752.90 ms | 18.57 ms | 40.55× |
| 2 MiB sector payload + full provenance projection | 575.31 ms | 10.69 ms | 53.83× |
| 50,000 four-byte contiguous reads | 145.80 ms | 49.21 ms | 2.96× |
| 50,000 4 KiB contiguous reads | 138.27 ms | 48.79 ms | 2.83× |

These component measurements used six alternating-order pairs in fresh CPython 3.12.3 processes with SQLite 3.45.1 and one fixed logical CPU. The SQL kernel used placeholder BLOB digests without compression or durable I/O. The directory kernel included payload reconstruction and full source-span projection. Separate tracing observed 86.29 versus 6.25 MiB of peak Python allocations, 92.76% lower; fixture setup and native/process-tree memory were outside that tracing claim. Both read paths returned detached bytes.

The 74 affected retained tests passed. Additional comparisons covered 6,026 address/error cases, 1,818 provenance ranges, seven malformed-sector controls and 3,000 interval queries with an independent overlap oracle. Two constructed stores passed full verification. All 15 original inputs produced identical complete directory reports under both paths, with fresh source hashes and preservation checks. This established directory reconstruction and provenance parity, not semantic completeness or whole-capture parity for all 15 files.

| Input | Baseline | Candidate | Elapsed change | Sampled tree PSS change |
| --- | ---: | ---: | ---: | ---: |
| fracSIS_test_12 | 420.31 s | 412.31 s | -1.90% | -1.48% |
| fracSIS_test_14 | 63.03 s | 62.08 s | -1.51% | +0.42% |

The complete-operation screen used fresh verified captures, three fixed logical CPUs, two workers for input 12 and one for input 14, with reversed candidate order between inputs (claim EXP-20261007-CAPTURE). All four retained matching structural counts, coverage, normalised graphs, native statistics and stable discovery/document proofs; only two recorded discovery-duration values were normalised. The candidate passed the predefined screen requiring improvement on both inputs and at most a 3% sampled tree-PSS increase. One pair per input on a shared host is insufficient to establish repeatability, so no production promotion followed.

The stress measurements also exposed a relevance limit: the largest native directory stream in the 15 inputs was only 16,367 bytes, and the largest cluster in seven presently retained saved exports had 221 chunks. Large synthetic ratios therefore describe scaling opportunities rather than expected complete-decode speedups. A broad optional saved-BLOB aggregate exceeded its four-minute research budget; a bounded chunk-only diagnostic completed. The next priority is attribution and repeated complete captures, followed by measured admission-encoding reuse and cache-retention work rather than unprofiled increases in concurrency.

### 13.12. Promoting the overlap query and separating read attribution

The combined experiment led to a deliberately narrower implementation. Version 0.1.46 adopted only the indexed predecessor query for chunk admission (claim EXP-20261007-OVERLAP46). It required no additional index, cache, dependency, archive capability or C++ change. The canonical sector-directory and native-read representations remained unchanged. The reason for adoption was the bounded indexed lookup and simple interval argument, supported by the earlier independent overlap comparisons, rather than an expectation of a fortyfold improvement to an entire decode.

Twenty-three focused retained writer and integrity tests passed. The existing out-of-order interval test was extended to cover adjacency, duplicates, crossing overlaps, bounds, empty chunks and unchanged database counts after rejected writes. A fresh two-worker capture of `fracSIS_test_12` passed full capture-time verification in 411.92 seconds, with unchanged source/runtime identities and stable structural parity against the retained 0.1.45 capture. That historical capture was used for structural comparison only; its timing was not relabelled as a fresh paired performance baseline. The fresh archive retained 1,832,298 allocations, 1,966,325 pointers and 56,916,992 logical bytes. These counts describe captured structures, not newly discovered application datasets.

The next experiment separated the contiguous-read method from both the directory representation and overlap-query change (claim EXP-20261007-READ46). Its candidate differed from the promoted source in one native-storage method only, and all 14 retained native-storage/database tests passed before capture. Two complete pairs used the same source, two workers, three fixed logical CPUs, default compression, fixed hash seed and identical C++ helper bytes. Execution order was baseline/candidate followed by candidate/baseline.

| Pair | Baseline | Read candidate | Elapsed change | Sampled tree PSS change |
| --- | ---: | ---: | ---: | ---: |
| 1 | 411.92 s | 402.02 s | -2.40% | +2.72% |
| 2 | 403.74 s | 406.89 s | +0.78% | -0.48% |

All four fresh captures passed full capture-time verification and retained matching structural counts, logical coverage, native statistics, normalised graphs and stable document/discovery proofs. Comparison excluded only the two recorded discovery-duration values; raw hashes and timings remained available. The candidate failed the predefined requirement that both pairs improve elapsed time with no more than a 3% sampled tree-PSS increase. It was not promoted. Frequency and source-cache state were not controlled on the shared host, and the changes in the verification stage also caution against assigning complete-operation differences entirely to the read method. The earlier component gain therefore did not establish a repeatable whole-capture benefit.

### 13.13. Profiling repeated admission encoding

After the timed captures, a bounded preparation replay sampled eight separated insertion-order windows from the freshly capture-verified 0.1.46 archive (claim EXP-20261007-ADMISSION). Each window admitted at most 1,280 records within an 8 MiB metadata budget. The 10,240 sampled records, approximately 0.56% of the archive's allocations, produced context and template JSON bytes identical to those stored. This byte check made the restored replay relevant to the preparation boundary; it did not turn the replay into a native decode or independent semantic test.

The sample contained 134 distinct contexts and 228 distinct templates. Adjacent records shared a context in 10,106 of 10,232 within-window comparisons (98.77%). Five unprofiled repetitions per window produced a sum of window medians of 0.338 seconds. A separate cProfile replay attributed 0.377 of 0.520 seconds, 72.56%, to the two JSON-encoding calls in allocation preparation. Separate tracing observed 2,474 bytes of peak temporary Python allocations for preparation; preloaded inputs, reader caches, native memory and process-tree peaks were excluded. These measurements concern validation and metadata preparation only, excluding native materialisation, interning, durable SQL writes, graph hashing and source verification. They do not predict a complete-decode speedup or establish absence of memory leaks.

That study proposed bounded reuse of an immutable, source-derived page context's canonical encoding, subsequently implemented and tested in section 13.14. At the profiling baseline, the archive already interned repeated metadata but first re-encoded it for each admitted allocation. Reuse required an internal immutability and lifetime contract while retaining per-allocation bounds checks and independent capture comparison. A general cache keyed by mutable dictionary identity was unsuitable: mutation and identity reuse could preserve stale bytes. Template reuse also required care because templates contained record-specific tag and padding information. No admission cache was implemented during the profiling study itself, and no additional application datasets were established.

### 13.14. Implementing page-context encoding reuse

Version 0.1.47 adopted a narrow preparation change after the profiling study (claim EXP-20261007-CONTEXT47). A callback injected by the capture owner produces one canonical provenance encoding per admitted metadata page. Immutable context bytes accompany the existing bounded allocation batch; public calls keep fresh encoding. This avoids a global cache, mutable identity keys, new record wrappers and assumptions that all templates of a type are equal. Bounds, positive counts, per-row template generation, batch ceilings and independent capture comparison remain. The optional C++ helper, archive capabilities and payload codecs did not change.

A replay of the same eight 1,280-record windows included generation of context bytes and checks for context changes in every repetition. Six alternating fresh-process pairs were faster, with a median paired preparation reduction of 45.42% (claim EXP-20261007-CONTEXT-KERNEL). The medians across process results were 0.18275 seconds for baseline preparation and 0.10324 seconds for the candidate; the ratio of those medians differs from the median of paired reductions. Context encodings fell from 10,240 to 134 in the sample, while all 10,240 templates were still encoded. Template/context bytes matched the stored metadata. The replay excluded SQL, source materialisation and verification; its prior archive was opened for inspection, not newly fully verified by the replay.

The complete-operation screen used two fresh `fracSIS_test_12` pairs, two workers, three fixed logical CPUs, fixed hash seed, default compression and identical C++ helper bytes. Order was baseline/candidate followed by candidate/baseline.

| Pair | Baseline | Context candidate | Elapsed change | Sampled tree PSS change |
| --- | ---: | ---: | ---: | ---: |
| 1 | 402.05 s | 387.37 s | -3.65% | +0.12% |
| 2 | 403.77 s | 383.72 s | -4.97% | -0.78% |

All four captures passed full source-to-store verification, unchanged source/runtime checks and stable structural/discovery parity, excluding only the same two recorded discovery-duration values in comparison. Allocation processing fell from 90.95 to 74.08 seconds and from 89.17 to 71.61 seconds, supporting the intended preparation attribution. The candidate passed the predefined screen requiring both pairs to improve elapsed time with no more than a 3% sampled peak tree-PSS increase. This supported integration for the exercised workload. Shared-host frequency/cache variation and one-second sequential memory samples limit generalisation; the result does not establish a universal speedup or absence of leaks.

Thirty-six final focused canonical checks passed. Two existing behavior cases were extended for immutable context admission, public metadata mutation, rejected batches, and context/record parity across prepared pages. An existing self-consistent corruption control was extended so incorrect prepared context bytes must fail source comparison and publication. No new maintained test files or dependency were added. An initial fault-injection wrapper lacked the new private argument and was corrected without weakening its rejection assertion. Initial exploratory kernel timing overlapped corrective testing and was excluded from the acceptance screen; the six reported pairs ran afterward. A fresh canonical serial capture of `fracSIS_test_14` passed full source-to-store verification in 58.18 seconds, with unchanged source/runtime identities and stable structural/discovery parity against its retained reference (claim EXP-20261007-CONTEXT-SERIAL). That reference retained its historical execution pins; this validation timing was not a paired performance comparison. Current native execution evidence covers CPython 3.12.3 with SQLite 3.45.1 on Linux x86_64, not a new installed-wheel or full interpreter-support audit. No new geological interpretation or application datasets were established.

### 13.15. Attributing admission cost and reusing encoder configuration

After page-context reuse, a 0.1.47 study separated remaining work using single-thread component profiles (claim EXP-20261007-ADMISSION47). Eight bounded insertion-order windows covered 10,240 records from a prior capture-verified archive, freshly rehashed for read-only replay. Validation and template preparation accounted for 58.08% of profiled admission time, row construction with metadata/name admission for 22.49%, and SQLite batch insertion for 9.62%. JSON encoding, nested within preparation, accounted for 33.35% of the profile total; it is not an additional cost to sum with preparation. Inserted scalar and metadata checks passed. The replay excluded native materialisation, source-proof hashing, index building and transaction close, and its incomplete fixture was not a verified capture.

A fresh native sample selected 24 source-derived windows covering 369 pages and 86,920 parsed records, including free candidates. Canonical worker preparation materialised and encoded 60,521 records. Direct-call profiling recorded 1.626 seconds in JSON encoding and 1.101 seconds in materialisation, including its address/span and padding work. Repeated trusted preparation produced identical pickle bytes. Worker CPU overlaps owner activity in a real decode; these samples cannot be added together or extrapolated into full-stage elapsed time. An initial profile during the real two-worker allocation phase recorded impossible caller relationships while management threads were active. Its cumulative attribution was excluded rather than used as evidence. The corresponding unprofiled allocation phase took 73.61 seconds; this diagnostic intentionally stopped before later stages and published no FSDX.

The resulting candidate reused one standard-library JSONEncoder configuration per process with the same sorted keys, Unicode handling, finite-number policy, separators and conversion callback. Each call still encoded its supplied value afresh; no encoded-value cache or schema-specific shortcut was introduced. Independent byte, exception and mutation controls passed. Six alternating fresh-process preparation comparisons were faster, with a median paired reduction of 7.29% (claim EXP-20261007-ENCODER-KERNEL). Component timings excluded SQL and source materialisation and were not an acceptance substitute for complete captures.

Two complete native12 pairs used two workers and the same three-CPU allowance, reversing variant order in the second pair (claim EXP-20261007-ENCODER-CAPTURE):

| Pair | Baseline total (s) | Candidate total (s) | Elapsed change | Baseline peak tree-PSS (MiB) | Candidate peak tree-PSS (MiB) |
| --- | --- | --- | --- | --- | --- |
| Baseline then candidate | 393.39 | 375.34 | −4.59% | 298.33 | 296.10 |
| Candidate then baseline | 398.81 | 380.59 | −4.57% | 300.07 | 297.86 |

All four captures passed full source-to-store verification, unchanged source/runtime checks and stable structural/discovery parity. Only the two documented discovery duration fields were excluded from stable content comparison. Sampled memory changes were −0.75% and −0.74%; short peaks can be missed by one-second sampling. Both pairs passed the repeated elapsed-time and at-most-3% memory-regression screen. These observations remain specific to this workload on a shared host without frequency or source-cache controls.

Version 0.1.48 adopted the exact tested serialization algorithm after the screen passed. Timed candidates retained their base 0.1.47 package marker and distinct code hashes; the later release identity does not relabel those proofs. Seventy-eight retained candidate cases passed. One existing JSON case was extended for numeric/Unicode byte spelling, fresh mutation and independence after failed encoding; all five canonical JSON cases passed. A fresh canonical48 serial14 capture passed full verification in 57.06 seconds with stable parity to its retained47 reference (claim EXP-20261007-ENCODER48-SERIAL). This was validation, not a paired performance comparison. Native helper bytes, archive capabilities, codecs, resource budgets and application interpretation did not change. No new datasets were established, and this work did not refresh the installed-wheel or full interpreter-support audit.

### 13.16. Worker-result reconstruction and record ownership

A subsequent study of unchanged version 0.1.48 examined reconstruction of compact worker records and the shallow copy performed by the public allocation iterator (claim EXP-20261007-UNPACK48). A dynamically selected native12 sample covered 369 pages and 86,920 parsed records, including free candidates. Response sizes and reconstructed row counts were bounded. Seven alternating component measurements compared ordinary dictionary construction, a comprehension, and copying reusable dictionary shapes. Fixture preparation was excluded; output allocation and destruction were included. These were component observations on a shared host, not complete-capture benchmarks.

| Combined unpacking and existing record copy | Initial median seconds | Corrected-probe median seconds |
| --- | ---: | ---: |
| Canonical dictionary construction | 0.24142 | 0.27429 |
| Dictionary comprehension | 0.25188 | 0.25843 |
| Reusable dictionary shape | 0.22999 | 0.28425 |

The initial shape candidate appeared about 4.73% faster but failed constructed boundary checks: a short value row acquired absent fields set to None, and unused layouts were evaluated. These were defects in the experimental alternative, not observed failures of the maintained decoder. A lazy correction preserved the original zip behavior for unequal lengths and unsupported shapes. Eight constructed controls and all sampled native records agreed on values, ordered fields, fresh dictionary ownership and nested value identity (claim EXP-20261007-UNPACK-CONTROLS). The corrected combined median was about 3.63% slower. Substantial timing variation and the comprehension's reversed direction between probes prevented a repeatable benefit claim. Traced temporary output peaks were effectively identical; this retained whole-sample diagnostic did not measure normal decoder peak memory or establish leak absence.

A separate instrumented allocation phase used two workers and three logical CPUs. It admitted 1,832,298 allocations in 73.22 seconds, then stopped deliberately before pointer processing. Wall-clock wrappers accumulated 7.11 seconds for unpacking 2,632,432 candidate records and 1.42 seconds for 2,638,380 shallow copies (claim EXP-20261007-UNPACK-STAGE). Candidate counts included free records and reader paths, so they were not admitted allocation or dataset counts. Wrapper overhead, scheduling and preemption affected this diagnostic; the measurements cannot be added as pure CPU cost or extrapolated into whole-decode savings. No FSDX was published or fully verified. Normal cleanup removed the partial operation's owned staging, and fresh source, runtime and native-helper identities matched.

A synthetic check demonstrated why the public copy remains: changing a yielded top-level field must not change an externally supplied prepared trace. Nested values retain the existing shallow aliases (claim EXP-20261007-UNPACK-OWNERSHIP). The study therefore retained ordinary reconstruction and record copying. No runtime, helper, archive format, dependency or semantic interpretation change followed; no new datasets were established. Earlier complete-capture proofs retain their original dates and identities. The next proposed target is bounded attribution of verification reconstruction and logical reads, with full integrity checks retained and complete-operation measurements required before adoption.

### 13.17. Revalidating bounded pointer-proof framing

A study on 0.1.48 separated archive verification from source-to-store reconstruction (claim EXP-20261007-VERIFY48). Fresh standalone full verification of a retained archive took 65.06 seconds with one worker; all 1,832,298 saved allocations were separately reconstructed and canonically hashed in 63.07 seconds, matching the archive's embedded source proof. A fresh immutable native snapshot supplied an independent comparison of all 56,916,992 current logical bytes in 110 requests, taking 0.44 seconds. Saved allocation replay did not re-decode native allocations. The bounded 10,240-record profile attributed 66.84% of reconstruction/hashing time to canonical serialization and framed hashing, and 30.88% to reconstruction; serialization alone was 54.60%, nested within the former. A repeated-field-lookup candidate had inconsistent timings and was excluded. Component profiles did not partition an entire decode.

The stronger candidate reused existing bounded SQL-row framing for restored pointer-page comparisons. Native source proof generation and per-page count/hash comparisons stayed independent and unchanged. Nine alternating sample comparisons across 32 pages and 5,688 bindings had identical hashes, including Python fallback, with a 76.82% median paired reduction excluding SQL. Two complete saved-pointer replays across 1,966,325 bindings took 16.43 versus 8.02 seconds and 16.55 versus 7.88 seconds, including SQL and batch estimation (claim EXP-20261007-POINTER48). These replays checked the retained source proof; fresh native comparisons followed in the complete captures. Small traced temporary output peaks increased from 11,579 to 30,063 bytes, so the experiment was not a memory-reduction or leak-absence claim.

This revalidated the approach rejected under 0.1.38/0.1.39 in section 13.9, after subsequent allocation projection and context/encoder changes. The older failed gate remains historical. The new candidate changed only the restored pointer loop, without the older candidate's extra timing fields. Two complete native12 pairs used two workers, three fixed logical CPUs, default compression and identical helper bytes, reversing order in the second pair (claim EXP-20261007-POINTER-CAPTURE):

| Pair | Baseline seconds | Candidate seconds | Total reduction | Sampled tree-PSS change |
| --- | ---: | ---: | ---: | ---: |
| 1 | 385.07 | 367.19 | 4.64% | +0.45% |
| 2 | 376.01 | 369.11 | 1.83% | +2.05% |

All four captures passed full source-to-store verification and stable structural/discovery parity. Only two recorded discovery-duration fields were normalized. Aggregate verification times fell 141.86→131.06 seconds and 140.33→131.03 seconds. Both pairs passed the predefined elapsed-time and 3% sampled tree-PSS screen. Frequency and file-cache state were uncontrolled on the shared host; other phases varied, so the total differences cannot be assigned entirely to framing or generalized to other files. Allocation and pointer counts are not confirmed dataset counts.

Version 0.1.49 adopted the exact tested writer algorithm. The timed variants retain their 0.1.48 marker and distinct pins; release identity was updated afterward. Sixty existing format/writer cases passed, with six overlapping Python-only cases preserving framing, corruption rejection and cleanup. Fresh canonical49 serial14 capture passed full verification in 54.93 seconds and retained parity with its prior 48 reference (claim EXP-20261007-POINTER49-SERIAL). That serial run is validation, not a paired performance comparison. No native helper, portable format, parser, resource budget, public ownership or semantic interpretation changed; no new datasets were established. That study left the remaining standalone-verifier cost for a separate attribution experiment.

### 13.18. Separating standalone verification costs

A current 0.1.49 read-only study attributed full verification of a retained candidate48 archive, freshly hashed before and after (claim EXP-20261007-VERIFY49-ATTRIBUTION). Its 32,979 BLOBs and 32,870 documents included 10,634 ordinary pointer documents; indexed-tree and compact-envelope restoration were inactive. One worker on one fixed logical CPU took 69.42 seconds with lightweight timers: pointer-document validation used 21.29 seconds, BLOB validation including SQL and guards 17.84 seconds, ordered relational proofs 14.46 seconds, SQLite integrity checking 4.34 seconds, foreign-key checking 3.52 seconds, address checks 4.45 seconds and relational size admission 0.76 seconds. Other document validation used 0.74 seconds; remaining bookkeeping and wrapper overhead used 2.03 seconds. Every required check passed. This was fresh saved-store verification, not native decoding or a whole-capture benchmark.

A separate cProfile pass took 77.44 seconds with profiling overhead. Nested costs included 17.68 seconds in standard-library JSON raw decoding, 2.94 seconds in JSON preflight, 2.49 seconds in BLOB decompression, 4.42 seconds in BLOB SHA-256 construction and 7.50 seconds in source-identity checks across several operations. These figures overlap the stage timings and cannot be added to them. Raw decoding can include GC activity within the C parser; its timing does not isolate scanner CPU. The existing fused BLOB/document pass remained in use.

A bounded candidate reused the standard-library JSONDecoder configuration without caching values or changing preflight, policies, nonfinite rejection or error wrapping (claim EXP-20261007-DECODER-REUSE). Eight separated windows admitted 256 documents totalling 36.53 MiB before fetching their payloads. Exact restored value proofs and 36 valid/malformed/Unicode/nonfinite/resource controls matched. Nine alternating same-process pairs produced only a 0.99% median paired reduction, with six candidate wins. The predefined screen required a 5% reduction and at least six wins, so the candidate was rejected and 0.1.49 retained. SQL, BLOB checks, output reserialization and native capture were outside this component timing. Default-GC callback duration was a median 4.36% of baseline sample parsing time; it measures wall duration on that sample, not whole-decoder GC CPU. No complete native benchmark or new semantic recovery was claimed. Consolidating bounded BLOB SQL selection remains an untested proposal that would require malformed-input controls and full capture evidence before adoption.

### 13.19. Bounded BLOB admission and parallel document verification

The next study first consolidated a BLOB's metadata and payload retrieval into one SQL projection. Conditional selection admits payload bytes only after codec, exact integer length, stored length, storage type, raw-codec length equality and resource-policy checks. The existing Python error order, bounded decompression, stream-end/tail checks, length/SHA-256 validation and source guards remained. Three alternating fresh-process complete saved-BLOB comparisons produced a 24.95% median reduction (claim EXP-20261007-BLOB49). Two Python allocation-proof serialization candidates preserved exact streams but changed median time by +0.47% and +11.46%; both were excluded. Their caches and encoders were not added to the maintained implementation.

A combined candidate used the existing requested worker count to validate contiguous BLOB/document ranges in spawned read-only processes. The owner derived boundaries from actual stored digests, rejected orphan document targets and checked returned population counts, including every use of a shared BLOB. Workers retained runtime/source/resource checks and used the existing zero-cache option for their one-pass reads. Payloads stayed in the child; only small validation results returned. Default serial verification and public cache settings remained, as did whole ordered relational SHA streams, global indexed-tree/count/coverage checks and independent native source comparisons. Children joined on success, failure and cancellation. Two complete saved-store pairs took 57.56 versus 41.18 seconds and 58.37 versus 40.82 seconds, a 29.27% median paired reduction (claim EXP-20261007-VERIFY-PARALLEL49).

The adoption gate used two complete native12 pairs, two workers, three fixed logical CPUs, default compression, identical helper bytes and reversed candidate order in the second pair (claim EXP-20261007-VERIFY-CAPTURE). Its predeclared screen required both candidates faster, at least a 5% median total reduction, no more than a 3% sampled tree-PSS regression and exact full structural/discovery parity:

| Pair | Baseline seconds | Candidate seconds | Time reduction | Sampled tree-PSS reduction |
| --- | ---: | ---: | ---: | ---: |
| 1 | 372.02 | 350.06 | 5.90% | 7.02% |
| 2 | 372.33 | 356.94 | 4.13% | 6.29% |

The 5.018% median time reduction just cleared the threshold. All four fresh captures passed complete source/store/runtime verification, comparing 1,832,298 allocations, 1,966,325 pointer bindings and 56,916,992 logical bytes. Stable counts, coverage, normalized graphs, native statistics and document/discovery proofs matched; only the two previously documented discovery-duration values were normalized. Aggregate verification time changed 133.40 to 114.16 seconds and 132.66 to 114.21 seconds. Other phases varied on the shared host, so the whole gain cannot be assigned entirely to one subcomponent. Two pairs without frequency/cache control do not establish statistical significance or universal speedup. One-second sequential PSS samples can miss short peaks and do not prove leak absence.

Version 0.1.50 adopted the exact tested format/worker algorithms; timed variants retain marker 49 and distinct pins. Sixty existing format/writer methods passed, with three overlapping extended admission/lifecycle/indexed-document methods and four overlapping Python-only methods rechecked. No new maintained test methods/files, dependency, native API or archive feature was added. Canonical parallel/admission checks then passed, and a fresh canonical50 serial14 capture passed full verification in 54.42 seconds with stable parity to its retained49 reference (claim EXP-20261007-VERIFY50-SERIAL). That serial timing is validation, not a paired benchmark or installed-wheel/interpreter-matrix audit. No new application datasets, ownership interpretation or geological meaning were established.

### 13.20. Scheduling, proof framing and result lifetimes

The next experiment separated verification scheduling from the owner process's allocation proof work. Two reversed saved-store full-verification pairs found median changes of −2.01% for a shared pool with overlapping global checks and −1.30% for byte-balanced BLOB ranges. Both missed the declared 10% component screen. Four verification workers improved the saved component by 12.31%, but an exploratory complete native capture improved total time by only 0.526%, below the 5% continuation threshold. These scheduling alternatives were excluded (claims EXP-20261008-VERIFY-SCHEDULE and EXP-20261008-WORKER4). Saved-store component timings do not constitute native capture results.

Profiling identified canonical JSON framing in the restored allocation proof as a useful narrower target. A new optional C++ entry point frames exact builtin records into the same ordered, eight-byte-length-prefixed JSON stream used by Python. Conservative whole-tree admission precedes output allocation: at most 64 records, an estimated 1 MiB and depth 64. Supported values include string-keyed dictionaries, lists/tuples, signed 64-bit integers, booleans, null, strings and canonical byte wrappers. Floats, larger integers, subclasses, unsupported keys, oversized/deeper/cyclic values and selected encoding failures retain Python handling. Python still constructs and independently hashes the native source proof; the helper does not interpret FSD objects or change stored JSON (claim EXP-20261008-ALLOC-FRAME).

Nine reversed bounded-sample pairs reduced restoration/framing time by 44.61%, with exact independent Python streams. A complete saved replay also matched the recorded proof over 1,832,298 allocations. Those are component and historical-store observations. Fresh complete native captures were therefore required before adoption. Their gate required two reversed pairs, both faster, at least 5% median total-time reduction, no more than 3% sampled process-tree PSS increase in either pair, and equality of all eleven stable structural/discovery comparisons. Only two discovery-duration values were normalized for comparison; their originals remain retained.

| Complete native candidate | Median total-time change | Time-and-memory screen |
| --- | ---: | --- |
| Native framing | -5.170% | Failed |
| Framing and shorter result lifetimes | -4.969% | Failed |
| Actual-label metadata lookup | -6.969% | Failed |
| Smaller prefetch queue | -2.568% | Failed |
| Allocation-only smaller queue with ownership correction | -6.593% | Passed |

The original framing candidate passed the median time threshold but exceeded the memory allowance in one pair. The next candidate released consumed decoded pages, serialized transport buffers and completed Future references before refilling work; a constructed weak-reference control showed previously consumed pages could be released when the caller released its references. Its full-operation median reduction was 4.969%, below the 5% threshold, so it too was excluded. Neither observation proves universal leak absence (claims EXP-20261008-FRAME-NATIVE and EXP-20261008-FRAME-LIFETIME).

A further private proof iterator used dictionary lookup derived from the actual SQL cursor labels, avoiding repeated named lookup in sqlite3.Row. Its bounded component improved by 13.93%, and complete native pairs improved median total time by 6.969%, but one pair exceeded the memory screen. The private writer-created proof path retained existing metadata decoding, ordered iteration, byte/record admission and Python fallback; public readers and archive fields did not change. That failed result remains failed (claim EXP-20261008-PROOF-MAPPING).

An intermediate candidate separately reduced parallel prefetch from workers×2 slots to workers+1 slots. For two workers this admits three rather than four estimated 8 MiB results. Worker count, per-result cap, caller budget, batch pages and ordered output remain. This admission estimate is not a process RSS limit (claim EXP-20261008-PROOF-QUEUE).

The uniform queue missed its time gate, so the final candidate retained the original pointer-page queue while narrowing allocation-batch prefetch alone. Both use the same caller byte budget. Review also found that a C++ allocation failure could bypass release of a temporary dictionary-key list in the staged helper. RAII ownership corrected that exceptional path; deterministic artifact-only bad_alloc injection changed the key reference-count delta from +1 to zero, with MemoryError in both cases. The timed/adopted source contains no failure hook. This is a specific exceptional-path result, not universal leak absence (claim EXP-20261008-PHASE-QUEUE).

The phase-specific candidate passed its complete native gate with 6.593% median total-time reduction. A separate fresh native input also passed all stable comparisons, with 4.55% shorter total time and +0.42% sampled tree-PSS change. This single additional pair broadens input scope without establishing a replicated general speed claim. Version 0.1.51 adopted the exact tested framing, lookup, lifetime and queue algorithms; timed variants retain marker 50 and their own execution pins.

The two complete pairs were:

| Pair | Baseline s | Candidate s | Total-time change | Sampled tree-PSS change |
| --- | ---: | ---: | ---: | ---: |
| 1 | 331.99 | 307.77 | -7.30% | -2.34% |
| 2 | 329.38 | 309.98 | -5.89% | -0.08% |

Sixty existing format/writer methods were exercised during staging, with three existing methods extended and no new maintained test method or file. Fresh adopted-runtime checks covered the framing and worker lifecycle boundaries and the forced Python fallback. Separate canonical serial captures of a third input passed full verification with both native and Python backends and stable parity to the retained 50 reference (claim EXP-20261008-CANONICAL51). These final captures are validation, not paired speed measurements or an installed-wheel/interpreter-matrix audit.

Whole memory peaks varied across identical baselines, and several excess peaks occurred during pointer preparation before the framing helper ran. This motivated separate lifetime and queue experiments but did not justify waiving failed thresholds. Shared-host load, uncontrolled frequency/cache, a small number of pairs and one-second sequential PSS sampling limit attribution and generalisation. These experiments retain all source, logical-byte, graph, document, discovery and runtime guards. No new application dataset, ownership interpretation or geological meaning was established, and semantic recovery remains paused.

## 14. Testing the architecture

### 14.1. Different tests answer different questions

Testing developed alongside the architecture. Early byte reconstruction and deliberately corrupted layout cases tested inferred field boundaries. Native cross-database runs tested whether those interpretations transferred beyond the initial specimen. Source-to-store comparisons tested preservation across capture. Independent Python checks tested whether optional C++ execution altered selected archive contracts. Complete timed captures tested whether a proposed optimisation improved the operation that users actually performed.

| Test family | Question answered | Important boundary |
| --- | --- | --- |
| Binary-layout reconstruction and corruption tests | Does the inferred representation reproduce bytes and reject selected malformed structures? | Does not independently establish current object ownership or application meaning. |
| Native capture comparisons | Does the archive reproduce the admitted logical bytes and normalised structural records of the captured source? | Depends on the correctness and support limits of native reconstruction. |
| Python and C++ differential tests | Do supported values, encoded rows, and selected errors agree across backends? | Does not prove all possible inputs or interpreter combinations. |
| Source-independent restored tests | Can the selected operation use FSDX without reopening native inputs? | Covers the exercised path rather than every future discovery operation. |
| Lifecycle and failure-injection tests | Are resources released and exceptional paths handled as intended? | A passing scoped test is not a universal memory guarantee. |
| Paired complete-capture measurements | Does a candidate improve elapsed time without violating the agreed memory screen? | Shared-host variation and small sample counts limit generalisation. |

### 14.2. Property tests, malformed controls, and write sequences

The 0.1.1 property work used fixed seeds across seven bounded domains with independent byte, JSON, and address oracles. It reported 2,800 examples without finding a production defect. An intentionally dropped coordinate bit was then introduced as a faulty control, and the property test shrank the failure to a counterexample. This demonstrated sensitivity to that deliberate fault, not discovery of a previously existing decoder bug. The two references to 2,800 examples in the writer integration and property account describe the recorded work, not necessarily disjoint test populations to be added together.

The writer differential audit exposed why single-value properties are not enough. A document sequence can preserve valid outputs yet leave different state after a rejected write, while indexed keys can differ from ordinary JSON keys. Useful tests therefore compare error behaviour, rollback state, indexed restoration, and subsequent writes as well as successful serialised bytes. Recommendations from that audit remain recommendations unless a later integration establishes their implementation.

Independent parser controls also had different scopes. Construct, ImHex, and Kaitai checked selected structural representations; generated object patterns shared discovery inputs with Python. Cross-database tests challenged source-specific assumptions, while malformed controls established selected rejection behaviour. Neither form alone proved application ownership, and a synthetic schema conflict was not evidence that the same conflict occurred in a native specimen.

### 14.3. The subsequent 0.1.45 source review

A later review of the supplied source added constructed FSDX checks separate from the historical native experiments. It parsed all 90 Python files and imported all 85 package modules in a CPython 3.13.5 environment with SQLite 3.46.1. Thirty ordinary contract groups passed with the C++ backend and again with the Python fallback. Each backend run included 2,506 constructed preflight comparisons and 500 row-framing batches.

The checked behaviours included logical reads, pointer states, detached public metadata, corrupted BLOBs, modified relational records, reader-session drift, unsupported capabilities, existing-destination protection, sidecar refusal, source-independent restored access, and agreement between one-worker and two-worker verification on a small fixture. An 18 MiB aggregate document exercised the indexed-document route, while compact pointer-page tests exercised logical round-trip equivalence.

Four further groups intentionally reproduced existing limitations. They covered pointer bytes inconsistent with logical content being accepted by full verification but rejected on resolution, modification of selected unprotected provenance fields, acceptance of missing relational proofs with explicit component flags, and default repository-root behaviour that depended on a directory named `fsd`. These were successful characterisations of limitations, not repaired defects.

No real FSD was decoded in that source review. The original native specimens and historical regression suite were not included in the supplied repository. Its diagnostic package build also used available setuptools 82.0.1 rather than the declared isolated requirement of 84 or later. The results support the exercised contracts and local build, not a newly executed native-corpus result or a completed interpreter-support matrix.

### 14.4. Checks for the worked anatomical examples

Document revision 2 introduced 22 focused example-check groups against the supplied 0.1.45 source. They exercise the signature bytes, all four supported unsigned-32 payload widths, the packed-value example, truncated and unsupported scalar branches, leaf-reference decoding, hash-slot lookup, an all-free page-group bitmap, primitive and class-vector counts, ordinary and zero-offset PRM modes, chain closure, partial-page refusal, fragmented logical reads, and selected header refusals.

All 22 groups passed when preparing revision 2 under CPython 3.13.5 and were rerun successfully during the subsequent history integration against the unchanged original source. Their inputs are constructed specifically to make the mechanisms legible. They are not native specimens, a reconstructed full FSD fixture, or a substitute for the earlier recovery experiments. The separate history-revision bundle retains the same check script and the output of that rerun so the byte examples can be rechecked when the underlying implementation changes. No new native-corpus or performance experiment was conducted for that history integration.

### 14.5. Maintaining meaningful tests

The most useful regression tests protect the contracts that the prototypes established. Directory tests should preserve sequence selection, sector-boundary control handling, and rejection of unsupported events. Metadata tests should preserve leaf reconstruction and native probe behaviour. Allocation tests should cover displacement, vectors, padding, seek indexes, and cross-page deduplication. Pointer tests should cover context transitions, both widths, zero-offset modes, chain closure, and unresolved targets.

Archive tests should distinguish opening, standalone verification, and capture-time source comparison. Optimisation tests should retain canonical bytes, row ordering, detached public metadata, Python fallback, and exceptional-path behaviour. Complete-capture measurements should accompany performance claims that extend beyond a component. These are maintenance priorities for the living system, not assertions that every suggested case already exists in the distributed checkout.
