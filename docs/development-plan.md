# WXTLA Development Plan

## 0. Goal and non-goals

`wxtla` is the long-term read-only parsing backend for `regressor`. It owns concurrent byte-source abstractions and in-house parsers for storage images, partition tables, and filesystems. It does not own virtual path routing, session state, mount graphs, UI-facing metadata shaping, or scripting/runtime integration.

Non-goals for `wxtla`:

- no write support
- no FUSE/WinFsp/Dokan layer
- no global VFS or mount table
- no dependency on `keramics` or `regressor`
- no compatibility constraints with current `keramics` or `regressor` APIs

## 0.1 Implementation discipline

The migration process itself is part of the design.

- one format must be brought to a complete read-only implementation before the next format starts
- partial demo implementations are not acceptable, even if they satisfy a small fixture set
- every completed implementation step must be committed before the next step begins
- `formats/` fixtures are mandatory regression inputs for any implemented format
- library code must not panic on malformed input; errors must be reported through structured results
- `keramics` and `regressor` are the first references for parser semantics, fixture expectations, and current feature coverage
- mature external implementations should then be consulted to find missing edge cases and version-specific behavior
- `keramics` runtime architecture and crates must not be copied or reused
- `wxtla` should reuse its own internal source, cache, resolver, and typed-surface infrastructure wherever possible

## 1. Base capability set

The list below is an approved toolbox, not a mandatory baseline. `wxtla` should pull these crates only when a concrete parser or infrastructure module needs them.

### 1.1 Approved mature crates

| Capability             | Crate         | Minor pin | Why it is acceptable                                         |
| ---------------------- | ------------- | --------- | ------------------------------------------------------------ |
| Error types            | `thiserror`   | `"2.0"`   | Small, stable, and standard for library errors               |
| Flags                  | `bitflags`    | `"2.11"`  | Mature and widely used for on-disk flag sets                 |
| CRC32                  | `crc32fast`   | `"1.5"`   | Mature, fast, SIMD-aware                                     |
| Adler-32               | `adler2`      | `"2.0"`   | Tiny and sufficient for image/container checks               |
| Deflate / zlib / gzip  | `flate2`      | `"1.1"`   | Mature stream decompression for archives and image internals |
| BZip2                  | `bzip2`       | `"0.6"`   | Mature stream decompression                                  |
| XZ / LZMA              | `xz2`         | `"0.1"`   | More mature today than newer pure-Rust alternatives          |
| Zstandard              | `zstd`        | `"0.13"`  | Mature and widely used                                       |
| LZ4                    | `lz4_flex`    | `"0.13"`  | Small, pure-Rust, and fast                                   |
| Common text encodings  | `encoding_rs` | `"0.8"`   | Mature for common Windows/web encodings                      |
| XML                    | `quick-xml`   | `"0.39"`  | Fast and established for descriptor/meta parsing             |
| Apple plist            | `plist`       | `"1.8"`   | Mature plist reader for UDIF / sparsebundle metadata         |
| UUID / GUID            | `uuid`        | `"1.22"`  | Mature, stable, and ubiquitous                               |
| Generic date/time math | `time`        | `"0.3"`   | Mature for normalized timestamp conversion and formatting    |
| TAR parser             | `tar`         | `"0.4"`   | Approved exception: archive parsing may reuse mature crate   |
| ZIP parser             | `zip`         | `"8.2"`   | Approved exception: archive parsing may reuse mature crate   |

Notes:

- `xz2 = "0.1"` is preferred over younger pure-Rust LZMA/XZ crates for now. If a strict pure-Rust requirement appears later, reevaluate that choice separately.
- `tar` and `zip` are the only approved parser crates for actual storage formats.
- Compression crates are approved as infrastructure, even when used inside self-implemented parsers.

### 1.2 Functionality that should be implemented in-house

The following must remain inside `wxtla` instead of being delegated to parser crates:

- positional concurrent source model (`DataSource`) and capability reporting
- parser-local source wrappers such as slices, probe caches, sparse/overlay mappers, and backing-chain readers
- related-source resolution model for multipart images and backing files
- probe logic and signature validation for every supported format
- all on-disk structure parsing for complex formats: EWF, QCOW, VHD, VHDX, VMDK, UDIF, sparseimage, sparsebundle, split raw, PDI, MBR, GPT, APM, LVM2, FAT, NTFS, HFS/HFS+/HFSX, ext2/3/4, XFS
- filesystem-specific path/name semantics such as FAT short/long-name assembly, NTFS attribute naming, HFS name normalization, and ext/xfs directory semantics
- filesystem-specific timestamp decoding such as FAT date/time variants, FILETIME, HFS epoch timestamps, and format-local epoch conversions
- sparse block maps, allocation tables, extent trees, runlists, and partition/volume translation layers
- parser-local caching, read-ahead heuristics, and layout-aware concurrency tuning

### 1.3 Crates explicitly not adopted for complex parser ownership

During exploration, several format crates were found on crates.io, for example:

- `gpt = "4.1"`
- `mbrman = "0.6"`
- `fatfs = "0.3"`
- `ntfs = "0.4"`
- `ext4-view = "0.9"`
- `hfsplus = "0.2"`
- `ewf = "0.1"`
- `qcow = "1.2"`
- `vhdx = "0.1"`
- `udif = "0.3"`
- `lvm2 = "0.0.3"`

These crates may be useful as references during implementation or for test cross-checking, but they are not part of the dependency plan. WXTLA owns the parser logic itself.

## 2. Boundary: WXTLA vs Regressor

### 2.1 WXTLA responsibilities

- concurrent positional byte-source abstractions
- source capability reporting (`concurrent` vs `serialized`, `cheap` vs `expensive` seek)
- parser-oriented wrappers (`slice`, `probe cache`, future `mapped source`, future `overlay source`)
- related-source resolver interface for multipart images and backing chains
- format probing and validation
- image/container parsers
- volume/partition parsers
- filesystem parsers
- parser-local metadata and typed parser results
- parser-local caches and performance heuristics

### 2.2 Regressor responsibilities

- host path discovery and opening policy
- local filesystem adapters and path-origin policy
- virtual path normalization and URI semantics
- mount graph, recursive automount policy, and session lifetime
- temp extraction/materialization policy
- user-facing metadata flattening and JSON shaping
- Python/runtime/UI integration
- registry orchestration and product-level feature toggles

### 2.3 Immediate boundary consequence

`wxtla` should not expose host-path-aware source helpers in its core API. A parser should receive bytes and related-resource resolution through abstract interfaces, not by reaching back into a local path or a VFS mount context.

That means the correct long-term split is:

- `wxtla`: `DataSource` + future `TableSource` + `RelatedSourceResolver`
- `regressor`: local file opening, mount/session routing, and VFS behavior

## 3. Concurrent read architecture

### 3.1 Core model

Every parser reads from a positional, immutable, thread-safe source.

```rust
trait DataSource: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn size(&self) -> Result<u64>;
    fn capabilities(&self) -> DataSourceCapabilities;
    fn telemetry_name(&self) -> &'static str;
}
```

Important properties:

- no shared cursor
- no `seek + read` API
- safe to call from multiple parser tasks
- capabilities let higher layers choose concurrency strategy instead of guessing

### 3.2 Planned layering

1. `DataSource`
   - lowest-level positional byte source
   - path-agnostic and storage-backend-agnostic
2. `RelatedSourceResolver`
   - parser-facing resolver for sibling files, split segments, backing files, and bundle bands
   - implemented by `regressor` or another host application
3. Mapping wrappers
   - `SliceDataSource`
   - future sparse-mapped sources
   - future backing-chain/overlay sources
4. Probe/read helpers
   - `ProbeCachedDataSource`
   - future bounded read planner
   - future parser-local prefetch policy
5. Parser-local caches
   - sector/block cache
   - metadata table cache
   - runlist/extent cache
   - decompressed block cache where needed
6. Typed parser APIs
   - image/container readers
   - partition/volume readers
   - single-filesystem read-only readers
   - future `TableSource`-backed database readers

### 3.3 Concurrency rules

- parsing code must prefer independent `read_at` calls over shared mutable state
- parser caches should be sharded or otherwise low-contention
- expensive-seek backends should coalesce reads into larger ranges
- concurrent/cheap-seek backends should allow speculative metadata reads
- probe paths should stay tiny and cheap; the first small window is worth caching aggressively
- parser output should expose typed results, not VFS semantics

### 3.4 Why VFS stays out of WXTLA

VFS concerns compose multiple parsers into one product-level namespace. That is where mount tables, path normalization, recursive mount policy, UI metadata, and conflict handling live. Those are service concerns, not parser concerns, and they would make the backend harder to benchmark and harder to reuse outside `regressor`.

## 4. Format-facing parser model

The intended WXTLA stack is:

- image/container parser -> yields logical readable address space and child descriptors
- partition/volume parser -> yields partition slices / logical volumes
- filesystem parser -> yields directory/file metadata and file content readers
- table/database parser -> yields schemas, tables, rows, and typed cell/blob access through a future `TableSource`

Each layer stays individually reusable. `regressor` can compose them into a VFS, but `wxtla` itself should stop at typed read-only parser outputs.

### 4.1 Planned second core read interface: `TableSource`

`DataSource` remains the correct primitive for byte-addressable media, files, archive members, image payloads, and filesystem file contents. It is not sufficient for structured forensic databases where the natural consumer model is tables, columns, rows, and large cell/blob payloads.

The planned second core interface is therefore `TableSource`, which should model read-only structured stores such as ESE databases, thumbnail caches, browser cache databases, mail stores that can be projected into tables, and similar record-heavy formats.

The interface should stay intentionally small and parser-facing:

```rust
trait TableSource: Send + Sync {
    fn tables(&self) -> Result<Vec<TableInfo>>;
    fn schema(&self, table_id: TableId) -> Result<TableSchema>;
    fn scan_rows(&self, table_id: TableId) -> Result<Box<dyn RowCursor>>;
    fn open_blob(&self, table_id: TableId, row_id: RowId, column_id: ColumnId) -> Result<Option<DataSourceHandle>>;
    fn telemetry_name(&self) -> &'static str;
}
```

Design constraints for `TableSource`:

- read-only only
- schema-first, not SQL-first
- no query planner inside `wxtla`
- row iteration may be sequential even when `DataSource` stays concurrent underneath
- large binary/text cells should be exposed as `DataSourceHandle` when streaming is more appropriate than materialization
- the abstraction must work for true relational stores and for table-shaped forensic stores that are not fully relational

## 5. Migration plan

### Phase 0: boundary freeze

- document the split between parser backend and session/VFS layer
- keep only path-agnostic source primitives in current core
- remove host-path-aware helpers from the current WXTLA surface

### Phase 1: stable parser core

- finalize `DataSource` and capability model
- add `RelatedSourceResolver`
- add a common probe API
- add parser-local cache utilities and benchmark harnesses

### Phase 2: archive/container quick wins

- ship `tar` / `tar.*` using `tar` plus approved compression crates
- ship `zip` using `zip`
- use these as early integration targets for the new core and benchmark tooling

### Phase 3: partition and low-complexity container base

- MBR
- GPT
- APM
- split raw

These are relatively contained and establish the offset-mapping model that later image parsers will reuse.

### Phase 4: image/container parsers

- EWF
- QCOW
- VHD
- VHDX
- VMDK
- UDIF / sparseimage / sparsebundle
- PDI / split raw runtime image handling

Common concerns for this phase:

- related-source resolution
- sparse map translation
- backing-chain translation
- internal block decompression
- integrity checks

### Phase 5: filesystem parsers

The filesystem wave should now follow common forensic prevalence instead of historical implementation convenience:

1. NTFS (`libfsntfs`)
2. FAT12 / FAT16 / FAT32 (`libfsfat`)
3. ext2 / ext3 / ext4 (`libfsext`)
4. HFS / HFS+ / HFSX (`libfshfs`)
5. XFS (`libfsxfs`)
6. ReFS (`libfsrefs`)

### Phase 5a: long-term modern filesystem wave

The following newer copy-on-write or snapshot-heavy filesystems should be treated as a later long-term wave after the mainstream forensic set is stable:

1. APFS (`libfsapfs`, https://github.com/fox-it/dissect.apfs)
2. Btrfs (https://github.com/fox-it/dissect.btrfs)
3. ZFS (https://github.com/openzfs/zfs/blob/master/include/libzfs.h)
4. VMFS (VMWare VMFS, https://github.com/fox-it/dissect.vmfs)
5. squashfs (https://github.com/fox-it/dissect.squashfs)
6. FFS (https://github.com/fox-it/dissect.ffs)
7. LUKS (https://github.com/fox-it/dissect.fve)
8. JFFS2 (https://github.com/fox-it/dissect.jffs)
9. QNXFS (https://github.com/fox-it/dissect.qnxfs)
10. CRAMFS (https://github.com/fox-it/dissect.cramfs)
11. CLFS (https://github.com/fox-it/dissect.clfs)

Reasons to defer them:

- significantly more complex copy-on-write and snapshot semantics
- lower immediate value than NTFS / FAT / ext / HFS / XFS / ReFS for the first broad coverage milestone
- higher likelihood of needing new shared abstractions for subvolumes, snapshots, checksums, and object trees

Common concerns for this phase:

- inode/file-record metadata decoding
- directory iteration semantics
- file extent translation
- timestamp conversion
- encoding/normalization edge cases

### Phase 6: table/database parsers

After the filesystem wave lands, add a `TableSource` domain for the highest-value structured forensic stores that already have mature `libyal` references:

1. ESE / EDB (`libesedb`)
2. Windows thumbnail cache databases (`libwtcdb`)
3. Windows SuperFetch / application database (`libagdb`)
4. MSIE cache / `index.dat` (`libmsiecf`)
5. Exchange MAPI database (`libmapidb`)
6. Notes NSF database (`libnsfdb`)
7. PST / OFF projections (`libpff`) for message/folder/attachment table views

These formats are not identical in structure, but they can share a read-only table-centric surface as long as `wxtla` keeps the abstraction schema-first and avoids pretending that every store is a general-purpose SQL engine.

Structured stores that are important but should not be forced into the first `TableSource` wave include:

- registry hives (`libregf`) - better modeled as hierarchical key/value stores
- event logs (`libevt`, `libevtx`) - better modeled as append-only record streams
- compound document containers (`libolecf`) - better modeled as nested storage/file graphs

### Phase 7: volume manager and stacking

- LVM2
- stacked flows such as image -> partition map -> filesystem
- performance tuning across layered sources

### Phase 8: regressor adoption and keramics retirement

- add a thin `regressor` adapter layer over WXTLA typed parsers
- replace the current keramics bridge incrementally
- migrate product features to the new adapter layer
- remove keramics as a runtime dependency once format coverage is sufficient

## 6. Success criteria

The migration is successful when:

- `regressor` depends on WXTLA as its only parsing backend
- complex parser crates are not used as runtime dependencies
- `wxtla` remains free of VFS/session/runtime concerns
- performance-sensitive paths are driven by `read_at` concurrency, cache locality, and layout-aware mapping rather than by shared cursors

## 7. Current migration state

The current landed state is:

- volume layer completed for `mbr`, `gpt`, and `apm`
- stacked volume-manager support completed for `bitlocker` and `lvm2`
- image layer completed for `ewf`, `qcow`, `vhd`, `vhdx`, `vmdk`, `udif`, `sparseimage`, `sparsebundle`, `pdi`, and `splitraw`
- archive layer completed for `ad1`, `tar`, `zip`, `7z`, and `rar`
- current next format target is `ntfs`

The active migration strategy is therefore:

1. move on to full filesystem drivers
2. add the `TableSource` database wave after the filesystem layer has initial coverage
3. revisit stacked-volume polish only after filesystems and table stores are stable

The concrete next-stage order is:

1. filesystem formats in this order:
   - `ntfs`
   - `fat12` / `fat16` / `fat32`
   - `ext2` / `ext3` / `ext4`
   - `hfs` / `hfs+` / `hfsx`
   - `xfs`
   - `refs`
2. long-term filesystem targets:
   - `apfs`
   - `btrfs`
   - `zfs`
3. `TableSource` database formats in this order:
   - `esedb`
   - `wtcdb`
   - `agdb`
   - `msiecf`
   - `mapidb`
   - `nsfdb`
   - `pff` table projections
4. deeper stacking/performance work
