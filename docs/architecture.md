# WXTLA Architecture

## 0. Architectural stance

`wxtla` is a concurrent, read-only parser backend. It is not a session layer, not a VFS, not a mount manager, and not a runtime bridge. Parsers receive positional byte sources and optional related-source hints, then expose typed read-only surfaces such as images, volumes, filesystems, or archives.

The current architecture deliberately avoids the state-machine cursor model used by `keramics`. `keramics` remains useful as a source of on-disk field definitions and format notes, but its runtime architecture must not be copied. All parser code in `wxtla` must be built around independent `read_at` operations, bounded caches, and layered source translation.

Reference order for implementation work is:

1. `keramics` and `regressor` for parser-visible semantics, fixture expectations, and current feature coverage
2. mature external implementations and public specifications for gap analysis and edge cases
3. `wxtla`'s own shared infrastructure as the implementation substrate

The important constraint is that `wxtla` may reuse its own internal primitives aggressively, but must not depend on `keramics` crates or import `keramics` runtime architecture.

## 1. Top-level crate layout

The crate is organized by parser domain:

- `src/core/`: shared read model, error types, probing, source hints, and related-source resolution
- `src/formats/`: inventory and probe-registry plumbing only; concrete drivers do not live here
- `src/images/`: image/container formats such as `ewf`, `qcow`, and `vhd`
- `src/volumes/`: partition and volume-system formats such as `mbr`, `gpt`, and `apm`
- `src/filesystems/`: read-only filesystem drivers
- `src/archives/`: read-only archive drivers
- future `src/tables/` or `src/databases/`: read-only structured table/database drivers

Each concrete format sits in its own module subtree, for example `src/images/ewf/` or `src/volumes/gpt/`. Once a format becomes non-trivial, its logic is split across multiple files by responsibility instead of accumulating in a single large module.

## 2. Shared core model

### 2.1 Data sources

All parsers consume `DataSource`, which provides positional reads with no shared cursor. The key requirements are:

- thread-safe (`Send + Sync`)
- immutable from the parser's point of view
- usable concurrently by multiple metadata and content readers
- capability-aware (`concurrent` vs `serialized`, `cheap` vs `expensive` seek)

Wrappers such as `SliceDataSource` and `ProbeCachedDataSource` stay in `src/core/` because they are backend primitives rather than format-specific logic.

### 2.1b Planned `TableSource`

`DataSource` remains the correct abstraction for byte-addressable media and stream-like payloads. A second parser-facing abstraction is needed for database and table-oriented forensic formats where callers need schemas, rows, typed cells, and optional blob streaming rather than raw byte offsets.

The planned `TableSource` role is:

- enumerate logical tables/collections
- expose schema metadata and typed columns
- scan rows without embedding a SQL engine in `wxtla`
- return `DataSourceHandle` for large cell/blob payloads when streaming is preferable

This should remain a read-only parser abstraction, not a query planner or an ORM surface.

### 2.2 Source hints and resolver

Formats that need sibling files, parent images, split segments, or bundle bands receive `SourceHints` and `RelatedSourceResolver`.

This is the only path by which parsers discover related sources. They must not assume host paths, must not perform their own filesystem access, and must not depend on a VFS layer. The resolver belongs to the embedding application, such as `regressor`.

### 2.3 Probe and inventory

The `inventory` crate is used for distributed format registration. Each format module contributes its own descriptor and probe registration. `src/formats/` then assembles probe registries by category or for the full built-in set.

This keeps probe metadata close to the owning format instead of maintaining a central registry file full of constants.

## 3. Domain-level interfaces

### 3.1 Images

Image drivers expose a logical random-access surface over an underlying container. They may internally translate chunk maps, backing chains, sparse allocations, compressed blocks, or split segments, but externally they still implement `DataSource`.

Current image-specific design patterns:

- chunk/block/cluster lookup is done from immutable metadata tables
- payload decompression happens per logical unit and is cached
- parent or sibling images are resolved through `SourceHints`
- image drivers report logical and physical sector sizes when known

### 3.2 Volumes

Volume-system drivers expose discovered partitions or logical volumes as `VolumeRecord`s and can open each one as a slice-backed `DataSource`. This layer is already suitable for composition into later filesystem parsers.

### 3.3 Filesystems and archives

Filesystem and archive drivers expose typed directory/file metadata and can open file contents as `DataSource`s. These higher layers should remain path-model agnostic and must not absorb VFS semantics from the application layer.

### 3.4 Tables and structured stores

Database and table drivers should eventually expose `TableSource` instead of forcing all structured formats into filesystem or archive semantics. The first wave should focus on truly table-like forensic stores such as ESE, thumbnail caches, and other row/column oriented databases that already have mature `libyal` references.

## 4. Format implementation pattern

Every non-trivial driver should follow a consistent internal structure:

1. `mod.rs`
   - public exports
   - descriptor
   - probe registration
2. low-level structure parsers
   - headers
   - entries
   - tables
   - metadata sections
3. `parser.rs`
   - orchestration of format metadata loading
   - validation of structure relationships
4. `image.rs` / `system.rs` / `filesystem.rs` / `archive.rs`
   - open read-only surface and `read_at` behavior
5. format-local caches
   - chunk/block metadata
   - decompressed payloads
6. validation helpers
   - integrity checks
   - range/alignment checks
   - relationship checks between mirrored structures

If a format gains additional complexity, new files should be introduced rather than expanding one file indefinitely.

## 5. Concurrency and performance rules

The architecture is intentionally optimized around concurrent reads:

- all parser IO is positional and parallel-friendly
- metadata parsing should prefer bounded random reads over long-lived mutable cursors
- caches should be small, explicit, and contention-aware
- decompression should happen at natural allocation-unit boundaries (chunks, clusters, blocks)
- sparse and backing-chain translation should happen before exposing bytes to upper layers
- probe paths must stay cheap and must not pre-parse an entire format

Specific consequences for image formats:

- `ewf`: chunk cache and per-segment chunk mapping must support multi-segment concurrency
- `qcow` / `vhd` / `vhdx` / `vmdk`: block or cluster translation tables must be immutable after open
- differential/backing formats must fall back to parent images through the same `read_at` path, not through ad hoc side channels
- new formats should first be mapped onto existing `DataSource`, cache, resolver, and typed-surface layers before introducing new shared abstractions

## 6. Panic policy

Library code must not panic on malformed or adversarial input. All parser failures must be returned as structured `Error` values.

Allowed `unwrap`/`expect` usage is limited to tests, synthetic test builders, or impossible internal situations already guarded by explicit validation. Production parser code must instead:

- validate fixed-size reads before decoding
- check arithmetic with `checked_*`
- convert size/index casts with `try_from`
- reject unsupported feature combinations with explicit errors
- surface missing related files as resolver errors, not panics

## 7. Current implementation snapshot

As of the current handoff point:

- completed volume drivers: `mbr`, `gpt`, `apm`, `bitlocker`, `lvm2`
- completed image drivers: `ewf`, `qcow`, `vhd`, `vhdx`, `vmdk`, `udif`, `sparseimage`, `sparsebundle`, `pdi`, `splitraw`
- completed archive drivers: `ad1`, `tar`, `zip`, `7z`, `rar`
- next active parser target: `ntfs`

The next architecture expansion after the filesystem wave begins should be:

- keep `DataSource` as the base byte model for media, files, and large cell/blob payloads
- introduce `TableSource` for row/column oriented forensic databases
- keep registry/event-log/compound-storage formats out of `TableSource` until a separate structured-store abstraction is justified
