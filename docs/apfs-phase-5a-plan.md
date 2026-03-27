# APFS Phase 5a Plan

## 0. Scope and compatibility bar

The APFS work must target complete read-only support for software-readable APFS containers and volumes. The implementation must not guess block sizes, magic values, record layouts, or name-hash behavior. Every constant and branch must come from authoritative on-disk sources: the Apple APFS reference, `libfsapfs` documentation, `dissect.apfs` schema/tests, and fixture-backed validation.

APFS cannot be treated as just another single-volume filesystem. A correct driver must cover container checkpoints, object maps, multiple volumes, snapshots, modern compression, software-encrypted volumes, sealed-volume extent trees, and volume-group semantics. The only acceptable degraded behavior is an explicit structured error for layouts that cannot be unlocked in public software, such as hardware-bound T2/SEP-protected keybags. The driver must detect those cases precisely and refuse to invent unsupported behavior.

## 1. Fit within the unified `wxtla` architecture

APFS should be the first real consumer of the unified source model described in `docs/unified-source-model.md`, not a format-specific exception.

Under that model:

- the current byte-level `DataSource` remains the byte primitive beneath APFS
- the opened APFS container becomes a generic opened `DataSource` with child views for volumes
- each opened APFS volume becomes a generic opened `DataSource` with a namespace facet
- snapshots become child views of an opened APFS volume rather than custom top-level methods
- system/data pairing and firmlink-aware traversal are modeled through generic view metadata plus namespace helpers, not APFS-only core traits

That same shape must be reusable later for Btrfs, ZFS, VMFS, and other snapshot-heavy filesystems.

The current `SourceHints` type is too small for APFS, but the answer should be a generic `OpenOptions` model rather than an APFS-only options type. The generic option carrier needs room for:

- view selectors such as index, name, UUID, role, transaction identifier, or other tags
- optional passwords, recovery keys, and pre-unwrapped keys
- an optional secondary physical-store source for Fusion layouts
- verification policy such as best-effort, strict metadata validation, or seal verification

APFS-specific parsing logic should still live under `src/filesystems/apfs/`, but its public shape should follow the shared model rather than inventing one-off surfaces.

## 2. Research basis and staged fixtures

The planning inputs for APFS are:

- `docs/development-plan.md`
- `docs/architecture.md`
- `docs/implementation-workflow.md`
- `/home/reverier/Code/C/libfsapfs/documentation/Apple File System (APFS).asciidoc`
- `https://raw.githubusercontent.com/fox-it/dissect.apfs/main/dissect/apfs/c_apfs.py`
- `https://raw.githubusercontent.com/fox-it/dissect.apfs/main/dissect/apfs/objects/fs.py`
- `https://raw.githubusercontent.com/fox-it/dissect.apfs/main/dissect/apfs/stream.py`
- `https://raw.githubusercontent.com/fox-it/dissect.apfs/main/tests/test_apfs.py`

The initial APFS fixture set now staged under `formats/apfs/` is:

- `formats/apfs/apfs.dmg`
  - Plaso sample DMG
  - exercises UDIF -> GPT -> APFS integration
  - single APFS volume named `SingleVolume`
- `formats/apfs/apfs_encrypted.dmg`
  - Plaso encrypted DMG
  - password `apfs-TEST`
- `formats/apfs/libfsapfs/*.1`
  - small binary structure fixtures for low-level unit tests
- `formats/apfs/dissect.apfs/case_insensitive.bin.gz`
- `formats/apfs/dissect.apfs/case_sensitive.bin.gz`
- `formats/apfs/dissect.apfs/jhfs_converted.bin.gz`
- `formats/apfs/dissect.apfs/encrypted.bin.gz`
- `formats/apfs/dissect.apfs/jhfs_encrypted.bin.gz`
- `formats/apfs/dissect.apfs/case_insensitive_beta.bin.gz`
- `formats/apfs/dissect.apfs/case_sensitive_beta.bin.gz`
- `formats/apfs/dissect.apfs/snapshot.bin.gz`
- `formats/apfs/dissect.apfs/corrupt.bin.gz`

Those gzip fixtures are especially valuable because the upstream `dissect.apfs` tests already define expected directory contents, hardlinks, symlinks, xattrs, resource forks, compression methods, snapshots, and corrupt-checkpoint fallback behavior.

## 3. What the finished APFS driver must cover

Before APFS can be called complete in `wxtla`, the implementation must cover at least these read-only compatibility branches:

- container checkpoints and latest-state selection
- object-map based OID resolution with transaction awareness
- multi-volume containers and explicit volume selection
- current/live filesystem trees
- case-sensitive, case-insensitive, and normalization-insensitive lookup
- inodes, directory records, xattrs, named forks, resource forks, symlinks, hardlinks, sparse files, special files, and FIFOs
- file data streams and xattr-backed data streams
- decmpfs compressed data in xattrs and resource forks
- compression methods 3, 4, 7, 8, 9, 10, 11, 12, and any fixture-backed later methods required by real containers
- software-encrypted APFS volumes, including password and recovery-key unlock paths
- snapshots: enumeration and opening a snapshot filesystem view
- sealed-volume file reads through the file extent tree (`FEXT_TREE`)
- volume groups and firmlink-aware system/data traversal
- precise rejection of T2/SEP-only hardware encryption without pretending to decrypt it
- Fusion containers once a real secondary-store fixture is available

Space-manager, reaper, checkpoint, extent-reference, integrity, and crypto-state objects also need parser coverage, even when they are not all required for every file read, because APFS correctness depends on validating real on-disk relationships rather than assuming the happy path.

## 4. End-to-end implementation process

### 4.1 Exact schema and checksum layer

Start by codifying the exact APFS object and record constants in one place. This layer should include:

- object headers, storage-type flags, object types, and object subtypes
- container and volume feature flags
- newer modern constants from `dissect.apfs`, such as `OBJECT_TYPE_FEXT_TREE`, `OBJECT_TYPE_INTEGRITY_META`, `OBJECT_TYPE_SNAP_META_EXT`, volume roles, firmlink flags, dataless flags, and sealed-volume flags
- Fletcher-64 object checksum verification
- APFS UUID decoding, nanosecond timestamp conversion, and little-endian helpers
- exact decmpfs method constants and extended-field constants

Nothing else should proceed until the constants are consolidated and cross-checked against both `libfsapfs` and `dissect.apfs`.

### 4.2 Container discovery and checkpoint state selection

The container open flow must:

1. read the primary `NXSB`
2. validate block size from the actual superblock instead of guessing it
3. scan the checkpoint descriptor area and checkpoint data area
4. handle descriptor/data areas stored directly or through the APFS checkpoint B-tree form
5. collect candidate container superblocks and checkpoint maps
6. choose the newest internally consistent checkpoint state rather than trusting block 0 blindly

This is mandatory. APFS is checkpointed, and the driver will be wrong on real media if it only trusts the first superblock.

### 4.3 Container object resolution

Once the current checkpoint state is known, implement the container object-resolution layer:

- checkpoint map parsing
- ephemeral-object lookup where required
- container object-map object parsing
- object-map B-tree parsing
- xid-aware OID -> physical-address resolution
- support for `OMAP_VAL_*` flags such as deleted, encrypted, and no-header objects

The implementation must keep object identifiers, filesystem object identifiers, and physical block numbers distinct at all times.

### 4.4 Volume enumeration and selectors

Next, open all volumes listed in `nx_fs_oid`:

- resolve each volume superblock through the container object map
- parse volume name, UUID, role, volume-group identifier, incompatible features, encryption state, and modern object pointers such as `apfs_integrity_meta_oid` and `apfs_fext_tree_oid`
- expose explicit selectors by index, UUID, name, and role

Do not silently select the first volume in a multi-volume container. That would be a demo behavior, not a compatible implementation.

### 4.5 Generic APFS B-tree engine

APFS depends on several different B-tree families. Implement one APFS-local B-tree engine with:

- node header/footer parsing
- fixed-size and variable-size entry decoding
- leaf and branch walking
- comparator-driven search helpers for:
  - object-map keys
  - filesystem object keys
  - file extents
  - hashed directory keys
  - snapshot metadata keys
  - sealed-volume file extent tree keys
- bounded node caches and immutable parsed-node reuse

This engine should be APFS-local, not a new generic `wxtla` abstraction.

### 4.6 Volume object map and live filesystem tree

Each volume then needs its own object map and live filesystem tree resolution:

- parse the volume object map
- resolve the root tree object
- resolve snapshot metadata tree when present
- resolve file extent tree for sealed volumes when present
- respect snapshot-superblock selection when a snapshot view is requested

At this stage the implementation should be able to identify the current root directory inode and walk the live filesystem tree safely.

### 4.7 Filesystem record decoding

The filesystem record layer must cover at least:

- inode records and inode extended fields
- directory records in both plain-name and hashed-name forms
- xattr records and xattr-backed data streams
- file extent records
- data-stream-id records
- sibling link and sibling map records for hardlinks
- directory-stats records
- snapshot metadata and snapshot-name records
- crypto-state records
- file-info hash records for sealed-volume metadata

Unknown extended fields must be preserved and ignored safely unless they are required for the current read path. The parser must not reject real images only because a newer harmless xfield exists.

### 4.8 Exact namespace behavior

APFS name lookup is not plain byte comparison. Implement the exact lookup behavior for:

- case-sensitive volumes
- case-insensitive volumes
- normalization-insensitive volumes
- hashed directory lookups plus collision verification
- Unicode NFD-based name hashing semantics

Hardlink handling must preserve sibling identities, multiple names, and multiple paths to the same inode. Symlink targets must come from `com.apple.fs.symlink`. Resource forks and named forks must be exposed deliberately rather than hidden behind ad hoc special cases.

### 4.9 Data-stream reading

The data path must support:

- normal file extents
- sparse extents (`phys_block_num == 0`)
- xattr-backed streams
- resource forks
- named forks
- special/device/FIFO/whiteout classification without trying to open them as regular files

The data reader should be a `DataSource` implementation over immutable extent maps, matching the existing `wxtla` concurrency model.

### 4.10 Compression and decmpfs

Modern APFS compatibility requires a real decmpfs implementation. The driver must support both inline-xattr and resource-fork-backed forms for:

- method 3: zlib in xattr
- method 4: zlib in resource fork
- method 7: LZVN in xattr
- method 8: LZVN in resource fork
- method 9: plain data in xattr
- method 10: plain data in resource fork
- method 11: LZFSE in xattr
- method 12: LZFSE in resource fork
- any fixture-backed later methods such as LZBITMAP if encountered in real containers

Where the existing crate set already supports a codec, reuse it. Where it does not, add an APFS-local implementation or a deliberate mature dependency; do not guess compressed block layouts.

### 4.11 Software encryption

APFS encryption support must include:

- container key bag parsing
- volume key bag parsing
- packed key/value parsing for KEKs and wrapped keys
- password hints
- password-based unlock
- recovery-key unlock
- pre-unwrapped or externally supplied volume-key injection for tests and advanced callers
- AES-XTS decryption of metadata and content blocks
- support for both one-key and multi-key software-encrypted layouts
- exact detection of hardware-bound/T2-protected layouts

This should reuse existing cryptographic building blocks already present in `wxtla` where possible, but APFS-specific key-bag parsing must stay in-house.

### 4.12 Snapshots and sealed volumes

Snapshots are not optional if the driver is supposed to be compatible with modern APFS. Implement:

- snapshot metadata-tree parsing
- enumeration by name and transaction identifier
- opening a snapshot as a separate `ApfsFileSystem` view
- exact checkpoint/omap selection for that snapshot view

For sealed volumes, implement:

- `FEXT_TREE` parsing and lookup
- sealed-volume read path selection
- integrity-metadata object parsing
- file-info hash record parsing
- optional seal-verification routine for explicit integrity checks

At minimum the driver must read sealed volumes correctly. Seal verification can be a separate explicit validation path, but the metadata needed for that validation must still be parsed.

### 4.13 Volume groups, firmlinks, and dataless objects

Modern macOS APFS commonly pairs system and data volumes. The driver therefore needs:

- volume-group identifier handling
- role-aware pairing (`System`, `Data`, `Preboot`, `Recovery`, and others)
- firmlink xattr parsing (`com.apple.fs.firmlink`)
- an APFS-local combined namespace helper for system/data traversal without introducing a global VFS layer
- dataless-object detection and explicit metadata-only or unavailable-content behavior

The parser must not silently flatten or ignore firmlinks; that would produce incorrect macOS namespace views.

### 4.14 Fusion and secondary stores

Fusion support should be planned explicitly rather than guessed later. That work needs:

- secondary physical-store discovery via APFS-specific open options or resolver callbacks
- fusion middle tree parsing
- write-back-cache metadata parsing
- tier-aware extent resolution across main and tier2 stores

Current public references are incomplete here, so this branch must wait for real fixtures and deliberate design work. It still belongs to the complete APFS roadmap and cannot be forgotten.

### 4.15 Metadata completeness beyond the read path

Even when they are not always on the hot path, the driver should eventually parse and expose:

- space manager / CAB / CIB structures
- reaper structures
- extent-reference tree
- encryption-rolling state objects
- snapshot metadata extension objects
- integrity metadata and document-ID side trees when present

These structures provide correctness checks, future compatibility hooks, and forensic inspection value.

## 5. Incremental development plan

Each numbered item below should be one coherent implementation step with its own tests and commit.

1. Unified source-model landing and fixture harness
   - land the generic `Driver` / opened `DataSource` / namespace-facet design before APFS-specific APIs
   - stage APFS fixtures under `formats/apfs/`
   - add APFS test helpers for gzip fixtures and DMG -> UDIF -> GPT -> APFS integration
   - exit criteria: fixture sources documented and APFS can target the shared multi-view model instead of an APFS-only surface

2. Object header, checksum, and schema constants
   - implement exact constants and helpers
   - add unit tests around `libfsapfs` structure blobs
   - exit criteria: container/volume headers and checksum helpers are stable

3. Container superblock, checkpoint map, and latest-checkpoint selection
   - implement container open flow
   - test with `libfsapfs/container_superblock.1`, `checkpoint_map.1`, `checkpoint_map_entry.1`, and `dissect.apfs/corrupt.bin.gz`
   - exit criteria: newest valid container state is chosen even with corrupted later checkpoints

4. Object map and volume enumeration
   - implement container omap and volume listing
   - add tests for volume name/UUID/role selection from `case_*`, `jhfs_*`, and the Plaso DMGs
   - exit criteria: all staged non-encrypted fixtures enumerate the expected volume set without opening files yet

5. Generic APFS B-tree engine
   - implement reusable node parsing and comparators
   - add unit coverage with `libfsapfs/btree_*.1` and object-map B-tree fixtures
   - exit criteria: cursor search can resolve omap and filesystem record branches safely

6. Filesystem records, namespace traversal, symlinks, hardlinks, xattrs, and forks
   - implement inode/xfield parsing, directory records, sibling records, xattrs, resource forks, and named forks
   - use `case_insensitive.bin.gz`, `case_sensitive.bin.gz`, and `jhfs_converted.bin.gz`
   - exit criteria: the upstream `dissect.apfs` directory-content expectations are reproducible in `wxtla`

7. File extents, sparse reads, and special-file classification
   - implement file data streams and sparse extents
   - add tests for empty files, regular files, hardlinks, FIFOs, devices, and resource-fork-backed content
   - exit criteria: all staged non-compressed, non-encrypted file reads succeed

8. Compression completeness
   - implement decmpfs xattr/resource-fork readers and all fixture-backed codecs
   - use the `dissect.apfs` fixtures to validate zlib, LZVN, and LZFSE branches
   - exit criteria: upstream compressed-file hashes and plaintext outputs match exactly

9. Encryption completeness
   - implement keybag parsing and unlock APIs
   - test with `encrypted.bin.gz`, `jhfs_encrypted.bin.gz`, and `apfs_encrypted.dmg`
   - exit criteria: software-encrypted staged fixtures unlock and read correctly, while unsupported hardware-protected variants fail explicitly

10. Snapshot support
    - implement snapshot enumeration and snapshot filesystem views
    - use `snapshot.bin.gz`
    - exit criteria: snapshot content differs correctly from the live view and matches known snapshot names/content

11. Sealed-volume support
    - implement `FEXT_TREE` lookups and integrity-metadata parsing
    - do not mark this step complete until a sealed-volume fixture is staged
    - exit criteria: a real macOS sealed system volume can be traversed and read through the sealed extent tree

12. Volume groups, firmlinks, and dataless behavior
    - add role-aware volume-group handling and firmlink-aware namespace support
    - do not mark this step complete until a real system/data pair fixture is staged
    - exit criteria: modern macOS system/data pairs resolve firmlinked paths correctly without a global VFS layer

13. Fusion support and remaining metadata trees
    - add secondary-store handling, fusion middle tree integration, and remaining advanced metadata parsers
    - do not mark this step complete until a real Fusion fixture is staged
    - exit criteria: dual-store Fusion containers resolve file data across both stores correctly

## 6. Fixture gaps that still need to be collected

The staged fixtures are a strong start, but they do not yet cover every modern APFS branch. Before the later steps above are declared complete, collect real fixtures for:

- a multi-volume container with distinct volume roles
- a sealed system volume with a real `FEXT_TREE` and integrity metadata
- a system/data volume-group pair with firmlinks
- a dataless file or dataless snapshot case
- a Fusion container with a secondary store
- a multi-key encrypted container if the currently staged fixtures only cover one-key layouts
- a T2/SEP-backed encrypted container for positive detection and explicit rejection tests
- any missing decmpfs algorithms that appear in real-world images but are absent from the current fixture set

The APFS driver should not be called complete until those branches are either covered by fixtures and implemented, or deliberately proven impossible to support in public software.

## 7. Validation rules for every APFS step

Every APFS implementation step should follow the existing repository workflow:

- add or extend `formats/apfs/` fixture-backed tests first
- cross-check parsed metadata and file reads against `libfsapfs` and/or `dissect.apfs`
- run:
  - `cargo +nightly fmt --all`
  - `cargo +nightly fmt --all -- --check`
  - `cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-features`
- commit one coherent APFS step at a time

APFS is complex enough that skipping any of those guardrails will almost certainly turn into a partial parser. This plan assumes the opposite: correctness first, completeness second only after correctness, and no silent shortcuts anywhere in the stack.
