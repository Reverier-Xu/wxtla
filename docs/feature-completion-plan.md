# Feature Completion Plan

This document tracks parser features that are still explicitly unsupported, narrowly rejected, or version-gated in the current `wxtla` codebase for filesystems, partition/volume layers, and image formats.

Scope rules for this plan:

- only `src/filesystems`, `src/volumes`, and `src/images`
- focus on explicit unsupported/rejected paths and strict layout guards already documented in code
- exclude archive formats and long-term format ideas that do not already have shipped parser code

Implementation rule for every item below:

1. obtain or synthesize a regression fixture for the missing layout
2. add parser support or a more precise degraded-mode behavior
3. add unit and integration coverage
4. update the relevant format docs after the parser lands

## Priority bands

Completed since the initial scan:

- NTFS `$MFT` attribute-list bootstrap support landed in `src/filesystems/ntfs/filesystem.rs`
- VHDX BAT-state compatibility now accepts the legacy v0.95 unmapped payload alias and rejects dynamic images that incorrectly allocate sector bitmap blocks in `src/images/vhdx/parser.rs`
- VHDX active log replay now runs through a read-only in-memory overlay in `src/images/vhdx/log_replay.rs`
- QCOW dirty images now open in read-only mode instead of being rejected up front in `src/images/qcow/parser.rs`
- QCOW extended L2 entries now read through the subcluster-aware data path in `src/images/qcow/image.rs`
- ReFS fragmented data streams now merge attribute runs instead of failing in `src/filesystems/refs/filesystem.rs`
- ReFS parsers now accept core format-version 3 metadata fixtures, including multi-block references and v3 checkpoint trailers, in `src/filesystems/refs/parser.rs`
- ext xattrs can now resolve external inode-backed values in `src/filesystems/ext/filesystem.rs` and `src/filesystems/ext/xattr.rs`
- HFS+ xattrs now merge extent-overflow records with fork-backed attribute data in `src/filesystems/hfs/filesystem.rs`
- QCOW corrupt-flag images now open in best-effort read-only mode instead of being rejected up front in `src/images/qcow/parser.rs`

### High priority

These items block common real-world images or prevent entire formats from opening when a known feature bit is present.

| Area | Format | Missing feature | Evidence | Impact | Planned work |
| --- | --- | --- | --- | --- | --- |
| Image | QCOW | Encrypted images are still rejected | `src/images/qcow/parser.rs` | Encrypted qcow2 images still cannot be opened at all | Add key-material / passphrase plumbing and then implement the qcow encryption variants deliberately instead of guessing at decryption semantics |

### Medium priority

These items reduce coverage on real-world data, but usually after the top-level format has already been recognized correctly.

| Area | Format | Missing feature | Evidence | Impact | Planned work |
| --- | --- | --- | --- | --- | --- |
| Filesystem | NTFS | Fragmented resident `$DATA` attributes and mixed resident/non-resident stream chains are rejected | `src/filesystems/ntfs/filesystem.rs` | Edge-case files and ADS streams cannot be sized or opened | Normalize mixed stream fragments into a single logical stream model; add synthetic record fixtures |
| Filesystem | NTFS | Encrypted NTFS `$DATA` (EFS) is unsupported | `src/filesystems/ntfs/record.rs` | Encrypted file contents remain unreadable even when the volume mounts | Decide whether to expose metadata-only fallback first or full decrypt support with external key material later |
| Filesystem | ext2/ext3/ext4 | External xattr blocks are still assumed to have a single backing block | `src/filesystems/ext/xattr.rs` | Some larger or less common ext metadata layouts can still be rejected | Extend external xattr loading across multi-block layouts once fixture coverage exists |
| Filesystem | ReFS | Full ReFS v3 filesystem layouts are still only partially covered despite the new core metadata parser support | `src/filesystems/refs/parser.rs`, `src/filesystems/refs/filesystem.rs` | Some newer ReFS volumes can still fail once object or allocator layouts diverge from the covered fixtures | Extend real-volume coverage for v3 object trees, allocator/container metadata, and any remaining multi-block layouts |
| Volume | BitLocker | Metadata and payload parsing are constrained to currently known versions and encodings | `src/volumes/bitlocker/metadata.rs`, `src/volumes/bitlocker/system.rs` | Some BitLocker volumes may fail to unlock | Add variant coverage incrementally, starting with metadata/header compatibility before new key payload types |
| Volume | LVM2 | Multi-stripe segments are unsupported | `src/volumes/lvm/model.rs` | Striped logical volumes cannot be mapped | Extend logical-to-physical mapping for striped segments and add synthetic PV/VG fixtures |
| Image | VMDK | Some descriptor extent types/access modes are rejected; sparse compression methods above `1` are rejected | `src/images/vmdk/image.rs`, `src/images/vmdk/header.rs` | Some VMware images remain unreadable | Expand descriptor coverage first, then add extra sparse-compression support if fixtures justify it |
| Image | UDIF / DMG | Unsupported `blkx` block types and strict trailer/block-table version gates remain | `src/images/udif/block_map.rs`, `src/images/udif/trailer.rs` | Less-common DMG layouts fail despite valid outer signatures | Add block-type coverage one family at a time with small fixture slices |

### Low priority

These items look real but uncommon, or they are mostly strictness/compatibility work after the broader parser wave is stable.

| Area | Format | Missing feature | Evidence | Impact | Planned work |
| --- | --- | --- | --- | --- | --- |
| Filesystem | XFS | Only known directory/data fork types are handled | `src/filesystems/xfs/filesystem.rs` | Some uncommon inode layouts are rejected | Add fork-type coverage after mainstream XFS fixture breadth improves |
| Volume | LVM2 | Only one metadata area and one raw metadata location are supported | `src/volumes/lvm/parser.rs` | More defensive or redundant PV layouts are rejected | Broaden metadata area discovery after stripe support lands |
| Volume | LVM2 | Metadata parser rejects negative numbers and non-simple root layouts | `src/volumes/lvm/metadata_text.rs` | Some valid text metadata variants can fail | Relax the text grammar once broader LVM fixtures are available |
| Volume | MBR | Multiple extended containers / multiple primary extended entries are unsupported | `src/volumes/mbr/parser.rs`, `src/volumes/mbr/validation.rs` | Odd or hybrid tables are rejected conservatively | Revisit after the common partition-table cases remain stable |
| Volume | GPT | Support is strict to revision `1.0`, 92-byte headers, and `512`/`4096` block sizes | `src/volumes/gpt/constants.rs`, `src/volumes/gpt/header.rs` | Nonstandard GPT variants are rejected | Expand compatibility only with real fixtures; do not loosen validation blindly |
| Image | EWF | Only known hash/volume/data payload sizes and common segment naming workflows are supported | `src/images/ewf/parser.rs`, `src/images/ewf/naming.rs` | Some lesser EWF variants fail to open | Add compatibility as sample coverage appears |

## Recommended execution order

1. QCOW feature-flag compatibility (`extended L2`, dirty/corrupt handling)
2. ReFS fragmented streams and version/layout widening
3. ext and HFS metadata completeness (`xattr`/overflow work)
4. BitLocker metadata compatibility expansion
5. LVM striped and redundant metadata layouts
6. VMDK / UDIF compatibility sweep
7. Low-priority strictness reductions in XFS, GPT, MBR, and EWF

## Formats with no explicit unsupported markers in the current scan

The current code scan did not find explicit unsupported-feature markers in these shipped parser families:

- FAT12 / FAT16 / FAT32
- APM
- VHD
- PDI
- Split Raw
- SparseImage
- SparseBundle

This does not mean they are complete forever. It only means the current source tree does not advertise obvious unsupported paths in those parsers today.
