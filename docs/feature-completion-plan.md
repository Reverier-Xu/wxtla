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
- LVM2 striped segments now map logical reads across multiple stripe legs in `src/volumes/lvm/model.rs`
- VMDK descriptor parsing now tolerates `NOACCESS ZERO` extents as synthetic zero regions in `src/images/vmdk/image.rs`
- LVM2 now selects the highest-seqno committed metadata copy across redundant metadata areas in `src/volumes/lvm/parser.rs`
- GPT now accepts larger header sizes and infers `1024`/`2048` logical block sizes in `src/volumes/gpt/header.rs` and `src/volumes/gpt/constants.rs`
- BitLocker fixed-volume headers now fall back to Vista-style metadata LCN discovery in `src/volumes/bitlocker/header.rs`
- LVM2 metadata parsing now tolerates negative numbers in ignored fields in `src/volumes/lvm/metadata_text.rs`
- MBR parsing now follows logical partitions from multiple primary extended containers in `src/volumes/mbr/parser.rs`
- XFS special/device inodes now classify as `Special` instead of tripping unsupported fork-type reads in `src/filesystems/xfs/filesystem.rs`
- EWF segment resolution now understands alpha-suffixed later segments such as `EAA` when the file header provides the segment number in `src/images/ewf/parser.rs`
- EWF volume/data sections now accept larger payloads by parsing the classic prefix and ignoring trailing bytes in `src/images/ewf/volume.rs`
- EWF digest sections now accept larger payloads by parsing the classic prefix and ignoring trailing bytes in `src/images/ewf/hash.rs`
- BitLocker unlocked reads now fall back to the metadata block header sector count when the volume-header metadata entry is absent in `src/volumes/bitlocker/system.rs`
- VMDK raw-device-map extent aliases now parse through the existing flat extent path in `src/images/vmdk/descriptor.rs`
- BitLocker VMK and FVEK decryptors now tolerate larger or newer key payload headers as long as the stable key offsets remain valid in `src/volumes/bitlocker/system.rs`
- UDIF now accepts newer trailer and blkx table version/size fields as long as the known fixed-layout prefix remains valid in `src/images/udif/trailer.rs` and `src/images/udif/block_map.rs`
- LVM2 metadata parsing now selects the real VG object even when extra root-level objects are present in `src/volumes/lvm/metadata_text.rs`

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
| Volume | BitLocker | Metadata and payload parsing are still constrained to the currently known protector and payload layouts despite Vista, volume-header, and relaxed key-header fallback support | `src/volumes/bitlocker/metadata.rs`, `src/volumes/bitlocker/system.rs` | Some BitLocker volumes may still fail to unlock or decrypt | Add variant coverage incrementally, starting with metadata-copy selection and payload compatibility before new key material types |
| Image | VMDK | Some descriptor extent types/access modes are still rejected, and sparse compression methods above `1` are rejected | `src/images/vmdk/image.rs`, `src/images/vmdk/header.rs` | Some VMware images remain unreadable | Continue expanding descriptor aliases first, then add extra sparse-compression support if fixtures justify it |
| Image | UDIF / DMG | Unsupported `blkx` block types still remain after version-gate relaxation | `src/images/udif/block_map.rs` | Less-common DMG layouts can still fail despite valid outer signatures | Add block-type coverage one family at a time with small fixture slices |

### Low priority

These items look real but uncommon, or they are mostly strictness/compatibility work after the broader parser wave is stable.

| Area | Format | Missing feature | Evidence | Impact | Planned work |
| --- | --- | --- | --- | --- | --- |
| Filesystem | XFS | Rare metadata-only fork formats still remain rejected after special/device inode support | `src/filesystems/xfs/filesystem.rs` | Some uncommon XFS metadata inodes could still fail if surfaced as regular content | Add fixture-backed handling only if real-world images require `UUID` or metadata-btree inode formats |
| Volume | LVM2 | Metadata parser still has a simplified object grammar even though ignored negative values and extra root objects are now tolerated | `src/volumes/lvm/metadata_text.rs` | Some valid text metadata variants can still fail | Relax the remaining root/object grammar once broader LVM fixtures are available |
| Volume | GPT | Support is still strict to revision `1.0` despite broader header-size and block-size tolerance | `src/volumes/gpt/header.rs`, `src/volumes/gpt/constants.rs` | Some nonstandard GPT variants are still rejected | Expand revision compatibility only with real fixtures; do not loosen validation blindly |
| Image | EWF | Only known hash payload sizes are still covered after alpha-segment naming and relaxed volume/data/digest prefix parsing | `src/images/ewf/parser.rs`, `src/images/ewf/hash.rs` | Some lesser EWF variants can still fail to open | Extend hash parsing only when real fixtures show additional section layouts |

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
