# Format Inventory

This inventory merges:

- `keramics-formats`
- native `regressor-storage` drivers
- `regressor` helper formats that matter for migration planning

## 1. Host adapters and non-format helpers

| Item | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| Local host filesystem access | native regressor | regressor | Adapter concern, not a WXTLA parser |
| Session / mount graph / VFS | native regressor | regressor | Explicitly out of WXTLA scope |
| Boot sector helper logic | native regressor helper | undecided helper | Detection/probing aid, not a standalone mounted format |
| Cache/temp extraction policy | native regressor | regressor | Product-level policy, not parser ownership |

## 2. Archive formats

| Format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| TAR | native regressor | wxtla | Use `tar = "0.4"` |
| TAR.GZ | native regressor | wxtla | Use `tar` + `flate2 = "1.1"` |
| TAR.BZ2 | native regressor | wxtla | Use `tar` + `bzip2 = "0.6"` |
| TAR.XZ | native regressor | wxtla | Use `tar` + `xz2 = "0.1"` |
| TAR.ZST | native regressor | wxtla | Use `tar` + `zstd = "0.13"` |
| ZIP | native regressor | wxtla | Use `zip = "8.2"` |

These are the only formats allowed to delegate parsing to mature crates directly.

## 3. Image and container formats

| Format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| EWF / E01 / S01 | regressor via keramics | wxtla | In-house parser required |
| QCOW (v1/v2/v3) | regressor via keramics | wxtla | In-house parser required |
| VHD | regressor via keramics | wxtla | In-house parser required |
| VHDX | regressor via keramics | wxtla | In-house parser required |
| VMDK | regressor via keramics | wxtla | In-house parser required |
| UDIF / DMG | regressor via keramics | wxtla | In-house parser required |
| SparseImage | regressor via keramics | wxtla | In-house parser required |
| SparseBundle | regressor via keramics | wxtla | In-house parser required |
| Split Raw | regressor via keramics | wxtla | In-house parser required |
| PDI | regressor via keramics | wxtla | In-house parser required |

Current image phase status:

- complete

## 3a. Archive formats

| Format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| AD1 / ADF | AccessData + `pyad1` spec | wxtla | Logical evidence container; archive semantics |
| TAR | native implementation target | wxtla | Landed |
| ZIP | native implementation target + cache fallback for encrypted access | wxtla | Landed |
| 7z | native implementation target + cache fallback | wxtla | Landed |
| RAR | native implementation target + cache fallback | wxtla | Next archive target |

Supporting data formats used by the image/container family:

| Supporting format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| XML descriptors | keramics internal | wxtla + `quick-xml` | Infrastructure only |
| Apple plist | keramics internal | wxtla + `plist` | Infrastructure only |

## 4. Partition, volume, and logical mapping formats

| Format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| MBR | regressor via keramics | wxtla | In-house parser required |
| GPT | regressor via keramics | wxtla | In-house parser required |
| APM | regressor via keramics | wxtla | In-house parser required |
| BitLocker | libyal `libbde` + synthetic coverage | wxtla | In-house parser required |
| LVM2 | native regressor + libyal `libvslvm` test blobs | wxtla | In-house parser required |

## 5. Filesystem formats

| Format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| FAT12 | regressor via keramics | wxtla | In-house parser required |
| FAT16 | regressor via keramics | wxtla | In-house parser required |
| FAT32 | regressor via keramics | wxtla | In-house parser required |
| NTFS | regressor via keramics | wxtla | In-house parser required |
| HFS | regressor via keramics | wxtla | In-house parser required |
| HFS+ | regressor via keramics | wxtla | In-house parser required |
| HFSX | regressor via keramics | wxtla | In-house parser required |
| ext2 | regressor via keramics | wxtla | In-house parser required |
| ext3 | regressor via keramics | wxtla | In-house parser required |
| ext4 | regressor via keramics | wxtla | In-house parser required |
| XFS | native regressor | wxtla | Native code exists already, but WXTLA should own it eventually |

## 6. Priority view

Recommended implementation order:

1. MBR / GPT / APM
2. EWF / QCOW / VHD / VHDX / VMDK
3. UDIF / sparseimage / sparsebundle / PDI / split raw runtime image handling
4. TAR / ZIP / 7Z / RAR
5. FAT / NTFS / ext / XFS / HFS family
6. LVM2 and deeper stacking/performance work

This order prioritizes:

- early removal of easy dependencies
- reuse of the offset-mapping core
- early availability of common forensic/storage workflows
- staged performance work on increasingly complex layering cases

Implementation note:

- each listed format should be completed end-to-end before the next format starts
- research should begin with `keramics` and `regressor`, then be checked against mature external implementations for missing cases
- parser logic should reuse `wxtla` core infrastructure where possible, but must not reuse `keramics` crates

## 7. Current status snapshot

Already landed in `wxtla`:

- `mbr`
- `gpt`
- `apm`
- `ewf`
- `qcow`
- `vhd`
- `vhdx`
- `vmdk`
- `udif`
- `sparseimage`
- `sparsebundle`
- `pdi`
- `splitraw`

Current next archive target:

- `tar`
