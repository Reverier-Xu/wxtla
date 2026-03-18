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
| RAR | native implementation target + cache fallback | wxtla | Landed |

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
| NTFS | regressor via keramics + `libfsntfs` | wxtla | Highest forensic priority on Windows systems |
| FAT12 | regressor via keramics + `libfsfat` | wxtla | Common removable / legacy media |
| FAT16 | regressor via keramics + `libfsfat` | wxtla | Common removable / legacy media |
| FAT32 | regressor via keramics + `libfsfat` | wxtla | Common removable / legacy media |
| ext2 | regressor via keramics + `libfsext` | wxtla | Linux family reference implementation |
| ext3 | regressor via keramics + `libfsext` | wxtla | Linux family reference implementation |
| ext4 | regressor via keramics + `libfsext` | wxtla | Linux family reference implementation |
| APFS | libyal `libfsapfs` | wxtla | Modern macOS default filesystem |
| HFS | regressor via keramics + `libfshfs` | wxtla | Legacy Apple filesystem family |
| HFS+ | regressor via keramics + `libfshfs` | wxtla | Legacy Apple filesystem family |
| HFSX | regressor via keramics + `libfshfs` | wxtla | Legacy Apple filesystem family |
| XFS | native regressor + `libfsxfs` | wxtla | Common on Linux/server deployments |
| ReFS | libyal `libfsrefs` | wxtla | Lower-frequency but high-forensic-value Windows server filesystem |

## 5a. Table and database formats

Planned `TableSource` wave after initial filesystem coverage:

| Format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| ESE / EDB | libyal `libesedb` | wxtla | First `TableSource` target; high forensic value and common in Windows artifacts |
| Thumbcache DB | libyal `libwtcdb` | wxtla | Small, table-like Windows cache database |
| SuperFetch DB | libyal `libagdb` | wxtla | Windows application database / structured records |
| IE cache / index.dat | libyal `libmsiecf` | wxtla | Legacy but still useful browser cache database |
| Exchange MAPI DB | libyal `libmapidb` | wxtla | Complex but still table-shaped enough for later `TableSource` work |
| Notes NSF DB | libyal `libnsfdb` | wxtla | Enterprise mail/database format |
| PST / OFF projections | libyal `libpff` | wxtla | Expose mailbox/folder/message/attachment views through table projections |

Adjacent structured stores that should be planned separately from the first `TableSource` wave:

| Format | Current source | Planned owner | Notes |
| --- | --- | --- | --- |
| Windows Registry (REGF) | libyal `libregf` | wxtla | Better modeled as hierarchical key/value than as tables |
| EVT / EVTX | libyal `libevt`, `libevtx` | wxtla | Better modeled as append-only record streams |
| OLECF | libyal `libolecf` | wxtla | Compound storage graph, not table-first |

## 6. Priority view

Recommended implementation order:

1. MBR / GPT / APM
2. EWF / QCOW / VHD / VHDX / VMDK
3. UDIF / sparseimage / sparsebundle / PDI / split raw runtime image handling
4. TAR / ZIP / 7Z / RAR
5. NTFS / FAT / ext / APFS / HFS family / XFS / ReFS
6. `TableSource` database wave (`esedb`, `wtcdb`, `agdb`, `msiecf`, `mapidb`, `nsfdb`, `pff` projections)
7. LVM2 and deeper stacking/performance work

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

Current next filesystem target:

- `ntfs`

Planned first `TableSource` target after initial filesystem coverage:

- `esedb`
