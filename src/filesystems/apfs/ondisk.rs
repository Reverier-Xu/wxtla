//! Low-level APFS on-disk parsing helpers.

use crate::{Error, Result};

pub(crate) const MIN_BLOCK_SIZE: u32 = 4096;
pub(crate) const MAX_BLOCK_SIZE: u32 = 65_536;
pub(crate) const DEFAULT_BLOCK_SIZE: usize = MIN_BLOCK_SIZE as usize;

pub(crate) const NX_MAGIC: &[u8; 4] = b"NXSB";
pub(crate) const APFS_MAGIC: &[u8; 4] = b"APSB";

pub(crate) const OBJECT_TYPE_MASK: u32 = 0x0000_FFFF;
pub(crate) const OBJ_STORAGETYPE_MASK: u32 = 0xC000_0000;

pub(crate) const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x0000_0001;
pub(crate) const OBJECT_TYPE_BTREE: u32 = 0x0000_0002;
pub(crate) const OBJECT_TYPE_BTREE_NODE: u32 = 0x0000_0003;
pub(crate) const OBJECT_TYPE_OMAP: u32 = 0x0000_000B;
pub(crate) const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0000_000C;
pub(crate) const OBJECT_TYPE_FS: u32 = 0x0000_000D;
pub(crate) const OBJECT_TYPE_FSTREE: u32 = 0x0000_000E;
pub(crate) const OBJECT_TYPE_BLOCKREFTREE: u32 = 0x0000_000F;
pub(crate) const OBJECT_TYPE_SNAP_META_TREE: u32 = 0x0000_0010;
pub(crate) const OBJECT_TYPE_NX_REAPER: u32 = 0x0000_0011;
pub(crate) const OBJECT_TYPE_OMAP_SNAPSHOT: u32 = 0x0000_0013;
pub(crate) const OBJECT_TYPE_EFI_JUMPSTART: u32 = 0x0000_0014;
pub(crate) const OBJECT_TYPE_FUSION_MIDDLE_TREE: u32 = 0x0000_0015;
pub(crate) const OBJECT_TYPE_NX_FUSION_WBC: u32 = 0x0000_0016;
pub(crate) const OBJECT_TYPE_NX_FUSION_WBC_LIST: u32 = 0x0000_0017;
pub(crate) const OBJECT_TYPE_ER_STATE: u32 = 0x0000_0018;
pub(crate) const OBJECT_TYPE_GBITMAP: u32 = 0x0000_0019;
pub(crate) const OBJECT_TYPE_GBITMAP_TREE: u32 = 0x0000_001A;
pub(crate) const OBJECT_TYPE_GBITMAP_BLOCK: u32 = 0x0000_001B;
pub(crate) const OBJECT_TYPE_ER_RECOVERY_BLOCK: u32 = 0x0000_001C;
pub(crate) const OBJECT_TYPE_SNAP_META_EXT: u32 = 0x0000_001D;
pub(crate) const OBJECT_TYPE_INTEGRITY_META: u32 = 0x0000_001E;
pub(crate) const OBJECT_TYPE_FEXT_TREE: u32 = 0x0000_001F;
pub(crate) const OBJECT_TYPE_RESERVED_20: u32 = 0x0000_0020;
pub(crate) const OBJECT_TYPE_TEST: u32 = 0x0000_00FF;
pub(crate) const APFS_OBJECT_TYPE_CONTAINER_KEYBAG: u32 = 0x6B65_7973;
pub(crate) const APFS_OBJECT_TYPE_VOLUME_KEYBAG: u32 = 0x7265_6373;
pub(crate) const APFS_OBJECT_TYPE_MEDIA_KEYBAG: u32 = 0x6D6B_6579;

pub(crate) const OBJ_VIRTUAL: u32 = 0x0000_0000;
pub(crate) const OBJ_PHYSICAL: u32 = 0x4000_0000;
pub(crate) const OBJ_EPHEMERAL: u32 = 0x8000_0000;
pub(crate) const OBJ_NOHEADER: u32 = 0x2000_0000;
pub(crate) const OBJ_ENCRYPTED: u32 = 0x1000_0000;
pub(crate) const OBJ_NONPERSISTENT: u32 = 0x0800_0000;

pub(crate) const BTREE_PHYSICAL: u32 = 0x0000_0010;
pub(crate) const BTREE_HASHED: u32 = 0x0000_0080;
pub(crate) const BTREE_NOHEADER: u32 = 0x0000_0100;

#[cfg(test)]
pub(crate) const BTNODE_ROOT: u16 = 0x0001;
pub(crate) const BTNODE_LEAF: u16 = 0x0002;
pub(crate) const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;
pub(crate) const BTNODE_HASHED: u16 = 0x0008;
pub(crate) const BTNODE_NOHEADER: u16 = 0x0010;

pub(crate) const CHECKPOINT_AREA_BTREE_FLAG: u32 = 0x8000_0000;

pub(crate) const OMAP_VAL_DELETED: u32 = 0x0000_0001;
pub(crate) const CHECKPOINT_MAP_LAST: u32 = 0x0000_0001;
pub(crate) const OMAP_MANUALLY_MANAGED: u32 = 0x0000_0001;
pub(crate) const OMAP_ENCRYPTING: u32 = 0x0000_0002;
pub(crate) const OMAP_DECRYPTING: u32 = 0x0000_0004;
pub(crate) const OMAP_KEYROLLING: u32 = 0x0000_0008;
pub(crate) const OMAP_CRYPTO_GENERATION: u32 = 0x0000_0010;

pub(crate) const NX_FEATURE_DEFRAG: u64 = 0x0000_0001;
pub(crate) const NX_FEATURE_LCFD: u64 = 0x0000_0002;
pub(crate) const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x0000_0001;
pub(crate) const APFS_INCOMPAT_DATALESS_SNAPS: u64 = 0x0000_0002;
pub(crate) const APFS_INCOMPAT_ENC_ROLLED: u64 = 0x0000_0004;
pub(crate) const APFS_INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x0000_0008;
pub(crate) const APFS_INCOMPAT_INCOMPLETE_RESTORE: u64 = 0x0000_0010;
pub(crate) const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x0000_0020;
pub(crate) const APFS_INCOMPAT_PFK_VOL: u64 = 0x0000_0040;
pub(crate) const APFS_INCOMPAT_RESERVED_80: u64 = 0x0000_0080;
pub(crate) const APFS_INCOMPAT_SECONDARY_FSROOT: u64 = 0x0000_0100;

pub(crate) const APFS_FEATURE_DEFRAG_PRERELEASE: u64 = 0x0000_0001;
pub(crate) const APFS_FEATURE_HARDLINK_MAP_RECORDS: u64 = 0x0000_0002;
pub(crate) const APFS_FEATURE_DEFRAG: u64 = 0x0000_0004;
pub(crate) const APFS_FEATURE_STRICTATIME: u64 = 0x0000_0008;
pub(crate) const APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE: u64 = 0x0000_0010;
pub(crate) const NX_INCOMPAT_FUSION: u64 = 0x0000_0100;
pub(crate) const NX_CRYPTO_SW: u64 = 0x0000_0004;

pub(crate) const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;
pub(crate) const APFS_FS_ONEKEY: u64 = 0x0000_0008;
pub(crate) const APFS_FS_SPILLEDOVER: u64 = 0x0000_0010;
pub(crate) const APFS_FS_RUN_SPILLOVER_CLEANER: u64 = 0x0000_0020;
pub(crate) const APFS_FS_ALWAYS_CHECK_EXTENTREF: u64 = 0x0000_0040;
pub(crate) const APFS_FS_PREVIOUSLY_SEALED: u64 = 0x0000_0080;
pub(crate) const APFS_FS_PFK: u64 = 0x0000_0100;

pub(crate) const APFS_VOL_ROLE_SYSTEM: u16 = 0x0001;
pub(crate) const APFS_VOL_ROLE_USER: u16 = 0x0002;
pub(crate) const APFS_VOL_ROLE_RECOVERY: u16 = 0x0004;
pub(crate) const APFS_VOL_ROLE_VM: u16 = 0x0008;
pub(crate) const APFS_VOL_ROLE_PREBOOT: u16 = 0x0010;
pub(crate) const APFS_VOL_ROLE_INSTALLER: u16 = 0x0020;
pub(crate) const APFS_VOLUME_ENUM_SHIFT: u16 = 6;
pub(crate) const APFS_VOL_ROLE_DATA: u16 = 1 << APFS_VOLUME_ENUM_SHIFT;
pub(crate) const APFS_VOL_ROLE_BASEBAND: u16 = 2 << APFS_VOLUME_ENUM_SHIFT;
pub(crate) const APFS_VOL_ROLE_UPDATE: u16 = 3 << APFS_VOLUME_ENUM_SHIFT;
pub(crate) const APFS_VOL_ROLE_XART: u16 = 4 << APFS_VOLUME_ENUM_SHIFT;
pub(crate) const APFS_VOL_ROLE_HARDWARE: u16 = 5 << APFS_VOLUME_ENUM_SHIFT;
pub(crate) const APFS_VOL_ROLE_BACKUP: u16 = 6 << APFS_VOLUME_ENUM_SHIFT;
pub(crate) const APFS_VOL_ROLE_ENTERPRISE: u16 = 9 << APFS_VOLUME_ENUM_SHIFT;
pub(crate) const APFS_VOL_ROLE_PRELOGIN: u16 = 11 << APFS_VOLUME_ENUM_SHIFT;

pub(crate) const OBJECT_HEADER_SIZE: usize = 32;
pub(crate) const BTREE_NODE_HEADER_SIZE: usize = 24;
pub(crate) const BTREE_INFO_SIZE: usize = 40;
pub(crate) const APFS_SEAL_BROKEN: u32 = 1;
pub(crate) const APFS_HASH_SHA256: u32 = 0x1;
pub(crate) const APFS_HASH_SHA512_256: u32 = 0x2;
pub(crate) const APFS_HASH_SHA384: u32 = 0x3;
pub(crate) const APFS_HASH_SHA512: u32 = 0x4;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsObjectHeader {
  pub checksum: u64,
  pub oid: u64,
  pub xid: u64,
  pub object_type: u32,
  pub subtype: u32,
}

impl ApfsObjectHeader {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    require_len(bytes, OBJECT_HEADER_SIZE, "apfs object header")?;
    Ok(Self {
      checksum: read_u64_le(bytes, 0)?,
      oid: read_u64_le(bytes, 8)?,
      xid: read_u64_le(bytes, 16)?,
      object_type: read_u32_le(bytes, 24)?,
      subtype: read_u32_le(bytes, 28)?,
    })
  }

  pub(crate) fn type_code(&self) -> u32 {
    self.object_type & OBJECT_TYPE_MASK
  }

  pub(crate) fn storage_type(&self) -> u32 {
    self.object_type & OBJ_STORAGETYPE_MASK
  }

  pub(crate) fn is_physical(&self) -> bool {
    self.storage_type() == OBJ_PHYSICAL
  }

  pub(crate) fn is_ephemeral(&self) -> bool {
    self.storage_type() == OBJ_EPHEMERAL
  }

  pub(crate) fn validate_checksum(&self, block: &[u8]) -> bool {
    self.checksum == fletcher64(&block[8..])
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsContainerSuperblock {
  pub header: ApfsObjectHeader,
  pub block_size: u32,
  pub block_count: u64,
  pub features: u64,
  pub readonly_compatible_features: u64,
  pub incompatible_features: u64,
  pub uuid: [u8; 16],
  pub next_oid: u64,
  pub next_xid: u64,
  pub checkpoint_descriptor_blocks: u32,
  pub checkpoint_data_blocks: u32,
  pub checkpoint_descriptor_base: u64,
  pub checkpoint_data_base: u64,
  pub checkpoint_descriptor_next: u32,
  pub checkpoint_data_next: u32,
  pub checkpoint_descriptor_index: u32,
  pub checkpoint_descriptor_len: u32,
  pub checkpoint_data_index: u32,
  pub checkpoint_data_len: u32,
  pub spaceman_oid: u64,
  pub omap_oid: u64,
  pub reaper_oid: u64,
  pub test_type: u32,
  pub counters: [u64; 32],
  pub blocked_out_prange: Option<ApfsPrange>,
  pub evict_mapping_tree_oid: u64,
  pub flags: u64,
  pub efi_jumpstart_oid: u64,
  pub fusion_uuid: [u8; 16],
  pub container_keybag_prange: Option<ApfsPrange>,
  pub ephemeral_info: [u64; 4],
  pub test_oid: u64,
  pub fusion_middle_tree_oid: u64,
  pub fusion_wbc_oid: u64,
  pub fusion_wbc_prange: Option<ApfsPrange>,
  pub newest_mounted_version: u64,
  pub media_keybag_prange: Option<ApfsPrange>,
  pub max_file_systems: u32,
  pub file_system_oids: Vec<u64>,
}

impl ApfsContainerSuperblock {
  pub(crate) fn parse(block: &[u8]) -> Result<Self> {
    require_len(block, 1408, "apfs container superblock")?;
    let header = ApfsObjectHeader::parse(block)?;
    let magic = read_array::<4>(block, 32)?;
    if &magic != NX_MAGIC {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs container superblock magic: {:?}",
        String::from_utf8_lossy(&magic)
      )));
    }

    let block_size = read_u32_le(block, 36)?;
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) || !block_size.is_power_of_two() {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs block size: {block_size}"
      )));
    }

    let max_file_systems = read_u32_le(block, 180)?;
    if max_file_systems > 100 {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs max file system count: {max_file_systems}"
      )));
    }

    let mut file_system_oids = Vec::new();
    for index in 0..100usize {
      let oid = read_u64_le(block, 184 + index * 8)?;
      if oid != 0 {
        file_system_oids.push(oid);
      }
    }

    Ok(Self {
      header,
      block_size,
      block_count: read_u64_le(block, 40)?,
      features: read_u64_le(block, 48)?,
      readonly_compatible_features: read_u64_le(block, 56)?,
      incompatible_features: read_u64_le(block, 64)?,
      uuid: read_array(block, 72)?,
      next_oid: read_u64_le(block, 88)?,
      next_xid: read_u64_le(block, 96)?,
      checkpoint_descriptor_blocks: read_u32_le(block, 104)?,
      checkpoint_data_blocks: read_u32_le(block, 108)?,
      checkpoint_descriptor_base: read_u64_le(block, 112)?,
      checkpoint_data_base: read_u64_le(block, 120)?,
      checkpoint_descriptor_next: read_u32_le(block, 128)?,
      checkpoint_data_next: read_u32_le(block, 132)?,
      checkpoint_descriptor_index: read_u32_le(block, 136)?,
      checkpoint_descriptor_len: read_u32_le(block, 140)?,
      checkpoint_data_index: read_u32_le(block, 144)?,
      checkpoint_data_len: read_u32_le(block, 148)?,
      spaceman_oid: read_u64_le(block, 152)?,
      omap_oid: read_u64_le(block, 160)?,
      reaper_oid: read_u64_le(block, 168)?,
      test_type: read_u32_le(block, 176)?,
      counters: read_u64_array::<32>(block, 984)?,
      blocked_out_prange: {
        let prange = ApfsPrange::parse(read_slice(block, 1240, 16, "apfs blocked out prange")?)?;
        (prange.start_paddr != 0 || prange.block_count != 0).then_some(prange)
      },
      evict_mapping_tree_oid: read_u64_le(block, 1256)?,
      flags: read_u64_le(block, 1264)?,
      efi_jumpstart_oid: read_u64_le(block, 1272)?,
      fusion_uuid: read_array(block, 1280)?,
      container_keybag_prange: {
        let prange =
          ApfsPrange::parse(read_slice(block, 1296, 16, "apfs container keybag prange")?)?;
        (prange.start_paddr != 0 && prange.block_count != 0).then_some(prange)
      },
      ephemeral_info: [
        read_u64_le(block, 1312)?,
        read_u64_le(block, 1320)?,
        read_u64_le(block, 1328)?,
        read_u64_le(block, 1336)?,
      ],
      test_oid: read_u64_le(block, 1344)?,
      fusion_middle_tree_oid: read_u64_le(block, 1352)?,
      fusion_wbc_oid: read_u64_le(block, 1360)?,
      fusion_wbc_prange: {
        let prange = ApfsPrange::parse(read_slice(block, 1368, 16, "apfs fusion wbc prange")?)?;
        (prange.start_paddr != 0 || prange.block_count != 0).then_some(prange)
      },
      newest_mounted_version: read_u64_le(block, 1384)?,
      media_keybag_prange: {
        let prange = ApfsPrange::parse(read_slice(block, 1392, 16, "apfs media keybag prange")?)?;
        (prange.start_paddr != 0 || prange.block_count != 0).then_some(prange)
      },
      max_file_systems,
      file_system_oids,
    })
  }

  pub(crate) fn validate(&self, block: &[u8], _address: u64) -> Result<()> {
    if self.header.type_code() != OBJECT_TYPE_NX_SUPERBLOCK {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs container object type: 0x{:08x}",
        self.header.object_type
      )));
    }
    if !self.header.is_ephemeral() {
      return Err(Error::InvalidFormat(
        "apfs container superblock must be ephemeral".to_string(),
      ));
    }
    if self.header.oid != 1 {
      return Err(Error::InvalidFormat(format!(
        "apfs container superblock oid {} must be 1",
        self.header.oid
      )));
    }
    if !self.header.validate_checksum(block) {
      return Err(Error::InvalidFormat(
        "invalid apfs container superblock checksum".to_string(),
      ));
    }
    Ok(())
  }

  pub(crate) fn compare_layout(&self, other: &Self) -> Result<()> {
    for (name, left, right) in [("uuid", self.uuid.as_slice(), other.uuid.as_slice())] {
      if left != right {
        return Err(Error::InvalidFormat(format!(
          "apfs container superblock {name} does not match"
        )));
      }
    }

    for (name, left, right) in [(
      "fusion_uuid",
      self.fusion_uuid.as_slice(),
      other.fusion_uuid.as_slice(),
    )] {
      if left != right {
        return Err(Error::InvalidFormat(format!(
          "apfs container superblock {name} does not match"
        )));
      }
    }

    for (name, left, right) in [
      (
        "block_size",
        u64::from(self.block_size),
        u64::from(other.block_size),
      ),
      ("block_count", self.block_count, other.block_count),
      (
        "checkpoint_descriptor_blocks",
        u64::from(self.checkpoint_descriptor_blocks),
        u64::from(other.checkpoint_descriptor_blocks),
      ),
      (
        "checkpoint_data_blocks",
        u64::from(self.checkpoint_data_blocks),
        u64::from(other.checkpoint_data_blocks),
      ),
      (
        "checkpoint_descriptor_base",
        self.checkpoint_descriptor_base,
        other.checkpoint_descriptor_base,
      ),
      (
        "checkpoint_data_base",
        self.checkpoint_data_base,
        other.checkpoint_data_base,
      ),
      (
        "evict_mapping_tree_oid",
        self.evict_mapping_tree_oid,
        other.evict_mapping_tree_oid,
      ),
      ("flags", self.flags, other.flags),
      (
        "efi_jumpstart_oid",
        self.efi_jumpstart_oid,
        other.efi_jumpstart_oid,
      ),
    ] {
      if left != right {
        return Err(Error::InvalidFormat(format!(
          "apfs container superblock {name} changed across checkpoints"
        )));
      }
    }

    Ok(())
  }

  pub(crate) fn descriptor_area_is_btree(&self) -> bool {
    (self.checkpoint_descriptor_blocks & CHECKPOINT_AREA_BTREE_FLAG) != 0
  }

  pub(crate) fn descriptor_area_block_count(&self) -> u32 {
    self.checkpoint_descriptor_blocks & !CHECKPOINT_AREA_BTREE_FLAG
  }

  pub(crate) fn is_fusion(&self) -> bool {
    (self.incompatible_features & NX_INCOMPAT_FUSION) != 0
  }

  pub(crate) fn uses_software_crypto(&self) -> bool {
    (self.flags & NX_CRYPTO_SW) != 0
  }
}

pub(crate) fn nx_feature_names(flags: u64) -> Vec<&'static str> {
  bit_names_u64(
    flags,
    &[(NX_FEATURE_DEFRAG, "defrag"), (NX_FEATURE_LCFD, "lcfd")],
  )
}

pub(crate) fn nx_incompat_feature_names(flags: u64) -> Vec<&'static str> {
  bit_names_u64(
    flags,
    &[
      (1, "version1"),
      (2, "version2"),
      (NX_INCOMPAT_FUSION, "fusion"),
    ],
  )
}

pub(crate) fn nx_flag_names(flags: u64) -> Vec<&'static str> {
  bit_names_u64(
    flags,
    &[
      (1, "reserved_1"),
      (2, "reserved_2"),
      (NX_CRYPTO_SW, "crypto_sw"),
    ],
  )
}

pub(crate) fn apfs_feature_names(flags: u64) -> Vec<&'static str> {
  bit_names_u64(
    flags,
    &[
      (APFS_FEATURE_DEFRAG_PRERELEASE, "defrag_prerelease"),
      (APFS_FEATURE_HARDLINK_MAP_RECORDS, "hardlink_map_records"),
      (APFS_FEATURE_DEFRAG, "defrag"),
      (APFS_FEATURE_STRICTATIME, "strictatime"),
      (
        APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE,
        "volgrp_system_ino_space",
      ),
    ],
  )
}

pub(crate) fn apfs_incompat_feature_names(flags: u64) -> Vec<&'static str> {
  bit_names_u64(
    flags,
    &[
      (APFS_INCOMPAT_CASE_INSENSITIVE, "case_insensitive"),
      (APFS_INCOMPAT_DATALESS_SNAPS, "dataless_snaps"),
      (APFS_INCOMPAT_ENC_ROLLED, "enc_rolled"),
      (
        APFS_INCOMPAT_NORMALIZATION_INSENSITIVE,
        "normalization_insensitive",
      ),
      (APFS_INCOMPAT_INCOMPLETE_RESTORE, "incomplete_restore"),
      (APFS_INCOMPAT_SEALED_VOLUME, "sealed_volume"),
      (APFS_INCOMPAT_PFK_VOL, "pfk"),
      (APFS_INCOMPAT_RESERVED_80, "reserved_80"),
      (APFS_INCOMPAT_SECONDARY_FSROOT, "secondary_fsroot"),
    ],
  )
}

pub(crate) fn apfs_fs_flag_names(flags: u64) -> Vec<&'static str> {
  bit_names_u64(
    flags,
    &[
      (APFS_FS_UNENCRYPTED, "unencrypted"),
      (APFS_FS_ONEKEY, "onekey"),
      (APFS_FS_SPILLEDOVER, "spilledover"),
      (APFS_FS_RUN_SPILLOVER_CLEANER, "run_spillover_cleaner"),
      (APFS_FS_ALWAYS_CHECK_EXTENTREF, "always_check_extentref"),
      (APFS_FS_PREVIOUSLY_SEALED, "previously_sealed"),
      (APFS_FS_PFK, "pfk"),
    ],
  )
}

pub(crate) fn apfs_omap_flag_names(flags: u32) -> Vec<&'static str> {
  bit_names_u32(
    flags,
    &[
      (OMAP_MANUALLY_MANAGED, "manually_managed"),
      (OMAP_ENCRYPTING, "encrypting"),
      (OMAP_DECRYPTING, "decrypting"),
      (OMAP_KEYROLLING, "keyrolling"),
      (OMAP_CRYPTO_GENERATION, "crypto_generation"),
    ],
  )
}

pub fn apfs_object_type_name(object_type: u32) -> &'static str {
  match object_type & OBJECT_TYPE_MASK {
    0 => "invalid",
    OBJECT_TYPE_NX_SUPERBLOCK => "nx_superblock",
    OBJECT_TYPE_BTREE => "btree",
    OBJECT_TYPE_BTREE_NODE => "btree_node",
    0x0000_0005 => "spaceman",
    0x0000_0006 => "spaceman_cab",
    0x0000_0007 => "spaceman_cib",
    0x0000_0008 => "spaceman_bitmap",
    0x0000_0009 => "spaceman_free_queue",
    0x0000_000A => "extent_list_tree",
    OBJECT_TYPE_OMAP => "omap",
    OBJECT_TYPE_CHECKPOINT_MAP => "checkpoint_map",
    OBJECT_TYPE_FS => "fs",
    OBJECT_TYPE_FSTREE => "fstree",
    OBJECT_TYPE_BLOCKREFTREE => "blockreftree",
    OBJECT_TYPE_SNAP_META_TREE => "snap_meta_tree",
    OBJECT_TYPE_NX_REAPER => "nx_reaper",
    0x0000_0012 => "nx_reap_list",
    OBJECT_TYPE_OMAP_SNAPSHOT => "omap_snapshot",
    OBJECT_TYPE_EFI_JUMPSTART => "efi_jumpstart",
    OBJECT_TYPE_FUSION_MIDDLE_TREE => "fusion_middle_tree",
    OBJECT_TYPE_NX_FUSION_WBC => "nx_fusion_wbc",
    OBJECT_TYPE_NX_FUSION_WBC_LIST => "nx_fusion_wbc_list",
    OBJECT_TYPE_ER_STATE => "er_state",
    OBJECT_TYPE_GBITMAP => "gbitmap",
    OBJECT_TYPE_GBITMAP_TREE => "gbitmap_tree",
    OBJECT_TYPE_GBITMAP_BLOCK => "gbitmap_block",
    OBJECT_TYPE_ER_RECOVERY_BLOCK => "er_recovery_block",
    OBJECT_TYPE_SNAP_META_EXT => "snap_meta_ext",
    OBJECT_TYPE_INTEGRITY_META => "integrity_meta",
    OBJECT_TYPE_FEXT_TREE => "fext_tree",
    OBJECT_TYPE_RESERVED_20 => "reserved_20",
    OBJECT_TYPE_TEST => "test",
    APFS_OBJECT_TYPE_CONTAINER_KEYBAG => "container_keybag",
    APFS_OBJECT_TYPE_VOLUME_KEYBAG => "volume_keybag",
    APFS_OBJECT_TYPE_MEDIA_KEYBAG => "media_keybag",
    _ => "unknown",
  }
}

pub fn apfs_object_storage_kind_name(object_type: u32) -> &'static str {
  match object_type & OBJ_STORAGETYPE_MASK {
    OBJ_VIRTUAL => "virtual",
    OBJ_PHYSICAL => "physical",
    OBJ_EPHEMERAL => "ephemeral",
    _ => "unknown",
  }
}

pub fn apfs_object_flag_names(object_type: u32) -> Vec<&'static str> {
  bit_names_u32(
    object_type,
    &[
      (OBJ_NONPERSISTENT, "nonpersistent"),
      (OBJ_ENCRYPTED, "encrypted"),
      (OBJ_NOHEADER, "noheader"),
    ],
  )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsObjectMap {
  pub header: ApfsObjectHeader,
  pub flags: u32,
  pub snapshot_count: u32,
  pub tree_type: u32,
  pub snapshot_tree_type: u32,
  pub tree_oid: u64,
  pub snapshot_tree_oid: u64,
  pub most_recent_snapshot_xid: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsCheckpointMapping {
  pub object_type: u32,
  pub object_subtype: u32,
  pub size: u32,
  pub file_system_object_id: u64,
  pub object_id: u64,
  pub physical_address: u64,
}

impl ApfsCheckpointMapping {
  pub fn parse(bytes: &[u8]) -> Result<Self> {
    require_len(bytes, 40, "apfs checkpoint map entry")?;
    Ok(Self {
      object_type: read_u32_le(bytes, 0)?,
      object_subtype: read_u32_le(bytes, 4)?,
      size: read_u32_le(bytes, 8)?,
      file_system_object_id: read_u64_le(bytes, 16)?,
      object_id: read_u64_le(bytes, 24)?,
      physical_address: read_u64_le(bytes, 32)?,
    })
  }

  pub fn object_type_name(&self) -> &'static str {
    apfs_object_type_name(self.object_type)
  }

  pub fn object_storage_kind_name(&self) -> &'static str {
    apfs_object_storage_kind_name(self.object_type)
  }

  pub fn object_flag_names(&self) -> Vec<&'static str> {
    apfs_object_flag_names(self.object_type)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsCheckpointMap {
  header: ApfsObjectHeader,
  pub flags: u32,
  pub entry_count: u32,
  pub entries: Vec<ApfsCheckpointMapping>,
}

impl ApfsCheckpointMap {
  pub fn parse(block: &[u8]) -> Result<Self> {
    require_len(block, 40, "apfs checkpoint map")?;
    let header = ApfsObjectHeader::parse(block)?;
    let entry_count = read_u32_le(block, 36)?;
    let entries_offset = 40usize;
    let entries_length = usize::try_from(entry_count)
      .map_err(|_| {
        Error::InvalidRange("apfs checkpoint map entry count exceeds usize".to_string())
      })?
      .checked_mul(40)
      .ok_or_else(|| Error::InvalidRange("apfs checkpoint map size overflow".to_string()))?;
    let entries_bytes = read_slice(
      block,
      entries_offset,
      entries_length,
      "apfs checkpoint map entries",
    )?;
    let mut entries = Vec::with_capacity(entry_count as usize);
    for chunk in entries_bytes.chunks_exact(40) {
      entries.push(ApfsCheckpointMapping::parse(chunk)?);
    }

    Ok(Self {
      header,
      flags: read_u32_le(block, 32)?,
      entry_count,
      entries,
    })
  }

  pub fn validate(&self, block: &[u8]) -> Result<()> {
    if self.header.type_code() != OBJECT_TYPE_CHECKPOINT_MAP {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs checkpoint map type: 0x{:08x}",
        self.header.object_type
      )));
    }
    if !self.header.is_physical() {
      return Err(Error::InvalidFormat(
        "apfs checkpoint map must be physical".to_string(),
      ));
    }
    if !self.header.validate_checksum(block) {
      return Err(Error::InvalidFormat(
        "invalid apfs checkpoint map checksum".to_string(),
      ));
    }
    Ok(())
  }

  pub fn is_last(&self) -> bool {
    (self.flags & CHECKPOINT_MAP_LAST) != 0
  }

  pub fn object_id(&self) -> u64 {
    self.header.oid
  }

  pub fn xid(&self) -> u64 {
    self.header.xid
  }
}

impl ApfsObjectMap {
  pub(crate) fn parse(block: &[u8]) -> Result<Self> {
    require_len(block, 88, "apfs object map")?;
    let header = ApfsObjectHeader::parse(block)?;
    Ok(Self {
      header,
      flags: read_u32_le(block, 32)?,
      snapshot_count: read_u32_le(block, 36)?,
      tree_type: read_u32_le(block, 40)?,
      snapshot_tree_type: read_u32_le(block, 44)?,
      tree_oid: read_u64_le(block, 48)?,
      snapshot_tree_oid: read_u64_le(block, 56)?,
      most_recent_snapshot_xid: read_u64_le(block, 64)?,
    })
  }

  pub(crate) fn validate(&self, block: &[u8], address: u64) -> Result<()> {
    if self.header.type_code() != OBJECT_TYPE_OMAP {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs object map type: 0x{:08x}",
        self.header.object_type
      )));
    }
    if !self.header.is_physical() {
      return Err(Error::InvalidFormat(
        "apfs object map must be physical".to_string(),
      ));
    }
    if self.header.oid != address {
      return Err(Error::InvalidFormat(format!(
        "apfs object map oid {} does not match address {address}",
        self.header.oid
      )));
    }
    if !self.header.validate_checksum(block) {
      return Err(Error::InvalidFormat(
        "invalid apfs object map checksum".to_string(),
      ));
    }
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsVolumeSuperblock {
  pub header: ApfsObjectHeader,
  pub fs_index: u32,
  pub features: u64,
  pub readonly_compatible_features: u64,
  pub incompatible_features: u64,
  pub unmount_time: u64,
  pub reserve_block_count: u64,
  pub quota_block_count: u64,
  pub alloc_block_count: u64,
  pub meta_crypto: ApfsMetaCryptoState,
  pub volume_uuid: [u8; 16],
  pub root_tree_type: u32,
  pub extentref_tree_type: u32,
  pub snap_meta_tree_type: u32,
  pub omap_oid: u64,
  pub root_tree_oid: u64,
  pub extentref_tree_oid: u64,
  pub snap_meta_tree_oid: u64,
  pub revert_to_xid: u64,
  pub revert_to_sblock_oid: u64,
  pub next_object_id: u64,
  pub number_of_files: u64,
  pub number_of_directories: u64,
  pub number_of_symlinks: u64,
  pub number_of_other_fsobjects: u64,
  pub number_of_snapshots: u64,
  pub total_blocks_allocated: u64,
  pub total_blocks_freed: u64,
  pub last_modification_time: u64,
  pub fs_flags: u64,
  pub formatted_by: ApfsChangeInfo,
  pub modified_by: Vec<ApfsChangeInfo>,
  pub volume_name: String,
  pub next_document_id: u32,
  pub role: u16,
  pub root_to_xid: u64,
  pub encryption_rolling_state_oid: u64,
  pub snap_meta_ext_oid: u64,
  pub volume_group_id: [u8; 16],
  pub integrity_meta_oid: u64,
  pub fext_tree_oid: u64,
  pub fext_tree_type: u32,
  pub pfkur_tree_type: u32,
  pub pfkur_tree_oid: u64,
  pub doc_id_index_xid: u64,
  pub doc_id_index_flags: u32,
  pub doc_id_tree_type: u32,
  pub doc_id_tree_oid: u64,
  pub prev_doc_id_tree_oid: u64,
  pub doc_id_fixup_cursor: u64,
  pub secondary_root_tree_oid: u64,
  pub secondary_root_tree_type: u32,
  pub clone_group_tree_flags: u32,
}

impl ApfsVolumeSuperblock {
  pub(crate) fn parse(block: &[u8]) -> Result<Self> {
    require_len(block, 1112, "apfs volume superblock")?;
    let header = ApfsObjectHeader::parse(block)?;
    let magic = read_array::<4>(block, 32)?;
    if &magic != APFS_MAGIC {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs volume superblock magic: {:?}",
        String::from_utf8_lossy(&magic)
      )));
    }
    let volume_name_bytes = read_slice(block, 704, 256, "apfs volume name")?;
    let volume_name = bytes_to_cstring(volume_name_bytes);
    Ok(Self {
      header,
      fs_index: read_u32_le(block, 36)?,
      features: read_u64_le(block, 40)?,
      readonly_compatible_features: read_u64_le(block, 48)?,
      incompatible_features: read_u64_le(block, 56)?,
      unmount_time: read_u64_le(block, 60)?,
      reserve_block_count: read_u64_le(block, 68)?,
      quota_block_count: read_u64_le(block, 76)?,
      alloc_block_count: read_u64_le(block, 84)?,
      meta_crypto: ApfsMetaCryptoState::parse(read_slice(
        block,
        96,
        20,
        "apfs meta crypto state",
      )?)?,
      root_tree_type: read_u32_le(block, 116)?,
      extentref_tree_type: read_u32_le(block, 120)?,
      snap_meta_tree_type: read_u32_le(block, 124)?,
      omap_oid: read_u64_le(block, 128)?,
      root_tree_oid: read_u64_le(block, 136)?,
      extentref_tree_oid: read_u64_le(block, 144)?,
      snap_meta_tree_oid: read_u64_le(block, 152)?,
      revert_to_xid: read_u64_le(block, 160)?,
      revert_to_sblock_oid: read_u64_le(block, 168)?,
      next_object_id: read_u64_le(block, 176)?,
      number_of_files: read_u64_le(block, 184)?,
      number_of_directories: read_u64_le(block, 192)?,
      number_of_symlinks: read_u64_le(block, 200)?,
      number_of_other_fsobjects: read_u64_le(block, 208)?,
      number_of_snapshots: read_u64_le(block, 216)?,
      total_blocks_allocated: read_u64_le(block, 224)?,
      total_blocks_freed: read_u64_le(block, 232)?,
      volume_uuid: read_array(block, 240)?,
      last_modification_time: read_u64_le(block, 256)?,
      fs_flags: read_u64_le(block, 264)?,
      formatted_by: parse_change_info(block, 272)?,
      modified_by: (0..8)
        .map(|index| parse_change_info(block, 320 + index * 48))
        .collect::<Result<Vec<_>>>()?,
      volume_name,
      next_document_id: read_u32_le(block, 960)?,
      role: read_u16_le(block, 964)?,
      root_to_xid: read_u64_le(block, 968)?,
      encryption_rolling_state_oid: read_u64_le(block, 976)?,
      snap_meta_ext_oid: read_u64_le(block, 1000)?,
      volume_group_id: read_array(block, 1008)?,
      integrity_meta_oid: read_u64_le(block, 1024)?,
      fext_tree_oid: read_u64_le(block, 1032)?,
      fext_tree_type: read_u32_le(block, 1040)?,
      pfkur_tree_type: read_u32_le(block, 1044)?,
      pfkur_tree_oid: read_u64_le(block, 1048)?,
      doc_id_index_xid: read_u64_le(block, 1056)?,
      doc_id_index_flags: read_u32_le(block, 1064)?,
      doc_id_tree_type: read_u32_le(block, 1068)?,
      doc_id_tree_oid: read_u64_le(block, 1072)?,
      prev_doc_id_tree_oid: read_u64_le(block, 1080)?,
      doc_id_fixup_cursor: read_u64_le(block, 1088)?,
      secondary_root_tree_oid: read_u64_le(block, 1096)?,
      secondary_root_tree_type: read_u32_le(block, 1104)?,
      clone_group_tree_flags: read_u32_le(block, 1108)?,
    })
  }

  pub(crate) fn validate(&self, block: &[u8]) -> Result<()> {
    if self.header.type_code() != OBJECT_TYPE_FS {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs volume superblock type: 0x{:08x}",
        self.header.object_type
      )));
    }
    if !self.header.validate_checksum(block) {
      return Err(Error::InvalidFormat(
        "invalid apfs volume superblock checksum".to_string(),
      ));
    }
    Ok(())
  }

  pub(crate) fn is_case_insensitive(&self) -> bool {
    (self.incompatible_features & APFS_INCOMPAT_CASE_INSENSITIVE) != 0
  }

  pub(crate) fn is_normalization_insensitive(&self) -> bool {
    (self.incompatible_features & APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0
  }

  pub(crate) fn is_sealed(&self) -> bool {
    (self.incompatible_features & APFS_INCOMPAT_SEALED_VOLUME) != 0
  }

  pub(crate) fn has_dataless_snapshots(&self) -> bool {
    (self.incompatible_features & APFS_INCOMPAT_DATALESS_SNAPS) != 0
  }

  pub(crate) fn has_secondary_fs_root(&self) -> bool {
    (self.incompatible_features & APFS_INCOMPAT_SECONDARY_FSROOT) != 0
      || self.secondary_root_tree_oid != 0
  }

  pub(crate) fn uses_volume_group_system_inode_space(&self) -> bool {
    (self.features & APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE) != 0
  }

  pub(crate) fn is_encrypted(&self) -> bool {
    (self.fs_flags & APFS_FS_UNENCRYPTED) == 0 && (self.fs_flags & APFS_FS_PFK) == 0
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsIntegrityMetadata {
  header: ApfsObjectHeader,
  pub version: u32,
  pub flags: u32,
  pub hash_type: u32,
  pub broken_xid: u64,
  pub root_hash: Box<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsChangeInfo {
  pub application_id: String,
  pub timestamp: u64,
  pub last_xid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApfsMetaCryptoState {
  pub major_version: u16,
  pub minor_version: u16,
  pub flags: u32,
  pub persistent_class: u32,
  pub key_os_version: u32,
  pub key_revision: u16,
}

impl ApfsMetaCryptoState {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    require_len(bytes, 20, "apfs meta crypto state")?;
    Ok(Self {
      major_version: read_u16_le(bytes, 0)?,
      minor_version: read_u16_le(bytes, 2)?,
      flags: read_u32_le(bytes, 4)?,
      persistent_class: read_u32_le(bytes, 8)?,
      key_os_version: read_u32_le(bytes, 12)?,
      key_revision: read_u16_le(bytes, 16)?,
    })
  }
}

impl ApfsChangeInfo {
  pub fn is_empty(&self) -> bool {
    self.application_id.is_empty() && self.timestamp == 0 && self.last_xid == 0
  }
}

impl ApfsIntegrityMetadata {
  pub(crate) fn parse(block: &[u8]) -> Result<Self> {
    require_len(block, 112, "apfs integrity metadata")?;
    let header = ApfsObjectHeader::parse(block)?;
    if header.type_code() != OBJECT_TYPE_INTEGRITY_META {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs integrity metadata type: 0x{:08x}",
        header.object_type
      )));
    }
    if !header.validate_checksum(block) {
      return Err(Error::InvalidFormat(
        "invalid apfs integrity metadata checksum".to_string(),
      ));
    }

    let hash_type = read_u32_le(block, 40)?;
    let root_hash_offset = usize::try_from(read_u32_le(block, 44)?).map_err(|_| {
      Error::InvalidRange("apfs integrity metadata root hash offset exceeds usize".to_string())
    })?;
    let root_hash_length = apfs_hash_size(hash_type)?;
    let root_hash = read_slice(
      block,
      root_hash_offset,
      root_hash_length,
      "apfs integrity metadata root hash",
    )?;

    Ok(Self {
      header,
      version: read_u32_le(block, 32)?,
      flags: read_u32_le(block, 36)?,
      hash_type,
      broken_xid: read_u64_le(block, 48)?,
      root_hash: root_hash.to_vec().into_boxed_slice(),
    })
  }

  pub fn seal_broken(&self) -> bool {
    (self.flags & APFS_SEAL_BROKEN) != 0
  }

  pub fn object_id(&self) -> u64 {
    self.header.oid
  }

  pub fn xid(&self) -> u64 {
    self.header.xid
  }
}

pub(crate) fn apfs_hash_size(hash_type: u32) -> Result<usize> {
  match hash_type {
    APFS_HASH_SHA256 | APFS_HASH_SHA512_256 => Ok(32),
    APFS_HASH_SHA384 => Ok(48),
    APFS_HASH_SHA512 => Ok(64),
    _ => Err(Error::Unsupported(format!(
      "unsupported apfs integrity hash type: {hash_type}"
    ))),
  }
}

fn parse_change_info(block: &[u8], offset: usize) -> Result<ApfsChangeInfo> {
  Ok(ApfsChangeInfo {
    application_id: bytes_to_cstring(read_slice(block, offset, 32, "apfs change info id")?),
    timestamp: read_u64_le(block, offset + 32)?,
    last_xid: read_u64_le(block, offset + 40)?,
  })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApfsPrange {
  pub start_paddr: u64,
  pub block_count: u64,
}

impl ApfsPrange {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    require_len(bytes, 16, "apfs prange")?;
    let start = read_i64_le(bytes, 0)?;
    if start < 0 {
      return Err(Error::InvalidFormat(
        "apfs prange start address must be non-negative".to_string(),
      ));
    }
    Ok(Self {
      start_paddr: start as u64,
      block_count: read_u64_le(bytes, 8)?,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsBtreeInfo {
  pub flags: u32,
  pub node_size: u32,
  pub key_size: u32,
  pub value_size: u32,
  pub longest_key: u32,
  pub longest_value: u32,
  pub key_count: u64,
  pub node_count: u64,
}

impl ApfsBtreeInfo {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    require_len(bytes, BTREE_INFO_SIZE, "apfs btree info")?;
    Ok(Self {
      flags: read_u32_le(bytes, 0)?,
      node_size: read_u32_le(bytes, 4)?,
      key_size: read_u32_le(bytes, 8)?,
      value_size: read_u32_le(bytes, 12)?,
      longest_key: read_u32_le(bytes, 16)?,
      longest_value: read_u32_le(bytes, 20)?,
      key_count: read_u64_le(bytes, 24)?,
      node_count: read_u64_le(bytes, 32)?,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsBtreeNodeHeader {
  pub flags: u16,
  pub level: u16,
  pub key_count: u32,
  pub table_space_offset: u16,
  pub table_space_length: u16,
  pub free_space_offset: u16,
  pub free_space_length: u16,
  pub key_free_list_offset: u16,
  pub key_free_list_length: u16,
  pub value_free_list_offset: u16,
  pub value_free_list_length: u16,
}

impl ApfsBtreeNodeHeader {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    require_len(bytes, BTREE_NODE_HEADER_SIZE, "apfs btree node header")?;
    Ok(Self {
      flags: read_u16_le(bytes, 0)?,
      level: read_u16_le(bytes, 2)?,
      key_count: read_u32_le(bytes, 4)?,
      table_space_offset: read_u16_le(bytes, 8)?,
      table_space_length: read_u16_le(bytes, 10)?,
      free_space_offset: read_u16_le(bytes, 12)?,
      free_space_length: read_u16_le(bytes, 14)?,
      key_free_list_offset: read_u16_le(bytes, 16)?,
      key_free_list_length: read_u16_le(bytes, 18)?,
      value_free_list_offset: read_u16_le(bytes, 20)?,
      value_free_list_length: read_u16_le(bytes, 22)?,
    })
  }
}

pub(crate) fn bytes_to_cstring(bytes: &[u8]) -> String {
  let end = bytes
    .iter()
    .position(|byte| *byte == 0)
    .unwrap_or(bytes.len());
  String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub(crate) fn format_uuid_le(bytes: &[u8; 16]) -> String {
  format!(
    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
    bytes[3],
    bytes[2],
    bytes[1],
    bytes[0],
    bytes[5],
    bytes[4],
    bytes[7],
    bytes[6],
    bytes[8],
    bytes[9],
    bytes[10],
    bytes[11],
    bytes[12],
    bytes[13],
    bytes[14],
    bytes[15],
  )
}

pub(crate) fn apfs_role_names(role: u16) -> Vec<&'static str> {
  let mut names = Vec::new();
  for (mask, name) in [
    (APFS_VOL_ROLE_SYSTEM, "system"),
    (APFS_VOL_ROLE_USER, "user"),
    (APFS_VOL_ROLE_RECOVERY, "recovery"),
    (APFS_VOL_ROLE_VM, "vm"),
    (APFS_VOL_ROLE_PREBOOT, "preboot"),
    (APFS_VOL_ROLE_INSTALLER, "installer"),
    (APFS_VOL_ROLE_DATA, "data"),
    (APFS_VOL_ROLE_BASEBAND, "baseband"),
    (APFS_VOL_ROLE_UPDATE, "update"),
    (APFS_VOL_ROLE_XART, "xart"),
    (APFS_VOL_ROLE_HARDWARE, "hardware"),
    (APFS_VOL_ROLE_BACKUP, "backup"),
    (APFS_VOL_ROLE_ENTERPRISE, "enterprise"),
    (APFS_VOL_ROLE_PRELOGIN, "prelogin"),
  ] {
    if (role & mask) != 0 {
      names.push(name);
    }
  }
  if names.is_empty() {
    names.push("none");
  }
  names
}

pub(crate) fn fletcher64(data: &[u8]) -> u64 {
  let mut sum1 = 0u64;
  let mut sum2 = 0u64;
  for chunk in data.chunks_exact(4) {
    let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
    sum1 = sum1.wrapping_add(word);
    sum2 = sum2.wrapping_add(sum1);
  }
  let checksum_low = 0xFFFF_FFFFu64 - ((sum1 + sum2) % 0xFFFF_FFFFu64);
  let checksum_high = 0xFFFF_FFFFu64 - ((sum1 + checksum_low) % 0xFFFF_FFFFu64);
  checksum_low | (checksum_high << 32)
}

pub(crate) fn read_slice<'a>(
  bytes: &'a [u8], offset: usize, length: usize, what: &str,
) -> Result<&'a [u8]> {
  let end = offset
    .checked_add(length)
    .ok_or_else(|| Error::InvalidRange(format!("{what} offset overflow")))?;
  bytes.get(offset..end).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "{what} extends beyond the available APFS block data"
    ))
  })
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  let slice = read_slice(bytes, offset, N, "apfs array")?;
  let mut result = [0u8; N];
  result.copy_from_slice(slice);
  Ok(result)
}

pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
  Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
  Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
  Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_i64_le(bytes: &[u8], offset: usize) -> Result<i64> {
  Ok(i64::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u64_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u64; N]> {
  let mut values = [0u64; N];
  for (index, slot) in values.iter_mut().enumerate() {
    *slot = read_u64_le(bytes, offset + index * 8)?;
  }
  Ok(values)
}

fn bit_names_u64(flags: u64, mapping: &[(u64, &'static str)]) -> Vec<&'static str> {
  mapping
    .iter()
    .filter_map(|(mask, name)| ((flags & *mask) != 0).then_some(*name))
    .collect()
}

fn bit_names_u32(flags: u32, mapping: &[(u32, &'static str)]) -> Vec<&'static str> {
  mapping
    .iter()
    .filter_map(|(mask, name)| ((flags & *mask) != 0).then_some(*name))
    .collect()
}

fn require_len(bytes: &[u8], length: usize, what: &str) -> Result<()> {
  if bytes.len() < length {
    return Err(Error::InvalidFormat(format!(
      "{what} requires at least {length} bytes"
    )));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use super::*;

  fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("apfs")
        .join("libfsapfs")
        .join(name),
    )
    .expect("fixture bytes")
  }

  #[test]
  fn fletcher64_matches_container_superblock_fixture() {
    let fixture = fixture_bytes("container_superblock.1");
    let header = ApfsObjectHeader::parse(&fixture).unwrap();

    assert_eq!(fletcher64(&fixture[8..]), header.checksum);
  }

  #[test]
  fn parses_container_superblock_fixture() {
    let fixture = fixture_bytes("container_superblock.1");
    let superblock = ApfsContainerSuperblock::parse(&fixture).unwrap();

    superblock.validate(&fixture, 1).unwrap();
    assert_eq!(superblock.block_size, 4096);
    assert_eq!(superblock.block_count, 246);
    assert_eq!(superblock.incompatible_features, 2);
    assert_eq!(superblock.checkpoint_descriptor_blocks, 8);
    assert_eq!(superblock.checkpoint_data_blocks, 52);
    assert_eq!(superblock.checkpoint_descriptor_base, 1);
    assert_eq!(superblock.checkpoint_data_base, 9);
    assert_eq!(superblock.omap_oid, 90);
    assert_eq!(superblock.file_system_oids, vec![1026]);
    assert_eq!(superblock.blocked_out_prange, None);
    assert_eq!(superblock.fusion_middle_tree_oid, 0);
    assert_eq!(superblock.media_keybag_prange, None);
  }

  #[test]
  fn parses_object_map_fixture() {
    let fixture = fixture_bytes("container_object_map.1");
    let omap = ApfsObjectMap::parse(&fixture).unwrap();

    omap.validate(&fixture, 83).unwrap();
    assert_eq!(omap.flags, 1);
    assert_eq!(omap.tree_type, OBJ_PHYSICAL | OBJECT_TYPE_BTREE);
    assert_eq!(omap.tree_oid, 84);
  }

  #[test]
  fn parses_checkpoint_map_fixture() {
    let fixture = fixture_bytes("checkpoint_map.1");
    let map = ApfsCheckpointMap::parse(&fixture).unwrap();

    map.validate(&fixture).unwrap();
    assert!(map.is_last());
    assert_eq!(map.entry_count, 2);
    assert_eq!(map.entries[0].object_type, 0x8000_0005);
    assert_eq!(map.entries[0].object_type_name(), "spaceman");
    assert_eq!(map.entries[0].object_storage_kind_name(), "ephemeral");
    assert_eq!(map.entries[0].object_flag_names(), Vec::<&str>::new());
    assert_eq!(map.entries[0].size, 0x1000);
    assert_eq!(map.entries[0].object_id, 1024);
    assert_eq!(map.entries[0].physical_address, 9);
    assert_eq!(map.entries[1].object_type, 0x8000_0011);
    assert_eq!(map.entries[1].object_type_name(), "nx_reaper");
    assert_eq!(map.entries[1].object_storage_kind_name(), "ephemeral");
    assert_eq!(map.entries[1].physical_address, 10);
  }

  #[test]
  fn parses_checkpoint_map_entry_fixture() {
    let entry = ApfsCheckpointMapping::parse(&fixture_bytes("checkpoint_map_entry.1")).unwrap();

    assert_eq!(entry.object_type, 0x8000_0005);
    assert_eq!(entry.object_subtype, 0);
    assert_eq!(entry.size, 0x1000);
    assert_eq!(entry.file_system_object_id, 0);
    assert_eq!(entry.object_id, 1024);
    assert_eq!(entry.physical_address, 9);
  }

  #[test]
  fn parses_volume_superblock_fixture() {
    let fixture = fixture_bytes("volume_superblock.1");
    let superblock = ApfsVolumeSuperblock::parse(&fixture).unwrap();

    superblock.validate(&fixture).unwrap();
    assert_eq!(superblock.fs_index, 0);
    assert_eq!(superblock.omap_oid, 105);
    assert_eq!(superblock.root_tree_oid, 1028);
    assert_eq!(superblock.snap_meta_tree_oid, 88);
    assert_eq!(superblock.role, 0);
    assert_eq!(superblock.volume_name, "TestVolume");
    assert_eq!(superblock.doc_id_tree_oid, 0);
    assert_eq!(superblock.secondary_root_tree_oid, 0);
  }

  #[test]
  fn parses_btree_header_and_footer_fixtures() {
    let header = ApfsBtreeNodeHeader::parse(&fixture_bytes("btree_header.1")).unwrap();
    let footer = ApfsBtreeInfo::parse(&fixture_bytes("btree_footer.1")).unwrap();

    assert_eq!(
      header.flags,
      BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE
    );
    assert_eq!(header.key_count, 1);
    assert_eq!(footer.flags, BTREE_PHYSICAL | 0x0000_0002);
    assert_eq!(footer.node_size, 4096);
    assert_eq!(footer.key_size, 16);
    assert_eq!(footer.value_size, 16);
  }

  #[test]
  fn parses_integrity_metadata_blocks() {
    let mut block = vec![0u8; 128];
    block[24..28].copy_from_slice(&OBJECT_TYPE_INTEGRITY_META.to_le_bytes());
    block[32..36].copy_from_slice(&2u32.to_le_bytes());
    block[36..40].copy_from_slice(&APFS_SEAL_BROKEN.to_le_bytes());
    block[40..44].copy_from_slice(&APFS_HASH_SHA256.to_le_bytes());
    block[44..48].copy_from_slice(&96u32.to_le_bytes());
    block[48..56].copy_from_slice(&123u64.to_le_bytes());
    block[96..128].copy_from_slice(&[0xAB; 32]);
    let checksum = fletcher64(&block[8..]);
    block[0..8].copy_from_slice(&checksum.to_le_bytes());

    let metadata = ApfsIntegrityMetadata::parse(&block).unwrap();

    assert_eq!(metadata.version, 2);
    assert!(metadata.seal_broken());
    assert_eq!(metadata.hash_type, APFS_HASH_SHA256);
    assert_eq!(metadata.broken_xid, 123);
    assert_eq!(metadata.root_hash.as_ref(), &[0xAB; 32]);
  }

  #[test]
  fn parses_modern_volume_superblock_tail_fields() {
    let mut block = fixture_bytes("volume_superblock.1");
    let features = APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE.to_le_bytes();
    block[40..48].copy_from_slice(&features);
    let incompat = (APFS_INCOMPAT_CASE_INSENSITIVE
      | APFS_INCOMPAT_DATALESS_SNAPS
      | APFS_INCOMPAT_SECONDARY_FSROOT)
      .to_le_bytes();
    block[56..64].copy_from_slice(&incompat);
    block[96..98].copy_from_slice(&1u16.to_le_bytes());
    block[98..100].copy_from_slice(&2u16.to_le_bytes());
    block[100..104].copy_from_slice(&3u32.to_le_bytes());
    block[104..108].copy_from_slice(&4u32.to_le_bytes());
    block[108..112].copy_from_slice(&5u32.to_le_bytes());
    block[112..114].copy_from_slice(&6u16.to_le_bytes());
    block[116..120].copy_from_slice(&2u32.to_le_bytes());
    block[120..124].copy_from_slice(&3u32.to_le_bytes());
    block[124..128].copy_from_slice(&4u32.to_le_bytes());
    block[1056..1064].copy_from_slice(&55u64.to_le_bytes());
    block[1064..1068].copy_from_slice(&7u32.to_le_bytes());
    block[1068..1072].copy_from_slice(&9u32.to_le_bytes());
    block[1072..1080].copy_from_slice(&100u64.to_le_bytes());
    block[1080..1088].copy_from_slice(&101u64.to_le_bytes());
    block[1088..1096].copy_from_slice(&102u64.to_le_bytes());
    block[1096..1104].copy_from_slice(&103u64.to_le_bytes());
    block[1104..1108].copy_from_slice(&11u32.to_le_bytes());
    block[1044..1048].copy_from_slice(&13u32.to_le_bytes());
    block[1048..1056].copy_from_slice(&104u64.to_le_bytes());
    block[1108..1112].copy_from_slice(&17u32.to_le_bytes());
    let checksum = fletcher64(&block[8..]);
    block[0..8].copy_from_slice(&checksum.to_le_bytes());

    let superblock = ApfsVolumeSuperblock::parse(&block).unwrap();
    superblock.validate(&block).unwrap();

    assert!(superblock.has_dataless_snapshots());
    assert!(superblock.has_secondary_fs_root());
    assert!(superblock.uses_volume_group_system_inode_space());
    assert_eq!(superblock.meta_crypto.major_version, 1);
    assert_eq!(superblock.meta_crypto.minor_version, 2);
    assert_eq!(superblock.meta_crypto.flags, 3);
    assert_eq!(superblock.meta_crypto.persistent_class, 4);
    assert_eq!(superblock.meta_crypto.key_os_version, 5);
    assert_eq!(superblock.meta_crypto.key_revision, 6);
    assert_eq!(superblock.pfkur_tree_type, 13);
    assert_eq!(superblock.pfkur_tree_oid, 104);
    assert_eq!(superblock.doc_id_index_xid, 55);
    assert_eq!(superblock.doc_id_index_flags, 7);
    assert_eq!(superblock.doc_id_tree_type, 9);
    assert_eq!(superblock.doc_id_tree_oid, 100);
    assert_eq!(superblock.prev_doc_id_tree_oid, 101);
    assert_eq!(superblock.doc_id_fixup_cursor, 102);
    assert_eq!(superblock.secondary_root_tree_oid, 103);
    assert_eq!(superblock.secondary_root_tree_type, 11);
    assert_eq!(superblock.clone_group_tree_flags, 17);
  }

  #[test]
  fn parses_volume_change_history_and_counters() {
    let mut block = fixture_bytes("volume_superblock.1");
    block[60..68].copy_from_slice(&7u64.to_le_bytes());
    block[68..76].copy_from_slice(&11u64.to_le_bytes());
    block[76..84].copy_from_slice(&13u64.to_le_bytes());
    block[84..92].copy_from_slice(&17u64.to_le_bytes());
    block[116..120].copy_from_slice(&2u32.to_le_bytes());
    block[120..124].copy_from_slice(&3u32.to_le_bytes());
    block[124..128].copy_from_slice(&4u32.to_le_bytes());
    block[160..168].copy_from_slice(&19u64.to_le_bytes());
    block[168..176].copy_from_slice(&23u64.to_le_bytes());
    block[184..192].copy_from_slice(&29u64.to_le_bytes());
    block[192..200].copy_from_slice(&31u64.to_le_bytes());
    block[200..208].copy_from_slice(&37u64.to_le_bytes());
    block[208..216].copy_from_slice(&41u64.to_le_bytes());
    block[224..232].copy_from_slice(&43u64.to_le_bytes());
    block[232..240].copy_from_slice(&47u64.to_le_bytes());
    let mut formatted_id = [0u8; 32];
    formatted_id[..13].copy_from_slice(b"mkfs.apfs 123");
    block[272..304].copy_from_slice(&formatted_id);
    block[304..312].copy_from_slice(&53u64.to_le_bytes());
    block[312..320].copy_from_slice(&59u64.to_le_bytes());
    let mut modified_id = [0u8; 32];
    modified_id[..15].copy_from_slice(b"diskmanagementd");
    block[320..352].copy_from_slice(&modified_id);
    block[352..360].copy_from_slice(&61u64.to_le_bytes());
    block[360..368].copy_from_slice(&67u64.to_le_bytes());
    let checksum = fletcher64(&block[8..]);
    block[0..8].copy_from_slice(&checksum.to_le_bytes());

    let superblock = ApfsVolumeSuperblock::parse(&block).unwrap();
    superblock.validate(&block).unwrap();

    assert_eq!(superblock.unmount_time, 7);
    assert_eq!(superblock.reserve_block_count, 11);
    assert_eq!(superblock.quota_block_count, 13);
    assert_eq!(superblock.alloc_block_count, 17);
    assert_eq!(superblock.root_tree_type, 2);
    assert_eq!(superblock.extentref_tree_type, 3);
    assert_eq!(superblock.snap_meta_tree_type, 4);
    assert_eq!(superblock.revert_to_xid, 19);
    assert_eq!(superblock.revert_to_sblock_oid, 23);
    assert_eq!(superblock.number_of_files, 29);
    assert_eq!(superblock.number_of_directories, 31);
    assert_eq!(superblock.number_of_symlinks, 37);
    assert_eq!(superblock.number_of_other_fsobjects, 41);
    assert_eq!(superblock.total_blocks_allocated, 43);
    assert_eq!(superblock.total_blocks_freed, 47);
    assert_eq!(superblock.formatted_by.application_id, "mkfs.apfs 123");
    assert_eq!(superblock.formatted_by.timestamp, 53);
    assert_eq!(superblock.formatted_by.last_xid, 59);
    assert_eq!(superblock.modified_by[0].application_id, "diskmanagementd");
    assert_eq!(superblock.modified_by[0].timestamp, 61);
    assert_eq!(superblock.modified_by[0].last_xid, 67);
    assert!(superblock.modified_by[1].is_empty());
  }

  #[test]
  fn parses_container_fusion_and_auxiliary_metadata() {
    let mut block = fixture_bytes("container_superblock.1");
    let incompat = (APFS_INCOMPAT_CASE_INSENSITIVE | NX_INCOMPAT_FUSION).to_le_bytes();
    block[64..72].copy_from_slice(&incompat);
    block[176..180].copy_from_slice(&67u32.to_le_bytes());
    block[984..992].copy_from_slice(&71u64.to_le_bytes());
    block[992..1000].copy_from_slice(&73u64.to_le_bytes());
    block[1240..1248].copy_from_slice(&71u64.to_le_bytes());
    block[1248..1256].copy_from_slice(&73u64.to_le_bytes());
    block[1256..1264].copy_from_slice(&79u64.to_le_bytes());
    block[1264..1272].copy_from_slice(&NX_CRYPTO_SW.to_le_bytes());
    block[1272..1280].copy_from_slice(&83u64.to_le_bytes());
    block[1280..1296].copy_from_slice(&[0x55; 16]);
    block[1296..1304].copy_from_slice(&89u64.to_le_bytes());
    block[1304..1312].copy_from_slice(&97u64.to_le_bytes());
    block[1312..1320].copy_from_slice(&101u64.to_le_bytes());
    block[1320..1328].copy_from_slice(&103u64.to_le_bytes());
    block[1328..1336].copy_from_slice(&107u64.to_le_bytes());
    block[1336..1344].copy_from_slice(&109u64.to_le_bytes());
    block[1344..1352].copy_from_slice(&113u64.to_le_bytes());
    block[1352..1360].copy_from_slice(&127u64.to_le_bytes());
    block[1360..1368].copy_from_slice(&131u64.to_le_bytes());
    block[1368..1376].copy_from_slice(&137u64.to_le_bytes());
    block[1376..1384].copy_from_slice(&139u64.to_le_bytes());
    block[1384..1392].copy_from_slice(&149u64.to_le_bytes());
    block[1392..1400].copy_from_slice(&151u64.to_le_bytes());
    block[1400..1408].copy_from_slice(&157u64.to_le_bytes());
    let checksum = fletcher64(&block[8..]);
    block[0..8].copy_from_slice(&checksum.to_le_bytes());

    let superblock = ApfsContainerSuperblock::parse(&block).unwrap();
    superblock.validate(&block, 1).unwrap();

    assert!(superblock.is_fusion());
    assert!(superblock.uses_software_crypto());
    assert_eq!(superblock.test_type, 67);
    assert_eq!(superblock.counters[0], 71);
    assert_eq!(superblock.counters[1], 73);
    assert_eq!(superblock.blocked_out_prange.unwrap().start_paddr, 71);
    assert_eq!(superblock.blocked_out_prange.unwrap().block_count, 73);
    assert_eq!(superblock.evict_mapping_tree_oid, 79);
    assert_eq!(superblock.efi_jumpstart_oid, 83);
    assert_eq!(superblock.fusion_uuid, [0x55; 16]);
    assert_eq!(superblock.container_keybag_prange.unwrap().start_paddr, 89);
    assert_eq!(superblock.container_keybag_prange.unwrap().block_count, 97);
    assert_eq!(superblock.ephemeral_info, [101, 103, 107, 109]);
    assert_eq!(superblock.test_oid, 113);
    assert_eq!(superblock.fusion_middle_tree_oid, 127);
    assert_eq!(superblock.fusion_wbc_oid, 131);
    assert_eq!(superblock.fusion_wbc_prange.unwrap().start_paddr, 137);
    assert_eq!(superblock.fusion_wbc_prange.unwrap().block_count, 139);
    assert_eq!(superblock.newest_mounted_version, 149);
    assert_eq!(superblock.media_keybag_prange.unwrap().start_paddr, 151);
    assert_eq!(superblock.media_keybag_prange.unwrap().block_count, 157);
  }
}
