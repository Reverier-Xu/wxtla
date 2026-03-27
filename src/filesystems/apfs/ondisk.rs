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
pub(crate) const OBJECT_TYPE_FS: u32 = 0x0000_000D;
pub(crate) const OBJECT_TYPE_SNAP_META_TREE: u32 = 0x0000_0010;
pub(crate) const OBJECT_TYPE_FEXT_TREE: u32 = 0x0000_001F;
pub(crate) const APFS_OBJECT_TYPE_CONTAINER_KEYBAG: u32 = 0x6B65_7973;
pub(crate) const APFS_OBJECT_TYPE_VOLUME_KEYBAG: u32 = 0x7265_6373;

pub(crate) const OBJ_PHYSICAL: u32 = 0x4000_0000;
pub(crate) const OBJ_EPHEMERAL: u32 = 0x8000_0000;

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

pub(crate) const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x0000_0001;
pub(crate) const APFS_INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x0000_0008;
pub(crate) const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x0000_0020;

pub(crate) const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;
pub(crate) const APFS_FS_ONEKEY: u64 = 0x0000_0008;
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
  pub flags: u64,
  pub container_keybag_prange: Option<ApfsPrange>,
  pub max_file_systems: u32,
  pub file_system_oids: Vec<u64>,
}

impl ApfsContainerSuperblock {
  pub(crate) fn parse(block: &[u8]) -> Result<Self> {
    require_len(block, 1312, "apfs container superblock")?;
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
      flags: read_u64_le(block, 1264)?,
      container_keybag_prange: {
        let prange =
          ApfsPrange::parse(read_slice(block, 1296, 16, "apfs container keybag prange")?)?;
        (prange.start_paddr != 0 && prange.block_count != 0).then_some(prange)
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
      ("flags", self.flags, other.flags),
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
  pub volume_uuid: [u8; 16],
  pub omap_oid: u64,
  pub root_tree_oid: u64,
  pub extentref_tree_oid: u64,
  pub snap_meta_tree_oid: u64,
  pub next_object_id: u64,
  pub number_of_snapshots: u64,
  pub last_modification_time: u64,
  pub fs_flags: u64,
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
}

impl ApfsVolumeSuperblock {
  pub(crate) fn parse(block: &[u8]) -> Result<Self> {
    require_len(block, 1044, "apfs volume superblock")?;
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
      omap_oid: read_u64_le(block, 128)?,
      root_tree_oid: read_u64_le(block, 136)?,
      extentref_tree_oid: read_u64_le(block, 144)?,
      snap_meta_tree_oid: read_u64_le(block, 152)?,
      next_object_id: read_u64_le(block, 176)?,
      number_of_snapshots: read_u64_le(block, 216)?,
      volume_uuid: read_array(block, 240)?,
      last_modification_time: read_u64_le(block, 256)?,
      fs_flags: read_u64_le(block, 264)?,
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

  pub(crate) fn is_encrypted(&self) -> bool {
    (self.fs_flags & APFS_FS_UNENCRYPTED) == 0 && (self.fs_flags & APFS_FS_PFK) == 0
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsPrange {
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
}
