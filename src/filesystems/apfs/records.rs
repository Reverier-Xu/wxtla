//! APFS filesystem-tree record parsing.

use std::sync::Arc;

use super::ondisk::{bytes_to_cstring, read_slice, read_u16_le, read_u32_le, read_u64_le};
use crate::{Error, Result};

pub(crate) const APFS_TYPE_SNAP_METADATA: u8 = 0x1;
pub(crate) const APFS_TYPE_INODE: u8 = 0x3;
pub(crate) const APFS_TYPE_XATTR: u8 = 0x4;
pub(crate) const APFS_TYPE_FILE_EXTENT: u8 = 0x8;
pub(crate) const APFS_TYPE_DIR_REC: u8 = 0x9;

pub(crate) const APFS_ROOT_DIRECTORY_OBJECT_ID: u64 = 2;

const FS_OBJECT_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
const FS_RECORD_TYPE_SHIFT: u64 = 60;
const DREC_LEN_MASK: u32 = 0x0000_03FF;
const DREC_TYPE_MASK: u16 = 0x000F;
const J_FILE_EXTENT_LEN_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;

const DT_DIR: u16 = 0x0004;
const DT_REG: u16 = 0x0008;
const DT_LNK: u16 = 0x000A;

const XATTR_DATA_STREAM: u16 = 0x0001;

const DREC_EXT_TYPE_SIBLING_ID: u8 = 1;

const INO_EXT_TYPE_NAME: u8 = 4;
const INO_EXT_TYPE_DSTREAM: u8 = 8;

pub(crate) const UF_COMPRESSED: u32 = 0x0000_0020;
pub(crate) const XATTR_SYMLINK_NAME: &str = "com.apple.fs.symlink";
pub(crate) const XATTR_RESOURCE_FORK_NAME: &str = "com.apple.ResourceFork";

const MODE_TYPE_MASK: u16 = 0xF000;
const MODE_FIFO: u16 = 0x1000;
const MODE_CHAR_DEVICE: u16 = 0x2000;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_BLOCK_DEVICE: u16 = 0x6000;
const MODE_REGULAR: u16 = 0x8000;
const MODE_SYMLINK: u16 = 0xA000;
const MODE_SOCKET: u16 = 0xC000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsFsKeyHeader {
  pub object_id: u64,
  pub record_type: u8,
}

impl ApfsFsKeyHeader {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    let raw = read_u64_le(bytes, 0)?;
    Ok(Self {
      object_id: raw & FS_OBJECT_ID_MASK,
      record_type: ((raw >> FS_RECORD_TYPE_SHIFT) & 0x0F) as u8,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsDstream {
  pub size: u64,
  pub allocated_size: u64,
  pub default_crypto_id: u64,
}

impl ApfsDstream {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    Ok(Self {
      size: read_u64_le(bytes, 0)?,
      allocated_size: read_u64_le(bytes, 8)?,
      default_crypto_id: read_u64_le(bytes, 16)?,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsInodeRecord {
  pub object_id: u64,
  pub parent_id: u64,
  pub private_id: u64,
  pub internal_flags: u64,
  pub bsd_flags: u32,
  pub owner: u32,
  pub group: u32,
  pub mode: u16,
  pub uncompressed_size: u64,
  pub name: Option<String>,
  pub dstream: Option<ApfsDstream>,
}

impl ApfsInodeRecord {
  pub(crate) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
    let header = ApfsFsKeyHeader::parse(key)?;
    if header.record_type != APFS_TYPE_INODE {
      return Err(Error::InvalidFormat(
        "apfs inode key has the wrong record type".to_string(),
      ));
    }
    if value.len() < 92 {
      return Err(Error::InvalidFormat(
        "apfs inode value is too short".to_string(),
      ));
    }

    let mut name = None;
    let mut dstream = None;
    for field in parse_xfields(&value[92..])? {
      match field.kind {
        INO_EXT_TYPE_NAME => {
          name = Some(bytes_to_cstring(&field.value));
        }
        INO_EXT_TYPE_DSTREAM => {
          dstream = Some(ApfsDstream::parse(&field.value)?);
        }
        _ => {}
      }
    }

    Ok(Self {
      object_id: header.object_id,
      parent_id: read_u64_le(value, 0)?,
      private_id: read_u64_le(value, 8)?,
      internal_flags: read_u64_le(value, 48)?,
      bsd_flags: read_u32_le(value, 68)?,
      owner: read_u32_le(value, 72)?,
      group: read_u32_le(value, 76)?,
      mode: read_u16_le(value, 80)?,
      uncompressed_size: read_u64_le(value, 84)?,
      name,
      dstream,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsSnapshotMetadataRecord {
  pub xid: u64,
  pub superblock_address: u64,
  pub create_time: u64,
  pub change_time: u64,
  pub flags: u32,
  pub name: String,
}

impl ApfsSnapshotMetadataRecord {
  pub(crate) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
    let header = ApfsFsKeyHeader::parse(key)?;
    if header.record_type != APFS_TYPE_SNAP_METADATA {
      return Err(Error::InvalidFormat(
        "apfs snapshot metadata key has the wrong record type".to_string(),
      ));
    }
    if value.len() < 50 {
      return Err(Error::InvalidFormat(
        "apfs snapshot metadata value is too short".to_string(),
      ));
    }

    let name_len = usize::from(read_u16_le(value, 48)?);
    let name = bytes_to_cstring(read_slice(
      value,
      50,
      name_len,
      "apfs snapshot metadata name",
    )?);

    Ok(Self {
      xid: header.object_id,
      superblock_address: read_u64_le(value, 8)?,
      create_time: read_u64_le(value, 16)?,
      change_time: read_u64_le(value, 24)?,
      flags: read_u32_le(value, 44)?,
      name,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsDirectoryRecord {
  pub parent_id: u64,
  pub name: String,
  pub file_id: u64,
  pub flags: u16,
  pub sibling_id: Option<u64>,
}

impl ApfsDirectoryRecord {
  pub(crate) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
    let key_header = ApfsFsKeyHeader::parse(key)?;
    if key_header.record_type != APFS_TYPE_DIR_REC {
      return Err(Error::InvalidFormat(
        "apfs directory key has the wrong record type".to_string(),
      ));
    }
    if value.len() < 18 {
      return Err(Error::InvalidFormat(
        "apfs directory value is too short".to_string(),
      ));
    }

    let (name, _) = parse_directory_name(key)?;
    let mut sibling_id = None;
    for field in parse_xfields(&value[18..])? {
      if field.kind == DREC_EXT_TYPE_SIBLING_ID && field.value.len() >= 8 {
        sibling_id = Some(read_u64_le(&field.value, 0)?);
      }
    }

    Ok(Self {
      parent_id: key_header.object_id,
      name,
      file_id: read_u64_le(value, 0)?,
      flags: read_u16_le(value, 16)?,
      sibling_id,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApfsXattrRecord {
  pub object_id: u64,
  pub name: String,
  pub storage: ApfsStreamStorageSpec,
}

impl ApfsXattrRecord {
  pub(crate) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
    let header = ApfsFsKeyHeader::parse(key)?;
    if header.record_type != APFS_TYPE_XATTR {
      return Err(Error::InvalidFormat(
        "apfs xattr key has the wrong record type".to_string(),
      ));
    }
    if value.len() < 4 {
      return Err(Error::InvalidFormat(
        "apfs xattr value is too short".to_string(),
      ));
    }
    let name_len = usize::from(read_u16_le(key, 8)?);
    let name = bytes_to_cstring(read_slice(key, 10, name_len, "apfs xattr name")?);
    let flags = read_u16_le(value, 0)?;
    let data_length = usize::from(read_u16_le(value, 2)?);
    let data = read_slice(value, 4, data_length, "apfs xattr data")?;

    let storage = if (flags & XATTR_DATA_STREAM) != 0 {
      if data.len() < 48 {
        return Err(Error::InvalidFormat(
          "apfs xattr stream descriptor is too short".to_string(),
        ));
      }
      let object_id = read_u64_le(data, 0)?;
      let dstream = ApfsDstream::parse(&data[8..48])?;
      ApfsStreamStorageSpec::DataStream {
        object_id,
        size: dstream.size,
      }
    } else {
      ApfsStreamStorageSpec::Inline(Arc::from(data.to_vec().into_boxed_slice()))
    };

    Ok(Self {
      object_id: header.object_id,
      name,
      storage,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApfsStreamStorageSpec {
  Inline(Arc<[u8]>),
  DataStream { object_id: u64, size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsFileExtentRecord {
  pub object_id: u64,
  pub logical_address: u64,
  pub length: u64,
  pub physical_block_number: u64,
  pub crypto_id: u64,
}

impl ApfsFileExtentRecord {
  pub(crate) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
    let header = ApfsFsKeyHeader::parse(key)?;
    if header.record_type != APFS_TYPE_FILE_EXTENT {
      return Err(Error::InvalidFormat(
        "apfs file extent key has the wrong record type".to_string(),
      ));
    }
    if value.len() < 24 {
      return Err(Error::InvalidFormat(
        "apfs file extent value is too short".to_string(),
      ));
    }
    let len_and_flags = read_u64_le(value, 0)?;
    Ok(Self {
      object_id: header.object_id,
      logical_address: read_u64_le(key, 8)?,
      length: len_and_flags & J_FILE_EXTENT_LEN_MASK,
      physical_block_number: read_u64_le(value, 8)?,
      crypto_id: read_u64_le(value, 16)?,
    })
  }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedXfield {
  pub kind: u8,
  pub value: Arc<[u8]>,
}

pub(crate) fn parse_xfields(bytes: &[u8]) -> Result<Vec<ParsedXfield>> {
  if bytes.is_empty() {
    return Ok(Vec::new());
  }
  if bytes.len() < 4 {
    return Err(Error::InvalidFormat(
      "apfs xfield blob is too short".to_string(),
    ));
  }

  let field_count = usize::from(read_u16_le(bytes, 0)?);
  let used_data = usize::from(read_u16_le(bytes, 2)?);
  let descriptors_length = field_count
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("apfs xfield descriptor length overflow".to_string()))?;
  let descriptors = read_slice(bytes, 4, descriptors_length, "apfs xfield descriptors")?;
  let values = read_slice(
    bytes,
    4 + descriptors_length,
    used_data,
    "apfs xfield values",
  )?;

  let mut offset = 0usize;
  let mut result = Vec::with_capacity(field_count);
  for index in 0..field_count {
    let descriptor_offset = index * 4;
    let kind = descriptors[descriptor_offset];
    let size = usize::from(read_u16_le(descriptors, descriptor_offset + 2)?);
    let value = read_slice(values, offset, size, "apfs xfield value")?;
    result.push(ParsedXfield {
      kind,
      value: Arc::from(value.to_vec().into_boxed_slice()),
    });
    offset = align_8(
      offset
        .checked_add(size)
        .ok_or_else(|| Error::InvalidRange("apfs xfield offset overflow".to_string()))?,
    );
  }

  Ok(result)
}

pub(crate) fn node_kind_from_mode(mode: u16) -> crate::NamespaceNodeKind {
  match mode & MODE_TYPE_MASK {
    MODE_DIRECTORY => crate::NamespaceNodeKind::Directory,
    MODE_REGULAR => crate::NamespaceNodeKind::File,
    MODE_SYMLINK => crate::NamespaceNodeKind::Symlink,
    MODE_FIFO | MODE_CHAR_DEVICE | MODE_BLOCK_DEVICE | MODE_SOCKET => {
      crate::NamespaceNodeKind::Special
    }
    _ => crate::NamespaceNodeKind::Special,
  }
}

pub(crate) fn directory_kind_from_flags(flags: u16) -> crate::NamespaceNodeKind {
  match flags & DREC_TYPE_MASK {
    DT_DIR => crate::NamespaceNodeKind::Directory,
    DT_REG => crate::NamespaceNodeKind::File,
    DT_LNK => crate::NamespaceNodeKind::Symlink,
    _ => crate::NamespaceNodeKind::Special,
  }
}

fn parse_directory_name(bytes: &[u8]) -> Result<(String, bool)> {
  if bytes.len() >= 12 {
    let name_len_and_hash = read_u32_le(bytes, 8)?;
    let name_length = (name_len_and_hash & DREC_LEN_MASK) as usize;
    if 12usize.saturating_add(name_length) == bytes.len() {
      let name = bytes_to_cstring(read_slice(bytes, 12, name_length, "apfs directory name")?);
      return Ok((name, true));
    }
  }

  let name_length = usize::from(read_u16_le(bytes, 8)?);
  let name = bytes_to_cstring(read_slice(bytes, 10, name_length, "apfs directory name")?);
  Ok((name, false))
}

fn align_8(value: usize) -> usize {
  (value + 7) & !7
}
