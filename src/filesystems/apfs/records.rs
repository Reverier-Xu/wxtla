//! APFS filesystem-tree record parsing.

use std::sync::Arc;

use super::ondisk::{bytes_to_cstring, read_slice, read_u16_le, read_u32_le, read_u64_le};
use crate::{Error, Result};

pub(crate) const APFS_TYPE_SNAP_METADATA: u8 = 0x1;
pub(crate) const APFS_TYPE_INODE: u8 = 0x3;
pub(crate) const APFS_TYPE_XATTR: u8 = 0x4;
pub(crate) const APFS_TYPE_FILE_EXTENT: u8 = 0x8;
pub(crate) const APFS_TYPE_DIR_REC: u8 = 0x9;
pub(crate) const APFS_TYPE_FILE_INFO: u8 = 0xD;

pub(crate) const APFS_ROOT_DIRECTORY_OBJECT_ID: u64 = 2;

const FS_OBJECT_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
const FS_RECORD_TYPE_SHIFT: u64 = 60;
const DREC_LEN_MASK: u32 = 0x0000_03FF;
const DREC_TYPE_MASK: u16 = 0x000F;
const J_FILE_EXTENT_LEN_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;
const FILE_INFO_LBA_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;
const FILE_INFO_TYPE_SHIFT: u64 = 56;

pub const APFS_FILE_INFO_DATA_HASH: u8 = 1;

const DT_DIR: u16 = 0x0004;
const DT_REG: u16 = 0x0008;
const DT_LNK: u16 = 0x000A;

const XATTR_DATA_STREAM: u16 = 0x0001;

const DREC_EXT_TYPE_SIBLING_ID: u8 = 1;

const INO_EXT_TYPE_NAME: u8 = 4;
const INO_EXT_TYPE_SNAP_XID: u8 = 1;
const INO_EXT_TYPE_DOCUMENT_ID: u8 = 3;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const INO_EXT_TYPE_SPARSE_BYTES: u8 = 13;
const INO_EXT_TYPE_RDEV: u8 = 14;

pub(crate) const UF_COMPRESSED: u32 = 0x0000_0020;
pub(crate) const SF_FIRMLINK: u32 = 0x0080_0000;
pub(crate) const SF_DATALESS: u32 = 0x4000_0000;
pub(crate) const XATTR_SYMLINK_NAME: &str = "com.apple.fs.symlink";
pub(crate) const XATTR_FIRMLINK_NAME: &str = "com.apple.fs.firmlink";
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
  pub create_time: u64,
  pub modification_time: u64,
  pub change_time: u64,
  pub access_time: u64,
  pub internal_flags: u64,
  pub children_or_links: u32,
  pub protection_class: u32,
  pub write_generation_counter: u32,
  pub bsd_flags: u32,
  pub owner: u32,
  pub group: u32,
  pub mode: u16,
  pub uncompressed_size: u64,
  pub name: Option<String>,
  pub dstream: Option<ApfsDstream>,
  pub snapshot_xid: Option<u64>,
  pub document_id: Option<u32>,
  pub sparse_bytes: Option<u64>,
  pub rdev: Option<u32>,
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
    let mut snapshot_xid = None;
    let mut document_id = None;
    let mut sparse_bytes = None;
    let mut rdev = None;
    for field in parse_xfields(&value[92..])? {
      match field.kind {
        INO_EXT_TYPE_SNAP_XID if field.value.len() >= 8 => {
          snapshot_xid = Some(read_u64_le(&field.value, 0)?);
        }
        INO_EXT_TYPE_DOCUMENT_ID if field.value.len() >= 4 => {
          document_id = Some(read_u32_le(&field.value, 0)?);
        }
        INO_EXT_TYPE_NAME => {
          name = Some(bytes_to_cstring(&field.value));
        }
        INO_EXT_TYPE_DSTREAM => {
          dstream = Some(ApfsDstream::parse(&field.value)?);
        }
        INO_EXT_TYPE_SPARSE_BYTES if field.value.len() >= 8 => {
          sparse_bytes = Some(read_u64_le(&field.value, 0)?);
        }
        INO_EXT_TYPE_RDEV if field.value.len() >= 4 => {
          rdev = Some(read_u32_le(&field.value, 0)?);
        }
        _ => {}
      }
    }

    Ok(Self {
      object_id: header.object_id,
      parent_id: read_u64_le(value, 0)?,
      private_id: read_u64_le(value, 8)?,
      create_time: read_u64_le(value, 16)?,
      modification_time: read_u64_le(value, 24)?,
      change_time: read_u64_le(value, 32)?,
      access_time: read_u64_le(value, 40)?,
      internal_flags: read_u64_le(value, 48)?,
      children_or_links: read_u32_le(value, 56)?,
      protection_class: read_u32_le(value, 60)?,
      write_generation_counter: read_u32_le(value, 64)?,
      bsd_flags: read_u32_le(value, 68)?,
      owner: read_u32_le(value, 72)?,
      group: read_u32_le(value, 76)?,
      mode: read_u16_le(value, 80)?,
      uncompressed_size: read_u64_le(value, 84)?,
      name,
      dstream,
      snapshot_xid,
      document_id,
      sparse_bytes,
      rdev,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsFextRecord {
  pub private_id: u64,
  pub logical_address: u64,
  pub length: u64,
  pub physical_block_number: u64,
}

impl ApfsFextRecord {
  pub(crate) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
    if key.len() != 16 {
      return Err(Error::InvalidFormat(
        "apfs fext key must be 16 bytes".to_string(),
      ));
    }
    if value.len() < 16 {
      return Err(Error::InvalidFormat(
        "apfs fext value is too short".to_string(),
      ));
    }

    let len_and_flags = read_u64_le(value, 0)?;
    Ok(Self {
      private_id: read_u64_le(key, 0)?,
      logical_address: read_u64_le(key, 8)?,
      length: len_and_flags & J_FILE_EXTENT_LEN_MASK,
      physical_block_number: read_u64_le(value, 8)?,
    })
  }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsFileInfoRecord {
  pub object_id: u64,
  pub info_type: u8,
  pub logical_block_address: u64,
  pub hashed_length: u16,
  pub hash: Box<[u8]>,
}

impl ApfsFileInfoRecord {
  pub(crate) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
    let header = ApfsFsKeyHeader::parse(key)?;
    if header.record_type != APFS_TYPE_FILE_INFO {
      return Err(Error::InvalidFormat(
        "apfs file-info key has the wrong record type".to_string(),
      ));
    }
    if key.len() != 16 {
      return Err(Error::InvalidFormat(
        "apfs file-info key must be 16 bytes".to_string(),
      ));
    }
    if value.len() < 3 {
      return Err(Error::InvalidFormat(
        "apfs file-info value is too short".to_string(),
      ));
    }

    let info_and_lba = read_u64_le(key, 8)?;
    let info_type = ((info_and_lba >> FILE_INFO_TYPE_SHIFT) & 0xFF) as u8;
    let hash_size = usize::from(value[2]);
    let hash = read_slice(value, 3, hash_size, "apfs file-info hash")?;

    Ok(Self {
      object_id: header.object_id,
      info_type,
      logical_block_address: info_and_lba & FILE_INFO_LBA_MASK,
      hashed_length: read_u16_le(value, 0)?,
      hash: hash.to_vec().into_boxed_slice(),
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_fext_records() {
    let key = [
      0x34, 0x12, 0, 0, 0, 0, 0, 0, // private id
      0x78, 0x56, 0, 0, 0, 0, 0, 0, // logical addr
    ];
    let value = [
      0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // length
      0x9A, 0xBC, 0, 0, 0, 0, 0, 0, // phys
    ];

    let record = ApfsFextRecord::parse(&key, &value).unwrap();

    assert_eq!(record.private_id, 0x1234);
    assert_eq!(record.logical_address, 0x5678);
    assert_eq!(record.length, 0x2000);
    assert_eq!(record.physical_block_number, 0xBC9A);
  }

  #[test]
  fn parses_file_info_records() {
    let key = [
      0x34, 0x12, 0, 0, 0, 0, 0, 0xD0, // object id + type
      0x78, 0x56, 0, 0, 0, 0, 0, 0x01, // lba + info type
    ];
    let value = [0x10, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];

    let record = ApfsFileInfoRecord::parse(&key, &value).unwrap();

    assert_eq!(record.object_id, 0x1234);
    assert_eq!(record.info_type, APFS_FILE_INFO_DATA_HASH);
    assert_eq!(record.logical_block_address, 0x5678);
    assert_eq!(record.hashed_length, 0x10);
    assert_eq!(record.hash.as_ref(), &[0xAA, 0xBB, 0xCC, 0xDD]);
  }

  #[test]
  fn parses_inode_metadata_and_xfields() {
    let key = [0x34, 0x12, 0, 0, 0, 0, 0, 0x30];
    let mut value = vec![0u8; 92 + 4 + 4 * 4 + 8 + 8 + 8 + 8 + 4];
    value[0..8].copy_from_slice(&5u64.to_le_bytes());
    value[8..16].copy_from_slice(&7u64.to_le_bytes());
    value[16..24].copy_from_slice(&11u64.to_le_bytes());
    value[24..32].copy_from_slice(&13u64.to_le_bytes());
    value[32..40].copy_from_slice(&17u64.to_le_bytes());
    value[40..48].copy_from_slice(&19u64.to_le_bytes());
    value[48..56].copy_from_slice(&23u64.to_le_bytes());
    value[56..60].copy_from_slice(&29u32.to_le_bytes());
    value[60..64].copy_from_slice(&31u32.to_le_bytes());
    value[64..68].copy_from_slice(&37u32.to_le_bytes());
    value[68..72].copy_from_slice(&41u32.to_le_bytes());
    value[72..76].copy_from_slice(&43u32.to_le_bytes());
    value[76..80].copy_from_slice(&47u32.to_le_bytes());
    value[80..82].copy_from_slice(&0x8000u16.to_le_bytes());
    value[84..92].copy_from_slice(&53u64.to_le_bytes());
    value[92..94].copy_from_slice(&4u16.to_le_bytes());
    value[94..96].copy_from_slice(&32u16.to_le_bytes());
    value[96..100].copy_from_slice(&[1, 0, 8, 0]);
    value[100..104].copy_from_slice(&[3, 0, 4, 0]);
    value[104..108].copy_from_slice(&[4, 0, 8, 0]);
    value[108..112].copy_from_slice(&[13, 0, 8, 0]);
    value[112..120].copy_from_slice(&59u64.to_le_bytes());
    value[120..124].copy_from_slice(&61u32.to_le_bytes());
    value[128..136].copy_from_slice(b"node\0\0\0\0");
    value[136..144].copy_from_slice(&67u64.to_le_bytes());

    let record = ApfsInodeRecord::parse(&key, &value).unwrap();

    assert_eq!(record.object_id, 0x1234);
    assert_eq!(record.parent_id, 5);
    assert_eq!(record.private_id, 7);
    assert_eq!(record.create_time, 11);
    assert_eq!(record.modification_time, 13);
    assert_eq!(record.change_time, 17);
    assert_eq!(record.access_time, 19);
    assert_eq!(record.internal_flags, 23);
    assert_eq!(record.children_or_links, 29);
    assert_eq!(record.protection_class, 31);
    assert_eq!(record.write_generation_counter, 37);
    assert_eq!(record.bsd_flags, 41);
    assert_eq!(record.owner, 43);
    assert_eq!(record.group, 47);
    assert_eq!(record.mode, 0x8000);
    assert_eq!(record.uncompressed_size, 53);
    assert_eq!(record.snapshot_xid, Some(59));
    assert_eq!(record.document_id, Some(61));
    assert_eq!(record.name.as_deref(), Some("node"));
    assert_eq!(record.sparse_bytes, Some(67));
  }
}
