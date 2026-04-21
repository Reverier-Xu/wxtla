use super::superblock::{read_u16_le, read_u32_le};
use crate::{Error, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, Result};

pub(crate) const DIR_HEADER_SIZE: usize = 12;
pub(crate) const DIR_ENTRY_BASE_SIZE: usize = 8;

pub(crate) const SQUASHFS_FILETYPE_DIR: u16 = 1;
pub(crate) const SQUASHFS_FILETYPE_REG: u16 = 2;
pub(crate) const SQUASHFS_FILETYPE_SYMLINK: u16 = 3;
pub(crate) const SQUASHFS_FILETYPE_BLKDEV: u16 = 4;
pub(crate) const SQUASHFS_FILETYPE_CHRDEV: u16 = 5;
pub(crate) const SQUASHFS_FILETYPE_FIFO: u16 = 6;
pub(crate) const SQUASHFS_FILETYPE_SOCKET: u16 = 7;
pub(crate) const SQUASHFS_FILETYPE_LDIR: u16 = 8;
pub(crate) const SQUASHFS_FILETYPE_LREG: u16 = 9;
pub(crate) const SQUASHFS_FILETYPE_LSYMLINK: u16 = 10;
pub(crate) const SQUASHFS_FILETYPE_LBLKDEV: u16 = 11;
pub(crate) const SQUASHFS_FILETYPE_LCHRDEV: u16 = 12;
pub(crate) const SQUASHFS_FILETYPE_LFIFO: u16 = 13;
pub(crate) const SQUASHFS_FILETYPE_LSOCKET: u16 = 14;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct SquashFsDirHeader {
  pub count: u32,
  pub start_block: u32,
  pub inode_number: u32,
}

impl SquashFsDirHeader {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    if bytes.len() < DIR_HEADER_SIZE {
      return Err(Error::invalid_format(
        "squashfs directory header is too short",
      ));
    }
    Ok(Self {
      count: read_u32_le(bytes, 0)?,
      start_block: read_u32_le(bytes, 4)?,
      inode_number: read_u32_le(bytes, 8)?,
    })
  }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct SquashFsDirEntry {
  pub offset: u16,
  pub inode_number: u32,
  pub entry_type: u16,
  pub name: String,
}

pub(crate) fn parse_directory_block(data: &[u8]) -> Result<Vec<SquashFsDirEntry>> {
  let mut entries = Vec::new();
  let mut offset = 0usize;

  while offset + DIR_HEADER_SIZE <= data.len() {
    let header = SquashFsDirHeader::parse(&data[offset..])?;
    if header.count == 0 {
      break;
    }
    offset += DIR_HEADER_SIZE;

    for _ in 0..header.count {
      if offset + DIR_ENTRY_BASE_SIZE > data.len() {
        return Err(Error::invalid_format(
          "squashfs directory entry is truncated",
        ));
      }

      let entry_offset = read_u16_le(data, offset)?;
      let inode_diff = read_i16_le(data, offset + 2)?;
      let entry_type = read_u16_le(data, offset + 4)?;
      let name_size = read_u16_le(data, offset + 6)? as usize;

      let name_start = offset + DIR_ENTRY_BASE_SIZE;
      if name_start + name_size > data.len() {
        return Err(Error::invalid_format(
          "squashfs directory entry name is truncated",
        ));
      }
      let name = String::from_utf8_lossy(&data[name_start..name_start + name_size]).to_string();

      let inode_number = (header.inode_number as i32 + inode_diff as i32) as u32;

      entries.push(SquashFsDirEntry {
        offset: entry_offset,
        inode_number,
        entry_type,
        name,
      });

      offset = name_start + name_size;
    }
  }

  Ok(entries)
}

#[allow(dead_code)]
pub(crate) fn to_namespace_entry(entry: &SquashFsDirEntry) -> NamespaceDirectoryEntry {
  NamespaceDirectoryEntry::new(
    entry.name.clone(),
    NamespaceNodeId::from_u64(entry.inode_number as u64),
    entry_type_to_kind(entry.entry_type),
  )
}

pub(crate) fn entry_type_to_kind(entry_type: u16) -> NamespaceNodeKind {
  match entry_type {
    SQUASHFS_FILETYPE_DIR | SQUASHFS_FILETYPE_LDIR => NamespaceNodeKind::Directory,
    SQUASHFS_FILETYPE_REG | SQUASHFS_FILETYPE_LREG => NamespaceNodeKind::File,
    SQUASHFS_FILETYPE_SYMLINK | SQUASHFS_FILETYPE_LSYMLINK => NamespaceNodeKind::Symlink,
    SQUASHFS_FILETYPE_BLKDEV
    | SQUASHFS_FILETYPE_LBLKDEV
    | SQUASHFS_FILETYPE_CHRDEV
    | SQUASHFS_FILETYPE_LCHRDEV
    | SQUASHFS_FILETYPE_FIFO
    | SQUASHFS_FILETYPE_LFIFO
    | SQUASHFS_FILETYPE_SOCKET
    | SQUASHFS_FILETYPE_LSOCKET => NamespaceNodeKind::Special,
    _ => NamespaceNodeKind::Special,
  }
}

fn read_i16_le(bytes: &[u8], offset: usize) -> Result<i16> {
  let array = super::superblock::read_array::<2>(bytes, offset)?;
  Ok(i16::from_le_bytes(array))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_simple_directory_block() {
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&100u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0i16.to_le_bytes());
    data.extend_from_slice(&SQUASHFS_FILETYPE_REG.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(b"file");

    let entries = parse_directory_block(&data).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].inode_number, 100);
    assert_eq!(entries[0].entry_type, SQUASHFS_FILETYPE_REG);
    assert_eq!(entries[0].name, "file");
  }

  #[test]
  fn parses_multiple_directory_entries() {
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&200u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0i16.to_le_bytes());
    data.extend_from_slice(&SQUASHFS_FILETYPE_DIR.to_le_bytes());
    data.extend_from_slice(&3u16.to_le_bytes());
    data.extend_from_slice(b"dir");
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&1i16.to_le_bytes());
    data.extend_from_slice(&SQUASHFS_FILETYPE_REG.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(b"file");

    let entries = parse_directory_block(&data).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].inode_number, 200);
    assert_eq!(entries[0].entry_type, SQUASHFS_FILETYPE_DIR);
    assert_eq!(entries[0].name, "dir");
    assert_eq!(entries[1].inode_number, 201);
    assert_eq!(entries[1].entry_type, SQUASHFS_FILETYPE_REG);
    assert_eq!(entries[1].name, "file");
  }
}
