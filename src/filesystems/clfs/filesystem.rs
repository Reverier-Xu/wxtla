use super::{
  CLFS_CONTROL_RECORD_MAGIC, DESCRIPTOR, SECTOR_SIZE, read_u16_le, read_u32_le, read_u64_le,
};
use crate::{
  ByteSourceHandle, Error, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind,
  NamespaceNodeRecord, Result, filesystems::FileSystem,
};

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ClfsLogBlockHeader {
  major_version: u8,
  minor_version: u8,
  total_sectors: u16,
  valid_sectors: u16,
  flags: u32,
  current_lsn: u64,
  next_lsn: u64,
}

impl ClfsLogBlockHeader {
  fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < 0x48 {
      return Err(Error::invalid_format("clfs log block header is too short"));
    }
    Ok(Self {
      major_version: data[0],
      minor_version: data[1],
      total_sectors: read_u16_le(data, 4)?,
      valid_sectors: read_u16_le(data, 6)?,
      flags: read_u32_le(data, 16)?,
      current_lsn: read_u64_le(data, 24)?,
      next_lsn: read_u64_le(data, 32)?,
    })
  }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ClfsControlRecord {
  magic: u64,
  version: u8,
  blocks: u32,
}

impl ClfsControlRecord {
  fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < 0x50 {
      return Err(Error::invalid_format("clfs control record is too short"));
    }
    Ok(Self {
      magic: read_u64_le(data, 8)?,
      version: data[16],
      blocks: read_u32_le(data, 0x48)?,
    })
  }
}

pub struct ClfsFileSystem {
  #[allow(dead_code)]
  source: ByteSourceHandle,
  #[allow(dead_code)]
  header: ClfsLogBlockHeader,
  #[allow(dead_code)]
  control: ClfsControlRecord,
}

impl ClfsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let data = source.read_bytes_at(0, SECTOR_SIZE as usize)?;
    let total_sectors = read_u16_le(&data, 4)? as u64;
    let block_size = total_sectors * SECTOR_SIZE;
    let block_data = source.read_bytes_at(0, block_size as usize)?;

    let header = ClfsLogBlockHeader::parse(&block_data)?;
    let control = ClfsControlRecord::parse(&block_data[0x40..])?;

    if control.magic != CLFS_CONTROL_RECORD_MAGIC {
      return Err(Error::invalid_format("invalid clfs control record magic"));
    }

    Ok(Self {
      source,
      header,
      control,
    })
  }
}

impl FileSystem for ClfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(1)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    Ok(
      NamespaceNodeRecord::new(node_id.clone(), NamespaceNodeKind::Directory, 0)
        .with_path(String::new()),
    )
  }

  fn read_dir(&self, _directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    Ok(Vec::new())
  }

  fn open_file(&self, _file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    Err(Error::unsupported(
      "clfs direct file access is not supported",
    ))
  }
}

crate::filesystems::driver::impl_file_system_data_source!(ClfsFileSystem);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_log_block_header() {
    let mut data = vec![0u8; 0x50];
    data[0] = 2;
    data[1] = 1;
    data[4..6].copy_from_slice(&8u16.to_le_bytes());
    data[6..8].copy_from_slice(&8u16.to_le_bytes());

    let header = ClfsLogBlockHeader::parse(&data).unwrap();
    assert_eq!(header.major_version, 2);
    assert_eq!(header.minor_version, 1);
    assert_eq!(header.total_sectors, 8);
  }
}
