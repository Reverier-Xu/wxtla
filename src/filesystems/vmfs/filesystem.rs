use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR, FS3_DESCRIPTOR_SIZE, FS3_DESCRIPTOR_TYPE_DIRECTORY, FS3_DESCRIPTOR_TYPE_REGFILE,
  FS3_DESCRIPTOR_TYPE_SYMLINK, FS3_FS_HEADER_OFFSET, FS3_MAX_FILE_NAME_LENGTH, ROOT_DIR_DESC_ADDR,
  S_IFDIR, S_IFLNK, S_IFMT, read_u32_le, read_u64_le,
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceReadConcurrency,
  ByteSourceSeekCost, BytesDataSource, Error, NamespaceDirectoryEntry, NamespaceNodeId,
  NamespaceNodeKind, NamespaceNodeRecord, Result, filesystems::FileSystem,
};

const FD_META_OFFSET: u64 = 512;
const FD_DATA_OFFSET: u64 = 1024;
const FD_SIZE: u64 = 2048;
const DIR_ENTRY_SIZE: usize = 0x8C;

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct VmfsDescriptor {
  major_version: u32,
  minor_version: u8,
  disk_block_size: u32,
  file_block_size: u64,
  sub_block_size: u32,
  fdc_cluster_group_offset: u32,
  fdc_clusters_per_group: u32,
  pb2_vol_addr: u64,
  pb2_fd_addr: u32,
  sdd_vol_addr: u64,
  sdd_fd_addr: u32,
  config: u32,
}

impl VmfsDescriptor {
  fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < FS3_DESCRIPTOR_SIZE {
      return Err(Error::invalid_format("vmfs descriptor is too short"));
    }
    Ok(Self {
      major_version: read_u32_le(data, 4)?,
      minor_version: data[8],
      disk_block_size: read_u32_le(data, 0x9D)?,
      file_block_size: read_u64_le(data, 0xA1)?,
      sub_block_size: read_u32_le(data, 0xD9)?,
      fdc_cluster_group_offset: read_u32_le(data, 0xD1)?,
      fdc_clusters_per_group: read_u32_le(data, 0xD5)?,
      pb2_vol_addr: read_u64_le(data, 0xE1)?,
      pb2_fd_addr: read_u32_le(data, 0xE9)?,
      sdd_vol_addr: read_u64_le(data, 0x105)?,
      sdd_fd_addr: read_u32_le(data, 0x10D)?,
      config: read_u32_le(data, 0x19)?,
    })
  }

  #[allow(dead_code)]
  fn is_vmfs5(&self) -> bool {
    self.major_version < 24
  }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct VmfsFileMetadata {
  desc_addr: u32,
  generation: u32,
  link_count: u32,
  desc_type: u32,
  flags: u32,
  file_length: u64,
  block_size: u64,
  num_blocks: u64,
  mode: u32,
  zero_level_addr_type: u32,
}

impl VmfsFileMetadata {
  fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < 0x90 {
      return Err(Error::invalid_format("vmfs file metadata is too short"));
    }
    Ok(Self {
      desc_addr: read_u32_le(data, 0)?,
      generation: read_u32_le(data, 4)?,
      link_count: read_u32_le(data, 8)?,
      desc_type: read_u32_le(data, 0xC)?,
      flags: read_u32_le(data, 0x10)?,
      file_length: read_u64_le(data, 0x14)?,
      block_size: read_u64_le(data, 0x1C)?,
      num_blocks: read_u64_le(data, 0x24)?,
      mode: read_u32_le(data, 0x40)?,
      zero_level_addr_type: read_u32_le(data, 0x44)?,
    })
  }

  fn node_kind(&self) -> NamespaceNodeKind {
    if self.desc_type == FS3_DESCRIPTOR_TYPE_DIRECTORY || (self.mode & S_IFMT) == S_IFDIR {
      NamespaceNodeKind::Directory
    } else if self.desc_type == FS3_DESCRIPTOR_TYPE_SYMLINK || (self.mode & S_IFMT) == S_IFLNK {
      NamespaceNodeKind::Symlink
    } else {
      NamespaceNodeKind::File
    }
  }
}

fn sfd_offset(descriptor: &VmfsDescriptor, resource: u32) -> u64 {
  let fsd = descriptor;
  let cg_offset = fsd.file_block_size * ((fsd.file_block_size + 0x3FFFFF) / fsd.file_block_size)
    + fsd.fdc_cluster_group_offset as u64;
  let resource_size = 1024u64;
  let resource_offset = (resource as u64) << 11;
  cg_offset + (fsd.fdc_clusters_per_group as u64 * resource_size) + resource_offset
}

pub struct VmfsFileSystem {
  source: ByteSourceHandle,
  descriptor: VmfsDescriptor,
  fd_cache: Mutex<HashMap<u32, VmfsFileMetadata>>,
}

impl VmfsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let data = source.read_bytes_at(FS3_FS_HEADER_OFFSET, FS3_DESCRIPTOR_SIZE)?;
    let descriptor = VmfsDescriptor::parse(&data)?;

    Ok(Self {
      source,
      descriptor,
      fd_cache: Mutex::new(HashMap::new()),
    })
  }

  fn read_fd_metadata(&self, fd_addr: u32) -> Result<VmfsFileMetadata> {
    if let Some(meta) = self
      .fd_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&fd_addr)
      .cloned()
    {
      return Ok(meta);
    }

    let (cluster, resource) = ((fd_addr >> 22) & 0x3FF, fd_addr & 0x3FFFFF);
    let _ = cluster;
    let offset = sfd_offset(&self.descriptor, resource);

    let fd_data = self.source.read_bytes_at(offset, FD_SIZE as usize)?;
    let meta_data = &fd_data[FD_META_OFFSET as usize..];
    let metadata = VmfsFileMetadata::parse(meta_data)?;

    self
      .fd_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .insert(fd_addr, metadata.clone());
    Ok(metadata)
  }

  fn read_directory(
    &self, fd_addr: u32, metadata: &VmfsFileMetadata,
  ) -> Result<Vec<NamespaceDirectoryEntry>> {
    let (cluster, resource) = ((fd_addr >> 22) & 0x3FF, fd_addr & 0x3FFFFF);
    let _ = cluster;
    let offset = sfd_offset(&self.descriptor, resource);

    let fd_data = self.source.read_bytes_at(offset, FD_SIZE as usize)?;
    let data_area = &fd_data[FD_DATA_OFFSET as usize..];

    let num_entries = metadata.file_length as usize / DIR_ENTRY_SIZE;
    let mut entries = Vec::new();

    for i in 0..num_entries {
      let entry_offset = i * DIR_ENTRY_SIZE;
      if entry_offset + DIR_ENTRY_SIZE > data_area.len() {
        break;
      }

      let entry = &data_area[entry_offset..entry_offset + DIR_ENTRY_SIZE];
      let desc_type = read_u32_le(entry, 0)?;
      let desc_addr = read_u32_le(entry, 4)?;

      if desc_addr == 0 {
        continue;
      }

      let name_bytes = &entry[0xC..0xC + FS3_MAX_FILE_NAME_LENGTH];
      let name =
        String::from_utf8_lossy(name_bytes.split(|&b| b == 0).next().unwrap_or(b"")).to_string();

      if name.is_empty() {
        continue;
      }

      let kind = match desc_type {
        FS3_DESCRIPTOR_TYPE_DIRECTORY => NamespaceNodeKind::Directory,
        FS3_DESCRIPTOR_TYPE_SYMLINK => NamespaceNodeKind::Symlink,
        _ => NamespaceNodeKind::File,
      };

      entries.push(NamespaceDirectoryEntry::new(
        name,
        NamespaceNodeId::from_u64(desc_addr as u64),
        kind,
      ));
    }

    Ok(entries)
  }

  fn open_file_data(&self, fd_addr: u32, metadata: &VmfsFileMetadata) -> Result<ByteSourceHandle> {
    let (cluster, resource) = ((fd_addr >> 22) & 0x3FF, fd_addr & 0x3FFFFF);
    let _ = cluster;
    let offset = sfd_offset(&self.descriptor, resource);

    let fd_data = self.source.read_bytes_at(offset, FD_SIZE as usize)?;
    let data_area = &fd_data[FD_DATA_OFFSET as usize..];

    let block_addrs: Vec<u32> = data_area
      .chunks_exact(4)
      .take(256)
      .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
      .filter(|&a| a != 0)
      .collect();

    Ok(Arc::new(VmfsFileDataSource {
      source: self.source.clone(),
      block_addrs: Arc::from(block_addrs.into_boxed_slice()),
      file_size: metadata.file_length,
      block_size: if metadata.block_size > 0 {
        metadata.block_size
      } else {
        1_048_576
      },
    }) as ByteSourceHandle)
  }
}

impl FileSystem for VmfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(ROOT_DIR_DESC_ADDR as u64)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let fd_addr = decode_node_id(node_id)?;
    let metadata = self.read_fd_metadata(fd_addr)?;

    Ok(
      NamespaceNodeRecord::new(
        node_id.clone(),
        metadata.node_kind(),
        if metadata.desc_type == FS3_DESCRIPTOR_TYPE_REGFILE {
          metadata.file_length
        } else {
          0
        },
      )
      .with_path(String::new()),
    )
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let fd_addr = decode_node_id(directory_id)?;
    let metadata = self.read_fd_metadata(fd_addr)?;
    self.read_directory(fd_addr, &metadata)
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let fd_addr = decode_node_id(file_id)?;
    let metadata = self.read_fd_metadata(fd_addr)?;

    if metadata.desc_type == FS3_DESCRIPTOR_TYPE_SYMLINK {
      let (cluster, resource) = ((fd_addr >> 22) & 0x3FF, fd_addr & 0x3FFFFF);
      let _ = cluster;
      let offset = sfd_offset(&self.descriptor, resource);
      let fd_data = self.source.read_bytes_at(offset, FD_SIZE as usize)?;
      let data = &fd_data[FD_DATA_OFFSET as usize..];
      return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
        data.to_vec().into_boxed_slice(),
      ))) as ByteSourceHandle);
    }

    self.open_file_data(fd_addr, &metadata)
  }
}

struct VmfsFileDataSource {
  source: ByteSourceHandle,
  block_addrs: Arc<[u32]>,
  file_size: u64,
  block_size: u64,
}

impl ByteSource for VmfsFileDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;

    while written < remaining {
      let block_index = (file_offset / self.block_size) as usize;
      let block_offset = (file_offset % self.block_size) as usize;

      let block_addr = if let Some(&addr) = self.block_addrs.get(block_index) {
        addr as u64
      } else {
        break;
      };

      let data = self
        .source
        .read_bytes_at(block_addr, self.block_size as usize)?;
      let step = remaining
        .saturating_sub(written)
        .min(data.len().saturating_sub(block_offset));
      if step == 0 {
        break;
      }

      buf[written..written + step].copy_from_slice(&data[block_offset..block_offset + step]);
      written += step;
      file_offset += step as u64;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.file_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::new(
      ByteSourceReadConcurrency::Serialized,
      ByteSourceSeekCost::Cheap,
    )
  }
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u32> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::invalid_format(
      "vmfs node identifiers must be 8 bytes",
    ));
  }
  let value = u64::from_le_bytes(
    bytes
      .try_into()
      .map_err(|_| Error::invalid_format("vmfs node id is truncated"))?,
  );
  u32::try_from(value).map_err(|_| Error::invalid_format("vmfs fd address is too large"))
}

crate::filesystems::driver::impl_file_system_data_source!(VmfsFileSystem);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_fs3_descriptor() {
    let mut data = vec![0u8; FS3_DESCRIPTOR_SIZE];
    data[4..8].copy_from_slice(&14u32.to_le_bytes());
    data[8] = 81;
    data[0x9D..0xA1].copy_from_slice(&512u32.to_le_bytes());
    data[0xA1..0xA9].copy_from_slice(&1_048_576u64.to_le_bytes());

    let desc = VmfsDescriptor::parse(&data).unwrap();
    assert_eq!(desc.major_version, 14);
    assert!(desc.is_vmfs5());
  }
}
