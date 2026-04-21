use std::{
  collections::HashMap,
  io::Read,
  sync::{Arc, Mutex},
};

use flate2::read::ZlibDecoder;

use super::{
  CRAMFS_BLOCK_SIZE, CRAMFS_FLAG_DIRECT_POINTER, CRAMFS_FLAG_UNCOMPRESSED_BLOCK,
  CRAMFS_SUPERBLOCK_SIZE, DESCRIPTOR, read_slice, read_u32_le,
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceReadConcurrency,
  ByteSourceSeekCost, BytesDataSource, Error, NamespaceDirectoryEntry, NamespaceNodeId,
  NamespaceNodeKind, NamespaceNodeRecord, Result, filesystems::FileSystem,
};

const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;
#[allow(dead_code)]
const S_IFBLK: u16 = 0x6000;
#[allow(dead_code)]
const S_IFCHR: u16 = 0x2000;
#[allow(dead_code)]
const S_IFIFO: u16 = 0x1000;
#[allow(dead_code)]
const S_IFSOCK: u16 = 0xC000;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct CramFsInode {
  pub mode: u16,
  pub uid: u16,
  pub gid: u8,
  pub size: u32,
  pub name: String,
  pub data_offset: u32,
  pub inode_offset: u32,
}

impl CramFsInode {
  pub(crate) fn parse(bytes: &[u8], inode_offset: u32) -> Result<Self> {
    if bytes.len() < 12 {
      return Err(Error::invalid_format("cramfs inode is too short"));
    }

    let mode = u16::from_le_bytes(
      bytes[0..2]
        .try_into()
        .map_err(|_| Error::invalid_format("cramfs inode mode is truncated"))?,
    );
    let uid = u16::from_le_bytes(
      bytes[2..4]
        .try_into()
        .map_err(|_| Error::invalid_format("cramfs inode uid is truncated"))?,
    );

    let size_gid = u32::from_le_bytes(
      bytes[4..8]
        .try_into()
        .map_err(|_| Error::invalid_format("cramfs inode size/gid is truncated"))?,
    );
    let size = size_gid & 0x00FF_FFFF;
    let gid = ((size_gid >> 24) & 0xFF) as u8;

    let namelen_offset = u32::from_le_bytes(
      bytes[8..12]
        .try_into()
        .map_err(|_| Error::invalid_format("cramfs inode namelen/offset is truncated"))?,
    );
    let namelen = (namelen_offset & 0x3F) as usize;
    let data_offset = (namelen_offset >> 6) & 0x03FF_FFFF;

    let name_bytes_len = namelen
      .checked_mul(4)
      .ok_or_else(|| Error::invalid_range("cramfs name length overflow"))?;
    let name_bytes = read_slice(bytes, 12, name_bytes_len, "cramfs inode name")?;
    let name = String::from_utf8_lossy(name_bytes)
      .trim_end_matches('\0')
      .to_string();

    Ok(Self {
      mode,
      uid,
      gid,
      size,
      name,
      data_offset: data_offset << 2,
      inode_offset,
    })
  }

  pub(crate) fn inode_size(&self) -> usize {
    12 + self.namelen() * 4
  }

  fn namelen(&self) -> usize {
    let raw_len = self.name.len().div_ceil(4) * 4;
    raw_len.min(252) / 4
  }

  pub(crate) fn is_dir(&self) -> bool {
    (self.mode & S_IFMT) == S_IFDIR
  }

  pub(crate) fn is_reg(&self) -> bool {
    (self.mode & S_IFMT) == S_IFREG
  }

  pub(crate) fn is_symlink(&self) -> bool {
    (self.mode & S_IFMT) == S_IFLNK
  }

  pub(crate) fn node_kind(&self) -> NamespaceNodeKind {
    match self.mode & S_IFMT {
      S_IFDIR => NamespaceNodeKind::Directory,
      S_IFREG => NamespaceNodeKind::File,
      S_IFLNK => NamespaceNodeKind::Symlink,
      _ => NamespaceNodeKind::Special,
    }
  }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct CramFsSuperblock {
  pub size: u32,
  pub flags: u32,
  pub root_inode: CramFsInode,
}

impl CramFsSuperblock {
  pub(crate) fn parse(source: &dyn ByteSource) -> Result<Self> {
    let data = source.read_bytes_at(0, CRAMFS_SUPERBLOCK_SIZE)?;

    let magic = read_u32_le(&data, 0)?;
    if magic != super::CRAMFS_MAGIC {
      return Err(Error::invalid_format("invalid cramfs magic"));
    }

    let size = read_u32_le(&data, 4)?;
    let flags = read_u32_le(&data, 8)?;
    let sig = read_slice(&data, 16, 16, "cramfs signature")?;
    if sig != super::CRAMFS_SIGNATURE {
      return Err(Error::invalid_format("invalid cramfs signature"));
    }

    let root_inode = CramFsInode::parse(&data[48..], 0)?;

    Ok(Self {
      size,
      flags,
      root_inode,
    })
  }

  #[allow(dead_code)]
  pub(crate) fn block_size(&self) -> u64 {
    CRAMFS_BLOCK_SIZE
  }
}

struct CramFsBlockReader {
  source: ByteSourceHandle,
}

impl CramFsBlockReader {
  fn new(source: ByteSourceHandle) -> Self {
    Self { source }
  }

  fn read_block(&self, pointer: u32) -> Result<Vec<u8>> {
    let is_uncompressed = (pointer & CRAMFS_FLAG_UNCOMPRESSED_BLOCK) != 0;
    let is_direct = (pointer & CRAMFS_FLAG_DIRECT_POINTER) != 0;

    if is_direct {
      return Err(Error::unsupported(
        "cramfs direct pointers are not yet supported",
      ));
    }

    let offset = pointer & !(CRAMFS_FLAG_UNCOMPRESSED_BLOCK | CRAMFS_FLAG_DIRECT_POINTER);
    let data = self
      .source
      .read_bytes_at(offset as u64, CRAMFS_BLOCK_SIZE as usize)?;

    if is_uncompressed || data.is_empty() {
      return Ok(data);
    }

    let mut decoder = ZlibDecoder::new(&data[..]);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
  }

  fn read_file_data(&self, data_offset: u32, file_size: u32) -> Result<Vec<Vec<u8>>> {
    if file_size == 0 {
      return Ok(Vec::new());
    }

    let num_blocks = (file_size as u64).div_ceil(CRAMFS_BLOCK_SIZE);
    let num_blocks = num_blocks as usize;
    if num_blocks == 0 {
      return Ok(Vec::new());
    }

    let pointer_size = num_blocks
      .checked_mul(4)
      .ok_or_else(|| Error::invalid_range("cramfs block pointer array size overflow"))?;
    let pointers_raw = self
      .source
      .read_bytes_at(data_offset as u64, pointer_size)?;

    let mut pointers = Vec::with_capacity(num_blocks);
    for chunk in pointers_raw.chunks_exact(4) {
      let p = u32::from_le_bytes(
        chunk
          .try_into()
          .map_err(|_| Error::invalid_format("cramfs block pointer is truncated"))?,
      );
      pointers.push(p);
    }

    let mut blocks = Vec::with_capacity(num_blocks);
    let mut prev = data_offset + pointer_size as u32;

    for &pointer in &pointers {
      let raw_offset = pointer & !(CRAMFS_FLAG_UNCOMPRESSED_BLOCK | CRAMFS_FLAG_DIRECT_POINTER);
      let size = raw_offset.saturating_sub(prev) as usize;

      if size == 0 {
        blocks.push(vec![0u8; CRAMFS_BLOCK_SIZE as usize]);
      } else {
        let block_data = self.read_block(pointer)?;
        blocks.push(block_data);
      }

      prev = raw_offset;
    }

    Ok(blocks)
  }
}

pub struct CramFsFileSystem {
  #[allow(dead_code)]
  source: ByteSourceHandle,
  #[allow(dead_code)]
  superblock: CramFsSuperblock,
  block_reader: CramFsBlockReader,
  inode_cache: Mutex<HashMap<u32, CramFsInode>>,
}

impl CramFsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let superblock = CramFsSuperblock::parse(source.as_ref())?;
    let block_reader = CramFsBlockReader::new(source.clone());

    Ok(Self {
      source,
      superblock,
      block_reader,
      inode_cache: Mutex::new(HashMap::new()),
    })
  }

  pub fn symlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    let inode_offset = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_offset)?;
    if !inode.is_symlink() {
      return Ok(None);
    }

    let data = self
      .source
      .read_bytes_at(inode.data_offset as u64, inode.size as usize)?;
    Ok(Some(
      String::from_utf8_lossy(&data)
        .trim_end_matches('\0')
        .to_string(),
    ))
  }

  fn read_inode(&self, offset: u32) -> Result<CramFsInode> {
    if let Some(inode) = self
      .inode_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&offset)
      .cloned()
    {
      return Ok(inode);
    }

    let data = self.source.read_bytes_at(offset as u64, 256)?;
    let inode = CramFsInode::parse(&data, offset)?;

    self
      .inode_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .insert(offset, inode.clone());
    Ok(inode)
  }

  fn read_directory(&self, inode: &CramFsInode) -> Result<Vec<NamespaceDirectoryEntry>> {
    if !inode.is_dir() {
      return Err(Error::invalid_format(
        "cramfs directory reads require a directory inode",
      ));
    }

    let dir_data = self
      .source
      .read_bytes_at(inode.data_offset as u64, inode.size as usize)?;

    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < dir_data.len() {
      let remaining = &dir_data[offset..];
      let child = CramFsInode::parse(remaining, inode.data_offset + offset as u32)?;
      let child_size = child.inode_size();

      entries.push(NamespaceDirectoryEntry::new(
        child.name.clone(),
        NamespaceNodeId::from_u64(child.inode_offset as u64),
        child.node_kind(),
      ));

      offset += child_size;
    }

    Ok(entries)
  }

  fn open_file_data(&self, inode: &CramFsInode) -> Result<ByteSourceHandle> {
    if !inode.is_reg() {
      return Err(Error::invalid_format(
        "cramfs file content requires a regular file inode",
      ));
    }

    let blocks = self
      .block_reader
      .read_file_data(inode.data_offset, inode.size)?;

    Ok(Arc::new(CramFsFileDataSource {
      blocks: Arc::from(blocks.into_boxed_slice()),
      file_size: inode.size as u64,
    }) as ByteSourceHandle)
  }
}

impl FileSystem for CramFsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(0)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let inode_offset = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_offset)?;

    Ok(
      NamespaceNodeRecord::new(
        node_id.clone(),
        inode.node_kind(),
        if inode.is_reg() { inode.size as u64 } else { 0 },
      )
      .with_path(inode.name),
    )
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let inode_offset = decode_node_id(directory_id)?;
    let inode = self.read_inode(inode_offset)?;
    self.read_directory(&inode)
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let inode_offset = decode_node_id(file_id)?;
    let inode = self.read_inode(inode_offset)?;

    if inode.is_symlink() {
      let data = self
        .source
        .read_bytes_at(inode.data_offset as u64, inode.size as usize)?;
      return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
        data.into_boxed_slice(),
      ))) as ByteSourceHandle);
    }

    self.open_file_data(&inode)
  }
}

struct CramFsFileDataSource {
  blocks: Arc<[Vec<u8>]>,
  file_size: u64,
}

impl ByteSource for CramFsFileDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;

    while written < remaining {
      let block_index = (file_offset / CRAMFS_BLOCK_SIZE) as usize;
      let block_offset = (file_offset % CRAMFS_BLOCK_SIZE) as usize;

      let block = if let Some(block) = self.blocks.get(block_index) {
        block
      } else {
        break;
      };

      let step = remaining
        .saturating_sub(written)
        .min(block.len().saturating_sub(block_offset));
      if step == 0 {
        break;
      }

      buf[written..written + step].copy_from_slice(&block[block_offset..block_offset + step]);
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
      "cramfs node identifiers must be 8 bytes",
    ));
  }
  let value = u64::from_le_bytes(
    bytes
      .try_into()
      .map_err(|_| Error::invalid_format("cramfs node id is truncated"))?,
  );
  u32::try_from(value).map_err(|_| Error::invalid_format("cramfs inode offset is too large"))
}

crate::filesystems::driver::impl_file_system_data_source!(CramFsFileSystem);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_inode_fields() {
    let mut data = vec![0u8; 16];
    data[0..2].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
    data[2..4].copy_from_slice(&1000u16.to_le_bytes());
    data[4..8].copy_from_slice(&(100 | (5u32 << 24)).to_le_bytes());
    data[8..12].copy_from_slice(&1u32.to_le_bytes());
    data[12..16].copy_from_slice(b"test");

    let inode = CramFsInode::parse(&data, 0).unwrap();

    assert_eq!(inode.mode & S_IFMT, S_IFREG);
    assert_eq!(inode.uid, 1000);
    assert_eq!(inode.gid, 5);
    assert_eq!(inode.size, 100);
    assert_eq!(inode.name, "test");
    assert_eq!(inode.inode_size(), 16);
  }

  #[test]
  fn parses_directory_inode() {
    let mut data = vec![0u8; 16];
    data[0..2].copy_from_slice(&(S_IFDIR | 0o755).to_le_bytes());
    data[4..8].copy_from_slice(&(512u32).to_le_bytes());
    data[8..12].copy_from_slice(&(1u32 | (100u32 << 6)).to_le_bytes());
    data[12..16].copy_from_slice(b"dir\0");

    let inode = CramFsInode::parse(&data, 0).unwrap();

    assert!(inode.is_dir());
    assert_eq!(inode.name, "dir");
  }
}
