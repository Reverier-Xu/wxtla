use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR, DT_BLK, DT_CHR, DT_DIR, DT_FIFO, DT_LNK, DT_REG, DT_SOCK, FS_UFS1_MAGIC,
  FS_UFS2_MAGIC, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, SBLOCK_SEARCH, SBLOCKSIZE, UFS_MAXNAMLEN,
  UFS_NDADDR, UFS_NIADDR, UFS_ROOTINO, read_i32_le, read_i64_le, read_u16_le, read_u32_le,
  read_u64_le,
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceReadConcurrency,
  ByteSourceSeekCost, BytesDataSource, Error, NamespaceDirectoryEntry, NamespaceNodeId,
  NamespaceNodeKind, NamespaceNodeRecord, Result, filesystems::FileSystem,
};

const UFS1_INODE_SIZE: usize = 128;
const UFS2_INODE_SIZE: usize = 256;

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FfsSuperblock {
  is_ufs2: bool,
  block_size: u32,
  frag_size: u32,
  frag_per_block: i32,
  inodes_per_group: u32,
  blocks_per_group: i32,
  cylinder_groups: u32,
  block_offset: u64,
}

impl FfsSuperblock {
  fn parse(source: &dyn ByteSource) -> Result<(Self, u64)> {
    for &offset in SBLOCK_SEARCH {
      let Ok(data) = source.read_bytes_at(offset, SBLOCKSIZE) else {
        continue;
      };
      let magic = read_u32_le(&data, 0x21C)?;

      let is_ufs2 = match magic {
        FS_UFS1_MAGIC => false,
        FS_UFS2_MAGIC => true,
        _ => continue,
      };

      let block_size = read_i32_le(&data, 0x20)? as u32;

      if !(4096..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        continue;
      }

      let frag_size = read_i32_le(&data, 0x24)? as u32;
      let frag_per_block = read_i32_le(&data, 0x28)?;
      let inodes_per_group = read_u32_le(&data, 0x48)?;
      let blocks_per_group = read_i32_le(&data, 0x50)?;
      let cylinder_groups = read_u32_le(&data, 0x18)?;

      return Ok((
        Self {
          is_ufs2,
          block_size,
          frag_size,
          frag_per_block,
          inodes_per_group,
          blocks_per_group,
          cylinder_groups,
          block_offset: offset,
        },
        offset,
      ));
    }

    Err(Error::invalid_format("no valid ffs superblock found"))
  }

  fn inode_size(&self) -> usize {
    if self.is_ufs2 {
      UFS2_INODE_SIZE
    } else {
      UFS1_INODE_SIZE
    }
  }

  #[allow(dead_code)]
  fn block_to_offset(&self, block: i64) -> u64 {
    if block < 0 {
      return 0;
    }
    block as u64 * self.block_size as u64
  }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FfsInode {
  mode: u16,
  size: u64,
  nlink: u16,
  direct_blocks: [i64; UFS_NDADDR],
  indirect_blocks: [i64; UFS_NIADDR],
}

impl FfsInode {
  fn parse_ufs1(data: &[u8]) -> Result<Self> {
    if data.len() < UFS1_INODE_SIZE {
      return Err(Error::invalid_format("ffs ufs1 inode is too short"));
    }

    let mode = read_u16_le(data, 0)?;
    let nlink = read_u16_le(data, 2)? as u16;
    let size = read_u64_le(data, 8)?;

    let mut direct_blocks = [0i64; UFS_NDADDR];
    for (i, block) in direct_blocks.iter_mut().enumerate() {
      *block = read_i32_le(data, 40 + i * 4)? as i64;
    }

    let mut indirect_blocks = [0i64; UFS_NIADDR];
    for (i, block) in indirect_blocks.iter_mut().enumerate() {
      *block = read_i32_le(data, 88 + i * 4)? as i64;
    }

    Ok(Self {
      mode,
      size,
      nlink,
      direct_blocks,
      indirect_blocks,
    })
  }

  fn parse_ufs2(data: &[u8]) -> Result<Self> {
    if data.len() < UFS2_INODE_SIZE {
      return Err(Error::invalid_format("ffs ufs2 inode is too short"));
    }

    let mode = read_u16_le(data, 0)?;
    let nlink = read_u16_le(data, 2)? as u16;
    let size = read_u64_le(data, 16)?;

    let mut direct_blocks = [0i64; UFS_NDADDR];
    for (i, block) in direct_blocks.iter_mut().enumerate() {
      *block = read_i64_le(data, 112 + i * 8)?;
    }

    let mut indirect_blocks = [0i64; UFS_NIADDR];
    for (i, block) in indirect_blocks.iter_mut().enumerate() {
      *block = read_i64_le(data, 208 + i * 8)?;
    }

    Ok(Self {
      mode,
      size,
      nlink,
      direct_blocks,
      indirect_blocks,
    })
  }

  fn is_dir(&self) -> bool {
    (self.mode & S_IFMT) == S_IFDIR
  }

  fn is_reg(&self) -> bool {
    (self.mode & S_IFMT) == S_IFREG
  }

  fn is_symlink(&self) -> bool {
    (self.mode & S_IFMT) == S_IFLNK
  }

  fn node_kind(&self) -> NamespaceNodeKind {
    match self.mode & S_IFMT {
      S_IFDIR => NamespaceNodeKind::Directory,
      S_IFREG => NamespaceNodeKind::File,
      S_IFLNK => NamespaceNodeKind::Symlink,
      _ => NamespaceNodeKind::Special,
    }
  }

  fn block_count(&self, block_size: u32) -> usize {
    if self.size == 0 {
      return 0;
    }
    self.size.div_ceil(block_size as u64) as usize
  }

  fn collect_blocks(
    &self, block_size: u32, source: &dyn ByteSource, is_ufs2: bool,
  ) -> Result<Vec<u64>> {
    let num_blocks = self.block_count(block_size);
    let mut blocks = Vec::with_capacity(num_blocks);
    let addr_size = if is_ufs2 { 8usize } else { 4usize };
    let addrs_per_block = (block_size as usize) / addr_size;

    self.collect_blocks_recursive(
      block_size,
      source,
      is_ufs2,
      addrs_per_block,
      &mut blocks,
      num_blocks,
    )?;

    Ok(blocks)
  }

  #[allow(clippy::too_many_arguments)]
  fn collect_blocks_recursive(
    &self, block_size: u32, source: &dyn ByteSource, is_ufs2: bool, addrs_per_block: usize,
    blocks: &mut Vec<u64>, limit: usize,
  ) -> Result<()> {
    for &direct in &self.direct_blocks {
      if blocks.len() >= limit || direct == 0 {
        continue;
      }
      blocks.push(direct as u64 * block_size as u64);
    }

    if blocks.len() >= limit {
      return Ok(());
    }

    let nindir = addrs_per_block;
    for &indirect in &self.indirect_blocks {
      if blocks.len() >= limit || indirect == 0 {
        continue;
      }
      self.read_indirect_blocks(
        indirect, 0, block_size, source, is_ufs2, nindir, blocks, limit,
      )?;
    }

    Ok(())
  }

  #[allow(clippy::too_many_arguments)]
  fn read_indirect_blocks(
    &self, block: i64, level: usize, block_size: u32, source: &dyn ByteSource, is_ufs2: bool,
    nindir: usize, blocks: &mut Vec<u64>, limit: usize,
  ) -> Result<()> {
    if level >= UFS_NIADDR {
      return Ok(());
    }

    let data = source.read_bytes_at(block as u64 * block_size as u64, block_size as usize)?;

    let addr_size = if is_ufs2 { 8 } else { 4 };
    for i in (0..nindir).step_by(1) {
      if blocks.len() >= limit {
        break;
      }
      let offset = i * addr_size;
      if offset + addr_size > data.len() {
        break;
      }

      let addr: i64 = if is_ufs2 {
        read_i64_le(&data, offset)?
      } else {
        read_i32_le(&data, offset)? as i64
      };

      if addr == 0 {
        continue;
      }

      if level == 0 {
        blocks.push(addr as u64 * block_size as u64);
      } else {
        self.read_indirect_blocks(
          addr,
          level - 1,
          block_size,
          source,
          is_ufs2,
          nindir,
          blocks,
          limit,
        )?;
      }
    }

    Ok(())
  }
}

fn dir_entry_type_to_kind(d_type: u8) -> NamespaceNodeKind {
  match d_type {
    DT_DIR => NamespaceNodeKind::Directory,
    DT_REG => NamespaceNodeKind::File,
    DT_LNK => NamespaceNodeKind::Symlink,
    DT_BLK | DT_CHR | DT_FIFO | DT_SOCK => NamespaceNodeKind::Special,
    _ => NamespaceNodeKind::Special,
  }
}

fn read_direct_entries(data: &[u8]) -> Result<Vec<(u32, String, u8)>> {
  let mut entries = Vec::new();
  let mut offset = 0usize;

  while offset + 8 <= data.len() {
    let inode_num = u32::from_le_bytes(
      data[offset..offset + 4]
        .try_into()
        .map_err(|_| Error::invalid_format("ffs directory entry inode is truncated"))?,
    );
    let reclen = u16::from_le_bytes(
      data[offset + 4..offset + 6]
        .try_into()
        .map_err(|_| Error::invalid_format("ffs directory entry reclen is truncated"))?,
    ) as usize;

    if reclen == 0 {
      break;
    }

    let d_type = data[offset + 6];
    let namlen = data[offset + 7] as usize;

    if namlen > UFS_MAXNAMLEN || offset + 8 + namlen > data.len() {
      break;
    }

    let name = String::from_utf8_lossy(&data[offset + 8..offset + 8 + namlen]).to_string();

    if inode_num != 0 {
      entries.push((inode_num, name, d_type));
    }

    offset += reclen;
  }

  Ok(entries)
}

pub struct FfsFileSystem {
  source: ByteSourceHandle,
  superblock: FfsSuperblock,
  inode_cache: Mutex<HashMap<u32, FfsInode>>,
}

impl FfsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let (superblock, _) = FfsSuperblock::parse(source.as_ref())?;

    Ok(Self {
      source,
      superblock,
      inode_cache: Mutex::new(HashMap::new()),
    })
  }

  pub fn symlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    let inode_num = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_num)?;
    if !inode.is_symlink() {
      return Ok(None);
    }

    if inode.size < 256 {
      let blocks = inode.collect_blocks(
        self.superblock.block_size,
        self.source.as_ref(),
        self.superblock.is_ufs2,
      )?;
      if let Some(&block_offset) = blocks.first() {
        let data = self
          .source
          .read_bytes_at(block_offset, inode.size as usize)?;
        return Ok(Some(
          String::from_utf8_lossy(&data)
            .trim_end_matches('\0')
            .to_string(),
        ));
      }
    }
    Ok(None)
  }

  fn read_inode(&self, inode_num: u32) -> Result<FfsInode> {
    if let Some(inode) = self
      .inode_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&inode_num)
      .cloned()
    {
      return Ok(inode);
    }

    let inode = self.read_inode_disk(inode_num)?;

    self
      .inode_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .insert(inode_num, inode.clone());
    Ok(inode)
  }

  fn read_inode_disk(&self, inode_num: u32) -> Result<FfsInode> {
    let inodes_per_group = self.superblock.inodes_per_group;
    let cg = (inode_num / inodes_per_group) as usize;
    let cg_inode = (inode_num % inodes_per_group) as usize;

    if cg >= self.superblock.cylinder_groups as usize {
      return Err(Error::not_found(format!(
        "ffs inode {inode_num} is out of bounds"
      )));
    }

    let inode_size = self.superblock.inode_size();

    let cg_offset =
      cg as u64 * self.superblock.blocks_per_group as u64 * self.superblock.block_size as u64;

    let inode_offset = cg_offset + cg_inode as u64 * inode_size as u64;

    let data = self.source.read_bytes_at(inode_offset, inode_size)?;

    if self.superblock.is_ufs2 {
      FfsInode::parse_ufs2(&data)
    } else {
      FfsInode::parse_ufs1(&data)
    }
  }

  fn read_directory(&self, inode: &FfsInode) -> Result<Vec<NamespaceDirectoryEntry>> {
    if !inode.is_dir() {
      return Err(Error::invalid_format(
        "ffs directory reads require a directory inode",
      ));
    }

    let blocks = inode.collect_blocks(
      self.superblock.block_size,
      self.source.as_ref(),
      self.superblock.is_ufs2,
    )?;

    let mut entries = Vec::new();
    for &block_offset in &blocks {
      if block_offset == 0 {
        continue;
      }
      let data = self
        .source
        .read_bytes_at(block_offset, self.superblock.block_size as usize)?;
      let dir_entries = read_direct_entries(&data)?;
      for (ino, name, d_type) in dir_entries {
        entries.push(NamespaceDirectoryEntry::new(
          name,
          NamespaceNodeId::from_u64(ino as u64),
          dir_entry_type_to_kind(d_type),
        ));
      }
    }

    Ok(entries)
  }

  fn open_file_data(&self, inode: &FfsInode) -> Result<ByteSourceHandle> {
    if !inode.is_reg() {
      return Err(Error::invalid_format(
        "ffs file content requires a regular file inode",
      ));
    }

    let blocks = inode.collect_blocks(
      self.superblock.block_size,
      self.source.as_ref(),
      self.superblock.is_ufs2,
    )?;

    Ok(Arc::new(FfsFileDataSource {
      source: self.source.clone(),
      block_size: self.superblock.block_size,
      blocks: Arc::from(blocks.into_boxed_slice()),
      file_size: inode.size,
    }) as ByteSourceHandle)
  }
}

impl FileSystem for FfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(UFS_ROOTINO as u64)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let inode_num = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_num)?;

    Ok(
      NamespaceNodeRecord::new(
        node_id.clone(),
        inode.node_kind(),
        if inode.is_reg() { inode.size } else { 0 },
      )
      .with_path(String::new()),
    )
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let inode_num = decode_node_id(directory_id)?;
    let inode = self.read_inode(inode_num)?;
    self.read_directory(&inode)
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let inode_num = decode_node_id(file_id)?;
    let inode = self.read_inode(inode_num)?;

    if inode.is_symlink() {
      let blocks = inode.collect_blocks(
        self.superblock.block_size,
        self.source.as_ref(),
        self.superblock.is_ufs2,
      )?;
      if let Some(&block_offset) = blocks.first() {
        let data = self
          .source
          .read_bytes_at(block_offset, inode.size as usize)?;
        return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
          data.into_boxed_slice(),
        ))) as ByteSourceHandle);
      }
      return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
        Vec::<u8>::new().into_boxed_slice(),
      ))) as ByteSourceHandle);
    }

    self.open_file_data(&inode)
  }
}

struct FfsFileDataSource {
  source: ByteSourceHandle,
  block_size: u32,
  blocks: Arc<[u64]>,
  file_size: u64,
}

impl ByteSource for FfsFileDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;
    let bs = self.block_size as u64;

    while written < remaining {
      let block_index = (file_offset / bs) as usize;
      let block_offset = (file_offset % bs) as usize;

      let block_addr = if let Some(&addr) = self.blocks.get(block_index) {
        addr
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
      "ffs node identifiers must be 8 bytes",
    ));
  }
  let value = u64::from_le_bytes(
    bytes
      .try_into()
      .map_err(|_| Error::invalid_format("ffs node id is truncated"))?,
  );
  u32::try_from(value).map_err(|_| Error::invalid_format("ffs inode number is too large"))
}

crate::filesystems::driver::impl_file_system_data_source!(FfsFileSystem);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_direct_directory_entries() {
    let mut data = vec![0u8; 256];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..6].copy_from_slice(&12u16.to_le_bytes());
    data[6] = DT_DIR;
    data[7] = 3;
    data[8..11].copy_from_slice(b"tmp");

    data[12..16].copy_from_slice(&3u32.to_le_bytes());
    data[16..18].copy_from_slice(&12u16.to_le_bytes());
    data[18] = DT_REG;
    data[19] = 4;
    data[20..24].copy_from_slice(b"file");

    let entries = read_direct_entries(&data).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, 2);
    assert_eq!(entries[0].1, "tmp");
    assert_eq!(entries[0].2, DT_DIR);
    assert_eq!(entries[1].0, 3);
    assert_eq!(entries[1].1, "file");
    assert_eq!(entries[1].2, DT_REG);
  }

  #[test]
  fn parses_ufs2_inode() {
    let mut data = vec![0u8; UFS2_INODE_SIZE];
    data[0..2].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
    data[16..24].copy_from_slice(&1024u64.to_le_bytes());

    let inode = FfsInode::parse_ufs2(&data).unwrap();
    assert!(inode.is_reg());
    assert_eq!(inode.size, 1024);
  }

  #[test]
  fn parses_ufs1_inode() {
    let mut data = vec![0u8; UFS1_INODE_SIZE];
    data[0..2].copy_from_slice(&(S_IFDIR | 0o755).to_le_bytes());
    data[8..16].copy_from_slice(&512u64.to_le_bytes());

    let inode = FfsInode::parse_ufs1(&data).unwrap();
    assert!(inode.is_dir());
    assert_eq!(inode.size, 512);
  }
}
