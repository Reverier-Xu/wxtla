use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR,
  constants::{
    BTREE_SIG_V4, BTREE_SIG_V5, DIR_LEAF_OFFSET, FILETYPE_BLOCK_DEVICE, FILETYPE_CHAR_DEVICE,
    FILETYPE_DIR, FILETYPE_FIFO, FILETYPE_MASK, FILETYPE_REGULAR, FILETYPE_SOCKET,
    FILETYPE_SYMLINK, FORK_BTREE, FORK_EXTENTS, FORK_INLINE, INOBT_SIG_V4, INOBT_SIG_V5,
    INODES_PER_CHUNK, XFS_MAX_INODE_NUMBER,
  },
  data_source::XfsExtentDataSource,
  directory::{XfsDirEntry, parse_block_directory, parse_shortform_directory},
  extent::{XfsExtent, normalize_sparse_extents, parse_extent_records},
  inode::XfsInode,
  io::{be_u16, be_u32, be_u64, read_exact_at, read_slice},
  superblock::XfsSuperblock,
};
use crate::{
  ByteSourceHandle, BytesDataSource, Error, Result, SourceHints,
  filesystems::{
    FileSystem, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord,
  },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfsNodeDetails {
  pub mode: u16,
  pub uid: u32,
  pub gid: u32,
  pub link_count: u32,
  pub fork_type: u8,
}

#[derive(Clone, Debug)]
struct XfsAgi {
  root: u32,
  level: u32,
}

pub struct XfsFileSystem {
  source: ByteSourceHandle,
  superblock: XfsSuperblock,
  inode_chunk_cache: Mutex<HashMap<u64, Arc<[u32]>>>,
}

impl XfsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let superblock = XfsSuperblock::read(source.as_ref())?;
    Ok(Self {
      source,
      superblock,
      inode_chunk_cache: Mutex::new(HashMap::new()),
    })
  }

  pub fn node_details(&self, node_id: &NamespaceNodeId) -> Result<XfsNodeDetails> {
    let inode = self.read_inode(decode_node_id(node_id)?)?;

    Ok(XfsNodeDetails {
      mode: inode.mode,
      uid: inode.uid,
      gid: inode.gid,
      link_count: inode.nlink,
      fork_type: inode.fork_type,
    })
  }

  pub fn symlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    let inode_number = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_number)?;
    if !inode.is_symlink() {
      return Ok(None);
    }
    Ok(Some(self.read_symlink_target(&inode, inode_number)?))
  }

  fn read_inode(&self, inode_number: u64) -> Result<XfsInode> {
    let offset = self.inode_offset(inode_number)?;
    let data = read_exact_at(
      self.source.as_ref(),
      offset,
      self.superblock.inode_size as usize,
    )?;
    XfsInode::parse(&data)
  }

  fn inode_offset(&self, inode_number: u64) -> Result<u64> {
    let inode_number = inode_number & XFS_MAX_INODE_NUMBER;
    let max_by_geometry = ((u64::from(self.superblock.ag_count))
      << self.superblock.relative_inode_bits)
      .saturating_sub(1);
    if inode_number == 0 || inode_number > max_by_geometry {
      return Err(Error::InvalidFormat(format!(
        "invalid xfs inode number: {inode_number}"
      )));
    }

    let ag_inode_bits = self.superblock.relative_inode_bits;
    let agno = inode_number >> ag_inode_bits;
    let agino_mask = (1u64 << ag_inode_bits) - 1;
    let agino = inode_number & agino_mask;
    let agbno = agino >> self.superblock.inodes_per_block_log2;
    let inode_index = agino & ((1u64 << self.superblock.inodes_per_block_log2) - 1);
    if agbno >= u64::from(self.superblock.ag_blocks) {
      return Err(Error::InvalidFormat(format!(
        "xfs inode block number is out of bounds: {agbno}"
      )));
    }
    if !self.inode_chunk_exists(agno, agino)? {
      return Err(Error::NotFound(format!(
        "xfs inode {inode_number} is not allocated"
      )));
    }

    let fs_block = u128::from(agno)
      .checked_mul(u128::from(self.superblock.ag_blocks))
      .and_then(|value| value.checked_add(u128::from(agbno)))
      .ok_or_else(|| Error::InvalidRange("xfs inode block overflow".to_string()))?;
    let offset = fs_block
      .checked_mul(u128::from(self.superblock.block_size))
      .and_then(|value| {
        value.checked_add(u128::from(inode_index) * u128::from(self.superblock.inode_size))
      })
      .ok_or_else(|| Error::InvalidRange("xfs inode offset overflow".to_string()))?;
    u64::try_from(offset).map_err(|_| Error::InvalidRange("xfs inode offset overflow".to_string()))
  }

  fn inode_chunk_exists(&self, agno: u64, agino: u64) -> Result<bool> {
    let chunk_starts = self.load_inode_chunk_starts(agno)?;
    let agino = u32::try_from(agino)
      .map_err(|_| Error::InvalidRange("xfs AG inode index is too large".to_string()))?;
    let Some(index) = chunk_starts
      .partition_point(|startino| *startino <= agino)
      .checked_sub(1)
    else {
      return Ok(false);
    };
    let startino = u64::from(chunk_starts[index]);

    Ok(u64::from(agino) < startino.saturating_add(INODES_PER_CHUNK))
  }

  fn load_inode_chunk_starts(&self, agno: u64) -> Result<Arc<[u32]>> {
    if let Some(chunk_starts) = self
      .inode_chunk_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&agno)
      .cloned()
    {
      return Ok(chunk_starts);
    }

    let agi = self.read_agi(agno)?;
    let loaded = if agi.root == 0 || agi.level == 0 {
      Arc::<[u32]>::from(Vec::<u32>::new().into_boxed_slice())
    } else {
      let mut chunk_starts = Vec::new();
      self.collect_inode_chunk_starts(agno, u64::from(agi.root), 0, &mut chunk_starts)?;
      chunk_starts.sort_unstable();
      chunk_starts.dedup();
      Arc::from(chunk_starts.into_boxed_slice())
    };

    let mut cache = self
      .inode_chunk_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(chunk_starts) = cache.get(&agno).cloned() {
      return Ok(chunk_starts);
    }
    cache.insert(agno, loaded.clone());

    Ok(loaded)
  }

  fn read_agi(&self, agno: u64) -> Result<XfsAgi> {
    let ag_start = u128::from(agno)
      .checked_mul(u128::from(self.superblock.ag_blocks))
      .and_then(|value| value.checked_mul(u128::from(self.superblock.block_size)))
      .ok_or_else(|| Error::InvalidRange("xfs AG offset overflow".to_string()))?;
    let agi_offset = ag_start
      .checked_add(u128::from(self.superblock.sector_size) * 2)
      .ok_or_else(|| Error::InvalidRange("xfs AGI offset overflow".to_string()))?;
    let agi = read_exact_at(
      self.source.as_ref(),
      u64::try_from(agi_offset)
        .map_err(|_| Error::InvalidRange("xfs AGI offset overflow".to_string()))?,
      self.superblock.sector_size as usize,
    )?;
    if &agi[0..4] != b"XAGI" {
      return Err(Error::InvalidFormat(
        "invalid xfs AGI signature".to_string(),
      ));
    }

    Ok(XfsAgi {
      root: be_u32(&agi[20..24]),
      level: be_u32(&agi[24..28]),
    })
  }

  fn collect_inode_chunk_starts(
    &self, agno: u64, agbno: u64, depth: usize, out: &mut Vec<u32>,
  ) -> Result<()> {
    if depth > 128 {
      return Err(Error::InvalidFormat(
        "xfs inode btree recursion depth exceeded".to_string(),
      ));
    }

    let fs_block = u128::from(agno)
      .checked_mul(u128::from(self.superblock.ag_blocks))
      .and_then(|value| value.checked_add(u128::from(agbno)))
      .ok_or_else(|| Error::InvalidRange("xfs inode btree block overflow".to_string()))?;
    let block = read_exact_at(
      self.source.as_ref(),
      u64::try_from(fs_block * u128::from(self.superblock.block_size))
        .map_err(|_| Error::InvalidRange("xfs inode btree offset overflow".to_string()))?,
      self.superblock.block_size as usize,
    )?;

    let signature = &block[0..4];
    let header_size = if signature == INOBT_SIG_V5 {
      56usize
    } else if signature == INOBT_SIG_V4 {
      16usize
    } else {
      return Err(Error::InvalidFormat(
        "unsupported xfs inode btree signature".to_string(),
      ));
    };

    let level = be_u16(&block[4..6]);
    let nrecs = be_u16(&block[6..8]) as usize;
    if level == 0 {
      for index in 0..nrecs {
        let record = read_slice(&block, header_size + index * 16, 16)?;
        out.push(be_u32(&record[0..4]));
      }
      return Ok(());
    }

    let records_data_size = block.len() - header_size;
    let pairs = records_data_size / 8;
    if nrecs > pairs {
      return Err(Error::InvalidFormat(
        "invalid xfs inode btree record count".to_string(),
      ));
    }

    for index in 0..nrecs {
      let ptr_offset = header_size + (pairs + index) * 4;
      let child = u64::from(be_u32(read_slice(&block, ptr_offset, 4)?));
      self.collect_inode_chunk_starts(agno, child, depth + 1, out)?;
    }

    Ok(())
  }

  fn read_symlink_target(&self, inode: &XfsInode, inode_number: u64) -> Result<String> {
    let data = if inode.fork_type == FORK_INLINE {
      inode
        .inline_data
        .clone()
        .ok_or_else(|| Error::InvalidFormat("missing inline xfs symlink data".to_string()))?
    } else {
      self
        .open_inode_data_source(inode_number, inode)?
        .read_all()?
    };
    let end = data
      .iter()
      .position(|byte| *byte == 0)
      .unwrap_or(data.len());
    let target = String::from_utf8_lossy(&data[..end]).to_string();
    if target.is_empty() {
      return Err(Error::InvalidFormat(
        "xfs symlink target is empty".to_string(),
      ));
    }
    Ok(target)
  }

  fn read_dir_entries(&self, inode: &XfsInode) -> Result<Vec<XfsDirEntry>> {
    if !inode.is_dir() {
      return Err(Error::InvalidFormat(
        "xfs inode is not a directory".to_string(),
      ));
    }

    let mut entries = match inode.fork_type {
      FORK_INLINE => {
        let data = inode.inline_data.as_ref().ok_or_else(|| {
          Error::InvalidFormat("missing xfs shortform directory data".to_string())
        })?;
        parse_shortform_directory(data, self.superblock.has_ftype())?
      }
      FORK_EXTENTS | FORK_BTREE => self.parse_extent_dir(inode)?,
      other => {
        return Err(Error::InvalidFormat(format!(
          "unsupported xfs directory fork type: {other}"
        )));
      }
    };

    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
  }

  fn parse_extent_dir(&self, inode: &XfsInode) -> Result<Vec<XfsDirEntry>> {
    let extents = self.read_data_extents(inode, false)?;
    let mut entries = Vec::new();

    for extent in extents {
      if extent.logical_block >= DIR_LEAF_OFFSET || extent.is_sparse || extent.number_of_blocks == 0
      {
        continue;
      }

      let extent_offset = extent
        .physical_block
        .checked_mul(self.superblock.block_size as u64)
        .ok_or_else(|| Error::InvalidRange("xfs directory extent offset overflow".to_string()))?;
      let extent_size = extent
        .number_of_blocks
        .checked_mul(self.superblock.block_size as u64)
        .ok_or_else(|| Error::InvalidRange("xfs directory extent size overflow".to_string()))?;
      let logical_base = extent
        .logical_block
        .checked_mul(self.superblock.block_size as u64)
        .ok_or_else(|| Error::InvalidRange("xfs directory logical offset overflow".to_string()))?;

      let mut rel = 0u64;
      let dir_block_size = self.superblock.dir_block_size as u64;
      while rel + dir_block_size <= extent_size {
        let logical_offset = logical_base.checked_add(rel).ok_or_else(|| {
          Error::InvalidRange("xfs directory logical offset overflow".to_string())
        })?;
        if logical_offset >= DIR_LEAF_OFFSET {
          return Ok(entries);
        }

        let block = read_exact_at(
          self.source.as_ref(),
          extent_offset + rel,
          self.superblock.dir_block_size as usize,
        )?;
        parse_block_directory(&block, self.superblock.has_ftype(), &mut entries)?;
        rel += dir_block_size;
      }
    }

    Ok(entries)
  }

  fn read_data_extents(&self, inode: &XfsInode, add_sparse: bool) -> Result<Vec<XfsExtent>> {
    let mut extents = match inode.fork_type {
      FORK_INLINE => Vec::new(),
      FORK_EXTENTS => parse_extent_records(&inode.data_fork, inode.nextents as usize)?,
      FORK_BTREE => self.parse_extent_btree_root(&inode.data_fork)?,
      other => {
        return Err(Error::InvalidFormat(format!(
          "unsupported xfs data fork type: {other}"
        )));
      }
    };

    for extent in &mut extents {
      if extent.is_sparse || extent.number_of_blocks == 0 {
        continue;
      }
      extent.physical_block = self.fsblock_to_absolute_block(extent.physical_block)?;
    }

    extents.sort_by_key(|extent| extent.logical_block);
    if !add_sparse {
      return Ok(extents);
    }
    normalize_sparse_extents(extents, self.superblock.block_size as u64, inode.size)
  }

  fn parse_extent_btree_root(&self, data: &[u8]) -> Result<Vec<XfsExtent>> {
    if data.len() < 4 {
      return Err(Error::InvalidFormat(
        "xfs btree root is too small".to_string(),
      ));
    }

    let level = be_u16(&data[0..2]);
    let nrecs = be_u16(&data[2..4]) as usize;
    let records = &data[4..];
    let mut extents = Vec::new();
    if level == 0 {
      extents.extend(parse_extent_records(records, nrecs)?);
      return Ok(extents);
    }

    let pairs = records.len() / 16;
    if nrecs > pairs {
      return Err(Error::InvalidFormat(
        "invalid xfs btree root record count".to_string(),
      ));
    }

    let ptr_base = pairs * 8;
    for index in 0..nrecs {
      let block = be_u64(read_slice(records, ptr_base + index * 8, 8)?);
      self.parse_extent_btree_node(block, 1, &mut extents)?;
    }

    Ok(extents)
  }

  fn parse_extent_btree_node(
    &self, block_number: u64, depth: usize, out: &mut Vec<XfsExtent>,
  ) -> Result<()> {
    if depth > 256 {
      return Err(Error::InvalidFormat(
        "xfs extent btree recursion depth exceeded".to_string(),
      ));
    }

    let absolute_block_number = self.fsblock_to_absolute_block(block_number)?;
    let block = read_exact_at(
      self.source.as_ref(),
      absolute_block_number
        .checked_mul(self.superblock.block_size as u64)
        .ok_or_else(|| Error::InvalidRange("xfs btree block offset overflow".to_string()))?,
      self.superblock.block_size as usize,
    )?;

    let expected = if self.superblock.format_version == 5 {
      BTREE_SIG_V5
    } else {
      BTREE_SIG_V4
    };
    if &block[0..4] != expected {
      return Err(Error::InvalidFormat(
        "unsupported xfs extent btree signature".to_string(),
      ));
    }

    let level = be_u16(&block[4..6]);
    let nrecs = be_u16(&block[6..8]) as usize;
    let header_size = if self.superblock.format_version == 5 {
      56
    } else {
      24
    };
    let records = read_slice(&block, header_size, block.len() - header_size)?;

    if level == 0 {
      out.extend(parse_extent_records(records, nrecs)?);
      return Ok(());
    }

    let pairs = records.len() / 16;
    if nrecs > pairs {
      return Err(Error::InvalidFormat(
        "invalid xfs branch btree record count".to_string(),
      ));
    }

    let ptr_base = pairs * 8;
    for index in 0..nrecs {
      let child = be_u64(read_slice(records, ptr_base + index * 8, 8)?);
      self.parse_extent_btree_node(child, depth + 1, out)?;
    }
    Ok(())
  }

  fn fsblock_to_absolute_block(&self, fsblock: u64) -> Result<u64> {
    let agno = fsblock >> self.superblock.relative_block_bits;
    if agno >= u64::from(self.superblock.ag_count) {
      return Err(Error::InvalidFormat(format!(
        "xfs filesystem block allocation group is out of bounds: {agno}"
      )));
    }
    let agbno = fsblock & ((1u64 << self.superblock.relative_block_bits) - 1);
    if agbno >= u64::from(self.superblock.ag_blocks) {
      return Err(Error::InvalidFormat(format!(
        "xfs relative block is out of bounds: {agbno}"
      )));
    }

    u64::try_from(
      u128::from(agno)
        .checked_mul(u128::from(self.superblock.ag_blocks))
        .and_then(|value| value.checked_add(u128::from(agbno)))
        .ok_or_else(|| Error::InvalidRange("xfs absolute block overflow".to_string()))?,
    )
    .map_err(|_| Error::InvalidRange("xfs absolute block overflow".to_string()))
  }

  fn open_inode_data_source(
    &self, _inode_number: u64, inode: &XfsInode,
  ) -> Result<ByteSourceHandle> {
    if inode.fork_type == FORK_INLINE {
      let data = inode
        .inline_data
        .as_ref()
        .ok_or_else(|| Error::InvalidFormat("missing xfs inline file data".to_string()))?;
      let len = data.len().min(inode.size as usize);
      return Ok(
        Arc::new(BytesDataSource::new(Arc::<[u8]>::from(&data[..len]))) as ByteSourceHandle,
      );
    }

    Ok(Arc::new(XfsExtentDataSource {
      source: Arc::clone(&self.source),
      block_size: self.superblock.block_size as u64,
      file_size: inode.size,
      extents: self.read_data_extents(inode, true)?,
    }) as ByteSourceHandle)
  }
}

impl FileSystem for XfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(self.superblock.root_ino)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let inode_number = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_number)?;
    Ok(NamespaceNodeRecord::new(
      NamespaceNodeId::from_u64(inode_number),
      kind_from_inode(&inode),
      if inode.is_dir() { 0 } else { inode.size },
    ))
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let inode = self.read_inode(decode_node_id(directory_id)?)?;
    let mut entries = self.read_dir_entries(&inode)?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let mut directory_entries = Vec::with_capacity(entries.len());
    for entry in entries {
      let child_inode = self.read_inode(entry.inode_number)?;
      directory_entries.push(NamespaceDirectoryEntry::new(
        entry.name,
        NamespaceNodeId::from_u64(entry.inode_number),
        kind_from_inode(&child_inode),
      ));
    }
    Ok(directory_entries)
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let inode_number = decode_node_id(file_id)?;
    let inode = self.read_inode(inode_number)?;
    if kind_from_inode(&inode) != NamespaceNodeKind::File {
      return Err(Error::NotFound(format!(
        "xfs inode {inode_number} is not a readable file"
      )));
    }
    self.open_inode_data_source(inode_number, &inode)
  }
}

fn kind_from_inode(inode: &XfsInode) -> NamespaceNodeKind {
  match inode.mode & FILETYPE_MASK {
    FILETYPE_DIR => NamespaceNodeKind::Directory,
    FILETYPE_SYMLINK => NamespaceNodeKind::Symlink,
    FILETYPE_REGULAR => NamespaceNodeKind::File,
    FILETYPE_FIFO | FILETYPE_CHAR_DEVICE | FILETYPE_BLOCK_DEVICE | FILETYPE_SOCKET => {
      NamespaceNodeKind::Special
    }
    _ => NamespaceNodeKind::Special,
  }
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u64> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::InvalidSourceReference(
      "xfs node identifiers must be encoded as 8-byte little-endian values".to_string(),
    ));
  }
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
  use std::{
    collections::HashMap,
    sync::{
      Arc, Mutex,
      atomic::{AtomicUsize, Ordering},
    },
  };

  use super::*;
  use crate::ByteSource;

  struct CountingDataSource {
    data: Vec<u8>,
    reads: AtomicUsize,
  }

  impl ByteSource for CountingDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      self.reads.fetch_add(1, Ordering::Relaxed);
      let offset = usize::try_from(offset)
        .map_err(|_| Error::InvalidRange("test read offset is too large".to_string()))?;
      if offset >= self.data.len() {
        return Ok(0);
      }
      let read = buf.len().min(self.data.len() - offset);
      buf[..read].copy_from_slice(&self.data[offset..offset + read]);
      Ok(read)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.data.len() as u64)
    }
  }

  #[test]
  fn caches_inode_chunk_lookups_per_allocation_group() {
    let source = Arc::new(CountingDataSource {
      data: synthetic_inode_btree_source(),
      reads: AtomicUsize::new(0),
    });
    let filesystem = XfsFileSystem {
      source: source.clone(),
      superblock: test_superblock(),
      inode_chunk_cache: Mutex::new(HashMap::new()),
    };

    assert_eq!(filesystem.inode_offset(64).unwrap(), 32_768);
    assert_eq!(source.reads.load(Ordering::Relaxed), 2);

    assert_eq!(filesystem.inode_offset(80).unwrap(), 40_960);
    assert_eq!(source.reads.load(Ordering::Relaxed), 2);
  }

  #[test]
  fn classifies_special_inodes_and_rejects_open_file() {
    let filesystem = XfsFileSystem {
      source: Arc::new(BytesDataSource::new(synthetic_special_inode_source())),
      superblock: test_superblock(),
      inode_chunk_cache: Mutex::new(HashMap::new()),
    };
    let node_id = NamespaceNodeId::from_u64(64);

    let node = filesystem.node(&node_id).unwrap();
    let error = filesystem.open_file(&node_id).err().unwrap();

    assert_eq!(node.kind, NamespaceNodeKind::Special);
    assert!(matches!(error, Error::NotFound(_)));
  }

  fn test_superblock() -> XfsSuperblock {
    XfsSuperblock {
      block_size: 4096,
      sector_size: 512,
      inode_size: 512,
      inodes_per_block_log2: 3,
      ag_blocks: 32,
      ag_count: 1,
      root_ino: 64,
      format_version: 5,
      secondary_feature_flags: 0,
      dir_block_size: 4096,
      relative_block_bits: 5,
      relative_inode_bits: 8,
    }
  }

  fn synthetic_inode_btree_source() -> Vec<u8> {
    let mut data = vec![0u8; 5 * 4096];

    data[1024..1028].copy_from_slice(b"XAGI");
    data[1044..1048].copy_from_slice(&4u32.to_be_bytes());
    data[1048..1052].copy_from_slice(&1u32.to_be_bytes());

    let block = &mut data[4 * 4096..5 * 4096];
    block[0..4].copy_from_slice(INOBT_SIG_V5);
    block[4..6].copy_from_slice(&0u16.to_be_bytes());
    block[6..8].copy_from_slice(&1u16.to_be_bytes());
    block[56..60].copy_from_slice(&64u32.to_be_bytes());

    data
  }

  fn synthetic_special_inode_source() -> Vec<u8> {
    let mut data = vec![0u8; 9 * 4096];
    data[1024..1028].copy_from_slice(b"XAGI");
    data[1044..1048].copy_from_slice(&4u32.to_be_bytes());
    data[1048..1052].copy_from_slice(&1u32.to_be_bytes());

    let block = &mut data[4 * 4096..5 * 4096];
    block[0..4].copy_from_slice(INOBT_SIG_V5);
    block[4..6].copy_from_slice(&0u16.to_be_bytes());
    block[6..8].copy_from_slice(&1u16.to_be_bytes());
    block[56..60].copy_from_slice(&64u32.to_be_bytes());

    let inode = &mut data[8 * 4096..8 * 4096 + 512];
    inode[0..2].copy_from_slice(b"IN");
    inode[2..4].copy_from_slice(&FILETYPE_CHAR_DEVICE.to_be_bytes());
    inode[4] = 2;
    inode[16..20].copy_from_slice(&1u32.to_be_bytes());

    data
  }
}

crate::filesystems::driver::impl_file_system_data_source!(XfsFileSystem);
