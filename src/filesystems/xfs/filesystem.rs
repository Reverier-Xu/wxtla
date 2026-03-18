use std::sync::Arc;

use super::{
  DESCRIPTOR,
  constants::{
    BTREE_SIG_V4, BTREE_SIG_V5, DIR_LEAF_OFFSET, FILETYPE_DIR, FILETYPE_MASK, FILETYPE_SYMLINK,
    FORK_BTREE, FORK_EXTENTS, FORK_INLINE, INOBT_SIG_V4, INOBT_SIG_V5, INODES_PER_CHUNK,
    XFS_MAX_INODE_NUMBER,
  },
  data_source::XfsExtentDataSource,
  directory::{XfsDirEntry, parse_block_directory, parse_shortform_directory},
  extent::{XfsExtent, normalize_sparse_extents, parse_extent_records},
  inode::XfsInode,
  io::{be_u16, be_u32, be_u64, read_exact_at, read_slice},
  superblock::XfsSuperblock,
};
use crate::{
  BytesDataSource, DataSourceHandle, Error, Result, SourceHints,
  filesystems::{
    DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, FileSystemNodeRecord,
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
  source: DataSourceHandle,
  superblock: XfsSuperblock,
}

impl XfsFileSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let superblock = XfsSuperblock::read(source.as_ref())?;
    Ok(Self { source, superblock })
  }

  pub fn node_details(&self, node_id: &FileSystemNodeId) -> Result<XfsNodeDetails> {
    let inode = self.read_inode(decode_node_id(node_id)?)?;

    Ok(XfsNodeDetails {
      mode: inode.mode,
      uid: inode.uid,
      gid: inode.gid,
      link_count: inode.nlink,
      fork_type: inode.fork_type,
    })
  }

  pub fn symlink_target(&self, node_id: &FileSystemNodeId) -> Result<Option<String>> {
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
    let agi = self.read_agi(agno)?;
    if agi.root == 0 || agi.level == 0 {
      return Ok(false);
    }
    self.search_inobt_for_agino(agno, u64::from(agi.root), agino, 0)
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

  fn search_inobt_for_agino(
    &self, agno: u64, agbno: u64, agino: u64, depth: usize,
  ) -> Result<bool> {
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
        let startino = u64::from(be_u32(&record[0..4]));
        if agino >= startino && agino < startino + INODES_PER_CHUNK {
          return Ok(true);
        }
      }
      return Ok(false);
    }

    let records_data_size = block.len() - header_size;
    let pairs = records_data_size / 8;
    if nrecs > pairs {
      return Err(Error::InvalidFormat(
        "invalid xfs inode btree record count".to_string(),
      ));
    }

    let mut record_index = 0usize;
    for index in 0..nrecs {
      let key = u64::from(be_u32(read_slice(&block, header_size + index * 4, 4)?));
      if agino < key {
        break;
      }
      record_index += 1;
    }

    if record_index == 0 {
      return Ok(false);
    }

    let ptr_offset = header_size + (pairs + record_index - 1) * 4;
    let child = u64::from(be_u32(read_slice(&block, ptr_offset, 4)?));
    self.search_inobt_for_agino(agno, child, agino, depth + 1)
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
  ) -> Result<DataSourceHandle> {
    if inode.fork_type == FORK_INLINE {
      let data = inode
        .inline_data
        .as_ref()
        .ok_or_else(|| Error::InvalidFormat("missing xfs inline file data".to_string()))?;
      let len = data.len().min(inode.size as usize);
      return Ok(
        Arc::new(BytesDataSource::new(Arc::<[u8]>::from(&data[..len]))) as DataSourceHandle,
      );
    }

    Ok(Arc::new(XfsExtentDataSource {
      source: Arc::clone(&self.source),
      block_size: self.superblock.block_size as u64,
      file_size: inode.size,
      extents: self.read_data_extents(inode, true)?,
    }) as DataSourceHandle)
  }
}

impl FileSystem for XfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> FileSystemNodeId {
    FileSystemNodeId::from_u64(self.superblock.root_ino)
  }

  fn node(&self, node_id: &FileSystemNodeId) -> Result<FileSystemNodeRecord> {
    let inode_number = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_number)?;
    Ok(FileSystemNodeRecord::new(
      FileSystemNodeId::from_u64(inode_number),
      kind_from_inode(&inode),
      if inode.is_dir() { 0 } else { inode.size },
    ))
  }

  fn read_dir(&self, directory_id: &FileSystemNodeId) -> Result<Vec<DirectoryEntry>> {
    let inode = self.read_inode(decode_node_id(directory_id)?)?;
    let mut entries = self.read_dir_entries(&inode)?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let mut directory_entries = Vec::with_capacity(entries.len());
    for entry in entries {
      let child_inode = self.read_inode(entry.inode_number)?;
      directory_entries.push(DirectoryEntry::new(
        entry.name,
        FileSystemNodeId::from_u64(entry.inode_number),
        kind_from_inode(&child_inode),
      ));
    }
    Ok(directory_entries)
  }

  fn open_file(&self, file_id: &FileSystemNodeId) -> Result<DataSourceHandle> {
    let inode_number = decode_node_id(file_id)?;
    let inode = self.read_inode(inode_number)?;
    if inode.is_dir() || inode.is_symlink() {
      return Err(Error::NotFound(format!(
        "xfs inode {inode_number} is not a readable file"
      )));
    }
    self.open_inode_data_source(inode_number, &inode)
  }
}

fn kind_from_inode(inode: &XfsInode) -> FileSystemNodeKind {
  let file_type = inode.mode & FILETYPE_MASK;
  if file_type == FILETYPE_DIR {
    FileSystemNodeKind::Directory
  } else if file_type == FILETYPE_SYMLINK {
    FileSystemNodeKind::Symlink
  } else {
    FileSystemNodeKind::File
  }
}

fn decode_node_id(node_id: &FileSystemNodeId) -> Result<u64> {
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
