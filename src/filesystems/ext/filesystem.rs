//! Read-only ext2/ext3/ext4 filesystem surface.

use std::{
  collections::{HashMap, HashSet},
  sync::Arc,
};

use super::{
  DESCRIPTOR,
  superblock::{ExtGroupDescriptor, ExtSuperblock, INODE_FLAG_EXTENTS, read_group_descriptors},
};
use crate::{
  BytesDataSource, DataSource, DataSourceCapabilities, DataSourceHandle, Error, Result,
  SourceHints,
  filesystems::{
    DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, FileSystemNodeRecord,
  },
};

const ROOT_INODE: u32 = 2;

const MODE_TYPE_MASK: u16 = 0xF000;
const MODE_FIFO: u16 = 0x1000;
const MODE_CHAR_DEVICE: u16 = 0x2000;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_BLOCK_DEVICE: u16 = 0x6000;
const MODE_REGULAR: u16 = 0x8000;
const MODE_SYMLINK: u16 = 0xA000;
const MODE_SOCKET: u16 = 0xC000;

pub struct ExtFileSystem {
  source: DataSourceHandle,
  superblock: ExtSuperblock,
  nodes: HashMap<u64, ExtNode>,
  children: HashMap<u64, Vec<DirectoryEntry>>,
}

#[derive(Clone)]
struct ExtNode {
  record: FileSystemNodeRecord,
  inode: ExtInode,
}

#[derive(Clone)]
struct ExtInode {
  mode: u16,
  size: u64,
  flags: u32,
  block_data: [u8; 60],
}

struct ExtBuilder {
  source: DataSourceHandle,
  superblock: ExtSuperblock,
  groups: Arc<[ExtGroupDescriptor]>,
  nodes: HashMap<u64, ExtNode>,
  children: HashMap<u64, Vec<DirectoryEntry>>,
  visited_directories: HashSet<u32>,
}

#[derive(Clone)]
struct ExtByteRun {
  logical_offset: u64,
  physical_offset: Option<u64>,
  length: u64,
}

struct ExtBlockDataSource {
  source: DataSourceHandle,
  runs: Arc<[ExtByteRun]>,
  size: u64,
}

#[derive(Debug, Clone)]
struct ExtDirectoryEntryRecord {
  inode: u32,
  name: String,
}

impl ExtFileSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let superblock = ExtSuperblock::read(source.as_ref())?;
    let groups: Arc<[ExtGroupDescriptor]> =
      Arc::from(read_group_descriptors(source.as_ref(), &superblock)?.into_boxed_slice());
    let mut builder = ExtBuilder {
      source: source.clone(),
      superblock,
      groups: groups.clone(),
      nodes: HashMap::new(),
      children: HashMap::new(),
      visited_directories: HashSet::new(),
    };

    builder.ensure_node(ROOT_INODE)?;
    builder.populate_directory(ROOT_INODE)?;

    Ok(Self {
      source,
      superblock,
      nodes: builder.nodes,
      children: builder.children,
    })
  }

  fn build_data_source(&self, inode: &ExtInode) -> Result<DataSourceHandle> {
    if inode.size == 0 {
      return Ok(
        Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as DataSourceHandle,
      );
    }
    if inode.mode & MODE_TYPE_MASK == MODE_SYMLINK && inode.size <= 60 {
      let size = usize::try_from(inode.size)
        .map_err(|_| Error::InvalidRange("ext inline symlink size is too large".to_string()))?;
      return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
        &inode.block_data[..size],
      ))) as DataSourceHandle);
    }

    let runs = if inode.flags & INODE_FLAG_EXTENTS != 0 {
      self.read_extent_runs(&inode.block_data, inode.size)?
    } else {
      self.read_pointer_runs(inode)?
    };
    Ok(Arc::new(ExtBlockDataSource {
      source: self.source.clone(),
      runs: Arc::from(runs.into_boxed_slice()),
      size: inode.size,
    }) as DataSourceHandle)
  }

  fn read_extent_runs(&self, block_data: &[u8; 60], size: u64) -> Result<Vec<ExtByteRun>> {
    let mut runs = Vec::new();
    self.collect_extent_runs(block_data, &mut runs)?;
    runs.sort_by_key(|run| run.logical_offset);

    let required_length =
      size.div_ceil(self.superblock.block_size_u64()) * self.superblock.block_size_u64();
    let mut normalized = Vec::new();
    let mut expected_offset = 0u64;
    for run in runs {
      if run.logical_offset > expected_offset {
        normalized.push(ExtByteRun {
          logical_offset: expected_offset,
          physical_offset: None,
          length: run.logical_offset - expected_offset,
        });
      }
      expected_offset = run.logical_offset + run.length;
      normalized.push(run);
    }
    if expected_offset < required_length {
      normalized.push(ExtByteRun {
        logical_offset: expected_offset,
        physical_offset: None,
        length: required_length - expected_offset,
      });
    }
    Ok(normalized)
  }

  fn collect_extent_runs(&self, node: &[u8], runs: &mut Vec<ExtByteRun>) -> Result<()> {
    if node.len() < 12 {
      return Err(Error::InvalidFormat(
        "ext extent node is too small".to_string(),
      ));
    }
    let magic = le_u16(&node[0..2]);
    if magic != 0xF30A {
      return Err(Error::InvalidFormat(
        "ext extent header magic is invalid".to_string(),
      ));
    }

    let entries = usize::from(le_u16(&node[2..4]));
    let depth = le_u16(&node[6..8]);
    if depth == 0 {
      for index in 0..entries {
        let offset = 12 + index * 12;
        let extent = node
          .get(offset..offset + 12)
          .ok_or_else(|| Error::InvalidFormat("ext extent record is truncated".to_string()))?;
        let logical_block = u64::from(le_u32(&extent[0..4]));
        let length_raw = le_u16(&extent[4..6]);
        let block_count = u64::from(length_raw & 0x7FFF);
        if block_count == 0 {
          continue;
        }
        let length = block_count
          .checked_mul(self.superblock.block_size_u64())
          .ok_or_else(|| Error::InvalidRange("ext extent length overflow".to_string()))?;
        let physical_block = if length_raw & 0x8000 != 0 {
          None
        } else {
          Some(u64::from(le_u16(&extent[6..8])) << 32 | u64::from(le_u32(&extent[8..12])))
        };
        let physical_offset = physical_block
          .map(|block| self.superblock.block_offset(block))
          .transpose()?;
        runs.push(ExtByteRun {
          logical_offset: logical_block
            .checked_mul(self.superblock.block_size_u64())
            .ok_or_else(|| Error::InvalidRange("ext logical extent overflow".to_string()))?,
          physical_offset,
          length,
        });
      }
      return Ok(());
    }

    for index in 0..entries {
      let offset = 12 + index * 12;
      let extent_index = node
        .get(offset..offset + 12)
        .ok_or_else(|| Error::InvalidFormat("ext extent index is truncated".to_string()))?;
      let child_block =
        u64::from(le_u16(&extent_index[8..10])) << 32 | u64::from(le_u32(&extent_index[4..8]));
      let child = self.read_block(child_block)?;
      self.collect_extent_runs(&child, runs)?;
    }

    Ok(())
  }

  fn read_pointer_runs(&self, inode: &ExtInode) -> Result<Vec<ExtByteRun>> {
    let block_size = self.superblock.block_size_u64();
    let target_blocks = inode.size.div_ceil(block_size);
    let mut remaining = target_blocks;
    let mut blocks = Vec::<Option<u64>>::new();
    let pointers = inode
      .block_data
      .chunks_exact(4)
      .map(le_u32)
      .collect::<Vec<_>>();

    for pointer in pointers.iter().take(12) {
      append_pointer_tree(*pointer, 0, &mut remaining, &mut blocks, self)?;
      if remaining == 0 {
        break;
      }
    }
    if remaining != 0 {
      append_pointer_tree(pointers[12], 1, &mut remaining, &mut blocks, self)?;
    }
    if remaining != 0 {
      append_pointer_tree(pointers[13], 2, &mut remaining, &mut blocks, self)?;
    }
    if remaining != 0 {
      append_pointer_tree(pointers[14], 3, &mut remaining, &mut blocks, self)?;
    }
    if remaining != 0 {
      return Err(Error::InvalidFormat(
        "ext inode block pointers do not cover the recorded file size".to_string(),
      ));
    }

    compress_pointer_blocks(&blocks, block_size)
  }

  fn read_block(&self, block: u64) -> Result<Vec<u8>> {
    let block_size = usize::try_from(self.superblock.block_size_u64())
      .map_err(|_| Error::InvalidRange("ext block size is too large".to_string()))?;
    self
      .source
      .read_bytes_at(self.superblock.block_offset(block)?, block_size)
  }
}

impl FileSystem for ExtFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> FileSystemNodeId {
    FileSystemNodeId::from_u64(u64::from(ROOT_INODE))
  }

  fn node(&self, node_id: &FileSystemNodeId) -> Result<FileSystemNodeRecord> {
    let inode = decode_node_id(node_id)?;
    self
      .nodes
      .get(&inode)
      .map(|node| node.record.clone())
      .ok_or_else(|| Error::NotFound(format!("ext inode {inode} was not found")))
  }

  fn read_dir(&self, directory_id: &FileSystemNodeId) -> Result<Vec<DirectoryEntry>> {
    let inode = decode_node_id(directory_id)?;
    let node = self
      .nodes
      .get(&inode)
      .ok_or_else(|| Error::NotFound(format!("ext inode {inode} was not found")))?;
    if node.record.kind != FileSystemNodeKind::Directory {
      return Err(Error::NotFound(format!(
        "ext inode {inode} is not a directory"
      )));
    }

    Ok(self.children.get(&inode).cloned().unwrap_or_default())
  }

  fn open_file(&self, file_id: &FileSystemNodeId) -> Result<DataSourceHandle> {
    let inode = decode_node_id(file_id)?;
    let node = self
      .nodes
      .get(&inode)
      .ok_or_else(|| Error::NotFound(format!("ext inode {inode} was not found")))?;
    if node.record.kind != FileSystemNodeKind::File {
      return Err(Error::NotFound(format!(
        "ext inode {inode} is not a readable file"
      )));
    }
    self.build_data_source(&node.inode)
  }
}

impl ExtBuilder {
  fn ensure_node(&mut self, inode_number: u32) -> Result<()> {
    let key = u64::from(inode_number);
    if self.nodes.contains_key(&key) {
      return Ok(());
    }

    let inode = read_inode(
      self.source.as_ref(),
      &self.superblock,
      &self.groups,
      inode_number,
    )?;
    self.nodes.insert(
      key,
      ExtNode {
        record: FileSystemNodeRecord::new(
          FileSystemNodeId::from_u64(key),
          kind_from_mode(inode.mode),
          inode.size,
        ),
        inode,
      },
    );
    Ok(())
  }

  fn populate_directory(&mut self, inode_number: u32) -> Result<()> {
    if !self.visited_directories.insert(inode_number) {
      return Ok(());
    }
    self.ensure_node(inode_number)?;
    let inode = self
      .nodes
      .get(&u64::from(inode_number))
      .ok_or_else(|| Error::NotFound(format!("ext inode {inode_number} was not found")))?
      .inode
      .clone();
    if kind_from_mode(inode.mode) != FileSystemNodeKind::Directory {
      return Err(Error::InvalidFormat(format!(
        "ext inode {inode_number} is not a directory"
      )));
    }

    let data_source = ExtFileSystem {
      source: self.source.clone(),
      superblock: self.superblock,
      nodes: HashMap::new(),
      children: HashMap::new(),
    }
    .build_data_source(&inode)?;
    let entries = parse_directory_entries(&data_source.read_all()?)?;
    let mut children = Vec::new();

    for entry in entries {
      self.ensure_node(entry.inode)?;
      let child = self
        .nodes
        .get(&u64::from(entry.inode))
        .ok_or_else(|| Error::NotFound(format!("ext inode {} was not found", entry.inode)))?;
      children.push(DirectoryEntry::new(
        entry.name.clone(),
        child.record.id.clone(),
        child.record.kind,
      ));
      if child.record.kind == FileSystemNodeKind::Directory {
        self.populate_directory(entry.inode)?;
      }
    }

    children.sort_by(|left, right| left.name.cmp(&right.name));
    self.children.insert(u64::from(inode_number), children);
    Ok(())
  }
}

impl DataSource for ExtBlockDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.size || buf.is_empty() {
      return Ok(0);
    }

    let mut written = 0usize;
    let limit = usize::try_from(self.size - offset)
      .unwrap_or(usize::MAX)
      .min(buf.len());
    while written < limit {
      let absolute_offset = offset
        .checked_add(written as u64)
        .ok_or_else(|| Error::InvalidRange("ext file read overflow".to_string()))?;
      let run = self
        .runs
        .iter()
        .find(|run| {
          absolute_offset >= run.logical_offset && absolute_offset < run.logical_offset + run.length
        })
        .ok_or_else(|| {
          Error::InvalidFormat("ext block map does not cover the requested offset".to_string())
        })?;
      let run_offset = absolute_offset - run.logical_offset;
      let chunk = usize::try_from(run.length - run_offset)
        .unwrap_or(usize::MAX)
        .min(limit - written);
      if let Some(physical_offset) = run.physical_offset {
        self.source.read_exact_at(
          physical_offset
            .checked_add(run_offset)
            .ok_or_else(|| Error::InvalidRange("ext physical read overflow".to_string()))?,
          &mut buf[written..written + chunk],
        )?;
      } else {
        buf[written..written + chunk].fill(0);
      }
      written += chunk;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self.source.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    "filesystem.ext.block_map"
  }
}

fn read_inode(
  source: &dyn DataSource, superblock: &ExtSuperblock, groups: &[ExtGroupDescriptor],
  inode_number: u32,
) -> Result<ExtInode> {
  if inode_number == 0 {
    return Err(Error::InvalidFormat(
      "ext inode numbers start at 1".to_string(),
    ));
  }
  let inode_index = inode_number - 1;
  let group_index = usize::try_from(inode_index / superblock.inodes_per_group)
    .map_err(|_| Error::InvalidRange("ext inode group index is too large".to_string()))?;
  let index_within_group = inode_index % superblock.inodes_per_group;
  let descriptor = groups.get(group_index).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "ext inode {inode_number} group descriptor is missing"
    ))
  })?;

  let inode_offset = descriptor
    .inode_table_block
    .checked_mul(superblock.block_size_u64())
    .and_then(|offset| {
      offset.checked_add(u64::from(index_within_group) * u64::from(superblock.inode_size))
    })
    .ok_or_else(|| Error::InvalidRange("ext inode offset overflow".to_string()))?;
  let inode_size = usize::from(superblock.inode_size);
  let inode = source.read_bytes_at(inode_offset, inode_size)?;
  if inode.len() < 128 {
    return Err(Error::InvalidFormat("ext inode is too small".to_string()));
  }

  let mut block_data = [0u8; 60];
  block_data.copy_from_slice(&inode[40..100]);
  let size_lo = u64::from(le_u32(&inode[4..8]));
  let size_high = u64::from(le_u32(&inode[108..112]));
  let size = size_lo | (size_high << 32);

  Ok(ExtInode {
    mode: le_u16(&inode[0..2]),
    size,
    flags: le_u32(&inode[32..36]),
    block_data,
  })
}

fn append_pointer_tree(
  pointer: u32, depth: u8, remaining: &mut u64, blocks: &mut Vec<Option<u64>>,
  file_system: &ExtFileSystem,
) -> Result<()> {
  if *remaining == 0 {
    return Ok(());
  }

  if depth == 0 {
    blocks.push((pointer != 0).then_some(u64::from(pointer)));
    *remaining -= 1;
    return Ok(());
  }

  let pointers_per_block = file_system.superblock.block_size_u64() / 4;
  if pointer == 0 {
    let holes = pointers_per_block.pow(u32::from(depth)).min(*remaining);
    blocks.extend((0..holes).map(|_| None));
    *remaining -= holes;
    return Ok(());
  }

  let bytes = file_system.read_block(u64::from(pointer))?;
  for child in bytes.chunks_exact(4) {
    if *remaining == 0 {
      break;
    }
    append_pointer_tree(le_u32(child), depth - 1, remaining, blocks, file_system)?;
  }

  Ok(())
}

fn compress_pointer_blocks(blocks: &[Option<u64>], block_size: u64) -> Result<Vec<ExtByteRun>> {
  let mut runs = Vec::new();
  let mut logical_offset = 0u64;
  let mut index = 0usize;

  while index < blocks.len() {
    let current = blocks[index];
    let mut count = 1usize;
    while index + count < blocks.len() {
      match (current, blocks[index + count]) {
        (None, None) => {
          count += 1;
        }
        (Some(block), Some(next)) if next == block + count as u64 => {
          count += 1;
        }
        _ => break,
      }
    }

    runs.push(ExtByteRun {
      logical_offset,
      physical_offset: current.map(|block| block * block_size),
      length: u64::try_from(count)
        .unwrap_or(u64::MAX)
        .checked_mul(block_size)
        .ok_or_else(|| Error::InvalidRange("ext block run length overflow".to_string()))?,
    });
    logical_offset = logical_offset
      .checked_add(
        u64::try_from(count)
          .unwrap_or(u64::MAX)
          .checked_mul(block_size)
          .ok_or_else(|| Error::InvalidRange("ext logical run offset overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange("ext logical run offset overflow".to_string()))?;
    index += count;
  }

  Ok(runs)
}

fn parse_directory_entries(bytes: &[u8]) -> Result<Vec<ExtDirectoryEntryRecord>> {
  let mut entries = Vec::new();
  let mut offset = 0usize;

  while offset + 8 <= bytes.len() {
    let inode = le_u32(&bytes[offset..offset + 4]);
    let rec_len = usize::from(le_u16(&bytes[offset + 4..offset + 6]));
    if rec_len < 8 || offset + rec_len > bytes.len() {
      return Err(Error::InvalidFormat(
        "ext directory entry length is invalid".to_string(),
      ));
    }

    let name_len = usize::from(bytes[offset + 6]);
    if 8 + name_len > rec_len {
      return Err(Error::InvalidFormat(
        "ext directory entry name exceeds its record length".to_string(),
      ));
    }

    if inode != 0 {
      let name = String::from_utf8_lossy(&bytes[offset + 8..offset + 8 + name_len]).to_string();
      if name != "." && name != ".." {
        entries.push(ExtDirectoryEntryRecord { inode, name });
      }
    }

    offset += rec_len;
  }

  Ok(entries)
}

fn kind_from_mode(mode: u16) -> FileSystemNodeKind {
  match mode & MODE_TYPE_MASK {
    MODE_DIRECTORY => FileSystemNodeKind::Directory,
    MODE_SYMLINK => FileSystemNodeKind::Symlink,
    MODE_REGULAR => FileSystemNodeKind::File,
    MODE_FIFO | MODE_CHAR_DEVICE | MODE_BLOCK_DEVICE | MODE_SOCKET => FileSystemNodeKind::Special,
    _ => FileSystemNodeKind::Special,
  }
}

fn decode_node_id(node_id: &FileSystemNodeId) -> Result<u64> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::InvalidSourceReference(
      "ext node identifiers must be encoded as 8-byte little-endian values".to_string(),
    ));
  }
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  Ok(u64::from_le_bytes(raw))
}

fn le_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_le_bytes(raw)
}

fn le_u32(bytes: &[u8]) -> u32 {
  let mut raw = [0u8; 4];
  raw.copy_from_slice(bytes);
  u32::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_inode_modes() {
    assert_eq!(
      kind_from_mode(MODE_DIRECTORY),
      FileSystemNodeKind::Directory
    );
    assert_eq!(kind_from_mode(MODE_SYMLINK), FileSystemNodeKind::Symlink);
    assert_eq!(kind_from_mode(MODE_REGULAR), FileSystemNodeKind::File);
  }
}
