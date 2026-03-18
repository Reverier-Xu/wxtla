//! Read-only FAT12/16/32 filesystem surface.

use std::{
  collections::{HashMap, HashSet},
  sync::Arc,
};

use super::{
  DESCRIPTOR,
  boot_sector::{FatBootSector, FatType},
};
use crate::{
  BytesDataSource, DataSource, DataSourceCapabilities, DataSourceHandle, Error, Result,
  SourceHints,
  filesystems::{
    DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, FileSystemNodeRecord,
  },
};

const ROOT_NODE_ID: u64 = 0;
const ATTR_LONG_NAME: u8 = 0x0F;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_LABEL: u8 = 0x08;

pub struct FatFileSystem {
  nodes: HashMap<u64, FatNode>,
  children: HashMap<u64, Vec<DirectoryEntry>>,
}

struct FatNode {
  record: FileSystemNodeRecord,
  data_source: Option<DataSourceHandle>,
}

struct FatBuilder {
  source: DataSourceHandle,
  boot_sector: FatBootSector,
  fat_table: FatTable,
  nodes: HashMap<u64, FatNode>,
  children: HashMap<u64, Vec<DirectoryEntry>>,
  next_node_id: u64,
}

#[derive(Clone)]
enum DirectorySource {
  Fixed { offset: u64, size: usize },
  Chain(Vec<u32>),
}

#[derive(Debug, Clone)]
struct FatDirectoryEntryRecord {
  name: String,
  kind: FileSystemNodeKind,
  start_cluster: u32,
  size: u64,
}

struct FatTable {
  fat_type: FatType,
  bytes: Arc<[u8]>,
}

enum FatClusterStatus {
  Next(u32),
  EndOfChain,
  Free,
  Bad,
}

struct FatChainDataSource {
  source: DataSourceHandle,
  cluster_offsets: Arc<[u64]>,
  cluster_size: usize,
  size: u64,
}

impl FatFileSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let boot_sector = FatBootSector::read(source.as_ref())?;
    let fat_offset = boot_sector.fat_offset(0)?;
    let fat_size = boot_sector.fat_size_bytes()?;
    let fat_table = FatTable {
      fat_type: boot_sector.fat_type,
      bytes: Arc::from(source.read_bytes_at(fat_offset, fat_size)?),
    };
    let mut builder = FatBuilder {
      source,
      boot_sector,
      fat_table,
      nodes: HashMap::new(),
      children: HashMap::new(),
      next_node_id: ROOT_NODE_ID + 1,
    };

    builder.nodes.insert(
      ROOT_NODE_ID,
      FatNode {
        record: FileSystemNodeRecord::new(
          FileSystemNodeId::from_u64(ROOT_NODE_ID),
          FileSystemNodeKind::Directory,
          0,
        ),
        data_source: None,
      },
    );
    let root_source = match builder.boot_sector.fat_type {
      FatType::Fat12 | FatType::Fat16 => DirectorySource::Fixed {
        offset: builder.boot_sector.root_dir_offset()?,
        size: builder.boot_sector.root_dir_size_bytes()?,
      },
      FatType::Fat32 => DirectorySource::Chain(
        builder.follow_cluster_chain(builder.boot_sector.root_cluster, None)?,
      ),
    };
    builder.populate_directory(ROOT_NODE_ID, root_source)?;

    Ok(Self {
      nodes: builder.nodes,
      children: builder.children,
    })
  }
}

impl FileSystem for FatFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> FileSystemNodeId {
    FileSystemNodeId::from_u64(ROOT_NODE_ID)
  }

  fn node(&self, node_id: &FileSystemNodeId) -> Result<FileSystemNodeRecord> {
    let node_id = decode_node_id(node_id)?;
    self
      .nodes
      .get(&node_id)
      .map(|node| node.record.clone())
      .ok_or_else(|| Error::NotFound(format!("fat node {node_id} was not found")))
  }

  fn read_dir(&self, directory_id: &FileSystemNodeId) -> Result<Vec<DirectoryEntry>> {
    let node_id = decode_node_id(directory_id)?;
    let node = self
      .nodes
      .get(&node_id)
      .ok_or_else(|| Error::NotFound(format!("fat node {node_id} was not found")))?;
    if node.record.kind != FileSystemNodeKind::Directory {
      return Err(Error::NotFound(format!(
        "fat node {node_id} is not a directory"
      )));
    }
    Ok(self.children.get(&node_id).cloned().unwrap_or_default())
  }

  fn open_file(&self, file_id: &FileSystemNodeId) -> Result<DataSourceHandle> {
    let node_id = decode_node_id(file_id)?;
    let node = self
      .nodes
      .get(&node_id)
      .ok_or_else(|| Error::NotFound(format!("fat node {node_id} was not found")))?;
    node
      .data_source
      .clone()
      .ok_or_else(|| Error::NotFound(format!("fat node {node_id} is not a readable file")))
  }
}

impl FatBuilder {
  fn populate_directory(&mut self, directory_id: u64, source: DirectorySource) -> Result<()> {
    let entries = self.read_directory(source)?;
    let mut children = Vec::with_capacity(entries.len());

    for entry in entries {
      let node_id = self.next_node_id;
      self.next_node_id = self
        .next_node_id
        .checked_add(1)
        .ok_or_else(|| Error::InvalidRange("fat node id overflow".to_string()))?;
      let (data_source, size) = if entry.kind == FileSystemNodeKind::Directory {
        (None, 0)
      } else if entry.size == 0 {
        (
          Some(
            Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as DataSourceHandle,
          ),
          0,
        )
      } else {
        let chain = self.follow_cluster_chain(entry.start_cluster, Some(entry.size))?;
        let cluster_offsets = chain
          .iter()
          .map(|cluster| self.boot_sector.cluster_offset(*cluster))
          .collect::<Result<Vec<_>>>()?;
        let data_source = Arc::new(FatChainDataSource {
          source: self.source.clone(),
          cluster_offsets: Arc::from(cluster_offsets.into_boxed_slice()),
          cluster_size: usize::try_from(self.boot_sector.cluster_size()?)
            .map_err(|_| Error::InvalidRange("fat cluster size is too large".to_string()))?,
          size: entry.size,
        }) as DataSourceHandle;
        (Some(data_source), entry.size)
      };

      self.nodes.insert(
        node_id,
        FatNode {
          record: FileSystemNodeRecord::new(FileSystemNodeId::from_u64(node_id), entry.kind, size),
          data_source,
        },
      );
      children.push(DirectoryEntry::new(
        entry.name.clone(),
        FileSystemNodeId::from_u64(node_id),
        entry.kind,
      ));

      if entry.kind == FileSystemNodeKind::Directory {
        let chain = self.follow_cluster_chain(entry.start_cluster, None)?;
        self.populate_directory(node_id, DirectorySource::Chain(chain))?;
      }
    }

    children.sort_by(|left, right| left.name.cmp(&right.name));
    self.children.insert(directory_id, children);
    Ok(())
  }

  fn read_directory(&self, source: DirectorySource) -> Result<Vec<FatDirectoryEntryRecord>> {
    let bytes = match source {
      DirectorySource::Fixed { offset, size } => self.source.read_bytes_at(offset, size)?,
      DirectorySource::Chain(chain) => self.read_cluster_chain_bytes(&chain)?,
    };

    parse_directory_entries(&bytes)
  }

  fn read_cluster_chain_bytes(&self, chain: &[u32]) -> Result<Vec<u8>> {
    let cluster_size = usize::try_from(self.boot_sector.cluster_size()?)
      .map_err(|_| Error::InvalidRange("fat cluster size is too large".to_string()))?;
    let mut bytes = Vec::with_capacity(cluster_size.saturating_mul(chain.len()));
    for cluster in chain {
      bytes.extend_from_slice(
        &self
          .source
          .read_bytes_at(self.boot_sector.cluster_offset(*cluster)?, cluster_size)?,
      );
    }
    Ok(bytes)
  }

  fn follow_cluster_chain(&self, start_cluster: u32, size_hint: Option<u64>) -> Result<Vec<u32>> {
    if let Some(size_hint) = size_hint
      && size_hint == 0
    {
      return Ok(Vec::new());
    }
    if start_cluster < 2 {
      return Err(Error::InvalidFormat(format!(
        "fat cluster chains must start at cluster 2 or later, got {start_cluster}"
      )));
    }

    let cluster_size = self.boot_sector.cluster_size()?;
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut cluster = start_cluster;
    let required_clusters = size_hint.map(|size| size.div_ceil(cluster_size));

    loop {
      if !visited.insert(cluster) {
        return Err(Error::InvalidFormat(format!(
          "fat cluster chain loops back to cluster {cluster}"
        )));
      }
      chain.push(cluster);

      if required_clusters.is_some_and(|required| chain.len() as u64 >= required) {
        break;
      }

      match self.fat_table.cluster_status(cluster)? {
        FatClusterStatus::Next(next_cluster) => {
          cluster = next_cluster;
        }
        FatClusterStatus::EndOfChain => {
          break;
        }
        FatClusterStatus::Free => {
          return Err(Error::InvalidFormat(format!(
            "fat cluster chain unexpectedly ends at free cluster {cluster}"
          )));
        }
        FatClusterStatus::Bad => {
          return Err(Error::InvalidFormat(format!(
            "fat cluster chain reaches bad cluster {cluster}"
          )));
        }
      }
    }

    if let Some(size_hint) = size_hint {
      let covered = u64::try_from(chain.len())
        .unwrap_or(u64::MAX)
        .checked_mul(cluster_size)
        .ok_or_else(|| Error::InvalidRange("fat cluster coverage overflow".to_string()))?;
      if covered < size_hint {
        return Err(Error::InvalidFormat(
          "fat cluster chain is shorter than the recorded file size".to_string(),
        ));
      }
    }

    Ok(chain)
  }
}

impl FatTable {
  fn cluster_status(&self, cluster: u32) -> Result<FatClusterStatus> {
    let value = match self.fat_type {
      FatType::Fat12 => {
        let offset = usize::try_from(
          (u64::from(cluster) * 3)
            .checked_div(2)
            .ok_or_else(|| Error::InvalidRange("fat12 offset overflow".to_string()))?,
        )
        .map_err(|_| Error::InvalidRange("fat12 offset is too large".to_string()))?;
        let slice = self.bytes.get(offset..offset + 2).ok_or_else(|| {
          Error::InvalidFormat(format!("fat12 table is truncated at cluster {cluster}"))
        })?;
        let pair = u16::from_le_bytes([slice[0], slice[1]]);
        if cluster & 1 == 0 {
          u32::from(pair & 0x0FFF)
        } else {
          u32::from(pair >> 4)
        }
      }
      FatType::Fat16 => {
        let offset = usize::try_from(u64::from(cluster) * 2)
          .map_err(|_| Error::InvalidRange("fat16 offset is too large".to_string()))?;
        let slice = self.bytes.get(offset..offset + 2).ok_or_else(|| {
          Error::InvalidFormat(format!("fat16 table is truncated at cluster {cluster}"))
        })?;
        u32::from(u16::from_le_bytes([slice[0], slice[1]]))
      }
      FatType::Fat32 => {
        let offset = usize::try_from(u64::from(cluster) * 4)
          .map_err(|_| Error::InvalidRange("fat32 offset is too large".to_string()))?;
        let slice = self.bytes.get(offset..offset + 4).ok_or_else(|| {
          Error::InvalidFormat(format!("fat32 table is truncated at cluster {cluster}"))
        })?;
        u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) & 0x0FFF_FFFF
      }
    };

    Ok(match self.fat_type {
      FatType::Fat12 => match value {
        0x000 => FatClusterStatus::Free,
        0x0FF7 => FatClusterStatus::Bad,
        0x0FF8..=0x0FFF => FatClusterStatus::EndOfChain,
        next => FatClusterStatus::Next(next),
      },
      FatType::Fat16 => match value {
        0x0000 => FatClusterStatus::Free,
        0xFFF7 => FatClusterStatus::Bad,
        0xFFF8..=0xFFFF => FatClusterStatus::EndOfChain,
        next => FatClusterStatus::Next(next),
      },
      FatType::Fat32 => match value {
        0x0000_0000 => FatClusterStatus::Free,
        0x0FFF_FFF7 => FatClusterStatus::Bad,
        0x0FFF_FFF8..=0x0FFF_FFFF => FatClusterStatus::EndOfChain,
        next => FatClusterStatus::Next(next),
      },
    })
  }
}

impl DataSource for FatChainDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.size || buf.is_empty() {
      return Ok(0);
    }

    let mut written = 0usize;
    let limit = usize::try_from(self.size - offset)
      .unwrap_or(usize::MAX)
      .min(buf.len());
    while written < limit {
      let absolute = offset
        .checked_add(written as u64)
        .ok_or_else(|| Error::InvalidRange("fat file read overflow".to_string()))?;
      let cluster_index = usize::try_from(absolute / self.cluster_size as u64)
        .map_err(|_| Error::InvalidRange("fat cluster index is too large".to_string()))?;
      let cluster_offset = usize::try_from(absolute % self.cluster_size as u64)
        .map_err(|_| Error::InvalidRange("fat cluster offset is too large".to_string()))?;
      let physical_offset = *self.cluster_offsets.get(cluster_index).ok_or_else(|| {
        Error::InvalidFormat(
          "fat file cluster chain does not cover the requested offset".to_string(),
        )
      })?;
      let chunk = (self.cluster_size - cluster_offset).min(limit - written);
      self.source.read_exact_at(
        physical_offset
          .checked_add(cluster_offset as u64)
          .ok_or_else(|| Error::InvalidRange("fat physical read overflow".to_string()))?,
        &mut buf[written..written + chunk],
      )?;
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
    "filesystem.fat.cluster_chain"
  }
}

fn parse_directory_entries(bytes: &[u8]) -> Result<Vec<FatDirectoryEntryRecord>> {
  let mut entries = Vec::new();
  let mut pending_long_name = Vec::<LongNameFragment>::new();

  for slot in bytes.chunks_exact(32) {
    match slot[0] {
      0x00 => break,
      0xE5 => {
        pending_long_name.clear();
        continue;
      }
      _ => {}
    }

    let attributes = slot[11];
    if attributes == ATTR_LONG_NAME {
      pending_long_name.push(parse_long_name_fragment(slot)?);
      continue;
    }

    if attributes & ATTR_VOLUME_LABEL != 0 {
      pending_long_name.clear();
      continue;
    }

    let name = if pending_long_name.is_empty() {
      decode_short_name(slot)?
    } else {
      assemble_long_name(&pending_long_name)?
    };
    pending_long_name.clear();
    if name == "." || name == ".." {
      continue;
    }

    let start_cluster = u32::from(le_u16(&slot[26..28])) | (u32::from(le_u16(&slot[20..22])) << 16);
    let file_size = u64::from(le_u32(&slot[28..32]));
    entries.push(FatDirectoryEntryRecord {
      name,
      kind: if attributes & ATTR_DIRECTORY != 0 {
        FileSystemNodeKind::Directory
      } else {
        FileSystemNodeKind::File
      },
      start_cluster,
      size: file_size,
    });
  }

  Ok(entries)
}

#[derive(Debug)]
struct LongNameFragment {
  order: u8,
  text: String,
}

fn parse_long_name_fragment(slot: &[u8]) -> Result<LongNameFragment> {
  let order = slot[0] & 0x1F;
  if order == 0 {
    return Err(Error::InvalidFormat(
      "fat long-file-name entry has an invalid order value".to_string(),
    ));
  }
  Ok(LongNameFragment {
    order,
    text: decode_long_name_component(slot)?,
  })
}

fn assemble_long_name(fragments: &[LongNameFragment]) -> Result<String> {
  let mut fragments = fragments.iter().collect::<Vec<_>>();
  fragments.sort_by_key(|fragment| fragment.order);
  let mut name = String::new();
  for fragment in fragments {
    name.push_str(&fragment.text);
  }
  if name.is_empty() {
    return Err(Error::InvalidFormat(
      "fat long-file-name sequence decoded to an empty name".to_string(),
    ));
  }
  Ok(name)
}

fn decode_long_name_component(slot: &[u8]) -> Result<String> {
  let mut units = Vec::new();
  for range in [&slot[1..11], &slot[14..26], &slot[28..32]] {
    for bytes in range.chunks_exact(2) {
      let value = u16::from_le_bytes([bytes[0], bytes[1]]);
      match value {
        0x0000 | 0xFFFF => break,
        other => units.push(other),
      }
    }
  }
  String::from_utf16(&units)
    .map_err(|_| Error::InvalidFormat("fat long-file-name data is not valid UTF-16".to_string()))
}

fn decode_short_name(slot: &[u8]) -> Result<String> {
  let mut stem = slot[0..8].to_vec();
  if stem[0] == 0x05 {
    stem[0] = 0xE5;
  }
  let extension = &slot[8..11];
  let stem = decode_short_component(&stem)?;
  let extension = decode_short_component(extension)?;
  if extension.is_empty() {
    Ok(stem)
  } else {
    Ok(format!("{stem}.{extension}"))
  }
}

fn decode_short_component(bytes: &[u8]) -> Result<String> {
  let trimmed = bytes
    .iter()
    .copied()
    .take_while(|byte| *byte != b' ')
    .collect::<Vec<_>>();
  String::from_utf8(trimmed)
    .map_err(|_| Error::InvalidFormat("fat short name is not valid ASCII/UTF-8".to_string()))
}

fn decode_node_id(node_id: &FileSystemNodeId) -> Result<u64> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::InvalidSourceReference(
      "fat node identifiers must be encoded as 8-byte little-endian values".to_string(),
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
  fn decodes_short_names() {
    let mut slot = [b' '; 32];
    slot[0..8].copy_from_slice(b"README  ");
    slot[8..11].copy_from_slice(b"TXT");

    assert_eq!(decode_short_name(&slot).unwrap(), "README.TXT");
  }

  #[test]
  fn assembles_long_name_fragments() {
    let fragments = vec![
      LongNameFragment {
        order: 2,
        text: " very long".to_string(),
      },
      LongNameFragment {
        order: 1,
        text: "My".to_string(),
      },
    ];

    assert_eq!(assemble_long_name(&fragments).unwrap(), "My very long");
  }
}
