//! Read-only FAT12/16/32 filesystem surface.

use std::{
  collections::{HashMap, HashSet},
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR,
  boot_sector::{FatBootSector, FatType},
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, BytesDataSource, Error,
  NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord, Result,
  SourceHints, filesystems::FileSystem,
};

const ROOT_NODE_ID: u64 = 0;
const ATTR_LONG_NAME: u8 = 0x0F;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_LABEL: u8 = 0x08;

type FatNodeMap = HashMap<u64, Arc<FatNode>>;
type FatChildrenMap = HashMap<u64, Arc<[NamespaceDirectoryEntry]>>;

pub struct FatFileSystem {
  source: ByteSourceHandle,
  boot_sector: FatBootSector,
  fat_table: FatTable,
  volume_label: Option<String>,
  state: Mutex<FatState>,
  file_sources: Mutex<HashMap<u64, ByteSourceHandle>>,
}

struct FatNode {
  record: NamespaceNodeRecord,
  details: FatNodeDetails,
}

struct FatState {
  nodes: FatNodeMap,
  children: FatChildrenMap,
  next_node_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatNodeDetails {
  pub short_name: String,
  pub attribute_flags: u8,
  pub created_time: u16,
  pub created_date: u16,
  pub created_centiseconds: u8,
  pub accessed_date: u16,
  pub modified_time: u16,
  pub modified_date: u16,
  pub start_cluster: u32,
}

#[derive(Clone)]
enum DirectorySource {
  Fixed { offset: u64, size: usize },
  Chain(Vec<u32>),
}

#[derive(Debug, Clone)]
struct FatDirectoryEntryRecord {
  name: String,
  short_name: String,
  kind: NamespaceNodeKind,
  attribute_flags: u8,
  created_time: u16,
  created_date: u16,
  created_centiseconds: u8,
  accessed_date: u16,
  modified_time: u16,
  modified_date: u16,
  start_cluster: u32,
  size: u64,
}

struct FatDirectoryListing {
  volume_label: Option<String>,
  entries: Vec<FatDirectoryEntryRecord>,
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
  source: ByteSourceHandle,
  boot_sector: FatBootSector,
  clusters: Arc<[u32]>,
  cluster_size: usize,
  size: u64,
}

impl FatFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let boot_sector = FatBootSector::read(source.as_ref())?;
    let fat_offset = boot_sector.fat_offset(0)?;
    let fat_size = boot_sector.fat_size_bytes()?;
    let fat_table = FatTable {
      fat_type: boot_sector.fat_type,
      bytes: Arc::from(source.read_bytes_at(fat_offset, fat_size)?),
    };
    let mut state = FatState {
      nodes: HashMap::new(),
      children: HashMap::new(),
      next_node_id: ROOT_NODE_ID + 1,
    };
    state.nodes.insert(
      ROOT_NODE_ID,
      Arc::new(FatNode {
        record: NamespaceNodeRecord::new(
          NamespaceNodeId::from_u64(ROOT_NODE_ID),
          NamespaceNodeKind::Directory,
          0,
        ),
        details: FatNodeDetails {
          short_name: String::new(),
          attribute_flags: ATTR_DIRECTORY,
          created_time: 0,
          created_date: 0,
          created_centiseconds: 0,
          accessed_date: 0,
          modified_time: 0,
          modified_date: 0,
          start_cluster: 0,
        },
      }),
    );
    let root_source = match boot_sector.fat_type {
      FatType::Fat12 | FatType::Fat16 => DirectorySource::Fixed {
        offset: boot_sector.root_dir_offset()?,
        size: boot_sector.root_dir_size_bytes()?,
      },
      FatType::Fat32 => DirectorySource::Chain(follow_cluster_chain(
        &fat_table,
        &boot_sector,
        boot_sector.root_cluster,
        None,
      )?),
    };
    let root_listing = read_directory(source.as_ref(), &boot_sector, root_source)?;
    let volume_label = root_listing.volume_label;
    insert_directory_entries(&mut state, ROOT_NODE_ID, root_listing.entries)?;

    Ok(Self {
      source,
      boot_sector,
      fat_table,
      volume_label,
      state: Mutex::new(state),
      file_sources: Mutex::new(HashMap::new()),
    })
  }

  pub fn volume_label(&self) -> Option<&str> {
    self.volume_label.as_deref()
  }

  pub fn node_details(&self, node_id: &NamespaceNodeId) -> Result<FatNodeDetails> {
    Ok(self.lookup_node(node_id)?.details.clone())
  }

  fn lookup_node(&self, node_id: &NamespaceNodeId) -> Result<Arc<FatNode>> {
    let node_id = decode_node_id(node_id)?;
    self
      .state
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .nodes
      .get(&node_id)
      .cloned()
      .ok_or_else(|| Error::NotFound(format!("fat node {node_id} was not found")))
  }

  fn directory_children(
    &self, directory_id: u64, node: &FatNode,
  ) -> Result<Arc<[NamespaceDirectoryEntry]>> {
    if let Some(children) = self
      .state
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .children
      .get(&directory_id)
      .cloned()
    {
      return Ok(children);
    }

    let source = if directory_id == ROOT_NODE_ID {
      match self.boot_sector.fat_type {
        FatType::Fat12 | FatType::Fat16 => DirectorySource::Fixed {
          offset: self.boot_sector.root_dir_offset()?,
          size: self.boot_sector.root_dir_size_bytes()?,
        },
        FatType::Fat32 => DirectorySource::Chain(follow_cluster_chain(
          &self.fat_table,
          &self.boot_sector,
          self.boot_sector.root_cluster,
          None,
        )?),
      }
    } else {
      DirectorySource::Chain(follow_cluster_chain(
        &self.fat_table,
        &self.boot_sector,
        node.details.start_cluster,
        None,
      )?)
    };
    let listing = read_directory(self.source.as_ref(), &self.boot_sector, source)?;

    let mut state = self
      .state
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(children) = state.children.get(&directory_id).cloned() {
      return Ok(children);
    }

    insert_directory_entries(&mut state, directory_id, listing.entries)
  }
}

impl FileSystem for FatFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(ROOT_NODE_ID)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    self.lookup_node(node_id).map(|node| node.record.clone())
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let node_id = decode_node_id(directory_id)?;
    let node = self.lookup_node(directory_id)?;
    if node.record.kind != NamespaceNodeKind::Directory {
      return Err(Error::NotFound(format!(
        "fat node {node_id} is not a directory"
      )));
    }
    Ok(self.directory_children(node_id, &node)?.to_vec())
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let node_id = decode_node_id(file_id)?;
    let node = self.lookup_node(file_id)?;
    if node.record.kind != NamespaceNodeKind::File {
      return Err(Error::NotFound(format!(
        "fat node {node_id} is not a readable file"
      )));
    }

    if let Some(cached) = self
      .file_sources
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&node_id)
      .cloned()
    {
      return Ok(cached);
    }

    let built = build_file_data_source(
      self.source.clone(),
      &self.boot_sector,
      &self.fat_table,
      node.details.start_cluster,
      node.record.size,
    )?;

    let mut file_sources = self
      .file_sources
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = file_sources.get(&node_id).cloned() {
      return Ok(cached);
    }
    file_sources.insert(node_id, built.clone());

    Ok(built)
  }
}

fn follow_cluster_chain(
  fat_table: &FatTable, boot_sector: &FatBootSector, start_cluster: u32, size_hint: Option<u64>,
) -> Result<Vec<u32>> {
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

  let cluster_size = boot_sector.cluster_size()?;
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

    match fat_table.cluster_status(cluster)? {
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

fn insert_directory_entries(
  state: &mut FatState, directory_id: u64, entries: Vec<FatDirectoryEntryRecord>,
) -> Result<Arc<[NamespaceDirectoryEntry]>> {
  let mut children = Vec::with_capacity(entries.len());

  for entry in entries {
    let node_id = state.next_node_id;
    state.next_node_id = state
      .next_node_id
      .checked_add(1)
      .ok_or_else(|| Error::InvalidRange("fat node id overflow".to_string()))?;
    let size = if entry.kind == NamespaceNodeKind::Directory {
      0
    } else {
      entry.size
    };

    state.nodes.insert(
      node_id,
      Arc::new(FatNode {
        record: NamespaceNodeRecord::new(NamespaceNodeId::from_u64(node_id), entry.kind, size),
        details: FatNodeDetails {
          short_name: entry.short_name,
          attribute_flags: entry.attribute_flags,
          created_time: entry.created_time,
          created_date: entry.created_date,
          created_centiseconds: entry.created_centiseconds,
          accessed_date: entry.accessed_date,
          modified_time: entry.modified_time,
          modified_date: entry.modified_date,
          start_cluster: entry.start_cluster,
        },
      }),
    );
    children.push(NamespaceDirectoryEntry::new(
      entry.name,
      NamespaceNodeId::from_u64(node_id),
      entry.kind,
    ));
  }

  children.sort_by(|left, right| left.name.cmp(&right.name));
  let children = Arc::<[NamespaceDirectoryEntry]>::from(children.into_boxed_slice());
  state.children.insert(directory_id, children.clone());

  Ok(children)
}

fn read_directory(
  source: &dyn ByteSource, boot_sector: &FatBootSector, directory_source: DirectorySource,
) -> Result<FatDirectoryListing> {
  let bytes = match directory_source {
    DirectorySource::Fixed { offset, size } => source.read_bytes_at(offset, size)?,
    DirectorySource::Chain(chain) => read_cluster_chain_bytes(source, boot_sector, &chain)?,
  };

  parse_directory_entries(&bytes)
}

fn read_cluster_chain_bytes(
  source: &dyn ByteSource, boot_sector: &FatBootSector, chain: &[u32],
) -> Result<Vec<u8>> {
  let cluster_size = usize::try_from(boot_sector.cluster_size()?)
    .map_err(|_| Error::InvalidRange("fat cluster size is too large".to_string()))?;
  let mut bytes = Vec::with_capacity(cluster_size.saturating_mul(chain.len()));
  for cluster in chain {
    bytes.extend_from_slice(
      &source.read_bytes_at(boot_sector.cluster_offset(*cluster)?, cluster_size)?,
    );
  }

  Ok(bytes)
}

fn build_file_data_source(
  source: ByteSourceHandle, boot_sector: &FatBootSector, fat_table: &FatTable, start_cluster: u32,
  size: u64,
) -> Result<ByteSourceHandle> {
  if size == 0 {
    return Ok(
      Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as ByteSourceHandle,
    );
  }

  let chain = follow_cluster_chain(fat_table, boot_sector, start_cluster, Some(size))?;

  Ok(Arc::new(FatChainDataSource {
    source,
    boot_sector: *boot_sector,
    clusters: Arc::from(chain.into_boxed_slice()),
    cluster_size: usize::try_from(boot_sector.cluster_size()?)
      .map_err(|_| Error::InvalidRange("fat cluster size is too large".to_string()))?,
    size,
  }) as ByteSourceHandle)
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

impl ByteSource for FatChainDataSource {
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
      let cluster = *self.clusters.get(cluster_index).ok_or_else(|| {
        Error::InvalidFormat(
          "fat file cluster chain does not cover the requested offset".to_string(),
        )
      })?;
      let physical_offset = self.boot_sector.cluster_offset(cluster)?;
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

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    "filesystem.fat.cluster_chain"
  }
}

fn parse_directory_entries(bytes: &[u8]) -> Result<FatDirectoryListing> {
  let mut entries = Vec::new();
  let mut volume_label = None;
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

    let short_name = decode_short_name(slot)?;
    let name = if pending_long_name.is_empty() {
      short_name.clone()
    } else {
      assemble_long_name(&pending_long_name)?
    };
    pending_long_name.clear();

    if attributes & ATTR_VOLUME_LABEL != 0 {
      let volume_name = if pending_long_name.is_empty() {
        decode_volume_label(slot)?
      } else {
        name
      };
      if !volume_name.is_empty() {
        volume_label = Some(volume_name);
      }
      pending_long_name.clear();
      continue;
    }

    if name == "." || name == ".." {
      continue;
    }

    let start_cluster = u32::from(le_u16(&slot[26..28])) | (u32::from(le_u16(&slot[20..22])) << 16);
    let file_size = u64::from(le_u32(&slot[28..32]));
    entries.push(FatDirectoryEntryRecord {
      name,
      short_name,
      kind: if attributes & ATTR_DIRECTORY != 0 {
        NamespaceNodeKind::Directory
      } else {
        NamespaceNodeKind::File
      },
      attribute_flags: attributes,
      created_time: le_u16(&slot[14..16]),
      created_date: le_u16(&slot[16..18]),
      created_centiseconds: slot[13],
      accessed_date: le_u16(&slot[18..20]),
      modified_time: le_u16(&slot[22..24]),
      modified_date: le_u16(&slot[24..26]),
      start_cluster,
      size: file_size,
    });
  }

  Ok(FatDirectoryListing {
    volume_label,
    entries,
  })
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
  let nt_reserved = slot[12];
  let stem = decode_short_component(&stem, nt_reserved & 0x08 != 0)?;
  let extension = decode_short_component(&slot[8..11], nt_reserved & 0x10 != 0)?;
  if extension.is_empty() {
    Ok(stem)
  } else {
    Ok(format!("{stem}.{extension}"))
  }
}

fn decode_volume_label(slot: &[u8]) -> Result<String> {
  let trimmed = slot[0..11]
    .iter()
    .copied()
    .take_while(|byte| *byte != b' ')
    .collect::<Vec<_>>();
  String::from_utf8(trimmed)
    .map_err(|_| Error::InvalidFormat("fat volume label is not valid ASCII/UTF-8".to_string()))
}

fn decode_short_component(bytes: &[u8], lowercase: bool) -> Result<String> {
  let trimmed = bytes
    .iter()
    .copied()
    .take_while(|byte| *byte != b' ')
    .collect::<Vec<_>>();
  let component = String::from_utf8(trimmed)
    .map_err(|_| Error::InvalidFormat("fat short name is not valid ASCII/UTF-8".to_string()))?;
  if lowercase {
    Ok(component.to_ascii_lowercase())
  } else {
    Ok(component)
  }
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u64> {
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
  use std::{path::Path, sync::Arc};

  use super::*;

  fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("fat")
      .join("libfsfat")
      .join(relative)
  }

  #[test]
  fn decodes_short_names() {
    let mut slot = [b' '; 32];
    slot[0..8].copy_from_slice(b"README  ");
    slot[8..11].copy_from_slice(b"TXT");

    assert_eq!(decode_short_name(&slot).unwrap(), "README.TXT");
  }

  #[test]
  fn decodes_short_names_with_nt_lowercase_flags() {
    let mut slot = [b' '; 32];
    slot[0..8].copy_from_slice(b"README  ");
    slot[8..11].copy_from_slice(b"TXT");
    slot[12] = 0x18;

    assert_eq!(decode_short_name(&slot).unwrap(), "readme.txt");
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

  #[test]
  fn parses_libfsfat_directory_entry_fixture() {
    let bytes = std::fs::read(fixture_path("directory_entry.1")).unwrap();
    let listing = parse_directory_entries(&bytes).unwrap();

    assert_eq!(listing.volume_label, None);
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].name, "testdir1");
    assert_eq!(listing.entries[0].short_name, "testdir1");
    assert_eq!(listing.entries[0].kind, NamespaceNodeKind::Directory);
    assert_eq!(listing.entries[0].attribute_flags, 0x10);
    assert_eq!(listing.entries[0].created_centiseconds, 0x82);
    assert_eq!(listing.entries[0].created_time, 0xA259);
    assert_eq!(listing.entries[0].created_date, 0x52C9);
    assert_eq!(listing.entries[0].accessed_date, 0x52C9);
    assert_eq!(listing.entries[0].modified_time, 0xA25A);
    assert_eq!(listing.entries[0].modified_date, 0x52C9);
    assert_eq!(listing.entries[0].start_cluster, 2);
    assert_eq!(listing.entries[0].size, 0);
  }

  #[test]
  fn parses_libfsfat_directory_fixture_volume_label() {
    let bytes = std::fs::read(fixture_path("directory.1")).unwrap();
    let listing = parse_directory_entries(&bytes).unwrap();

    assert_eq!(listing.volume_label.as_deref(), Some("TESTVOLUME"));
    assert!(listing.entries.iter().any(|entry| entry.name == "testdir1"));
  }

  #[test]
  fn lazily_builds_and_caches_file_sources() {
    let source: ByteSourceHandle = Arc::new(
      crate::FileDataSource::open(
        Path::new(env!("CARGO_MANIFEST_DIR"))
          .join("formats")
          .join("fat")
          .join("fat12.raw"),
      )
      .unwrap(),
    );
    let file_system = FatFileSystem::open(source).unwrap();
    let root_id = file_system.root_node_id();

    assert!(
      file_system
        .file_sources
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty()
    );

    let testdir = file_system
      .read_dir(&root_id)
      .unwrap()
      .into_iter()
      .find(|entry| entry.name == "testdir1")
      .unwrap();
    let testfile = file_system
      .read_dir(&testdir.node_id)
      .unwrap()
      .into_iter()
      .find(|entry| entry.name == "testfile1")
      .unwrap();

    let first = file_system.open_file(&testfile.node_id).unwrap();
    assert_eq!(
      file_system
        .file_sources
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len(),
      1
    );

    let second = file_system.open_file(&testfile.node_id).unwrap();
    assert_eq!(
      file_system
        .file_sources
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len(),
      1
    );
    assert!(Arc::ptr_eq(&first, &second));
  }
}

crate::filesystems::driver::impl_file_system_data_source!(FatFileSystem);
