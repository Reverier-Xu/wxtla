//! Read-only HFS and HFS+ filesystem surface.

use std::{
  collections::{HashMap, HashSet},
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR, PLUS_DESCRIPTOR,
  btree::{parse_btree_header, read_leaf_records},
};
use crate::{
  BytesDataSource, DataSource, DataSourceCapabilities, DataSourceHandle, Error, Result,
  SourceHints,
  filesystems::{
    DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, FileSystemNodeRecord,
  },
};

const ROOT_CNID: u32 = 2;

const MODE_TYPE_MASK: u16 = 0xF000;
const MODE_FIFO: u16 = 0x1000;
const MODE_CHAR_DEVICE: u16 = 0x2000;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_BLOCK_DEVICE: u16 = 0x6000;
const MODE_REGULAR: u16 = 0x8000;
const MODE_SYMLINK: u16 = 0xA000;
const MODE_SOCKET: u16 = 0xC000;

const HFS_SIGNATURE: &[u8; 2] = b"BD";
const HFS_PLUS_SIGNATURE: &[u8; 2] = b"H+";
const HFSX_SIGNATURE: &[u8; 2] = b"HX";
const HFS_PLUS_HARD_LINK_FLAG: u16 = 0x0020;

type HfsNodeMap = Arc<HashMap<u64, Arc<HfsNode>>>;
type HfsChildrenMap = Arc<HashMap<u64, Arc<[DirectoryEntry]>>>;
type HfsAttributeMap = Arc<HashMap<u64, Arc<[HfsExtendedAttribute]>>>;

pub struct HfsFileSystem {
  descriptor: crate::FormatDescriptor,
  source: DataSourceHandle,
  allocation_block_size: u32,
  allocation_base_offset: u64,
  catalog_kind: HfsCatalogKind,
  catalog_fork: HfsFork,
  attribute_fork: Option<HfsFork>,
  catalog_index: Mutex<Option<Arc<HfsCatalogIndex>>>,
  extended_attributes: Mutex<Option<HfsAttributeMap>>,
}

#[derive(Clone, Copy)]
enum HfsCatalogKind {
  Hfs,
  HfsPlus,
}

struct HfsCatalogIndex {
  nodes: HfsNodeMap,
  children: HfsChildrenMap,
}

#[derive(Clone)]
struct HfsNode {
  record: FileSystemNodeRecord,
  fork: Option<HfsFork>,
  resource_fork: Option<HfsFork>,
  hard_link_target: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsExtendedAttribute {
  pub name: String,
  pub value: Arc<[u8]>,
}

#[derive(Clone)]
struct HfsFork {
  logical_size: u64,
  extents: Arc<[HfsExtent]>,
}

#[derive(Clone, Copy)]
struct HfsExtent {
  start_block: u32,
  block_count: u32,
}

struct HfsForkDataSource {
  source: DataSourceHandle,
  allocation_block_size: u32,
  allocation_base_offset: u64,
  fork: HfsFork,
}

#[derive(Default)]
struct HfsBuilder {
  nodes: HashMap<u64, HfsNode>,
  names: HashMap<u64, String>,
  parents: HashMap<u64, u32>,
  hidden_ids: HashSet<u32>,
}

struct HfsNodeInsert {
  cnid: u32,
  parent_id: u32,
  name: String,
  kind: FileSystemNodeKind,
  fork: Option<HfsFork>,
  resource_fork: Option<HfsFork>,
  hard_link_target: Option<u32>,
}

impl HfsFileSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let signature = source.read_bytes_at(1024, 2)?;
    if signature == HFS_SIGNATURE {
      Self::open_hfs(source)
    } else if signature == HFS_PLUS_SIGNATURE || signature == HFSX_SIGNATURE {
      Self::open_hfs_plus(source, signature == HFSX_SIGNATURE)
    } else {
      Err(Error::InvalidFormat(
        "unsupported hfs family signature".to_string(),
      ))
    }
  }

  fn open_hfs(source: DataSourceHandle) -> Result<Self> {
    let mdb = source.read_bytes_at(1024, 162)?;
    let allocation_block_size = be_u32(&mdb[20..24]);
    let allocation_base_offset = u64::from(be_u16(&mdb[28..30])) * u64::from(allocation_block_size);
    let catalog_fork = HfsFork {
      logical_size: u64::from(be_u32(&mdb[146..150])),
      extents: Arc::from(parse_hfs_extents(&mdb[150..162])),
    };
    Ok(Self {
      descriptor: DESCRIPTOR,
      source,
      allocation_block_size,
      allocation_base_offset,
      catalog_kind: HfsCatalogKind::Hfs,
      catalog_fork,
      attribute_fork: None,
      catalog_index: Mutex::new(None),
      extended_attributes: Mutex::new(None),
    })
  }

  fn open_hfs_plus(source: DataSourceHandle, _is_hfsx: bool) -> Result<Self> {
    let header = source.read_bytes_at(1024, 512)?;
    let allocation_block_size = be_u32(&header[40..44]);
    let catalog_fork = parse_hfs_plus_fork(&header[272..352])?;
    let attributes_fork = parse_hfs_plus_fork(&header[352..432])?;

    Ok(Self {
      descriptor: PLUS_DESCRIPTOR,
      source,
      allocation_block_size,
      allocation_base_offset: 0,
      catalog_kind: HfsCatalogKind::HfsPlus,
      catalog_fork,
      attribute_fork: (attributes_fork.logical_size != 0).then_some(attributes_fork),
      catalog_index: Mutex::new(None),
      extended_attributes: Mutex::new(None),
    })
  }

  fn build_data_source(&self, fork: &HfsFork) -> Result<DataSourceHandle> {
    if fork.logical_size == 0 {
      return Ok(
        Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as DataSourceHandle,
      );
    }
    Ok(Arc::new(HfsForkDataSource {
      source: self.source.clone(),
      allocation_block_size: self.allocation_block_size,
      allocation_base_offset: self.allocation_base_offset,
      fork: fork.clone(),
    }) as DataSourceHandle)
  }

  pub fn symlink_target(&self, node_id: &FileSystemNodeId) -> Result<Option<String>> {
    let raw_node_id = decode_node_id(node_id)?;
    let node = self.lookup_node(node_id)?;
    if node.record.kind != FileSystemNodeKind::Symlink {
      return Ok(None);
    }

    let fork = node.fork.as_ref().ok_or_else(|| {
      Error::NotFound(format!(
        "hfs node {raw_node_id} does not expose a data fork"
      ))
    })?;
    let data = self.build_data_source(fork)?.read_all()?;
    Ok(Some(String::from_utf8_lossy(&data).to_string()))
  }

  pub fn open_resource_fork(&self, node_id: &FileSystemNodeId) -> Result<DataSourceHandle> {
    let raw_node_id = decode_node_id(node_id)?;
    let node = self.lookup_node(node_id)?;
    let resource_fork = node.resource_fork.as_ref().ok_or_else(|| {
      Error::NotFound(format!(
        "hfs node {raw_node_id} does not expose a resource fork"
      ))
    })?;
    self.build_data_source(resource_fork)
  }

  pub fn extended_attributes(
    &self, node_id: &FileSystemNodeId,
  ) -> Result<Vec<HfsExtendedAttribute>> {
    let node_id = decode_node_id(node_id)?;
    let Some(attributes) = self.extended_attribute_index()? else {
      return Ok(Vec::new());
    };

    Ok(
      attributes
        .get(&node_id)
        .map_or_else(Vec::new, |value| value.to_vec()),
    )
  }

  fn lookup_node(&self, node_id: &FileSystemNodeId) -> Result<Arc<HfsNode>> {
    let node_id = decode_node_id(node_id)?;
    self
      .catalog_index()?
      .nodes
      .get(&node_id)
      .cloned()
      .ok_or_else(|| Error::NotFound(format!("hfs node {node_id} was not found")))
  }

  fn catalog_index(&self) -> Result<Arc<HfsCatalogIndex>> {
    if let Some(index) = self
      .catalog_index
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .as_ref()
      .cloned()
    {
      return Ok(index);
    }

    let built = Arc::new(match self.catalog_kind {
      HfsCatalogKind::Hfs => build_hfs_catalog_index(
        self.source.clone(),
        self.allocation_block_size,
        self.allocation_base_offset,
        &self.catalog_fork,
      )?,
      HfsCatalogKind::HfsPlus => build_hfs_plus_catalog_index(
        self.source.clone(),
        self.allocation_block_size,
        &self.catalog_fork,
      )?,
    });

    let mut cached = self
      .catalog_index
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cached.as_ref().cloned() {
      return Ok(existing);
    }
    *cached = Some(built.clone());

    Ok(built)
  }

  fn extended_attribute_index(&self) -> Result<Option<HfsAttributeMap>> {
    let Some(attribute_fork) = &self.attribute_fork else {
      return Ok(None);
    };
    if let Some(attributes) = self
      .extended_attributes
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .as_ref()
      .cloned()
    {
      return Ok(Some(attributes));
    }

    let built = Arc::new(parse_hfs_plus_attributes(
      self.source.clone(),
      self.allocation_block_size,
      attribute_fork,
    )?);

    let mut cached = self
      .extended_attributes
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cached.as_ref().cloned() {
      return Ok(Some(existing));
    }
    *cached = Some(built.clone());

    Ok(Some(built))
  }
}

impl FileSystem for HfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    self.descriptor
  }

  fn root_node_id(&self) -> FileSystemNodeId {
    FileSystemNodeId::from_u64(u64::from(ROOT_CNID))
  }

  fn node(&self, node_id: &FileSystemNodeId) -> Result<FileSystemNodeRecord> {
    self.lookup_node(node_id).map(|node| node.record.clone())
  }

  fn read_dir(&self, directory_id: &FileSystemNodeId) -> Result<Vec<DirectoryEntry>> {
    let node_id = decode_node_id(directory_id)?;
    let node = self.lookup_node(directory_id)?;
    if node.record.kind != FileSystemNodeKind::Directory {
      return Err(Error::NotFound(format!(
        "hfs node {node_id} is not a directory"
      )));
    }
    let index = self.catalog_index()?;
    Ok(
      index
        .children
        .get(&node_id)
        .map_or_else(Vec::new, |entries| entries.to_vec()),
    )
  }

  fn open_file(&self, file_id: &FileSystemNodeId) -> Result<DataSourceHandle> {
    let node_id = decode_node_id(file_id)?;
    let node = self.lookup_node(file_id)?;
    if node.record.kind != FileSystemNodeKind::File {
      return Err(Error::NotFound(format!(
        "hfs node {node_id} is not a readable file"
      )));
    }
    let fork = node
      .fork
      .as_ref()
      .ok_or_else(|| Error::NotFound(format!("hfs node {node_id} does not expose a data fork")))?;
    self.build_data_source(fork)
  }
}

impl DataSource for HfsForkDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.fork.logical_size || buf.is_empty() {
      return Ok(0);
    }

    let mut written = 0usize;
    let limit = usize::try_from(self.fork.logical_size - offset)
      .unwrap_or(usize::MAX)
      .min(buf.len());
    let mut extent_start = 0u64;
    for extent in self
      .fork
      .extents
      .iter()
      .copied()
      .filter(|extent| extent.block_count != 0)
    {
      if written >= limit {
        break;
      }
      let extent_length = u64::from(extent.block_count) * u64::from(self.allocation_block_size);
      let extent_end = extent_start + extent_length;
      let request_start = offset + written as u64;
      if request_start >= extent_end {
        extent_start = extent_end;
        continue;
      }
      let within_extent = request_start.saturating_sub(extent_start);
      let chunk = usize::try_from(extent_length - within_extent)
        .unwrap_or(usize::MAX)
        .min(limit - written);
      let physical_offset = self
        .allocation_base_offset
        .checked_add(u64::from(extent.start_block) * u64::from(self.allocation_block_size))
        .and_then(|base| base.checked_add(within_extent))
        .ok_or_else(|| Error::InvalidRange("hfs fork offset overflow".to_string()))?;
      self
        .source
        .read_exact_at(physical_offset, &mut buf[written..written + chunk])?;
      written += chunk;
      extent_start = extent_end;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.fork.logical_size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self.source.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    "filesystem.hfs.fork"
  }
}

fn build_hfs_catalog_index(
  source: DataSourceHandle, allocation_block_size: u32, allocation_base_offset: u64,
  catalog_fork: &HfsFork,
) -> Result<HfsCatalogIndex> {
  let catalog_source = HfsForkDataSource {
    source,
    allocation_block_size,
    allocation_base_offset,
    fork: catalog_fork.clone(),
  };
  let btree_header = parse_btree_header(&catalog_source)?;
  let mut builder = HfsBuilder::default();
  for record in read_leaf_records(&catalog_source, &btree_header)? {
    parse_hfs_catalog_record(&record, &mut builder)?;
  }
  builder
    .nodes
    .entry(u64::from(ROOT_CNID))
    .or_insert(HfsNode {
      record: FileSystemNodeRecord::new(
        FileSystemNodeId::from_u64(u64::from(ROOT_CNID)),
        FileSystemNodeKind::Directory,
        0,
      ),
      fork: None,
      resource_fork: None,
      hard_link_target: None,
    });

  Ok(finish_catalog_index(builder, None))
}

fn build_hfs_plus_catalog_index(
  source: DataSourceHandle, allocation_block_size: u32, catalog_fork: &HfsFork,
) -> Result<HfsCatalogIndex> {
  let catalog_source = HfsForkDataSource {
    source,
    allocation_block_size,
    allocation_base_offset: 0,
    fork: catalog_fork.clone(),
  };
  let btree_header = parse_btree_header(&catalog_source)?;
  let mut builder = HfsBuilder::default();
  let mut metadata_dir_id = None::<u32>;
  for record in read_leaf_records(&catalog_source, &btree_header)? {
    parse_hfs_plus_catalog_record(&record, &mut builder, &mut metadata_dir_id)?;
  }
  if let Some(metadata_dir_id) = metadata_dir_id {
    builder.hidden_ids.insert(metadata_dir_id);
    for (node_id, parent_id) in &builder.parents {
      if *parent_id == metadata_dir_id {
        builder.hidden_ids.insert(*node_id as u32);
      }
    }
  }

  let mut resolved_nodes = builder.nodes.clone();
  let keys = resolved_nodes.keys().copied().collect::<Vec<_>>();
  for node_id in keys {
    if builder
      .names
      .get(&node_id)
      .is_some_and(|name| name.starts_with("iNode"))
    {
      continue;
    }
    let Some(target) = resolved_nodes
      .get(&node_id)
      .and_then(|node| node.hard_link_target)
    else {
      continue;
    };
    if let Some(target_node) = resolved_nodes.get(&u64::from(target)).cloned()
      && let Some(node) = resolved_nodes.get_mut(&node_id)
    {
      node.fork = target_node.fork.clone();
      node.record.size = target_node.record.size;
    }
  }
  builder.nodes = resolved_nodes;
  builder
    .nodes
    .entry(u64::from(ROOT_CNID))
    .or_insert(HfsNode {
      record: FileSystemNodeRecord::new(
        FileSystemNodeId::from_u64(u64::from(ROOT_CNID)),
        FileSystemNodeKind::Directory,
        0,
      ),
      fork: None,
      resource_fork: None,
      hard_link_target: None,
    });

  Ok(finish_catalog_index(builder, metadata_dir_id))
}

fn finish_catalog_index(builder: HfsBuilder, metadata_dir_id: Option<u32>) -> HfsCatalogIndex {
  let children = Arc::new(
    build_children(&builder, metadata_dir_id)
      .into_iter()
      .map(|(node_id, entries)| (node_id, Arc::from(entries.into_boxed_slice())))
      .collect::<HashMap<_, _>>(),
  );
  let nodes = Arc::new(
    builder
      .nodes
      .into_iter()
      .map(|(node_id, node)| (node_id, Arc::new(node)))
      .collect::<HashMap<_, _>>(),
  );

  HfsCatalogIndex { nodes, children }
}

fn parse_hfs_catalog_record(record: &[u8], builder: &mut HfsBuilder) -> Result<()> {
  if record.len() < 8 {
    return Ok(());
  }
  let key_size = usize::from(record[0]);
  if key_size < 6 || 1 + key_size > record.len() {
    return Ok(());
  }
  let parent_id = be_u32(&record[2..6]);
  let name_len = usize::from(record[6]);
  let name_end = 7 + name_len;
  if name_end > record.len() {
    return Err(Error::InvalidFormat(
      "hfs catalog key name exceeds the record bounds".to_string(),
    ));
  }
  let mut value_offset = 1 + key_size;
  if value_offset % 2 != 0 {
    value_offset += 1;
  }
  if value_offset + 2 > record.len() {
    return Ok(());
  }

  let name = String::from_utf8_lossy(&record[7..name_end]).to_string();
  match be_u16(&record[value_offset..value_offset + 2]) {
    0x0100 => {
      let cnid = be_u32(&record[value_offset + 6..value_offset + 10]);
      insert_node(
        builder,
        HfsNodeInsert {
          cnid,
          parent_id,
          name,
          kind: FileSystemNodeKind::Directory,
          fork: None,
          resource_fork: None,
          hard_link_target: None,
        },
      );
    }
    0x0200 => {
      let cnid = be_u32(&record[value_offset + 20..value_offset + 24]);
      let data_fork = HfsFork {
        logical_size: u64::from(be_u32(&record[value_offset + 26..value_offset + 30])),
        extents: Arc::from(parse_hfs_extents(
          &record[value_offset + 74..value_offset + 86],
        )),
      };
      let resource_fork = HfsFork {
        logical_size: u64::from(be_u32(&record[value_offset + 36..value_offset + 40])),
        extents: Arc::from(parse_hfs_extents(
          &record[value_offset + 86..value_offset + 98],
        )),
      };
      insert_node(
        builder,
        HfsNodeInsert {
          cnid,
          parent_id,
          name,
          kind: FileSystemNodeKind::File,
          fork: Some(data_fork),
          resource_fork: Some(resource_fork),
          hard_link_target: None,
        },
      );
    }
    _ => {}
  }

  Ok(())
}

fn parse_hfs_plus_catalog_record(
  record: &[u8], builder: &mut HfsBuilder, metadata_dir_id: &mut Option<u32>,
) -> Result<()> {
  if record.len() < 10 {
    return Ok(());
  }
  let key_size = usize::from(be_u16(&record[0..2]));
  if key_size < 4 || 2 + key_size > record.len() {
    return Ok(());
  }
  let parent_id = be_u32(&record[2..6]);
  let name_len = if key_size >= 6 {
    usize::from(be_u16(&record[6..8]))
  } else {
    0
  };
  let name_end = 8 + name_len * 2;
  if name_end > 2 + key_size {
    return Err(Error::InvalidFormat(
      "hfs+ catalog key name exceeds the encoded key size".to_string(),
    ));
  }
  let name = decode_hfs_plus_name(&record[8..name_end])?;
  let value_offset = 2 + key_size;
  if value_offset + 2 > record.len() {
    return Ok(());
  }

  match be_u16(&record[value_offset..value_offset + 2]) {
    0x0001 => {
      let cnid = be_u32(&record[value_offset + 8..value_offset + 12]);
      let kind = kind_from_mode(be_u16(&record[value_offset + 42..value_offset + 44]));
      if name.contains("HFS+ Private Data") {
        *metadata_dir_id = Some(cnid);
      }
      insert_node(
        builder,
        HfsNodeInsert {
          cnid,
          parent_id,
          name,
          kind,
          fork: None,
          resource_fork: None,
          hard_link_target: None,
        },
      );
    }
    0x0002 => {
      let cnid = be_u32(&record[value_offset + 8..value_offset + 12]);
      let flags = be_u16(&record[value_offset + 2..value_offset + 4]);
      let kind = kind_from_mode(be_u16(&record[value_offset + 42..value_offset + 44]));
      let special = be_u32(&record[value_offset + 44..value_offset + 48]);
      let data_fork = parse_hfs_plus_fork(&record[value_offset + 88..value_offset + 168])?;
      let resource_fork = parse_hfs_plus_fork(&record[value_offset + 168..value_offset + 248])?;
      insert_node(
        builder,
        HfsNodeInsert {
          cnid,
          parent_id,
          name,
          kind,
          fork: Some(data_fork),
          resource_fork: Some(resource_fork),
          hard_link_target: (flags & HFS_PLUS_HARD_LINK_FLAG != 0).then_some(special),
        },
      );
    }
    _ => {}
  }

  Ok(())
}

fn insert_node(builder: &mut HfsBuilder, node: HfsNodeInsert) {
  builder.parents.insert(u64::from(node.cnid), node.parent_id);
  builder.names.insert(u64::from(node.cnid), node.name);
  builder.nodes.insert(
    u64::from(node.cnid),
    HfsNode {
      record: FileSystemNodeRecord::new(
        FileSystemNodeId::from_u64(u64::from(node.cnid)),
        node.kind,
        node.fork.as_ref().map_or(0, |fork| fork.logical_size),
      ),
      fork: node.fork,
      resource_fork: node.resource_fork,
      hard_link_target: node.hard_link_target,
    },
  );
}

fn build_children(
  builder: &HfsBuilder, hide_metadata_dir: Option<u32>,
) -> HashMap<u64, Vec<DirectoryEntry>> {
  let mut children = HashMap::<u64, Vec<DirectoryEntry>>::new();
  for (node_id, parent_id) in &builder.parents {
    if *node_id == u64::from(ROOT_CNID) {
      continue;
    }
    if builder.hidden_ids.contains(&(*node_id as u32)) {
      continue;
    }
    if hide_metadata_dir.is_some_and(|hidden| hidden == *node_id as u32 || hidden == *parent_id) {
      continue;
    }
    let Some(node) = builder.nodes.get(node_id) else {
      continue;
    };
    let Some(name) = builder.names.get(node_id) else {
      continue;
    };
    children
      .entry(u64::from(*parent_id))
      .or_default()
      .push(DirectoryEntry::new(
        name.clone(),
        node.record.id.clone(),
        node.record.kind,
      ));
  }
  for entries in children.values_mut() {
    entries.sort_by(|left, right| left.name.cmp(&right.name));
  }
  children
}

fn parse_hfs_plus_attributes(
  source: DataSourceHandle, allocation_block_size: u32, fork: &HfsFork,
) -> Result<HashMap<u64, Arc<[HfsExtendedAttribute]>>> {
  let attributes_source = HfsForkDataSource {
    source,
    allocation_block_size,
    allocation_base_offset: 0,
    fork: fork.clone(),
  };
  let btree_header = parse_btree_header(&attributes_source)?;
  let mut attributes = HashMap::<u64, Vec<HfsExtendedAttribute>>::new();

  for record in read_leaf_records(&attributes_source, &btree_header)? {
    if record.len() < 14 {
      continue;
    }
    let key_size = usize::from(be_u16(&record[0..2]));
    if key_size < 12 || 2 + key_size > record.len() {
      continue;
    }

    let cnid = u64::from(be_u32(&record[4..8]));
    let name_length = usize::from(be_u16(&record[12..14]));
    let name_end = 14 + name_length * 2;
    if name_end > 2 + key_size {
      return Err(Error::InvalidFormat(
        "hfs+ attribute key name exceeds the encoded key size".to_string(),
      ));
    }
    let name = decode_utf16be_string(&record[14..name_end], false)?;
    let value_offset = 2 + key_size;
    if value_offset + 4 > record.len() {
      continue;
    }

    let value = match be_u32(&record[value_offset..value_offset + 4]) {
      0x0000_0010 => {
        let size = usize::try_from(be_u32(&record[value_offset + 12..value_offset + 16]))
          .map_err(|_| Error::InvalidRange("hfs+ inline xattr size is too large".to_string()))?;
        let data_offset = value_offset + 16;
        let data_end = data_offset
          .checked_add(size)
          .ok_or_else(|| Error::InvalidRange("hfs+ inline xattr end overflow".to_string()))?;
        let data = record.get(data_offset..data_end).ok_or_else(|| {
          Error::InvalidFormat("hfs+ inline xattr exceeds the record bounds".to_string())
        })?;
        Arc::from(data)
      }
      0x0000_0020 => {
        let fork = parse_hfs_plus_fork(&record[value_offset + 8..value_offset + 88])?;
        HfsForkDataSource {
          source: attributes_source.source.clone(),
          allocation_block_size,
          allocation_base_offset: 0,
          fork,
        }
        .read_all()?
        .into()
      }
      0x0000_0030 => {
        return Err(Error::InvalidFormat(
          "hfs+ xattr extent overflow records are not supported yet".to_string(),
        ));
      }
      other => {
        return Err(Error::InvalidFormat(format!(
          "unsupported hfs+ xattr record type: 0x{other:08x}"
        )));
      }
    };

    attributes
      .entry(cnid)
      .or_default()
      .push(HfsExtendedAttribute { name, value });
  }

  Ok(
    attributes
      .into_iter()
      .map(|(node_id, values)| (node_id, Arc::from(values.into_boxed_slice())))
      .collect(),
  )
}

fn parse_hfs_extents(bytes: &[u8]) -> Box<[HfsExtent]> {
  let mut extents = Vec::new();
  for chunk in bytes.chunks_exact(4) {
    let start_block = u32::from(be_u16(&chunk[0..2]));
    let block_count = u32::from(be_u16(&chunk[2..4]));
    if block_count != 0 {
      extents.push(HfsExtent {
        start_block,
        block_count,
      });
    }
  }
  extents.into_boxed_slice()
}

fn parse_hfs_plus_fork(bytes: &[u8]) -> Result<HfsFork> {
  if bytes.len() < 80 {
    return Err(Error::InvalidFormat(
      "hfs+ fork descriptor is truncated".to_string(),
    ));
  }
  let logical_size = be_u64(&bytes[0..8]);
  let mut extents = Vec::new();
  for chunk in bytes[16..80].chunks_exact(8) {
    let start_block = be_u32(&chunk[0..4]);
    let block_count = be_u32(&chunk[4..8]);
    if block_count != 0 {
      extents.push(HfsExtent {
        start_block,
        block_count,
      });
    }
  }
  Ok(HfsFork {
    logical_size,
    extents: Arc::from(extents.into_boxed_slice()),
  })
}

fn decode_utf16be_string(bytes: &[u8], translate_path_separator: bool) -> Result<String> {
  let units = bytes
    .chunks_exact(2)
    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  let decoded = String::from_utf16(&units)
    .map_err(|_| Error::InvalidFormat("hfs+ name is not valid UTF-16".to_string()))?;
  if !translate_path_separator {
    return Ok(decoded);
  }

  Ok(
    decoded
      .chars()
      .map(|character| match character {
        '/' => ':',
        '\0' => '\u{2400}',
        other => other,
      })
      .collect(),
  )
}

fn decode_hfs_plus_name(bytes: &[u8]) -> Result<String> {
  decode_utf16be_string(bytes, true)
}

fn kind_from_mode(mode: u16) -> FileSystemNodeKind {
  match mode & MODE_TYPE_MASK {
    MODE_DIRECTORY => FileSystemNodeKind::Directory,
    MODE_SYMLINK => FileSystemNodeKind::Symlink,
    MODE_REGULAR => FileSystemNodeKind::File,
    MODE_FIFO | MODE_CHAR_DEVICE | MODE_BLOCK_DEVICE | MODE_SOCKET => FileSystemNodeKind::Special,
    _ => FileSystemNodeKind::File,
  }
}

fn decode_node_id(node_id: &FileSystemNodeId) -> Result<u64> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::InvalidSourceReference(
      "hfs node identifiers must be encoded as 8-byte little-endian values".to_string(),
    ));
  }
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  Ok(u64::from_le_bytes(raw))
}

fn be_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_be_bytes(raw)
}

fn be_u32(bytes: &[u8]) -> u32 {
  let mut raw = [0u8; 4];
  raw.copy_from_slice(bytes);
  u32::from_be_bytes(raw)
}

fn be_u64(bytes: &[u8]) -> u64 {
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  u64::from_be_bytes(raw)
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use super::*;

  fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("hfs")
      .join("libfshfs")
      .join(relative)
  }

  #[test]
  fn decodes_hfs_plus_name_transformations() {
    let name = decode_hfs_plus_name(&[
      0x00, 0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x77, 0x00, 0x61, 0x00, 0x72, 0x00, 0x64, 0x00,
      0x2F, 0x00, 0x73,
    ])
    .unwrap();

    assert_eq!(name, "forward:s");
  }

  #[test]
  fn parses_libfshfs_catalog_key_fixture_name() {
    let bytes = std::fs::read(fixture_path("catalog_btree_key.1")).unwrap();
    let name_length = usize::from(be_u16(&bytes[6..8]));

    assert_eq!(be_u16(&bytes[0..2]), 12);
    assert_eq!(be_u32(&bytes[2..6]), 1);
    assert_eq!(
      decode_hfs_plus_name(&bytes[8..8 + name_length * 2]).unwrap(),
      "osx"
    );
  }
}
