//! Read-only ReFS v1 filesystem surface.

use std::{
  collections::{BTreeMap, HashMap, HashSet},
  sync::Arc,
};

use super::{
  DESCRIPTOR,
  data_source::RefsDataRunsDataSource,
  parser::{
    ATTRIBUTE_NON_RESIDENT_HEADER_SIZE, OBJECTS_TREE_INDEX, ROOT_DIRECTORY_OBJECT_ID,
    RefsAttribute, RefsAttributeValue, RefsBlockReference, RefsCheckpoint, RefsMinistoreNode,
    RefsNodeRecord, RefsVolumeHeader, decode_utf16le_string, le_u32, le_u64, metadata_header_size,
    parse_block_reference, parse_checkpoint_metadata, parse_data_run, parse_directory_entry_name,
    parse_directory_entry_type, parse_directory_values, parse_file_values,
    parse_metadata_block_header_v1, parse_ministore_node_data, parse_resident_attribute,
    parse_superblock_metadata,
  },
};
use crate::{
  ByteSourceHandle, BytesDataSource, Error, Result, SourceHints,
  filesystems::{
    FileSystem, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord,
  },
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RefsIdentifier {
  lower: u64,
  upper: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefsNodeDetails {
  pub attribute_flags: u32,
  pub creation_time: u64,
  pub modification_time: u64,
  pub entry_modification_time: u64,
  pub access_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefsDataStreamInfo {
  pub name: Option<String>,
  pub size: u64,
}

struct RefsNode {
  record: NamespaceNodeRecord,
  details: RefsNodeDetails,
  streams: BTreeMap<Option<String>, ByteSourceHandle>,
}

pub struct RefsFileSystem {
  nodes: HashMap<RefsIdentifier, RefsNode>,
  children: HashMap<RefsIdentifier, Vec<NamespaceDirectoryEntry>>,
}

struct RefsContext {
  source: ByteSourceHandle,
  volume_header: RefsVolumeHeader,
  object_references: HashMap<u64, RefsBlockReference>,
}

impl RefsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let volume_header = RefsVolumeHeader::read(source.as_ref())?;
    let superblock_offset = u64::from(volume_header.metadata_block_size) * 30;
    let superblock_bytes = source.read_bytes_at(
      superblock_offset,
      volume_header.metadata_block_size as usize,
    )?;
    let superblock = parse_superblock_metadata(&superblock_bytes, volume_header.major_version)?;

    let primary_checkpoint = read_checkpoint(
      source.clone(),
      &volume_header,
      superblock.primary_checkpoint_block_number,
    )?;
    let secondary_checkpoint = read_checkpoint(
      source.clone(),
      &volume_header,
      superblock.secondary_checkpoint_block_number,
    )?;
    let checkpoint = if secondary_checkpoint.sequence_number > primary_checkpoint.sequence_number {
      secondary_checkpoint
    } else {
      primary_checkpoint
    };
    let objects_reference = checkpoint
      .block_references
      .get(OBJECTS_TREE_INDEX)
      .ok_or_else(|| {
        Error::InvalidFormat("refs objects tree block reference is missing".to_string())
      })?;
    let objects_root =
      read_ministore_node_from_reference(source.clone(), &volume_header, objects_reference)?;
    if (objects_root.node_type_flags & 0x02) == 0 {
      return Err(Error::InvalidFormat(
        "refs objects tree root node must be a root node".to_string(),
      ));
    }
    let object_references =
      build_object_reference_index(source.clone(), &volume_header, &objects_root)?;

    let context = RefsContext {
      source,
      volume_header,
      object_references,
    };
    let mut nodes = HashMap::new();
    let mut children = HashMap::new();
    let mut visited_directories = HashSet::new();
    build_directory_tree(
      &context,
      ROOT_DIRECTORY_OBJECT_ID,
      &mut nodes,
      &mut children,
      &mut visited_directories,
    )?;

    Ok(Self { nodes, children })
  }

  pub fn node_details(&self, node_id: &NamespaceNodeId) -> Result<RefsNodeDetails> {
    let identifier = decode_node_id(node_id)?;
    self
      .nodes
      .get(&identifier)
      .map(|node| node.details.clone())
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))
  }

  pub fn data_streams(&self, node_id: &NamespaceNodeId) -> Result<Vec<RefsDataStreamInfo>> {
    let identifier = decode_node_id(node_id)?;
    let node = self
      .nodes
      .get(&identifier)
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))?;
    node
      .streams
      .iter()
      .map(|(name, source)| {
        Ok(RefsDataStreamInfo {
          name: name.clone(),
          size: source.size()?,
        })
      })
      .collect::<Result<Vec<_>>>()
  }

  pub fn open_data_stream(
    &self, node_id: &NamespaceNodeId, name: Option<&str>,
  ) -> Result<ByteSourceHandle> {
    let identifier = decode_node_id(node_id)?;
    let node = self
      .nodes
      .get(&identifier)
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))?;
    node
      .streams
      .get(&name.map(str::to_string))
      .cloned()
      .ok_or_else(|| Error::NotFound("refs data stream was not found".to_string()))
  }
}

impl FileSystem for RefsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    encode_node_id(&RefsIdentifier {
      lower: 0,
      upper: ROOT_DIRECTORY_OBJECT_ID,
    })
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let identifier = decode_node_id(node_id)?;
    self
      .nodes
      .get(&identifier)
      .map(|node| node.record.clone())
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let identifier = decode_node_id(directory_id)?;
    let node = self
      .nodes
      .get(&identifier)
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))?;
    if node.record.kind != NamespaceNodeKind::Directory {
      return Err(Error::NotFound("refs node is not a directory".to_string()));
    }

    Ok(self.children.get(&identifier).cloned().unwrap_or_default())
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    self.open_data_stream(file_id, None)
  }
}

fn build_directory_tree(
  context: &RefsContext, object_identifier: u64, nodes: &mut HashMap<RefsIdentifier, RefsNode>,
  children: &mut HashMap<RefsIdentifier, Vec<NamespaceDirectoryEntry>>,
  visited_directories: &mut HashSet<u64>,
) -> Result<()> {
  if !visited_directories.insert(object_identifier) {
    return Ok(());
  }

  let directory_id = RefsIdentifier {
    lower: 0,
    upper: object_identifier,
  };
  nodes
    .entry(directory_id.clone())
    .or_insert_with(|| RefsNode {
      record: NamespaceNodeRecord::new(
        encode_node_id(&directory_id),
        NamespaceNodeKind::Directory,
        0,
      ),
      details: RefsNodeDetails {
        attribute_flags: 0x10,
        creation_time: 0,
        modification_time: 0,
        entry_modification_time: 0,
        access_time: 0,
      },
      streams: BTreeMap::new(),
    });

  let root = get_object_ministore_tree(context, object_identifier)?;
  let mut directory_entries = Vec::new();
  read_directory_node(
    context,
    &root,
    nodes,
    children,
    visited_directories,
    &mut directory_entries,
  )?;
  directory_entries.sort_by(|left, right| left.name.cmp(&right.name));
  children.insert(directory_id, directory_entries);
  Ok(())
}

fn read_directory_node(
  context: &RefsContext, node: &RefsMinistoreNode, nodes: &mut HashMap<RefsIdentifier, RefsNode>,
  children: &mut HashMap<RefsIdentifier, Vec<NamespaceDirectoryEntry>>,
  visited_directories: &mut HashSet<u64>, directory_entries: &mut Vec<NamespaceDirectoryEntry>,
) -> Result<()> {
  for record in &node.records {
    if record.key_data.len() >= 2 && super::parser::le_u16(&record.key_data[0..2]) != 0x0030 {
      continue;
    }

    if node.node_type_flags & 0x01 == 0 {
      let entry_type = parse_directory_entry_type(&record.key_data)?;
      let name = parse_directory_entry_name(&record.key_data)?;
      match entry_type {
        1 => {
          let file_node = parse_file_entry(context, record)?;
          directory_entries.push(NamespaceDirectoryEntry::new(
            name,
            file_node.record.id.clone(),
            file_node.record.kind,
          ));
          nodes.insert(decode_node_id(&file_node.record.id)?, file_node);
        }
        2 => {
          let values = parse_directory_values(&record.value_data)?;
          let identifier = RefsIdentifier {
            lower: 0,
            upper: values.object_identifier,
          };
          nodes.insert(
            identifier.clone(),
            RefsNode {
              record: NamespaceNodeRecord::new(
                encode_node_id(&identifier),
                NamespaceNodeKind::Directory,
                0,
              ),
              details: RefsNodeDetails {
                attribute_flags: values.file_attribute_flags,
                creation_time: values.creation_time,
                modification_time: values.modification_time,
                entry_modification_time: values.entry_modification_time,
                access_time: values.access_time,
              },
              streams: BTreeMap::new(),
            },
          );
          directory_entries.push(NamespaceDirectoryEntry::new(
            name,
            encode_node_id(&identifier),
            NamespaceNodeKind::Directory,
          ));
          build_directory_tree(
            context,
            values.object_identifier,
            nodes,
            children,
            visited_directories,
          )?;
        }
        _ => {}
      }
    } else {
      let block_reference =
        parse_block_reference(&record.value_data, context.volume_header.major_version)?;
      let sub_node = read_ministore_node_from_reference(
        context.source.clone(),
        &context.volume_header,
        &block_reference,
      )?;
      read_directory_node(
        context,
        &sub_node,
        nodes,
        children,
        visited_directories,
        directory_entries,
      )?;
    }
  }

  Ok(())
}

fn parse_file_entry(context: &RefsContext, record: &RefsNodeRecord) -> Result<RefsNode> {
  let file_node =
    parse_ministore_node_data(&record.value_data, context.volume_header.major_version)?;
  if (file_node.node_type_flags & 0x02) == 0 {
    return Err(Error::InvalidFormat(
      "refs file values node must be a root node".to_string(),
    ));
  }
  let file_values = parse_file_values(&file_node.header_data)?;
  let attributes = collect_file_attributes(context, &file_node)?;
  let streams = build_stream_sources(context, &attributes)?;

  let identifier = RefsIdentifier {
    lower: file_values.identifier_lower,
    upper: file_values.identifier_upper,
  };

  Ok(RefsNode {
    record: NamespaceNodeRecord::new(
      encode_node_id(&identifier),
      NamespaceNodeKind::File,
      file_values.data_size,
    ),
    details: RefsNodeDetails {
      attribute_flags: file_values.file_attribute_flags,
      creation_time: file_values.creation_time,
      modification_time: file_values.modification_time,
      entry_modification_time: file_values.entry_modification_time,
      access_time: file_values.access_time,
    },
    streams,
  })
}

fn get_object_ministore_tree(
  context: &RefsContext, object_identifier: u64,
) -> Result<RefsMinistoreNode> {
  let reference = context
    .object_references
    .get(&object_identifier)
    .ok_or_else(|| {
      Error::NotFound(format!(
        "refs object 0x{object_identifier:08x} was not found"
      ))
    })?;
  read_ministore_node_from_reference(context.source.clone(), &context.volume_header, reference)
}

fn build_object_reference_index(
  source: ByteSourceHandle, volume_header: &RefsVolumeHeader, root: &RefsMinistoreNode,
) -> Result<HashMap<u64, RefsBlockReference>> {
  let mut loader = |reference: &RefsBlockReference| {
    read_ministore_node_from_reference(source.clone(), volume_header, reference)
  };
  build_object_reference_index_with(root, volume_header.major_version, 0, &mut loader)
}

fn build_object_reference_index_with<F>(
  node: &RefsMinistoreNode, major_version: u8, depth: usize, load_subnode: &mut F,
) -> Result<HashMap<u64, RefsBlockReference>>
where
  F: FnMut(&RefsBlockReference) -> Result<RefsMinistoreNode>, {
  let mut object_references = HashMap::new();
  collect_object_references_with(
    node,
    major_version,
    depth,
    load_subnode,
    &mut object_references,
  )?;
  Ok(object_references)
}

fn collect_object_references_with<F>(
  node: &RefsMinistoreNode, major_version: u8, depth: usize, load_subnode: &mut F,
  object_references: &mut HashMap<u64, RefsBlockReference>,
) -> Result<()>
where
  F: FnMut(&RefsBlockReference) -> Result<RefsMinistoreNode>, {
  if depth > 256 {
    return Err(Error::InvalidFormat(
      "refs tree recursion depth exceeded".to_string(),
    ));
  }
  if node.node_type_flags & 0x01 == 0 {
    for record in &node.records {
      let object_identifier = parse_object_identifier(&record.key_data)?;
      let reference = parse_object_record_reference(&record.value_data, major_version)?;
      if object_references
        .insert(object_identifier, reference)
        .is_some()
      {
        return Err(Error::InvalidFormat(format!(
          "duplicate refs object identifier: 0x{object_identifier:08x}"
        )));
      }
    }
    return Ok(());
  }

  for record in &node.records {
    let reference = parse_block_reference(&record.value_data, major_version)?;
    let sub_node = load_subnode(&reference)?;
    collect_object_references_with(
      &sub_node,
      major_version,
      depth + 1,
      load_subnode,
      object_references,
    )?;
  }

  Ok(())
}

fn parse_object_identifier(key_data: &[u8]) -> Result<u64> {
  let key_data = key_data
    .get(..16)
    .ok_or_else(|| Error::InvalidFormat("refs object-tree key data is truncated".to_string()))?;

  Ok(le_u64(&key_data[8..16]))
}

fn collect_file_attributes(
  context: &RefsContext, node: &RefsMinistoreNode,
) -> Result<Vec<RefsAttribute>> {
  let records = collect_leaf_records_from_source(context, node)?;
  if records.is_empty() {
    return Err(Error::InvalidFormat(
      "refs file values node does not contain attribute records".to_string(),
    ));
  }

  records
    .iter()
    .map(|record| parse_attribute_record_with_context(context, record))
    .collect()
}

fn parse_attribute_record_with_context(
  context: &RefsContext, record: &RefsNodeRecord,
) -> Result<RefsAttribute> {
  if record.key_data.len() < 14 {
    return Err(Error::InvalidFormat(
      "refs attribute key data is truncated".to_string(),
    ));
  }

  let attribute_type = le_u32(&record.key_data[8..12]);
  let name = decode_utf16le_string(&record.key_data[12..])?;
  let name = if name.is_empty() { None } else { Some(name) };
  let value = if record.flags & 0x0008 != 0 {
    parse_non_resident_attribute_with_context(context, &record.value_data)?
  } else {
    parse_resident_attribute(&record.value_data)?
  };

  Ok(RefsAttribute {
    attribute_type,
    name,
    value,
  })
}

fn parse_non_resident_attribute_with_context(
  context: &RefsContext, bytes: &[u8],
) -> Result<RefsAttributeValue> {
  let node = parse_ministore_node_data(bytes, context.volume_header.major_version)?;
  if (node.node_type_flags & 0x02) == 0 {
    return Err(Error::InvalidFormat(
      "refs non-resident attribute node must be a root node".to_string(),
    ));
  }
  if node.header_data.len() != ATTRIBUTE_NON_RESIDENT_HEADER_SIZE {
    return Err(Error::InvalidFormat(
      "refs non-resident attribute header-data size is invalid".to_string(),
    ));
  }

  let records = collect_leaf_records_from_source(context, &node)?;
  let mut data_runs = Vec::with_capacity(records.len());
  for record in records {
    data_runs.push(parse_data_run(&record.value_data)?);
  }

  Ok(RefsAttributeValue::NonResident {
    allocated_data_size: le_u64(&node.header_data[12..20]),
    data_size: le_u64(&node.header_data[20..28]),
    valid_data_size: le_u64(&node.header_data[28..36]),
    data_runs,
  })
}

fn build_stream_sources(
  context: &RefsContext, attributes: &[RefsAttribute],
) -> Result<BTreeMap<Option<String>, ByteSourceHandle>> {
  let mut grouped = BTreeMap::<Option<String>, Vec<RefsAttribute>>::new();
  for attribute in attributes {
    let key = match attribute.attribute_type {
      0x80 => None,
      0xB0 => attribute.name.clone(),
      _ => continue,
    };
    grouped.entry(key).or_default().push(attribute.clone());
  }

  let mut streams = BTreeMap::new();
  for (name, attributes) in grouped {
    let source = build_stream_source(context, &attributes)?;
    streams.insert(name, source);
  }

  Ok(streams)
}

fn build_stream_source(
  context: &RefsContext, attributes: &[RefsAttribute],
) -> Result<ByteSourceHandle> {
  let resident = attributes
    .iter()
    .filter_map(|attribute| match &attribute.value {
      RefsAttributeValue::Resident(data) => Some(data.clone()),
      RefsAttributeValue::NonResident { .. } => None,
    })
    .collect::<Vec<_>>();
  let non_resident = attributes
    .iter()
    .filter_map(|attribute| match &attribute.value {
      RefsAttributeValue::Resident(_) => None,
      RefsAttributeValue::NonResident {
        data_size,
        valid_data_size,
        data_runs,
        ..
      } => Some((*data_size, *valid_data_size, data_runs.clone())),
    })
    .collect::<Vec<_>>();

  if !resident.is_empty() && !non_resident.is_empty() {
    return Err(Error::InvalidFormat(
      "mixed resident and non-resident refs data streams are not supported".to_string(),
    ));
  }
  if let Some(data) = resident.first() {
    if resident.len() != 1 {
      return Err(Error::InvalidFormat(
        "fragmented resident refs data streams are not supported yet".to_string(),
      ));
    }

    return Ok(Arc::new(BytesDataSource::new(data.clone())) as ByteSourceHandle);
  }

  let mut sorted_runs = non_resident
    .iter()
    .flat_map(|(_, _, data_runs)| data_runs.iter().cloned())
    .collect::<Vec<_>>();
  sorted_runs.sort_by_key(|run| run.logical_offset);
  let data_size = non_resident
    .iter()
    .map(|(data_size, ..)| *data_size)
    .max()
    .unwrap_or(0);
  let valid_data_size = non_resident
    .iter()
    .map(|(_, valid_data_size, _)| *valid_data_size)
    .max()
    .unwrap_or(data_size);

  Ok(Arc::new(RefsDataRunsDataSource {
    source: context.source.clone(),
    metadata_block_size: u64::from(context.volume_header.metadata_block_size),
    data_size,
    valid_data_size,
    data_runs: Arc::from(sorted_runs.into_boxed_slice()),
  }) as ByteSourceHandle)
}

fn collect_leaf_records_from_source(
  context: &RefsContext, node: &RefsMinistoreNode,
) -> Result<Vec<RefsNodeRecord>> {
  let mut loader = |reference: &RefsBlockReference| {
    read_ministore_node_from_reference(context.source.clone(), &context.volume_header, reference)
  };
  collect_leaf_records_with(node, context.volume_header.major_version, 0, &mut loader)
}

fn collect_leaf_records_with<F>(
  node: &RefsMinistoreNode, major_version: u8, depth: usize, load_subnode: &mut F,
) -> Result<Vec<RefsNodeRecord>>
where
  F: FnMut(&RefsBlockReference) -> Result<RefsMinistoreNode>, {
  if depth > 256 {
    return Err(Error::InvalidFormat(
      "refs tree recursion depth exceeded".to_string(),
    ));
  }
  if node.node_type_flags & 0x01 == 0 {
    return Ok(node.records.clone());
  }

  let mut records = Vec::new();
  for record in &node.records {
    let reference = parse_block_reference(&record.value_data, major_version)?;
    let sub_node = load_subnode(&reference)?;
    records.extend(collect_leaf_records_with(
      &sub_node,
      major_version,
      depth + 1,
      load_subnode,
    )?);
  }
  Ok(records)
}

fn read_checkpoint(
  source: ByteSourceHandle, volume_header: &RefsVolumeHeader, block_number: u64,
) -> Result<RefsCheckpoint> {
  let bytes =
    read_metadata_blocks_from_numbers(source.as_ref(), volume_header, &[block_number, 0, 0, 0])?;
  parse_checkpoint_metadata(&bytes, volume_header.major_version)
}

fn read_ministore_node_from_reference(
  source: ByteSourceHandle, volume_header: &RefsVolumeHeader, reference: &RefsBlockReference,
) -> Result<RefsMinistoreNode> {
  let bytes = read_metadata_blocks_from_reference(source.as_ref(), volume_header, reference)?;
  let header_size = metadata_header_size(volume_header.major_version)?;
  parse_ministore_node_data(&bytes[header_size..], volume_header.major_version)
}

fn parse_object_record_reference(bytes: &[u8], major_version: u8) -> Result<RefsBlockReference> {
  let bytes = if major_version == 3 {
    bytes
      .get(32..)
      .ok_or_else(|| Error::InvalidFormat("refs object record value is truncated".to_string()))?
  } else {
    bytes
  };
  parse_block_reference(bytes, major_version)
}

fn read_metadata_blocks_from_reference(
  source: &dyn crate::ByteSource, volume_header: &RefsVolumeHeader, reference: &RefsBlockReference,
) -> Result<Vec<u8>> {
  let present = reference.present_block_numbers().collect::<Vec<_>>();
  read_metadata_blocks_from_slice(source, volume_header, &present)
}

fn read_metadata_blocks_from_numbers(
  source: &dyn crate::ByteSource, volume_header: &RefsVolumeHeader, block_numbers: &[u64; 4],
) -> Result<Vec<u8>> {
  read_metadata_blocks_from_slice(
    source,
    volume_header,
    &block_numbers
      .iter()
      .copied()
      .filter(|block_number| *block_number != 0)
      .collect::<Vec<_>>(),
  )
}

fn read_metadata_blocks_from_slice(
  source: &dyn crate::ByteSource, volume_header: &RefsVolumeHeader, block_numbers: &[u64],
) -> Result<Vec<u8>> {
  let present = block_numbers.to_vec();
  if present.is_empty() {
    return Err(Error::InvalidFormat(
      "refs metadata block reference does not contain any block numbers".to_string(),
    ));
  }

  let block_size = usize::try_from(volume_header.metadata_block_size)
    .map_err(|_| Error::InvalidRange("refs metadata block size is too large".to_string()))?;
  let mut bytes = Vec::with_capacity(
    block_size
      .checked_mul(present.len())
      .ok_or_else(|| Error::InvalidRange("refs metadata block range overflow".to_string()))?,
  );
  for block_number in present {
    let offset = block_number
      .checked_mul(u64::from(volume_header.metadata_block_size))
      .ok_or_else(|| Error::InvalidRange("refs block offset overflow".to_string()))?;
    bytes.extend_from_slice(&source.read_bytes_at(offset, block_size)?);
  }

  if volume_header.major_version == 1 {
    let _metadata = parse_metadata_block_header_v1(&bytes)?;
  }
  Ok(bytes)
}

fn encode_node_id(identifier: &RefsIdentifier) -> NamespaceNodeId {
  let mut bytes = Vec::with_capacity(16);
  bytes.extend_from_slice(&identifier.lower.to_le_bytes());
  bytes.extend_from_slice(&identifier.upper.to_le_bytes());
  NamespaceNodeId::from_bytes(bytes)
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<RefsIdentifier> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 16 {
    return Err(Error::InvalidSourceReference(
      "refs node identifiers must be 16 bytes".to_string(),
    ));
  }

  let mut lower = [0u8; 8];
  let mut upper = [0u8; 8];
  lower.copy_from_slice(&bytes[..8]);
  upper.copy_from_slice(&bytes[8..]);
  Ok(RefsIdentifier {
    lower: u64::from_le_bytes(lower),
    upper: u64::from_le_bytes(upper),
  })
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, sync::Arc};

  use super::*;
  use crate::{
    BytesDataSource,
    filesystems::refs::parser::{RefsDataRun, build_object_key},
  };

  fn sample_context() -> RefsContext {
    RefsContext {
      source: Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))),
      volume_header: RefsVolumeHeader {
        bytes_per_sector: 512,
        cluster_block_size: 65_536,
        metadata_block_size: 16 * 1024,
        volume_size: 1024 * 1024,
        major_version: 1,
        minor_version: 2,
        volume_serial_number: 1,
        container_size: 0,
      },
      object_references: HashMap::new(),
    }
  }

  fn record_with_reference(block_number: u64) -> RefsNodeRecord {
    let mut value = Vec::new();
    value.extend_from_slice(&block_number.to_le_bytes());
    value.extend_from_slice(&0u16.to_le_bytes());
    value.push(2);
    value.push(8);
    value.extend_from_slice(&8u16.to_le_bytes());
    value.extend_from_slice(&0u16.to_le_bytes());
    RefsNodeRecord {
      size: 0,
      flags: 0,
      key_data: Arc::<[u8]>::from(Vec::<u8>::new()),
      value_data: Arc::from(value.into_boxed_slice()),
    }
  }

  fn object_record_with_reference(object_identifier: u64, block_number: u64) -> RefsNodeRecord {
    let mut record = record_with_reference(block_number);
    record.key_data = Arc::from(build_object_key(object_identifier));
    record
  }

  #[test]
  fn collects_leaf_records_from_branch_nodes() {
    let leaf = RefsMinistoreNode {
      header_data: Arc::<[u8]>::from(Vec::<u8>::new()),
      node_type_flags: 0x02,
      records: vec![RefsNodeRecord {
        size: 0,
        flags: 0,
        key_data: Arc::from(vec![1, 2, 3].into_boxed_slice()),
        value_data: Arc::from(vec![4, 5, 6].into_boxed_slice()),
      }],
    };
    let branch = RefsMinistoreNode {
      header_data: Arc::<[u8]>::from(Vec::<u8>::new()),
      node_type_flags: 0x03,
      records: vec![record_with_reference(7)],
    };
    let mut children = HashMap::from([(7u64, leaf)]);
    let mut loader = |reference: &RefsBlockReference| {
      children
        .remove(&reference.block_numbers[0])
        .ok_or_else(|| Error::NotFound("missing synthetic child node".to_string()))
    };

    let records = collect_leaf_records_with(&branch, 1, 0, &mut loader).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].key_data.as_ref(), &[1, 2, 3]);
  }

  #[test]
  fn builds_named_data_stream_sources() {
    let context = sample_context();
    let streams = build_stream_sources(
      &context,
      &[
        RefsAttribute {
          attribute_type: 0x80,
          name: None,
          value: RefsAttributeValue::Resident(Arc::from(&b"default"[..])),
        },
        RefsAttribute {
          attribute_type: 0xB0,
          name: Some("secret".to_string()),
          value: RefsAttributeValue::Resident(Arc::from(&b"named"[..])),
        },
      ],
    )
    .unwrap();

    assert_eq!(streams.len(), 2);
    assert_eq!(streams.get(&None).unwrap().read_all().unwrap(), b"default");
    assert_eq!(
      streams
        .get(&Some("secret".to_string()))
        .unwrap()
        .read_all()
        .unwrap(),
      b"named"
    );
  }

  #[test]
  fn builds_fragmented_data_stream_sources() {
    let mut backing = vec![0u8; 3 * 16 * 1024];
    backing[16 * 1024..32 * 1024].fill(0x33);
    backing[32 * 1024..48 * 1024].fill(0x44);
    let mut context = sample_context();
    context.source = Arc::new(BytesDataSource::new(backing));
    let streams = build_stream_sources(
      &context,
      &[
        RefsAttribute {
          attribute_type: 0x80,
          name: None,
          value: RefsAttributeValue::NonResident {
            allocated_data_size: 16 * 1024,
            data_size: 32 * 1024,
            valid_data_size: 32 * 1024,
            data_runs: vec![RefsDataRun {
              logical_offset: 0,
              block_count: 1,
              physical_block_number: 1,
            }],
          },
        },
        RefsAttribute {
          attribute_type: 0x80,
          name: None,
          value: RefsAttributeValue::NonResident {
            allocated_data_size: 16 * 1024,
            data_size: 0,
            valid_data_size: 0,
            data_runs: vec![RefsDataRun {
              logical_offset: 16 * 1024,
              block_count: 1,
              physical_block_number: 2,
            }],
          },
        },
      ],
    )
    .unwrap();

    let data = streams.get(&None).unwrap().read_all().unwrap();

    assert_eq!(data.len(), 32 * 1024);
    assert!(data[..16 * 1024].iter().all(|byte| *byte == 0x33));
    assert!(data[16 * 1024..].iter().all(|byte| *byte == 0x44));
  }

  #[test]
  fn builds_object_reference_index_from_branch_nodes() {
    let leaf = RefsMinistoreNode {
      header_data: Arc::<[u8]>::from(Vec::<u8>::new()),
      node_type_flags: 0x02,
      records: vec![
        object_record_with_reference(0x600, 7),
        object_record_with_reference(0x601, 9),
      ],
    };
    let branch = RefsMinistoreNode {
      header_data: Arc::<[u8]>::from(Vec::<u8>::new()),
      node_type_flags: 0x03,
      records: vec![record_with_reference(11)],
    };
    let mut children = HashMap::from([(11u64, leaf)]);
    let mut loader = |reference: &RefsBlockReference| {
      children
        .remove(&reference.block_numbers[0])
        .ok_or_else(|| Error::NotFound("missing synthetic child node".to_string()))
    };

    let object_references = build_object_reference_index_with(&branch, 1, 0, &mut loader).unwrap();

    assert_eq!(object_references.len(), 2);
    assert_eq!(object_references.get(&0x600).unwrap().block_numbers[0], 7);
    assert_eq!(object_references.get(&0x601).unwrap().block_numbers[0], 9);
  }
}

crate::filesystems::driver::impl_file_system_data_source!(RefsFileSystem);
