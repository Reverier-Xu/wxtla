//! Read-only ReFS v1 filesystem surface.

use std::{
  collections::{HashMap, HashSet},
  sync::Arc,
};

use super::{
  DESCRIPTOR,
  data_source::RefsDataRunsDataSource,
  parser::{
    OBJECTS_TREE_INDEX, ROOT_DIRECTORY_OBJECT_ID, RefsAttribute, RefsAttributeValue,
    RefsBlockReference, RefsCheckpoint, RefsMinistoreNode, RefsNodeRecord, RefsVolumeHeader,
    build_object_key, parse_block_reference_v1, parse_checkpoint_metadata,
    parse_directory_entry_name, parse_directory_entry_type, parse_directory_values,
    parse_file_attributes, parse_file_values, parse_metadata_block_header_v1,
    parse_ministore_node_data, parse_superblock_metadata,
  },
};
use crate::{
  BytesDataSource, DataSourceHandle, Error, Result, SourceHints,
  filesystems::{
    DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, FileSystemNodeRecord,
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

struct RefsNode {
  record: FileSystemNodeRecord,
  details: RefsNodeDetails,
  data_source: Option<DataSourceHandle>,
}

pub struct RefsFileSystem {
  nodes: HashMap<RefsIdentifier, RefsNode>,
  children: HashMap<RefsIdentifier, Vec<DirectoryEntry>>,
}

struct RefsContext {
  source: DataSourceHandle,
  volume_header: RefsVolumeHeader,
  objects_root: RefsMinistoreNode,
}

impl RefsFileSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
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
    if (objects_root.node_type_flags & 0x03) != 0x02 {
      return Err(Error::InvalidFormat(
        "refs objects tree root node must be a root leaf node".to_string(),
      ));
    }

    let context = RefsContext {
      source,
      volume_header,
      objects_root,
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

  pub fn node_details(&self, node_id: &FileSystemNodeId) -> Result<RefsNodeDetails> {
    let identifier = decode_node_id(node_id)?;
    self
      .nodes
      .get(&identifier)
      .map(|node| node.details.clone())
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))
  }
}

impl FileSystem for RefsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> FileSystemNodeId {
    encode_node_id(&RefsIdentifier {
      lower: 0,
      upper: ROOT_DIRECTORY_OBJECT_ID,
    })
  }

  fn node(&self, node_id: &FileSystemNodeId) -> Result<FileSystemNodeRecord> {
    let identifier = decode_node_id(node_id)?;
    self
      .nodes
      .get(&identifier)
      .map(|node| node.record.clone())
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))
  }

  fn read_dir(&self, directory_id: &FileSystemNodeId) -> Result<Vec<DirectoryEntry>> {
    let identifier = decode_node_id(directory_id)?;
    let node = self
      .nodes
      .get(&identifier)
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))?;
    if node.record.kind != FileSystemNodeKind::Directory {
      return Err(Error::NotFound("refs node is not a directory".to_string()));
    }

    Ok(self.children.get(&identifier).cloned().unwrap_or_default())
  }

  fn open_file(&self, file_id: &FileSystemNodeId) -> Result<DataSourceHandle> {
    let identifier = decode_node_id(file_id)?;
    let node = self
      .nodes
      .get(&identifier)
      .ok_or_else(|| Error::NotFound("refs node was not found".to_string()))?;
    node
      .data_source
      .clone()
      .ok_or_else(|| Error::NotFound("refs node does not expose file data".to_string()))
  }
}

fn build_directory_tree(
  context: &RefsContext, object_identifier: u64, nodes: &mut HashMap<RefsIdentifier, RefsNode>,
  children: &mut HashMap<RefsIdentifier, Vec<DirectoryEntry>>,
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
      record: FileSystemNodeRecord::new(
        encode_node_id(&directory_id),
        FileSystemNodeKind::Directory,
        0,
      ),
      details: RefsNodeDetails {
        attribute_flags: 0x10,
        creation_time: 0,
        modification_time: 0,
        entry_modification_time: 0,
        access_time: 0,
      },
      data_source: None,
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
  children: &mut HashMap<RefsIdentifier, Vec<DirectoryEntry>>,
  visited_directories: &mut HashSet<u64>, directory_entries: &mut Vec<DirectoryEntry>,
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
          directory_entries.push(DirectoryEntry::new(
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
              record: FileSystemNodeRecord::new(
                encode_node_id(&identifier),
                FileSystemNodeKind::Directory,
                0,
              ),
              details: RefsNodeDetails {
                attribute_flags: values.file_attribute_flags,
                creation_time: values.creation_time,
                modification_time: values.modification_time,
                entry_modification_time: values.entry_modification_time,
                access_time: values.access_time,
              },
              data_source: None,
            },
          );
          directory_entries.push(DirectoryEntry::new(
            name,
            encode_node_id(&identifier),
            FileSystemNodeKind::Directory,
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
      let block_reference = parse_block_reference_v1(&record.value_data)?;
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
  if (file_node.node_type_flags & 0x03) != 0x02 {
    return Err(Error::InvalidFormat(
      "refs file values node must be a root leaf node".to_string(),
    ));
  }
  let file_values = parse_file_values(&file_node.header_data)?;
  let attributes = parse_file_attributes(&file_node)?;
  let default_data = attributes.into_iter().find(|attribute| {
    attribute.attribute_type == 0x80 && attribute.name.as_deref().is_none_or(str::is_empty)
  });

  let identifier = RefsIdentifier {
    lower: file_values.identifier_lower,
    upper: file_values.identifier_upper,
  };
  let data_source = match default_data {
    Some(RefsAttribute {
      value: RefsAttributeValue::Resident(data),
      ..
    }) => Some(Arc::new(BytesDataSource::new(data)) as DataSourceHandle),
    Some(RefsAttribute {
      value:
        RefsAttributeValue::NonResident {
          data_size,
          valid_data_size,
          data_runs,
          ..
        },
      ..
    }) => Some(Arc::new(RefsDataRunsDataSource {
      source: context.source.clone(),
      metadata_block_size: u64::from(context.volume_header.metadata_block_size),
      data_size,
      valid_data_size,
      data_runs: Arc::from(data_runs.into_boxed_slice()),
    }) as DataSourceHandle),
    None => None,
  };

  Ok(RefsNode {
    record: FileSystemNodeRecord::new(
      encode_node_id(&identifier),
      FileSystemNodeKind::File,
      file_values.data_size,
    ),
    details: RefsNodeDetails {
      attribute_flags: file_values.file_attribute_flags,
      creation_time: file_values.creation_time,
      modification_time: file_values.modification_time,
      entry_modification_time: file_values.entry_modification_time,
      access_time: file_values.access_time,
    },
    data_source,
  })
}

fn get_object_ministore_tree(
  context: &RefsContext, object_identifier: u64,
) -> Result<RefsMinistoreNode> {
  let key = build_object_key(object_identifier);
  let record = context
    .objects_root
    .records
    .iter()
    .find(|record| record.key_data.as_ref() == key)
    .ok_or_else(|| {
      Error::NotFound(format!(
        "refs object 0x{object_identifier:08x} was not found"
      ))
    })?;
  let reference = parse_block_reference_v1(&record.value_data)?;
  read_ministore_node_from_reference(context.source.clone(), &context.volume_header, &reference)
}

fn read_checkpoint(
  source: DataSourceHandle, volume_header: &RefsVolumeHeader, block_number: u64,
) -> Result<RefsCheckpoint> {
  let offset = block_number
    .checked_mul(u64::from(volume_header.metadata_block_size))
    .ok_or_else(|| Error::InvalidRange("refs checkpoint offset overflow".to_string()))?;
  let bytes = source.read_bytes_at(offset, volume_header.metadata_block_size as usize)?;
  let _metadata = parse_metadata_block_header_v1(&bytes)?;
  parse_checkpoint_metadata(&bytes, volume_header.major_version)
}

fn read_ministore_node_from_reference(
  source: DataSourceHandle, volume_header: &RefsVolumeHeader, reference: &RefsBlockReference,
) -> Result<RefsMinistoreNode> {
  let offset = reference
    .block_number
    .checked_mul(u64::from(volume_header.metadata_block_size))
    .ok_or_else(|| Error::InvalidRange("refs block offset overflow".to_string()))?;
  let bytes = source.read_bytes_at(offset, volume_header.metadata_block_size as usize)?;
  let _metadata = parse_metadata_block_header_v1(&bytes)?;
  parse_ministore_node_data(
    &bytes[super::parser::METADATA_BLOCK_HEADER_V1_SIZE..],
    volume_header.major_version,
  )
}

fn encode_node_id(identifier: &RefsIdentifier) -> FileSystemNodeId {
  let mut bytes = Vec::with_capacity(16);
  bytes.extend_from_slice(&identifier.lower.to_le_bytes());
  bytes.extend_from_slice(&identifier.upper.to_le_bytes());
  FileSystemNodeId::from_bytes(bytes)
}

fn decode_node_id(node_id: &FileSystemNodeId) -> Result<RefsIdentifier> {
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
