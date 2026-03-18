//! Read-only NTFS filesystem surface.

use std::{collections::HashMap, sync::Arc};

use super::{
  DESCRIPTOR,
  boot_sector::NtfsBootSector,
  record::{
    NtfsDataAttribute, NtfsDataAttributeValue, NtfsFileRecord, NtfsNonResidentAttribute,
    parse_file_record,
  },
  runlist::{NtfsDataRun, NtfsNonResidentDataSource, parse_runlist},
};
use crate::{
  BytesDataSource, DataSourceHandle, Error, Result, SourceHints,
  filesystems::{
    DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, FileSystemNodeRecord,
  },
};

const ROOT_FILE_RECORD_NUMBER: u64 = 5;

pub struct NtfsFileSystem {
  nodes: HashMap<u64, NtfsNode>,
  children: HashMap<u64, Vec<DirectoryEntry>>,
}

struct NtfsNode {
  name: String,
  parent_id: Option<u64>,
  record: FileSystemNodeRecord,
  data_source: Option<DataSourceHandle>,
}

impl NtfsFileSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let boot_sector = NtfsBootSector::read(source.as_ref())?;
    let file_record_size = boot_sector.file_record_size()?;
    let mft_offset = boot_sector.mft_offset()?;
    let first_record = read_file_record(source.as_ref(), mft_offset, file_record_size)?;
    let mft_record = parse_file_record(&first_record, 0)?.ok_or_else(|| {
      Error::InvalidFormat("ntfs master file table record is not in use".to_string())
    })?;
    if mft_record.has_attribute_list {
      return Err(Error::InvalidFormat(
        "ntfs master file table attribute lists are not supported".to_string(),
      ));
    }

    let mft_stream =
      build_stream_data_source(source.clone(), &boot_sector, &mft_record.data_attributes)?;
    let mft_stream_size = mft_stream.size()?;
    if mft_stream_size < file_record_size {
      return Err(Error::InvalidFormat(
        "ntfs master file table is smaller than one file record".to_string(),
      ));
    }

    let record_count = mft_stream_size / file_record_size;
    let mut nodes = HashMap::new();

    for record_number in 0..record_count {
      let record_bytes = read_file_record(
        mft_stream.as_ref(),
        record_number
          .checked_mul(file_record_size)
          .ok_or_else(|| Error::InvalidRange("ntfs MFT record offset overflow".to_string()))?,
        file_record_size,
      )?;
      let Some(record) = parse_file_record(&record_bytes, record_number)? else {
        continue;
      };
      if record.base_record_number.is_some() {
        continue;
      }
      let Some(name) = record.preferred_name().cloned() else {
        continue;
      };
      if record.has_attribute_list {
        return Err(Error::InvalidFormat(format!(
          "ntfs attribute lists are not supported for record {record_number}"
        )));
      }

      let parent_id = if record_number == ROOT_FILE_RECORD_NUMBER {
        None
      } else {
        Some(name.parent_record_number)
      };
      let (kind, data_source, size) = classify_node(source.clone(), &boot_sector, &record)?;
      nodes.insert(
        record_number,
        NtfsNode {
          name: if record_number == ROOT_FILE_RECORD_NUMBER {
            String::new()
          } else {
            name.name
          },
          parent_id,
          record: FileSystemNodeRecord::new(FileSystemNodeId::from_u64(record_number), kind, size),
          data_source,
        },
      );
    }

    if !nodes.contains_key(&ROOT_FILE_RECORD_NUMBER) {
      return Err(Error::InvalidFormat(
        "ntfs root directory record is missing".to_string(),
      ));
    }

    let mut children = HashMap::<u64, Vec<DirectoryEntry>>::new();
    for (record_number, node) in &nodes {
      let Some(parent_id) = node.parent_id else {
        continue;
      };
      if *record_number == ROOT_FILE_RECORD_NUMBER {
        continue;
      }
      children
        .entry(parent_id)
        .or_default()
        .push(DirectoryEntry::new(
          node.name.clone(),
          node.record.id.clone(),
          node.record.kind,
        ));
    }
    for entries in children.values_mut() {
      entries.sort_by(|left, right| left.name.cmp(&right.name));
    }

    Ok(Self { nodes, children })
  }
}

impl FileSystem for NtfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> FileSystemNodeId {
    FileSystemNodeId::from_u64(ROOT_FILE_RECORD_NUMBER)
  }

  fn node(&self, node_id: &FileSystemNodeId) -> Result<FileSystemNodeRecord> {
    let record_number = decode_node_id(node_id)?;
    self
      .nodes
      .get(&record_number)
      .map(|node| node.record.clone())
      .ok_or_else(|| Error::NotFound(format!("ntfs node {record_number} was not found")))
  }

  fn read_dir(&self, directory_id: &FileSystemNodeId) -> Result<Vec<DirectoryEntry>> {
    let record_number = decode_node_id(directory_id)?;
    let node = self
      .nodes
      .get(&record_number)
      .ok_or_else(|| Error::NotFound(format!("ntfs node {record_number} was not found")))?;
    if node.record.kind != FileSystemNodeKind::Directory {
      return Err(Error::NotFound(format!(
        "ntfs node {record_number} is not a directory"
      )));
    }

    Ok(
      self
        .children
        .get(&record_number)
        .cloned()
        .unwrap_or_default(),
    )
  }

  fn open_file(&self, file_id: &FileSystemNodeId) -> Result<DataSourceHandle> {
    let record_number = decode_node_id(file_id)?;
    let node = self
      .nodes
      .get(&record_number)
      .ok_or_else(|| Error::NotFound(format!("ntfs node {record_number} was not found")))?;
    node
      .data_source
      .clone()
      .ok_or_else(|| Error::NotFound(format!("ntfs node {record_number} is not a readable file")))
  }
}

fn classify_node(
  source: DataSourceHandle, boot_sector: &NtfsBootSector, record: &NtfsFileRecord,
) -> Result<(FileSystemNodeKind, Option<DataSourceHandle>, u64)> {
  if record.is_directory() {
    let kind = if record.has_reparse_point {
      FileSystemNodeKind::Symlink
    } else {
      FileSystemNodeKind::Directory
    };
    return Ok((kind, None, 0));
  }

  let data_source = build_default_data_source(source, boot_sector, record)?;
  let size = data_source.size()?;
  let kind = if record.has_reparse_point {
    FileSystemNodeKind::Symlink
  } else {
    FileSystemNodeKind::File
  };
  Ok((kind, Some(data_source), size))
}

fn build_default_data_source(
  source: DataSourceHandle, boot_sector: &NtfsBootSector, record: &NtfsFileRecord,
) -> Result<DataSourceHandle> {
  let data_attributes = record
    .data_attributes
    .iter()
    .filter(|attribute| attribute.name.is_none())
    .cloned()
    .collect::<Vec<_>>();
  build_stream_data_source(source, boot_sector, &data_attributes)
}

fn build_stream_data_source(
  source: DataSourceHandle, boot_sector: &NtfsBootSector, attributes: &[NtfsDataAttribute],
) -> Result<DataSourceHandle> {
  if attributes.is_empty() {
    return Ok(
      Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as DataSourceHandle,
    );
  }

  let resident = attributes
    .iter()
    .map(|attribute| match &attribute.value {
      NtfsDataAttributeValue::Resident(data) => Some(data.clone()),
      NtfsDataAttributeValue::NonResident(_) => None,
    })
    .collect::<Option<Vec<_>>>();
  if let Some(mut resident) = resident {
    if resident.len() != 1 {
      return Err(Error::InvalidFormat(
        "ntfs fragmented resident data attributes are not supported".to_string(),
      ));
    }
    return Ok(Arc::new(BytesDataSource::new(resident.remove(0))) as DataSourceHandle);
  }

  let cluster_size = boot_sector.cluster_size()?;
  let mut non_resident = attributes
    .iter()
    .map(|attribute| match &attribute.value {
      NtfsDataAttributeValue::Resident(_) => unreachable!(),
      NtfsDataAttributeValue::NonResident(non_resident) => {
        Ok((attribute.data_flags, non_resident.clone()))
      }
    })
    .collect::<Result<Vec<_>>>()?;
  non_resident.sort_by_key(|(_, attribute)| attribute.first_vcn);

  let stream_size = non_resident
    .iter()
    .map(|(_, attribute)| attribute.data_size)
    .max()
    .unwrap_or(0);
  let valid_size = non_resident
    .iter()
    .map(|(_, attribute)| attribute.valid_data_size)
    .max()
    .unwrap_or(stream_size);
  let mut expected_vcn = 0u64;
  let mut runs = Vec::<NtfsDataRun>::new();

  for (_, attribute) in non_resident {
    if attribute.first_vcn != expected_vcn {
      return Err(Error::InvalidFormat(
        "ntfs non-resident attribute chains must have continuous VCN ranges".to_string(),
      ));
    }

    let base_logical_offset = attribute
      .first_vcn
      .checked_mul(cluster_size)
      .ok_or_else(|| Error::InvalidRange("ntfs VCN offset overflow".to_string()))?;
    runs.extend(parse_attribute_runs(
      &attribute,
      cluster_size,
      base_logical_offset,
    )?);
    expected_vcn = attribute
      .last_vcn
      .checked_add(1)
      .ok_or_else(|| Error::InvalidRange("ntfs VCN range overflow".to_string()))?;
  }

  Ok(Arc::new(NtfsNonResidentDataSource::new(
    source,
    Arc::from(runs.into_boxed_slice()),
    stream_size,
    valid_size.min(stream_size),
  )) as DataSourceHandle)
}

fn parse_attribute_runs(
  attribute: &NtfsNonResidentAttribute, cluster_size: u64, base_logical_offset: u64,
) -> Result<Vec<NtfsDataRun>> {
  let mut runs = parse_runlist(attribute.runlist.as_ref(), cluster_size)?;
  for run in &mut runs {
    run.logical_offset = run
      .logical_offset
      .checked_add(base_logical_offset)
      .ok_or_else(|| Error::InvalidRange("ntfs run logical offset overflow".to_string()))?;
  }
  Ok(runs)
}

fn read_file_record(
  source: &dyn crate::DataSource, offset: u64, record_size: u64,
) -> Result<Vec<u8>> {
  let record_size = usize::try_from(record_size)
    .map_err(|_| Error::InvalidRange("ntfs file-record size is too large".to_string()))?;
  source.read_bytes_at(offset, record_size)
}

fn decode_node_id(node_id: &FileSystemNodeId) -> Result<u64> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::InvalidSourceReference(
      "ntfs node identifiers must be encoded as 8-byte little-endian values".to_string(),
    ));
  }
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  Ok(u64::from_le_bytes(raw))
}
