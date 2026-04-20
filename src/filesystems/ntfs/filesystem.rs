//! Read-only NTFS filesystem surface.

use std::{
  collections::{BTreeMap, HashMap},
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR,
  attribute_list::{NtfsAttributeListEntry, parse_attribute_list},
  boot_sector::NtfsBootSector,
  index::read_directory_index_entries,
  record::{
    NtfsDataAttribute, NtfsDataAttributeValue, NtfsFileRecord, NtfsNonResidentAttribute,
    parse_file_record,
  },
  reparse::{NtfsReparsePointInfo, NtfsReparsePointKind},
  runlist::{NtfsCompressedDataSource, NtfsDataRun, NtfsNonResidentDataSource, parse_runlist},
};
use crate::{
  ByteSourceHandle, BytesDataSource, Error, NamespaceDirectoryEntry, NamespaceNodeId,
  NamespaceNodeKind, NamespaceNodeRecord, Result, SourceHints, filesystems::FileSystem,
};

const ROOT_FILE_RECORD_NUMBER: u64 = 5;
const DEFAULT_NTFS_COMPRESSION_UNIT_CLUSTERS: u64 = 16;

pub struct NtfsFileSystem {
  source: ByteSourceHandle,
  boot_sector: NtfsBootSector,
  mft_stream: ByteSourceHandle,
  file_record_size: u64,
  record_count: u64,
  nodes: Mutex<HashMap<u64, Arc<NtfsNode>>>,
  children: Mutex<HashMap<u64, Arc<[NamespaceDirectoryEntry]>>>,
}

struct NtfsNode {
  name: String,
  parent_id: Option<u64>,
  record: NamespaceNodeRecord,
  data_attributes: Arc<[NtfsDataAttribute]>,
  index_root_attributes: Arc<[NtfsDataAttribute]>,
  index_allocation_attributes: Arc<[NtfsDataAttribute]>,
  reparse_point: Option<NtfsReparsePointInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsDataStreamInfo {
  pub name: Option<String>,
  pub size: u64,
}

impl NtfsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let boot_sector = NtfsBootSector::read(source.as_ref())?;
    let file_record_size = boot_sector.file_record_size()?;
    let mft_offset = boot_sector.mft_offset()?;
    let first_record = read_file_record(source.as_ref(), mft_offset, file_record_size)?;
    let mft_record = parse_file_record(&first_record, 0)?.ok_or_else(|| {
      Error::InvalidFormat("ntfs master file table record is not in use".to_string())
    })?;
    let bootstrap_mft_stream =
      build_stream_data_source(source.clone(), &boot_sector, &mft_record.data_attributes)?;
    let resolved_mft_record = resolve_bootstrap_mft_record(
      source.clone(),
      &boot_sector,
      bootstrap_mft_stream.clone(),
      file_record_size,
      &mft_record,
    )?;
    let mft_stream = if resolved_mft_record.attribute_list_entries.is_empty()
      && resolved_mft_record.attribute_list_attributes.is_empty()
    {
      bootstrap_mft_stream
    } else {
      build_stream_data_source(
        source.clone(),
        &boot_sector,
        &resolved_mft_record.data_attributes,
      )?
    };
    let mft_stream_size = mft_stream.size()?;
    if mft_stream_size < file_record_size {
      return Err(Error::InvalidFormat(
        "ntfs master file table is smaller than one file record".to_string(),
      ));
    }

    let filesystem = Self {
      source,
      boot_sector,
      mft_stream,
      file_record_size,
      record_count: mft_stream_size / file_record_size,
      nodes: Mutex::new(HashMap::new()),
      children: Mutex::new(HashMap::new()),
    };
    let root_id = NamespaceNodeId::from_u64(ROOT_FILE_RECORD_NUMBER);
    if filesystem.lookup_node(&root_id).is_err() {
      return Err(Error::InvalidFormat(
        "ntfs root directory record is missing".to_string(),
      ));
    }

    Ok(filesystem)
  }

  pub fn data_streams(&self, node_id: &NamespaceNodeId) -> Result<Vec<NtfsDataStreamInfo>> {
    let node = self.lookup_node(node_id)?;
    let mut streams = Vec::new();
    for (name, attributes) in grouped_stream_attributes(&node.data_attributes) {
      streams.push(NtfsDataStreamInfo {
        size: stream_size(&attributes)?,
        name,
      });
    }
    Ok(streams)
  }

  pub fn open_data_stream(
    &self, node_id: &NamespaceNodeId, name: Option<&str>,
  ) -> Result<ByteSourceHandle> {
    let node = self.lookup_node(node_id)?;
    let attributes = node
      .data_attributes
      .iter()
      .filter(|attribute| attribute.name.as_deref() == name)
      .cloned()
      .collect::<Vec<_>>();
    if attributes.is_empty() {
      let stream_name = name.unwrap_or("$DATA");
      return Err(Error::NotFound(format!(
        "ntfs data stream {stream_name} was not found on node {}",
        decode_node_id(node_id)?
      )));
    }

    build_stream_data_source(self.source.clone(), &self.boot_sector, &attributes)
  }

  pub fn reparse_point(&self, node_id: &NamespaceNodeId) -> Result<Option<NtfsReparsePointInfo>> {
    Ok(self.lookup_node(node_id)?.reparse_point.clone())
  }

  pub fn symlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    Ok(
      self
        .lookup_node(node_id)?
        .reparse_point
        .as_ref()
        .and_then(NtfsReparsePointInfo::preferred_target),
    )
  }

  fn lookup_node(&self, node_id: &NamespaceNodeId) -> Result<Arc<NtfsNode>> {
    let record_number = decode_node_id(node_id)?;
    self
      .load_node(record_number)?
      .ok_or_else(|| Error::NotFound(format!("ntfs node {record_number} was not found")))
  }

  fn load_node(&self, record_number: u64) -> Result<Option<Arc<NtfsNode>>> {
    if let Some(node) = self
      .nodes
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&record_number)
      .cloned()
    {
      return Ok(Some(node));
    }

    let Some(record) = self.load_resolved_record(record_number)? else {
      return Ok(None);
    };
    let Some(name) = record.preferred_name().cloned() else {
      return Ok(None);
    };
    let parent_id = if record_number == ROOT_FILE_RECORD_NUMBER {
      None
    } else {
      Some(name.parent_record_number)
    };
    let (kind, size) = classify_node(&record)?;
    let node = Arc::new(NtfsNode {
      name: if record_number == ROOT_FILE_RECORD_NUMBER {
        String::new()
      } else {
        name.name
      },
      parent_id,
      record: NamespaceNodeRecord::new(NamespaceNodeId::from_u64(record_number), kind, size),
      data_attributes: Arc::from(record.data_attributes),
      index_root_attributes: Arc::from(record.index_root_attributes),
      index_allocation_attributes: Arc::from(record.index_allocation_attributes),
      reparse_point: record.reparse_point,
    });

    let mut nodes = self
      .nodes
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = nodes.get(&record_number).cloned() {
      return Ok(Some(cached));
    }
    nodes.insert(record_number, node.clone());

    Ok(Some(node))
  }

  fn load_resolved_record(&self, record_number: u64) -> Result<Option<NtfsFileRecord>> {
    let Some(record) = self.read_parsed_record(record_number)? else {
      return Ok(None);
    };
    if record.base_record_number.is_some() {
      return Ok(None);
    }

    let attribute_list_entries =
      load_attribute_list_entries(self.source.clone(), &self.boot_sector, &record)?;
    resolve_attribute_list_record(
      record_number,
      &record,
      &attribute_list_entries,
      &mut |referenced_record| self.read_parsed_record(referenced_record),
    )
    .map(Some)
  }

  fn read_parsed_record(&self, record_number: u64) -> Result<Option<NtfsFileRecord>> {
    if record_number >= self.record_count {
      return Ok(None);
    }

    let record_bytes = read_file_record(
      self.mft_stream.as_ref(),
      record_number
        .checked_mul(self.file_record_size)
        .ok_or_else(|| Error::InvalidRange("ntfs MFT record offset overflow".to_string()))?,
      self.file_record_size,
    )?;
    parse_file_record(&record_bytes, record_number)
  }

  fn directory_entries(
    &self, record_number: u64, node: &NtfsNode,
  ) -> Result<Arc<[NamespaceDirectoryEntry]>> {
    if let Some(entries) = self
      .children
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&record_number)
      .cloned()
    {
      return Ok(entries);
    }

    let mut entries =
      if let Some(root_data) = resident_index_root_data(&node.index_root_attributes)? {
        let allocation_source = if node.index_allocation_attributes.is_empty() {
          None
        } else {
          let allocation_attributes = i30_attributes(&node.index_allocation_attributes)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
          Some(build_stream_data_source(
            self.source.clone(),
            &self.boot_sector,
            &allocation_attributes,
          )?)
        };
        let cluster_size = self.boot_sector.cluster_size()?;
        read_directory_index_entries(
          &root_data,
          allocation_source,
          cluster_size,
          &mut |child_record_number| {
            self
              .load_node(child_record_number)?
              .map(|child| child.record.kind)
              .ok_or_else(|| {
                Error::NotFound(format!(
                  "ntfs index entry points to missing record {child_record_number}"
                ))
              })
          },
        )?
      } else {
        self.scan_directory_entries(record_number)?
      };
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let entries: Arc<[NamespaceDirectoryEntry]> = Arc::from(entries.into_boxed_slice());

    let mut cache = self
      .children
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cache.get(&record_number).cloned() {
      return Ok(existing);
    }
    cache.insert(record_number, entries.clone());
    Ok(entries)
  }

  fn scan_directory_entries(&self, record_number: u64) -> Result<Vec<NamespaceDirectoryEntry>> {
    let mut entries = Vec::new();
    for child_record_number in 0..self.record_count {
      let Some(node) = self.load_node(child_record_number)? else {
        continue;
      };
      if node.parent_id != Some(record_number) || child_record_number == ROOT_FILE_RECORD_NUMBER {
        continue;
      }
      entries.push(NamespaceDirectoryEntry::new(
        node.name.clone(),
        node.record.id.clone(),
        node.record.kind,
      ));
    }

    Ok(entries)
  }
}

impl FileSystem for NtfsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(ROOT_FILE_RECORD_NUMBER)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    self.lookup_node(node_id).map(|node| node.record.clone())
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let record_number = decode_node_id(directory_id)?;
    let node = self.lookup_node(directory_id)?;
    if node.record.kind != NamespaceNodeKind::Directory {
      return Err(Error::NotFound(format!(
        "ntfs node {record_number} is not a directory"
      )));
    }

    Ok(self.directory_entries(record_number, &node)?.to_vec())
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let record_number = decode_node_id(file_id)?;
    let node = self.lookup_node(file_id)?;
    if node.record.kind == NamespaceNodeKind::Directory {
      return Err(Error::NotFound(format!(
        "ntfs node {record_number} is not a readable file"
      )));
    }

    build_default_data_source(
      self.source.clone(),
      &self.boot_sector,
      &node.data_attributes,
    )
  }
}

fn grouped_stream_attributes(
  data_attributes: &[NtfsDataAttribute],
) -> BTreeMap<Option<String>, Vec<NtfsDataAttribute>> {
  let mut streams = BTreeMap::<Option<String>, Vec<NtfsDataAttribute>>::new();
  for attribute in data_attributes {
    streams
      .entry(attribute.name.clone())
      .or_default()
      .push(attribute.clone());
  }
  streams
}

fn resolve_bootstrap_mft_record(
  source: ByteSourceHandle, boot_sector: &NtfsBootSector, bootstrap_mft_stream: ByteSourceHandle,
  file_record_size: u64, record: &NtfsFileRecord,
) -> Result<NtfsFileRecord> {
  let attribute_list_entries = load_attribute_list_entries(source, boot_sector, record)?;
  if attribute_list_entries.is_empty() {
    return Ok(record.clone());
  }

  let record_count = bootstrap_mft_stream.size()? / file_record_size;
  resolve_attribute_list_record(
    0,
    record,
    &attribute_list_entries,
    &mut |referenced_record| {
      if referenced_record >= record_count {
        return Ok(None);
      }

      let record_offset = referenced_record
        .checked_mul(file_record_size)
        .ok_or_else(|| Error::InvalidRange("ntfs MFT record offset overflow".to_string()))?;
      let bytes = read_file_record(
        bootstrap_mft_stream.as_ref(),
        record_offset,
        file_record_size,
      )?;
      parse_file_record(&bytes, referenced_record)
    },
  )
}

fn resolve_attribute_list_record<F>(
  record_number: u64, record: &NtfsFileRecord, attribute_list_entries: &[NtfsAttributeListEntry],
  load_record: &mut F,
) -> Result<NtfsFileRecord>
where
  F: FnMut(u64) -> Result<Option<NtfsFileRecord>>, {
  if attribute_list_entries.is_empty() {
    return Ok(record.clone());
  }

  let mut resolved = record.clone();
  resolved.attribute_list_entries = attribute_list_entries.to_vec();
  let mut referenced_records = BTreeMap::<u64, ()>::new();
  for entry in attribute_list_entries {
    if entry.base_file_record != record_number {
      referenced_records.insert(entry.base_file_record, ());
    }
  }

  for referenced_record in referenced_records.keys() {
    let extension = load_record(*referenced_record)?.ok_or_else(|| {
      Error::InvalidFormat(format!(
        "ntfs attribute list references missing file record {referenced_record}"
      ))
    })?;

    for file_name in &extension.file_names {
      if !resolved.file_names.contains(file_name) {
        resolved.file_names.push(file_name.clone());
      }
    }
    for data_attribute in &extension.data_attributes {
      if !resolved.data_attributes.contains(data_attribute) {
        resolved.data_attributes.push(data_attribute.clone());
      }
    }
    for index_root_attribute in &extension.index_root_attributes {
      if !resolved
        .index_root_attributes
        .contains(index_root_attribute)
      {
        resolved
          .index_root_attributes
          .push(index_root_attribute.clone());
      }
    }
    for index_allocation_attribute in &extension.index_allocation_attributes {
      if !resolved
        .index_allocation_attributes
        .contains(index_allocation_attribute)
      {
        resolved
          .index_allocation_attributes
          .push(index_allocation_attribute.clone());
      }
    }
    for attribute_list_attribute in &extension.attribute_list_attributes {
      if !resolved
        .attribute_list_attributes
        .contains(attribute_list_attribute)
      {
        resolved
          .attribute_list_attributes
          .push(attribute_list_attribute.clone());
      }
    }
    if resolved.reparse_point.is_none() && extension.reparse_point.is_some() {
      resolved.reparse_point = extension.reparse_point.clone();
      resolved.has_reparse_point = true;
    }
  }

  Ok(resolved)
}

fn load_attribute_list_entries(
  source: ByteSourceHandle, boot_sector: &NtfsBootSector, record: &NtfsFileRecord,
) -> Result<Vec<NtfsAttributeListEntry>> {
  if record.attribute_list_attributes.is_empty() {
    return Ok(record.attribute_list_entries.clone());
  }
  if !record.attribute_list_entries.is_empty() {
    return Err(Error::InvalidFormat(
      "ntfs file record stores $ATTRIBUTE_LIST as both resident and non-resident".to_string(),
    ));
  }

  let data =
    build_stream_data_source(source, boot_sector, &record.attribute_list_attributes)?.read_all()?;
  parse_attribute_list(&data)
}

fn i30_attributes(attributes: &[NtfsDataAttribute]) -> Vec<&NtfsDataAttribute> {
  let named = attributes
    .iter()
    .filter(|attribute| attribute.name.as_deref() == Some("$I30"))
    .collect::<Vec<_>>();
  if named.is_empty() {
    attributes.iter().collect()
  } else {
    named
  }
}

fn resident_index_root_data(attributes: &[NtfsDataAttribute]) -> Result<Option<Arc<[u8]>>> {
  let attributes = i30_attributes(attributes);
  if attributes.is_empty() {
    return Ok(None);
  }
  if attributes.len() != 1 {
    return Err(Error::InvalidFormat(
      "ntfs fragmented $INDEX_ROOT attributes are not supported".to_string(),
    ));
  }

  match &attributes[0].value {
    NtfsDataAttributeValue::Resident(data) => Ok(Some(data.clone())),
    NtfsDataAttributeValue::NonResident(_) => Err(Error::InvalidFormat(
      "ntfs non-resident $INDEX_ROOT attributes are not supported".to_string(),
    )),
  }
}

fn classify_node(record: &NtfsFileRecord) -> Result<(NamespaceNodeKind, u64)> {
  if record.is_directory() {
    let kind = match record.reparse_point.as_ref().map(|info| info.kind) {
      Some(NtfsReparsePointKind::MountPoint | NtfsReparsePointKind::SymbolicLink) => {
        NamespaceNodeKind::Symlink
      }
      _ => NamespaceNodeKind::Directory,
    };
    return Ok((kind, 0));
  }

  let size = default_stream_size(&record.data_attributes)?;
  let kind = match record.reparse_point.as_ref().map(|info| info.kind) {
    Some(NtfsReparsePointKind::MountPoint | NtfsReparsePointKind::SymbolicLink) => {
      NamespaceNodeKind::Symlink
    }
    _ => NamespaceNodeKind::File,
  };
  Ok((kind, size))
}

fn build_default_data_source(
  source: ByteSourceHandle, boot_sector: &NtfsBootSector, data_attributes: &[NtfsDataAttribute],
) -> Result<ByteSourceHandle> {
  let data_attributes = data_attributes
    .iter()
    .filter(|attribute| attribute.name.is_none())
    .cloned()
    .collect::<Vec<_>>();
  build_stream_data_source(source, boot_sector, &data_attributes)
}

fn default_stream_size(data_attributes: &[NtfsDataAttribute]) -> Result<u64> {
  let data_attributes = data_attributes
    .iter()
    .filter(|attribute| attribute.name.is_none())
    .cloned()
    .collect::<Vec<_>>();

  stream_size(&data_attributes)
}

fn stream_size(attributes: &[NtfsDataAttribute]) -> Result<u64> {
  if attributes.is_empty() {
    return Ok(0);
  }

  let resident = attributes
    .iter()
    .map(|attribute| match &attribute.value {
      NtfsDataAttributeValue::Resident(data) => Some(data.len()),
      NtfsDataAttributeValue::NonResident(_) => None,
    })
    .collect::<Option<Vec<_>>>();
  if let Some(mut resident) = resident {
    if resident.len() != 1 {
      return Err(Error::InvalidFormat(
        "ntfs fragmented resident data attributes are not supported".to_string(),
      ));
    }
    return u64::try_from(resident.remove(0))
      .map_err(|_| Error::InvalidRange("ntfs resident data size is too large".to_string()));
  }

  let mut non_resident = attributes
    .iter()
    .map(|attribute| match &attribute.value {
      NtfsDataAttributeValue::Resident(_) => Err(Error::InvalidFormat(
        "ntfs mixed resident and non-resident data attributes are not supported".to_string(),
      )),
      NtfsDataAttributeValue::NonResident(non_resident) => Ok(non_resident),
    })
    .collect::<Result<Vec<_>>>()?;
  non_resident.sort_by_key(|attribute| attribute.first_vcn);

  let stream_size = primary_non_resident_sizes(non_resident.iter().copied()).0;
  let mut expected_vcn = 0u64;
  for attribute in non_resident {
    if attribute.first_vcn != expected_vcn {
      return Err(Error::InvalidFormat(
        "ntfs non-resident attribute chains must have continuous VCN ranges".to_string(),
      ));
    }
    expected_vcn = next_vcn_after_attribute(attribute)?;
  }

  Ok(stream_size)
}

fn build_stream_data_source(
  source: ByteSourceHandle, boot_sector: &NtfsBootSector, attributes: &[NtfsDataAttribute],
) -> Result<ByteSourceHandle> {
  if attributes.is_empty() {
    return Ok(
      Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as ByteSourceHandle,
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
    return Ok(Arc::new(BytesDataSource::new(resident.remove(0))) as ByteSourceHandle);
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

  let (stream_size, valid_size) =
    primary_non_resident_sizes(non_resident.iter().map(|(_, attribute)| attribute));
  let compression_unit_size = compression_unit_size(
    non_resident
      .iter()
      .map(|(data_flags, attribute)| (*data_flags, attribute)),
    cluster_size,
  )?;
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
    expected_vcn = next_vcn_after_attribute(&attribute)?;
  }

  let runs = Arc::from(runs.into_boxed_slice());
  let valid_size = valid_size.min(stream_size);

  if let Some(compression_unit_size) = compression_unit_size {
    return Ok(Arc::new(NtfsCompressedDataSource::new(
      source,
      runs,
      stream_size,
      valid_size,
      cluster_size,
      compression_unit_size,
    )) as ByteSourceHandle);
  }

  Ok(Arc::new(NtfsNonResidentDataSource::new(
    source,
    runs,
    stream_size,
    valid_size,
  )) as ByteSourceHandle)
}

fn primary_non_resident_sizes<'a>(
  attributes: impl IntoIterator<Item = &'a NtfsNonResidentAttribute>,
) -> (u64, u64) {
  attributes
    .into_iter()
    .find(|attribute| attribute.first_vcn == 0)
    .map_or((0, 0), |attribute| {
      (attribute.data_size, attribute.valid_data_size)
    })
}

fn next_vcn_after_attribute(attribute: &NtfsNonResidentAttribute) -> Result<u64> {
  if attribute.first_vcn == 0 && attribute.last_vcn == u64::MAX && attribute.data_size == 0 {
    return Ok(0);
  }

  attribute
    .last_vcn
    .checked_add(1)
    .ok_or_else(|| Error::InvalidRange("ntfs VCN range overflow".to_string()))
}

fn compression_unit_size<'a>(
  attributes: impl IntoIterator<Item = (u16, &'a NtfsNonResidentAttribute)>, cluster_size: u64,
) -> Result<Option<u64>> {
  let mut compression_unit_clusters = None;

  for (data_flags, attribute) in attributes {
    let compression_method = data_flags & 0x00FF;
    if compression_method == 0 {
      continue;
    }
    if compression_method != 1 {
      return Err(Error::InvalidFormat(format!(
        "unsupported ntfs compression method 0x{compression_method:04x}"
      )));
    }

    let unit_clusters = if attribute.compression_unit == 0 {
      DEFAULT_NTFS_COMPRESSION_UNIT_CLUSTERS
    } else {
      1u64
        .checked_shl(u32::from(attribute.compression_unit))
        .ok_or_else(|| Error::InvalidRange("ntfs compression unit overflow".to_string()))?
    };
    if let Some(current) = compression_unit_clusters {
      if current != unit_clusters {
        return Err(Error::InvalidFormat(
          "ntfs compressed attribute chains must use a consistent compression unit".to_string(),
        ));
      }
    } else {
      compression_unit_clusters = Some(unit_clusters);
    }
  }

  compression_unit_clusters
    .map(|unit_clusters| {
      unit_clusters
        .checked_mul(cluster_size)
        .ok_or_else(|| Error::InvalidRange("ntfs compression unit size overflow".to_string()))
    })
    .transpose()
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
  source: &dyn crate::ByteSource, offset: u64, record_size: u64,
) -> Result<Vec<u8>> {
  let record_size = usize::try_from(record_size)
    .map_err(|_| Error::InvalidRange("ntfs file-record size is too large".to_string()))?;
  source.read_bytes_at(offset, record_size)
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u64> {
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

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, sync::Arc};

  use super::*;
  use crate::filesystems::ntfs::NtfsAttributeListEntry;

  #[derive(Clone, Copy, Default)]
  struct NonResidentOptions {
    data_flags: u16,
    compression_unit: u16,
  }

  fn resident_data_attribute(data: &[u8], attribute_id: u16) -> NtfsDataAttribute {
    NtfsDataAttribute {
      attribute_id,
      name: None,
      data_flags: 0,
      value: NtfsDataAttributeValue::Resident(Arc::from(data)),
    }
  }

  fn non_resident_data_attribute(
    first_vcn: u64, last_vcn: u64, data_size: u64, valid_data_size: u64, runlist: &[u8],
    attribute_id: u16,
  ) -> NtfsDataAttribute {
    non_resident_data_attribute_with_flags(
      first_vcn,
      last_vcn,
      data_size,
      valid_data_size,
      runlist,
      attribute_id,
      NonResidentOptions::default(),
    )
  }

  fn non_resident_data_attribute_with_flags(
    first_vcn: u64, last_vcn: u64, data_size: u64, valid_data_size: u64, runlist: &[u8],
    attribute_id: u16, options: NonResidentOptions,
  ) -> NtfsDataAttribute {
    NtfsDataAttribute {
      attribute_id,
      name: None,
      data_flags: options.data_flags,
      value: NtfsDataAttributeValue::NonResident(NtfsNonResidentAttribute {
        first_vcn,
        last_vcn,
        compression_unit: options.compression_unit,
        data_size,
        valid_data_size,
        runlist: Arc::from(runlist),
      }),
    }
  }

  fn sample_boot_sector() -> NtfsBootSector {
    NtfsBootSector {
      bytes_per_sector: 512,
      sectors_per_cluster: 8,
      total_sectors: 4096,
      mft_cluster: 4,
      mft_mirror_cluster: 8,
      clusters_per_file_record: 0xF6,
      clusters_per_index_buffer: 1,
      volume_serial_number: 0,
    }
  }

  fn sample_record_with_reparse(
    flags: u16, reparse_kind: NtfsReparsePointKind, data_attributes: Vec<NtfsDataAttribute>,
  ) -> NtfsFileRecord {
    NtfsFileRecord {
      flags,
      base_record_number: None,
      file_names: vec![],
      data_attributes,
      attribute_list_entries: vec![],
      attribute_list_attributes: vec![],
      index_root_attributes: vec![],
      index_allocation_attributes: vec![],
      reparse_point: Some(NtfsReparsePointInfo {
        kind: reparse_kind,
        tag: 0,
        substitute_name: None,
        print_name: None,
        flags: None,
        compression_method: None,
      }),
      has_reparse_point: true,
    }
  }

  fn synthetic_non_resident_attribute_bytes(
    first_vcn: u64, last_vcn: u64, data_size: u64, valid_data_size: u64, runlist: &[u8],
    attribute_id: u16,
  ) -> Vec<u8> {
    let attribute_size = (64 + runlist.len()).next_multiple_of(8);
    let mut attribute = vec![0u8; attribute_size];
    attribute[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    attribute[4..8].copy_from_slice(&(u32::try_from(attribute_size).unwrap()).to_le_bytes());
    attribute[8] = 1;
    attribute[14..16].copy_from_slice(&attribute_id.to_le_bytes());
    attribute[16..24].copy_from_slice(&first_vcn.to_le_bytes());
    attribute[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    attribute[32..34].copy_from_slice(&64u16.to_le_bytes());
    attribute[40..48].copy_from_slice(&data_size.to_le_bytes());
    attribute[48..56].copy_from_slice(&data_size.to_le_bytes());
    attribute[56..64].copy_from_slice(&valid_data_size.to_le_bytes());
    attribute[64..64 + runlist.len()].copy_from_slice(runlist);
    attribute
  }

  fn synthetic_attribute_list_entry_bytes(
    attribute_type: u32, starting_vcn: u64, base_file_record: u64, attribute_id: u16,
  ) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&attribute_type.to_le_bytes());
    bytes[4..6].copy_from_slice(&32u16.to_le_bytes());
    bytes[8..16].copy_from_slice(&starting_vcn.to_le_bytes());
    bytes[16..22].copy_from_slice(&base_file_record.to_le_bytes()[..6]);
    bytes[24..26].copy_from_slice(&attribute_id.to_le_bytes());
    bytes
  }

  fn synthetic_file_record(attribute: &[u8]) -> Vec<u8> {
    let mut record = vec![0u8; 512];
    record[0..4].copy_from_slice(b"FILE");
    record[4..6].copy_from_slice(&48u16.to_le_bytes());
    record[6..8].copy_from_slice(&2u16.to_le_bytes());
    record[16..18].copy_from_slice(&1u16.to_le_bytes());
    record[20..22].copy_from_slice(&56u16.to_le_bytes());
    record[22..24].copy_from_slice(&0x0001u16.to_le_bytes());
    let used_size = 56 + attribute.len() + 4;
    let record_size = u32::try_from(record.len()).unwrap();
    record[24..28].copy_from_slice(&(u32::try_from(used_size).unwrap()).to_le_bytes());
    record[28..32].copy_from_slice(&record_size.to_le_bytes());
    record[40..42].copy_from_slice(&2u16.to_le_bytes());
    record[48..50].copy_from_slice(&[0xAA, 0xBB]);
    record[50..52].copy_from_slice(&[0x11, 0x22]);
    record[56..56 + attribute.len()].copy_from_slice(attribute);
    record[56 + attribute.len()..60 + attribute.len()]
      .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    record[510..512].copy_from_slice(&[0xAA, 0xBB]);
    record
  }

  #[test]
  fn resolves_attribute_list_extension_records() {
    let base_record = NtfsFileRecord {
      flags: 0x0001,
      base_record_number: None,
      file_names: vec![],
      data_attributes: vec![resident_data_attribute(b"base", 1)],
      attribute_list_entries: vec![NtfsAttributeListEntry {
        attribute_type: 0x80,
        entry_length: 40,
        starting_vcn: 0,
        base_file_record: 42,
        base_file_sequence: 1,
        attribute_id: 7,
        name: None,
      }],
      attribute_list_attributes: vec![],
      index_root_attributes: vec![],
      index_allocation_attributes: vec![],
      reparse_point: None,
      has_reparse_point: false,
    };
    let extension_record = NtfsFileRecord {
      flags: 0x0001,
      base_record_number: Some(5),
      file_names: vec![super::super::record::NtfsFileNameAttribute {
        attribute_id: 2,
        parent_record_number: 5,
        name: "merged.txt".to_string(),
        namespace: 1,
      }],
      data_attributes: vec![resident_data_attribute(b"extension", 7)],
      attribute_list_entries: vec![],
      attribute_list_attributes: vec![],
      index_root_attributes: vec![],
      index_allocation_attributes: vec![],
      reparse_point: None,
      has_reparse_point: false,
    };
    let records = HashMap::from([(42u64, extension_record)]);
    let mut load_record = |record_number| Ok(records.get(&record_number).cloned());

    let resolved = resolve_attribute_list_record(
      5,
      &base_record,
      &base_record.attribute_list_entries,
      &mut load_record,
    )
    .unwrap();

    assert_eq!(resolved.file_names[0].name, "merged.txt");
    assert_eq!(resolved.data_attributes.len(), 2);
  }

  #[test]
  fn classifies_wof_reparse_records_as_regular_files() {
    let record = sample_record_with_reparse(
      0x0001,
      NtfsReparsePointKind::WofCompressed,
      vec![resident_data_attribute(b"wof", 1)],
    );

    let (kind, size) = classify_node(&record).unwrap();

    assert_eq!(kind, NamespaceNodeKind::File);
    assert_eq!(size, 3);
  }

  #[test]
  fn classifies_mount_point_directories_as_symlinks_only() {
    let mount_point =
      sample_record_with_reparse(0x0001 | 0x0002, NtfsReparsePointKind::MountPoint, vec![]);
    let unknown = sample_record_with_reparse(0x0001 | 0x0002, NtfsReparsePointKind::Other, vec![]);

    assert_eq!(
      classify_node(&mount_point).unwrap().0,
      NamespaceNodeKind::Symlink
    );
    assert_eq!(
      classify_node(&unknown).unwrap().0,
      NamespaceNodeKind::Directory
    );
  }

  #[test]
  fn loads_nonresident_attribute_list_entries() {
    let entry_bytes = synthetic_attribute_list_entry_bytes(0x80, 0, 42, 7);
    let mut source_bytes = vec![0u8; 2 * 4096];
    source_bytes[4096..4096 + entry_bytes.len()].copy_from_slice(&entry_bytes);
    let source = Arc::new(BytesDataSource::new(source_bytes)) as ByteSourceHandle;
    let record = NtfsFileRecord {
      flags: 0x0001,
      base_record_number: None,
      file_names: vec![],
      data_attributes: vec![],
      attribute_list_entries: vec![],
      attribute_list_attributes: vec![non_resident_data_attribute(
        0,
        0,
        32,
        32,
        &[0x11, 0x01, 0x01, 0x00],
        1,
      )],
      index_root_attributes: vec![],
      index_allocation_attributes: vec![],
      reparse_point: None,
      has_reparse_point: false,
    };

    let entries = load_attribute_list_entries(source, &sample_boot_sector(), &record).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].base_file_record, 42);
    assert_eq!(entries[0].attribute_id, 7);
  }

  #[test]
  fn resolves_bootstrap_mft_attribute_list_records_from_partial_stream() {
    let base_record = NtfsFileRecord {
      flags: 0x0001,
      base_record_number: None,
      file_names: vec![],
      data_attributes: vec![non_resident_data_attribute(
        0,
        0,
        1024,
        1024,
        &[0x11, 0x01, 0x01, 0x00],
        1,
      )],
      attribute_list_entries: vec![NtfsAttributeListEntry {
        attribute_type: 0x80,
        entry_length: 40,
        starting_vcn: 1,
        base_file_record: 1,
        base_file_sequence: 1,
        attribute_id: 7,
        name: None,
      }],
      attribute_list_attributes: vec![],
      index_root_attributes: vec![],
      index_allocation_attributes: vec![],
      reparse_point: None,
      has_reparse_point: false,
    };
    let extension_record = synthetic_file_record(&synthetic_non_resident_attribute_bytes(
      1,
      1,
      0,
      0,
      &[0x11, 0x01, 0x02, 0x00],
      7,
    ));
    let mut bootstrap_bytes = vec![0u8; 1024];
    bootstrap_bytes[512..1024].copy_from_slice(&extension_record);
    let bootstrap_stream = Arc::new(BytesDataSource::new(bootstrap_bytes)) as ByteSourceHandle;

    let resolved = resolve_bootstrap_mft_record(
      bootstrap_stream.clone(),
      &sample_boot_sector(),
      bootstrap_stream,
      512,
      &base_record,
    )
    .unwrap();

    assert_eq!(resolved.data_attributes.len(), 2);
    assert!(resolved.data_attributes.iter().any(|attribute| {
      matches!(
        &attribute.value,
        NtfsDataAttributeValue::NonResident(non_resident) if non_resident.first_vcn == 1
      )
    }));
  }

  #[test]
  fn stream_size_accepts_empty_nonresident_attributes() {
    let attributes = [non_resident_data_attribute(0, u64::MAX, 0, 0, &[0], 1)];

    assert_eq!(stream_size(&attributes).unwrap(), 0);
  }

  #[test]
  fn build_stream_data_source_accepts_empty_nonresident_attributes() {
    let source = Arc::new(BytesDataSource::new(Vec::<u8>::new())) as ByteSourceHandle;
    let attributes = [non_resident_data_attribute(0, u64::MAX, 0, 0, &[0], 1)];

    let stream = build_stream_data_source(source, &sample_boot_sector(), &attributes).unwrap();

    assert_eq!(stream.size().unwrap(), 0);
    assert_eq!(stream.read_all().unwrap(), Vec::<u8>::new());
  }

  #[test]
  fn build_stream_data_source_uses_primary_extent_sizes() {
    let mut bytes = vec![0u8; 3 * 4096];
    bytes[4096..8192].fill(b'A');
    bytes[8192..12288].fill(b'B');
    let source = Arc::new(BytesDataSource::new(bytes)) as ByteSourceHandle;
    let attributes = [
      non_resident_data_attribute(0, 0, 8192, 8192, &[0x11, 0x01, 0x01, 0x00], 1),
      non_resident_data_attribute(1, 1, 16384, 12288, &[0x11, 0x01, 0x02, 0x00], 2),
    ];

    let stream = build_stream_data_source(source, &sample_boot_sector(), &attributes).unwrap();
    let data = stream.read_all().unwrap();

    assert_eq!(stream.size().unwrap(), 8192);
    assert_eq!(data.len(), 8192);
    assert!(data[..4096].iter().all(|byte| *byte == b'A'));
    assert!(data[4096..].iter().all(|byte| *byte == b'B'));
  }

  #[test]
  fn build_stream_data_source_decompresses_lznt1_units() {
    let mut backing = vec![0u8; 2 * 4096];
    backing[4096..4104].copy_from_slice(&[0x05, 0xB0, 0x08, b'A', b'B', b'C', 0x06, 0x20]);
    let source = Arc::new(BytesDataSource::new(backing)) as ByteSourceHandle;
    let attributes = [non_resident_data_attribute_with_flags(
      0,
      15,
      12,
      12,
      &[0x11, 0x01, 0x01, 0x01, 0x0F, 0x00],
      1,
      NonResidentOptions {
        data_flags: 0x0001,
        compression_unit: 0,
      },
    )];

    let stream = build_stream_data_source(source, &sample_boot_sector(), &attributes).unwrap();

    assert_eq!(stream.read_all().unwrap(), b"ABCABCABCABC");
  }
}

crate::filesystems::driver::impl_file_system_data_source!(NtfsFileSystem);
