use std::{collections::BTreeMap, sync::Arc};

use super::{
  attribute_list::{NtfsAttributeListEntry, parse_attribute_list},
  boot_sector::NtfsBootSector,
  record::{
    NtfsDataAttribute, NtfsDataAttributeValue, NtfsFileRecord, NtfsNonResidentAttribute,
    parse_file_record,
  },
  runlist::{NtfsCompressedDataSource, NtfsDataRun, NtfsNonResidentDataSource, parse_runlist},
};
use crate::{
  ByteSourceHandle, BytesDataSource, Error, NamespaceNodeId, NamespaceNodeKind, Result,
  filesystems::ntfs::reparse::NtfsReparsePointKind,
};

const DEFAULT_NTFS_COMPRESSION_UNIT_CLUSTERS: u64 = 16;

pub(super) fn grouped_stream_attributes(
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

pub(super) fn resolve_bootstrap_mft_record(
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
        .ok_or_else(|| Error::invalid_range("ntfs MFT record offset overflow"))?;
      let bytes = read_file_record(
        bootstrap_mft_stream.as_ref(),
        record_offset,
        file_record_size,
      )?;
      parse_file_record(&bytes, referenced_record)
    },
  )
}

pub(super) fn resolve_attribute_list_record<F>(
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
      Error::invalid_format(format!(
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

pub(super) fn load_attribute_list_entries(
  source: ByteSourceHandle, boot_sector: &NtfsBootSector, record: &NtfsFileRecord,
) -> Result<Vec<NtfsAttributeListEntry>> {
  if record.attribute_list_attributes.is_empty() {
    return Ok(record.attribute_list_entries.clone());
  }
  if !record.attribute_list_entries.is_empty() {
    return Err(Error::invalid_format(
      "ntfs file record stores $ATTRIBUTE_LIST as both resident and non-resident".to_string(),
    ));
  }

  let data =
    build_stream_data_source(source, boot_sector, &record.attribute_list_attributes)?.read_all()?;
  parse_attribute_list(&data)
}

pub(super) fn i30_attributes(attributes: &[NtfsDataAttribute]) -> Vec<&NtfsDataAttribute> {
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

pub(super) fn resident_index_root_data(
  attributes: &[NtfsDataAttribute],
) -> Result<Option<Arc<[u8]>>> {
  let attributes = i30_attributes(attributes);
  if attributes.is_empty() {
    return Ok(None);
  }
  if attributes.len() != 1 {
    return Err(Error::invalid_format(
      "ntfs fragmented $INDEX_ROOT attributes are not supported".to_string(),
    ));
  }

  match &attributes[0].value {
    NtfsDataAttributeValue::Resident(data) => Ok(Some(data.clone())),
    NtfsDataAttributeValue::NonResident(_) => Err(Error::invalid_format(
      "ntfs non-resident $INDEX_ROOT attributes are not supported".to_string(),
    )),
  }
}

pub(super) fn classify_node(record: &NtfsFileRecord) -> Result<(NamespaceNodeKind, u64)> {
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

pub(super) fn build_default_data_source(
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

pub(super) fn stream_size(attributes: &[NtfsDataAttribute]) -> Result<u64> {
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
      return Err(Error::invalid_format(
        "ntfs fragmented resident data attributes are not supported".to_string(),
      ));
    }
    return u64::try_from(resident.remove(0))
      .map_err(|_| Error::invalid_range("ntfs resident data size is too large"));
  }

  let mut non_resident = attributes
    .iter()
    .map(|attribute| match &attribute.value {
      NtfsDataAttributeValue::Resident(_) => Err(Error::invalid_format(
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
      return Err(Error::invalid_format(
        "ntfs non-resident attribute chains must have continuous VCN ranges".to_string(),
      ));
    }
    expected_vcn = next_vcn_after_attribute(attribute)?;
  }

  Ok(stream_size)
}

pub(super) fn build_stream_data_source(
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
      return Err(Error::invalid_format(
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
      return Err(Error::invalid_format(
        "ntfs non-resident attribute chains must have continuous VCN ranges".to_string(),
      ));
    }

    let base_logical_offset = attribute
      .first_vcn
      .checked_mul(cluster_size)
      .ok_or_else(|| Error::invalid_range("ntfs VCN offset overflow"))?;
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
    .ok_or_else(|| Error::invalid_range("ntfs VCN range overflow"))
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
      return Err(Error::invalid_format(format!(
        "unsupported ntfs compression method 0x{compression_method:04x}"
      )));
    }

    let unit_clusters = if attribute.compression_unit == 0 {
      DEFAULT_NTFS_COMPRESSION_UNIT_CLUSTERS
    } else {
      1u64
        .checked_shl(u32::from(attribute.compression_unit))
        .ok_or_else(|| Error::invalid_range("ntfs compression unit overflow"))?
    };
    if let Some(current) = compression_unit_clusters {
      if current != unit_clusters {
        return Err(Error::invalid_format(
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
        .ok_or_else(|| Error::invalid_range("ntfs compression unit size overflow"))
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
      .ok_or_else(|| Error::invalid_range("ntfs run logical offset overflow"))?;
  }
  Ok(runs)
}

pub(super) fn read_file_record(
  source: &dyn crate::ByteSource, offset: u64, record_size: u64,
) -> Result<Vec<u8>> {
  let record_size = usize::try_from(record_size)
    .map_err(|_| Error::invalid_range("ntfs file-record size is too large"))?;
  source.read_bytes_at(offset, record_size)
}

pub(super) fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u64> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::invalid_source_reference(
      "ntfs node identifiers must be encoded as 8-byte little-endian values".to_string(),
    ));
  }
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  Ok(u64::from_le_bytes(raw))
}
