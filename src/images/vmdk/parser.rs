//! Parsing of monolithic sparse VMDK metadata.

use std::sync::Arc;

use super::{
  constants,
  descriptor::{VmdkDescriptor, VmdkExtentAccessMode, VmdkExtentType, VmdkFileType},
  header::VmdkSparseHeader,
};
use crate::{DataSource, DataSourceHandle, Error, Result};

pub(super) struct ParsedVmdk {
  pub header: VmdkSparseHeader,
  pub descriptor: VmdkDescriptor,
  pub grain_directory: Arc<[u32]>,
}

pub(super) fn parse(source: DataSourceHandle) -> Result<ParsedVmdk> {
  let source_size = source.size()?;
  let header = VmdkSparseHeader::read(source.as_ref())?;
  if header.has_compressed_grains() || header.has_markers() {
    return Err(Error::InvalidFormat(
      "compressed or marker-based vmdk sparse extents are not supported yet".to_string(),
    ));
  }

  let descriptor = read_descriptor(source.as_ref(), header, source_size)?;
  validate_descriptor_against_header(&header, &descriptor)?;
  let grain_directory = read_grain_directory(source.as_ref(), header, source_size)?;

  Ok(ParsedVmdk {
    header,
    descriptor,
    grain_directory,
  })
}

pub(super) fn grain_table_entry_count(header: VmdkSparseHeader) -> u64 {
  u64::from(header.grain_table_entries)
}

pub(super) fn grain_directory_entry_count(header: VmdkSparseHeader) -> Result<u64> {
  let sectors_per_table = grain_table_entry_count(header)
    .checked_mul(header.sectors_per_grain)
    .ok_or_else(|| Error::InvalidRange("vmdk grain-directory geometry overflow".to_string()))?;
  Ok(header.capacity_sectors.div_ceil(sectors_per_table))
}

fn read_descriptor(
  source: &dyn DataSource, header: VmdkSparseHeader, source_size: u64,
) -> Result<VmdkDescriptor> {
  let descriptor_offset = header
    .descriptor_start_sector
    .checked_mul(constants::BYTES_PER_SECTOR)
    .ok_or_else(|| Error::InvalidRange("vmdk descriptor offset overflow".to_string()))?;
  let descriptor_size = header
    .descriptor_size_sectors
    .checked_mul(constants::BYTES_PER_SECTOR)
    .ok_or_else(|| Error::InvalidRange("vmdk descriptor size overflow".to_string()))?;
  if descriptor_offset
    .checked_add(descriptor_size)
    .ok_or_else(|| Error::InvalidRange("vmdk descriptor end overflow".to_string()))?
    > source_size
  {
    return Err(Error::InvalidFormat(
      "vmdk embedded descriptor exceeds the source size".to_string(),
    ));
  }
  let descriptor_bytes = source.read_bytes_at(
    descriptor_offset,
    usize::try_from(descriptor_size)
      .map_err(|_| Error::InvalidRange("vmdk descriptor size is too large".to_string()))?,
  )?;
  VmdkDescriptor::from_bytes(&descriptor_bytes)
}

fn validate_descriptor_against_header(
  header: &VmdkSparseHeader, descriptor: &VmdkDescriptor,
) -> Result<()> {
  if descriptor.file_type != VmdkFileType::MonolithicSparse {
    return Err(Error::InvalidFormat(format!(
      "unsupported vmdk create type in the current step: {:?}",
      descriptor.file_type
    )));
  }
  if descriptor.parent_content_id.is_some() || descriptor.parent_file_name_hint.is_some() {
    return Err(Error::InvalidSourceReference(
      "parent-backed vmdk layers are not supported yet".to_string(),
    ));
  }
  if descriptor.extents.len() != 1 {
    return Err(Error::InvalidFormat(
      "monolithic sparse vmdk images must declare exactly one extent".to_string(),
    ));
  }

  let extent = &descriptor.extents[0];
  if extent.access_mode == VmdkExtentAccessMode::Unknown
    || extent.access_mode == VmdkExtentAccessMode::NoAccess
  {
    return Err(Error::InvalidFormat(
      "unsupported vmdk extent access mode".to_string(),
    ));
  }
  if extent.extent_type != VmdkExtentType::Sparse {
    return Err(Error::InvalidFormat(
      "monolithic sparse vmdk images must use a SPARSE extent".to_string(),
    ));
  }
  if extent.start_sector != 0 {
    return Err(Error::InvalidFormat(
      "monolithic sparse vmdk extents must start at sector 0".to_string(),
    ));
  }
  if extent.sector_count != header.capacity_sectors {
    return Err(Error::InvalidFormat(
      "vmdk descriptor extent length does not match the sparse header capacity".to_string(),
    ));
  }

  Ok(())
}

fn read_grain_directory(
  source: &dyn DataSource, header: VmdkSparseHeader, source_size: u64,
) -> Result<Arc<[u32]>> {
  let directory_start_sector = header.active_grain_directory_start_sector();
  if directory_start_sector == constants::GD_AT_END {
    return Err(Error::InvalidFormat(
      "gd-at-end sparse vmdk layouts are not supported yet".to_string(),
    ));
  }
  let entry_count = grain_directory_entry_count(header)?;
  let entry_count_usize = usize::try_from(entry_count).map_err(|_| {
    Error::InvalidRange("vmdk grain-directory entry count is too large".to_string())
  })?;
  let table_offset = directory_start_sector
    .checked_mul(constants::BYTES_PER_SECTOR)
    .ok_or_else(|| Error::InvalidRange("vmdk grain-directory offset overflow".to_string()))?;
  let table_bytes = entry_count
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("vmdk grain-directory size overflow".to_string()))?;
  if table_offset
    .checked_add(table_bytes)
    .ok_or_else(|| Error::InvalidRange("vmdk grain-directory end overflow".to_string()))?
    > source_size
  {
    return Err(Error::InvalidFormat(
      "vmdk grain directory exceeds the source size".to_string(),
    ));
  }

  let raw = source.read_bytes_at(
    table_offset,
    usize::try_from(table_bytes).map_err(|_| {
      Error::InvalidRange("vmdk grain-directory byte count is too large".to_string())
    })?,
  )?;
  let entries = raw
    .chunks_exact(4)
    .map(|chunk| Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
    .collect::<Result<Vec<_>>>()?;
  if entries.len() != entry_count_usize {
    return Err(Error::InvalidFormat(
      "vmdk grain-directory entry count is inconsistent".to_string(),
    ));
  }

  let grain_table_bytes = grain_table_entry_count(header)
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("vmdk grain-table size overflow".to_string()))?;
  for sector in &entries {
    if *sector == 0 || (header.uses_zero_grain_entries() && *sector == 1) {
      continue;
    }

    let offset = u64::from(*sector)
      .checked_mul(constants::BYTES_PER_SECTOR)
      .ok_or_else(|| Error::InvalidRange("vmdk grain-table offset overflow".to_string()))?;
    if offset
      .checked_add(grain_table_bytes)
      .ok_or_else(|| Error::InvalidRange("vmdk grain-table end overflow".to_string()))?
      > source_size
    {
      return Err(Error::InvalidFormat(
        "vmdk grain table exceeds the source size".to_string(),
      ));
    }
  }

  Ok(Arc::from(entries))
}
