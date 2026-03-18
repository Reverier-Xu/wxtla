//! Parsing of VMDK sparse metadata tables.

use std::sync::Arc;

use super::{
  constants, cowd_header::VmdkCowdHeader, descriptor::VmdkDescriptor, header::VmdkSparseHeader,
};
use crate::{DataSource, DataSourceHandle, Error, Result};

pub(super) struct ParsedSparseExtent {
  pub header: VmdkSparseHeader,
  pub embedded_descriptor: Option<VmdkDescriptor>,
  pub grain_directory: Arc<[u32]>,
}

pub(super) struct ParsedCowdVmdk {
  pub header: VmdkCowdHeader,
  pub grain_directory: Arc<[u32]>,
}

pub(super) fn parse_sparse_extent(source: DataSourceHandle) -> Result<ParsedSparseExtent> {
  let source_size = source.size()?;
  let header = VmdkSparseHeader::read(source.as_ref())?;
  if header.has_compressed_grains() && header.compression_method == 0 {
    return Err(Error::InvalidFormat(
      "vmdk compressed grains require a compression method".to_string(),
    ));
  }
  if header.compression_method != 0 && !header.has_compressed_grains() {
    return Err(Error::InvalidFormat(
      "vmdk compression method requires the compressed-grains flag".to_string(),
    ));
  }
  let directory_header = resolve_directory_header(source.as_ref(), source_size, header)?;

  let embedded_descriptor = if header.has_embedded_descriptor() {
    Some(read_descriptor(source.as_ref(), header, source_size)?)
  } else {
    None
  };
  let grain_directory = read_grain_directory(source.as_ref(), directory_header, source_size)?;

  Ok(ParsedSparseExtent {
    header,
    embedded_descriptor,
    grain_directory,
  })
}

pub(super) fn parse_cowd(source: DataSourceHandle) -> Result<ParsedCowdVmdk> {
  let source_size = source.size()?;
  let header = VmdkCowdHeader::read(source.as_ref())?;
  let grain_directory = read_cowd_grain_directory(source.as_ref(), &header, source_size)?;

  Ok(ParsedCowdVmdk {
    header,
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

pub(super) fn cowd_grain_table_entry_count() -> u64 {
  constants::COWD_GRAIN_TABLE_ENTRIES
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
fn read_grain_directory(
  source: &dyn DataSource, header: VmdkSparseHeader, source_size: u64,
) -> Result<Arc<[u32]>> {
  let directory_start_sector = header.active_grain_directory_start_sector();
  if directory_start_sector == constants::GD_AT_END {
    return Err(Error::InvalidFormat(
      "vmdk grain directory start sector is unresolved".to_string(),
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

fn resolve_directory_header(
  source: &dyn DataSource, source_size: u64, header: VmdkSparseHeader,
) -> Result<VmdkSparseHeader> {
  if !header.uses_gd_at_end() {
    return Ok(header);
  }
  if source_size < 1024 {
    return Err(Error::InvalidFormat(
      "vmdk gd-at-end layouts require a footer header near end-of-file".to_string(),
    ));
  }

  let footer_offset = source_size - 1024;
  let footer = VmdkSparseHeader::read_at(source, footer_offset)?;
  if footer.uses_gd_at_end() {
    return Err(Error::InvalidFormat(
      "vmdk footer header must expose the final grain-directory offset".to_string(),
    ));
  }
  if header.capacity_sectors != footer.capacity_sectors
    || header.sectors_per_grain != footer.sectors_per_grain
    || header.grain_table_entries != footer.grain_table_entries
    || header.descriptor_start_sector != footer.descriptor_start_sector
    || header.descriptor_size_sectors != footer.descriptor_size_sectors
    || header.flags != footer.flags
    || header.compression_method != footer.compression_method
  {
    return Err(Error::InvalidFormat(
      "vmdk footer header does not match the primary sparse header".to_string(),
    ));
  }

  Ok(footer)
}

fn read_cowd_grain_directory(
  source: &dyn DataSource, header: &VmdkCowdHeader, source_size: u64,
) -> Result<Arc<[u32]>> {
  let grain_size = header.grain_size_bytes()?;
  let directory_coverage = cowd_grain_table_entry_count()
    .checked_mul(grain_size)
    .ok_or_else(|| Error::InvalidRange("vmdk cowd directory coverage overflow".to_string()))?;
  let required_directory_entries = header.virtual_size_bytes()?.div_ceil(directory_coverage);
  if required_directory_entries > u64::from(header.grain_directory_entries) {
    return Err(Error::InvalidFormat(
      "vmdk cowd grain directory does not contain enough entries for the declared capacity"
        .to_string(),
    ));
  }
  let covered_size = u64::from(header.grain_directory_entries)
    .checked_mul(cowd_grain_table_entry_count())
    .and_then(|value| value.checked_mul(grain_size))
    .ok_or_else(|| Error::InvalidRange("vmdk cowd coverage overflow".to_string()))?;
  if covered_size < header.virtual_size_bytes()? {
    return Err(Error::InvalidFormat(
      "vmdk cowd grain directory does not cover the declared capacity".to_string(),
    ));
  }

  let table_offset = u64::from(header.grain_directory_start_sector)
    .checked_mul(constants::BYTES_PER_SECTOR)
    .ok_or_else(|| Error::InvalidRange("vmdk cowd grain-directory offset overflow".to_string()))?;
  let entry_count = usize::try_from(header.grain_directory_entries)
    .map_err(|_| Error::InvalidRange("vmdk cowd grain-directory count is too large".to_string()))?;
  let table_bytes = u64::from(header.grain_directory_entries)
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("vmdk cowd grain-directory size overflow".to_string()))?;
  if table_offset
    .checked_add(table_bytes)
    .ok_or_else(|| Error::InvalidRange("vmdk cowd grain-directory end overflow".to_string()))?
    > source_size
  {
    return Err(Error::InvalidFormat(
      "vmdk cowd grain directory exceeds the source size".to_string(),
    ));
  }

  let raw = source.read_bytes_at(
    table_offset,
    usize::try_from(table_bytes).map_err(|_| {
      Error::InvalidRange("vmdk cowd grain-directory size is too large".to_string())
    })?,
  )?;
  let entries = raw
    .chunks_exact(4)
    .map(|chunk| Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
    .collect::<Result<Vec<_>>>()?;
  if entries.len() != entry_count {
    return Err(Error::InvalidFormat(
      "vmdk cowd grain-directory entry count is inconsistent".to_string(),
    ));
  }

  let grain_table_bytes = cowd_grain_table_entry_count()
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("vmdk cowd grain-table size overflow".to_string()))?;
  for sector in entries
    .iter()
    .take(usize::try_from(required_directory_entries).map_err(|_| {
      Error::InvalidRange("vmdk cowd required directory count is too large".to_string())
    })?)
  {
    if *sector == 0 {
      continue;
    }

    let offset = u64::from(*sector)
      .checked_mul(constants::BYTES_PER_SECTOR)
      .ok_or_else(|| Error::InvalidRange("vmdk cowd grain-table offset overflow".to_string()))?;
    if offset
      .checked_add(grain_table_bytes)
      .ok_or_else(|| Error::InvalidRange("vmdk cowd grain-table end overflow".to_string()))?
      > source_size
    {
      return Err(Error::InvalidFormat(
        "vmdk cowd grain table exceeds the source size".to_string(),
      ));
    }
  }

  Ok(Arc::from(entries))
}
