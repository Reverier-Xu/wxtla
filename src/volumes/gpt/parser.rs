//! Parsing of GPT headers and entries.

use super::{
  constants,
  entry::{GptPartitionEntry, GptPartitionInfo},
  header::GptHeader,
  integrity::{validate_entry_array_crc, validate_header_crc, validate_header_pair},
  system::GptVolumeSystem,
  validation::validate_layout,
};
use crate::{DataSource, DataSourceHandle, Error, Result, volumes::mbr::MbrPartitionEntry};

pub(super) fn open(source: DataSourceHandle) -> Result<GptVolumeSystem> {
  for block_size in constants::SUPPORTED_BLOCK_SIZES {
    if let Ok(system) = open_with_block_size(source.clone(), block_size) {
      return Ok(system);
    }
  }

  Err(Error::InvalidFormat(
    "unable to infer a supported gpt block size".to_string(),
  ))
}

pub(super) fn open_with_block_size(
  source: DataSourceHandle, block_size: u32,
) -> Result<GptVolumeSystem> {
  validate_protective_mbr(source.as_ref())?;

  let (primary_header, primary_header_block) =
    read_header_block(source.as_ref(), block_size, constants::PRIMARY_HEADER_LBA)?;
  validate_header_crc(&primary_header_block, &primary_header)?;

  let primary_entry_array = read_entry_array(source.as_ref(), block_size, &primary_header)?;
  validate_entry_array_crc(&primary_entry_array, primary_header.entry_array_crc32)?;
  let partitions = parse_partitions(&primary_entry_array, block_size, &primary_header)?;

  let (backup_header, backup_header_block) =
    read_header_block(source.as_ref(), block_size, primary_header.backup_lba)?;
  validate_header_crc(&backup_header_block, &backup_header)?;
  validate_header_pair(&primary_header, &backup_header)?;

  let backup_entry_array = read_entry_array(source.as_ref(), block_size, &backup_header)?;
  validate_entry_array_crc(&backup_entry_array, backup_header.entry_array_crc32)?;

  validate_layout(source.size()?, block_size, &primary_header, &partitions)?;

  Ok(GptVolumeSystem::new(
    source,
    block_size,
    primary_header,
    backup_header,
    partitions,
  ))
}

fn read_header_block(
  source: &dyn DataSource, block_size: u32, lba: u64,
) -> Result<(GptHeader, Vec<u8>)> {
  let offset = lba
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("gpt header offset overflow".to_string()))?;
  let block = source.read_bytes_at(offset, block_size as usize)?;
  let header = GptHeader::parse(&block)?;
  Ok((header, block))
}

fn read_entry_array(
  source: &dyn DataSource, block_size: u32, header: &GptHeader,
) -> Result<Vec<u8>> {
  let entry_array_offset = header
    .entry_array_start_lba
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("gpt entry array offset overflow".to_string()))?;
  let total_entry_bytes = u64::from(header.entry_count)
    .checked_mul(u64::from(header.entry_size))
    .ok_or_else(|| Error::InvalidRange("gpt entry array size overflow".to_string()))?;

  source.read_bytes_at(
    entry_array_offset,
    usize::try_from(total_entry_bytes)
      .map_err(|_| Error::InvalidRange("gpt entry array is too large".to_string()))?,
  )
}

fn parse_partitions(
  data: &[u8], block_size: u32, header: &GptHeader,
) -> Result<Vec<GptPartitionInfo>> {
  let entry_size = usize::try_from(header.entry_size)
    .map_err(|_| Error::InvalidRange("gpt entry size is too large".to_string()))?;
  let mut partitions = Vec::new();

  for index in 0..header.entry_count as usize {
    let start = index
      .checked_mul(entry_size)
      .ok_or_else(|| Error::InvalidRange("gpt entry offset overflow".to_string()))?;
    let end = start
      .checked_add(entry_size)
      .ok_or_else(|| Error::InvalidRange("gpt entry end overflow".to_string()))?;
    let entry = GptPartitionEntry::parse(index, &data[start..end])?;
    if entry.is_unused() {
      continue;
    }
    partitions.push(GptPartitionInfo::from_entry(entry, block_size)?);
  }

  Ok(partitions)
}

fn validate_protective_mbr(source: &dyn DataSource) -> Result<()> {
  let sector = source.read_bytes_at(0, 512)?;
  if sector[510..512] != [0x55, 0xAA] {
    return Err(Error::InvalidFormat(
      "gpt protective mbr signature is missing".to_string(),
    ));
  }

  let mut has_protective_partition = false;
  for index in 0..4 {
    let start = 446 + index * 16;
    let end = start + 16;
    let entry = MbrPartitionEntry::parse(&sector[start..end])?;
    if entry.is_protective() {
      has_protective_partition = true;
      break;
    }
  }

  if !has_protective_partition {
    return Err(Error::InvalidFormat(
      "gpt protective mbr entry is missing".to_string(),
    ));
  }

  Ok(())
}
