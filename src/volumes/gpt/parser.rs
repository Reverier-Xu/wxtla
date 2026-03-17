//! Parsing of GPT headers and entries.

use super::{
  constants,
  entry::{GptPartitionEntry, GptPartitionInfo},
  header::GptHeader,
  system::GptVolumeSystem,
  validation::validate_layout,
};
use crate::{DataSource, DataSourceHandle, Result};

pub(super) fn open(source: DataSourceHandle) -> Result<GptVolumeSystem> {
  open_with_block_size(source, constants::DEFAULT_BLOCK_SIZE)
}

pub(super) fn open_with_block_size(
  source: DataSourceHandle, block_size: u32,
) -> Result<GptVolumeSystem> {
  let header = GptHeader::read(source.as_ref(), block_size, constants::PRIMARY_HEADER_LBA)?;
  let partitions = read_partitions(source.as_ref(), block_size, &header)?;

  validate_layout(source.size()?, block_size, &header, &partitions)?;

  Ok(GptVolumeSystem::new(source, block_size, header, partitions))
}

fn read_partitions(
  source: &dyn DataSource, block_size: u32, header: &GptHeader,
) -> Result<Vec<GptPartitionInfo>> {
  let entry_array_offset = header
    .entry_array_start_lba
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| crate::Error::InvalidRange("gpt entry array offset overflow".to_string()))?;
  let total_entry_bytes = u64::from(header.entry_count)
    .checked_mul(u64::from(header.entry_size))
    .ok_or_else(|| crate::Error::InvalidRange("gpt entry array size overflow".to_string()))?;
  let data = source.read_bytes_at(
    entry_array_offset,
    usize::try_from(total_entry_bytes)
      .map_err(|_| crate::Error::InvalidRange("gpt entry array is too large".to_string()))?,
  )?;
  let entry_size = usize::try_from(header.entry_size)
    .map_err(|_| crate::Error::InvalidRange("gpt entry size is too large".to_string()))?;
  let mut partitions = Vec::new();

  for index in 0..header.entry_count as usize {
    let start = index * entry_size;
    let end = start + entry_size;
    let entry = GptPartitionEntry::parse(index, &data[start..end])?;
    if entry.is_unused() {
      continue;
    }
    partitions.push(GptPartitionInfo::from_entry(entry, block_size)?);
  }

  Ok(partitions)
}
