//! Parsing of APM driver descriptors and partition maps.

use super::{
  constants::{PARTITION_ENTRY_SIZE, PARTITION_MAP_OFFSET},
  descriptor::ApmDriverDescriptor,
  entry::{ApmPartitionInfo, ApmPartitionMapEntry},
  system::ApmVolumeSystem,
  validation::validate_layout,
};
use crate::{ByteSource, ByteSourceHandle, Result};

pub(super) fn open(source: ByteSourceHandle) -> Result<ApmVolumeSystem> {
  let descriptor = ApmDriverDescriptor::read(source.as_ref())?;
  let partitions = read_partition_map(source.as_ref(), descriptor.block_size)?;

  validate_layout(source.size()?, &descriptor, &partitions)?;

  Ok(ApmVolumeSystem::new(source, descriptor, partitions))
}

fn read_partition_map(source: &dyn ByteSource, block_size: u16) -> Result<Vec<ApmPartitionInfo>> {
  let first_entry = ApmPartitionMapEntry::parse(
    &source.read_bytes_at(u64::from(PARTITION_MAP_OFFSET), PARTITION_ENTRY_SIZE)?,
  )?;
  let total_entry_count = usize::try_from(first_entry.total_entry_count).map_err(|_| {
    crate::Error::InvalidRange("apm partition entry count is too large".to_string())
  })?;

  let mut partitions = Vec::with_capacity(total_entry_count);
  partitions.push(first_entry.into_partition_info(0, block_size)?);

  for index in 1..total_entry_count {
    let offset = u64::from(PARTITION_MAP_OFFSET)
      .checked_add((index as u64) * PARTITION_ENTRY_SIZE as u64)
      .ok_or_else(|| crate::Error::InvalidRange("apm partition map offset overflow".to_string()))?;
    let entry = ApmPartitionMapEntry::parse(&source.read_bytes_at(offset, PARTITION_ENTRY_SIZE)?)?;
    partitions.push(entry.into_partition_info(index, block_size)?);
  }

  Ok(partitions)
}
