//! Validation of parsed APM layouts.

use super::{
  descriptor::ApmDriverDescriptor,
  entry::{ApmPartitionInfo, ApmPartitionMapEntry},
  type_identifiers,
};
use crate::{Error, Result};

pub(super) fn validate_layout(
  source_size: u64, descriptor: &ApmDriverDescriptor, partitions: &[ApmPartitionInfo],
) -> Result<()> {
  validate_descriptor(source_size, descriptor)?;
  validate_partitions(source_size, descriptor, partitions)?;
  Ok(())
}

fn validate_descriptor(source_size: u64, descriptor: &ApmDriverDescriptor) -> Result<()> {
  if descriptor.block_size == 0 {
    return Err(Error::InvalidFormat(
      "apm block size must be non-zero".to_string(),
    ));
  }
  if descriptor.block_count == 0 {
    return Err(Error::InvalidFormat(
      "apm block count must be non-zero".to_string(),
    ));
  }

  let total_size = u64::from(descriptor.block_size)
    .checked_mul(u64::from(descriptor.block_count))
    .ok_or_else(|| Error::InvalidRange("apm device size overflow".to_string()))?;
  if total_size > source_size {
    return Err(Error::InvalidFormat(
      "apm device size exceeds the source size".to_string(),
    ));
  }

  Ok(())
}

fn validate_partitions(
  source_size: u64, descriptor: &ApmDriverDescriptor, partitions: &[ApmPartitionInfo],
) -> Result<()> {
  let Some(first_partition) = partitions.first() else {
    return Err(Error::InvalidFormat(
      "apm partition map is empty".to_string(),
    ));
  };
  if first_partition.entry.type_identifier != type_identifiers::PARTITION_MAP {
    return Err(Error::InvalidFormat(
      "apm first partition entry must describe the partition map".to_string(),
    ));
  }

  let expected_entry_count = first_partition.entry.total_entry_count;
  if expected_entry_count == 0 {
    return Err(Error::InvalidFormat(
      "apm partition map entry count must be non-zero".to_string(),
    ));
  }
  if usize::try_from(expected_entry_count).ok() != Some(partitions.len()) {
    return Err(Error::InvalidFormat(
      "apm partition map entry count does not match the parsed entries".to_string(),
    ));
  }

  for partition in partitions {
    validate_partition(source_size, descriptor, &partition.entry)?;
    if partition.entry.total_entry_count != expected_entry_count {
      return Err(Error::InvalidFormat(format!(
        "apm partition {} has an inconsistent entry count",
        partition.record.index
      )));
    }
  }

  let mut spans = partitions
    .iter()
    .map(|partition| {
      Ok((
        partition.record.index,
        partition.record.span.byte_offset,
        partition
          .record
          .span
          .end_offset()
          .ok_or_else(|| Error::InvalidRange("apm partition end offset overflow".to_string()))?,
      ))
    })
    .collect::<Result<Vec<_>>>()?;
  spans.sort_unstable_by_key(|(_, start, _)| *start);
  for pair in spans.windows(2) {
    if pair[1].1 < pair[0].2 {
      return Err(Error::InvalidFormat(format!(
        "apm partitions {} and {} overlap",
        pair[0].0, pair[1].0
      )));
    }
  }

  Ok(())
}

fn validate_partition(
  source_size: u64, descriptor: &ApmDriverDescriptor, entry: &ApmPartitionMapEntry,
) -> Result<()> {
  if entry.block_count == 0 {
    return Err(Error::InvalidFormat(
      "apm partition block count must be non-zero".to_string(),
    ));
  }

  let start_block = u64::from(entry.start_block);
  let block_count = u64::from(entry.block_count);
  let end_block = start_block
    .checked_add(block_count)
    .ok_or_else(|| Error::InvalidRange("apm partition end block overflow".to_string()))?;
  if end_block > u64::from(descriptor.block_count) {
    return Err(Error::InvalidFormat(
      "apm partition exceeds the declared device block count".to_string(),
    ));
  }

  let byte_offset = start_block
    .checked_mul(u64::from(descriptor.block_size))
    .ok_or_else(|| Error::InvalidRange("apm partition byte offset overflow".to_string()))?;
  let byte_size = block_count
    .checked_mul(u64::from(descriptor.block_size))
    .ok_or_else(|| Error::InvalidRange("apm partition byte size overflow".to_string()))?;
  let byte_end = byte_offset
    .checked_add(byte_size)
    .ok_or_else(|| Error::InvalidRange("apm partition byte end overflow".to_string()))?;
  if byte_end > source_size {
    return Err(Error::InvalidFormat(
      "apm partition exceeds the source size".to_string(),
    ));
  }

  Ok(())
}
