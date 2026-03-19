//! Validation of parsed GPT layouts.

use super::{entry::GptPartitionInfo, header::GptHeader};
use crate::{Error, Result};

pub(super) fn validate_layout(
  source_size: u64, block_size: u32, expected_current_lba: u64, header: &GptHeader,
  partitions: &[GptPartitionInfo],
) -> Result<()> {
  validate_header(source_size, block_size, expected_current_lba, header)?;
  validate_partitions(source_size, block_size, header, partitions)?;
  Ok(())
}

fn validate_header(
  source_size: u64, block_size: u32, expected_current_lba: u64, header: &GptHeader,
) -> Result<()> {
  if header.current_lba != expected_current_lba {
    return Err(Error::InvalidFormat(format!(
      "gpt header is at unexpected lba {}",
      header.current_lba
    )));
  }
  if header.first_usable_lba > header.last_usable_lba {
    return Err(Error::InvalidFormat(
      "gpt usable lba range is invalid".to_string(),
    ));
  }

  let total_blocks = source_size / u64::from(block_size);
  if total_blocks <= header.current_lba || header.backup_lba >= total_blocks {
    return Err(Error::InvalidFormat(
      "gpt backup header lba is out of bounds".to_string(),
    ));
  }

  let entry_bytes = u64::from(header.entry_count)
    .checked_mul(u64::from(header.entry_size))
    .ok_or_else(|| Error::InvalidRange("gpt entry array size overflow".to_string()))?;
  let entry_offset = header
    .entry_array_start_lba
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("gpt entry array offset overflow".to_string()))?;
  let entry_end = entry_offset
    .checked_add(entry_bytes)
    .ok_or_else(|| Error::InvalidRange("gpt entry array end overflow".to_string()))?;
  if entry_end > source_size {
    return Err(Error::InvalidFormat(
      "gpt entry array exceeds source size".to_string(),
    ));
  }

  Ok(())
}

fn validate_partitions(
  source_size: u64, _block_size: u32, header: &GptHeader, partitions: &[GptPartitionInfo],
) -> Result<()> {
  for partition in partitions {
    if partition.first_lba < header.first_usable_lba || partition.last_lba > header.last_usable_lba
    {
      return Err(Error::InvalidFormat(format!(
        "gpt partition {} lies outside the usable area",
        partition.record.index
      )));
    }
    let Some(end_offset) = partition.record.span.end_offset() else {
      return Err(Error::InvalidRange(
        "gpt partition end offset overflow".to_string(),
      ));
    };
    if end_offset > source_size {
      return Err(Error::InvalidFormat(format!(
        "gpt partition {} exceeds source size",
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
          .ok_or_else(|| Error::InvalidRange("gpt partition end offset overflow".to_string()))?,
      ))
    })
    .collect::<Result<Vec<_>>>()?;
  spans.sort_unstable_by_key(|(_, start, _)| *start);
  for pair in spans.windows(2) {
    if pair[1].1 < pair[0].2 {
      return Err(Error::InvalidFormat(format!(
        "gpt partitions {} and {} overlap",
        pair[0].0, pair[1].0
      )));
    }
  }

  Ok(())
}
