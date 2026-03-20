//! Validation of parsed MBR layouts.

use super::entry::{MbrPartitionInfo, MbrPartitionOrigin};
use crate::{Error, Result, volumes::VolumeRole};

pub(super) fn validate_partitions(source_size: u64, partitions: &[MbrPartitionInfo]) -> Result<()> {
  validate_bounds(source_size, partitions)?;
  validate_extended_container(partitions)?;
  validate_overlaps(partitions)?;
  Ok(())
}

fn validate_bounds(source_size: u64, partitions: &[MbrPartitionInfo]) -> Result<()> {
  for partition in partitions {
    let Some(end_offset) = partition.record.span.end_offset() else {
      return Err(Error::InvalidRange(
        "mbr partition end offset overflow".to_string(),
      ));
    };
    if end_offset > source_size {
      return Err(Error::InvalidFormat(format!(
        "mbr partition {} exceeds source size",
        partition.record.index
      )));
    }
  }

  Ok(())
}

fn validate_extended_container(partitions: &[MbrPartitionInfo]) -> Result<()> {
  let extended_containers = partitions
    .iter()
    .filter(|partition| partition.record.role == VolumeRole::ExtendedContainer)
    .collect::<Vec<_>>();

  for partition in partitions {
    if partition.origin != MbrPartitionOrigin::Logical {
      continue;
    }

    if extended_containers.is_empty() {
      return Err(Error::InvalidFormat(
        "logical partitions require an extended container".to_string(),
      ));
    }

    let partition_end = partition
      .record
      .span
      .end_offset()
      .ok_or_else(|| Error::InvalidRange("logical partition end offset overflow".to_string()))?;
    let inside_any_container = extended_containers.iter().any(|container| {
      let Some(container_end) = container.record.span.end_offset() else {
        return false;
      };
      partition.record.span.byte_offset >= container.record.span.byte_offset
        && partition_end <= container_end
    });
    if !inside_any_container {
      return Err(Error::InvalidFormat(format!(
        "logical partition {} falls outside the extended container",
        partition.record.index
      )));
    }
  }

  Ok(())
}

fn validate_overlaps(partitions: &[MbrPartitionInfo]) -> Result<()> {
  for left_index in 0..partitions.len() {
    for right_index in (left_index + 1)..partitions.len() {
      let left = &partitions[left_index];
      let right = &partitions[right_index];
      if overlaps_are_allowed(left, right) {
        continue;
      }
      if spans_overlap(left, right)? {
        return Err(Error::InvalidFormat(format!(
          "mbr partitions {} and {} overlap",
          left.record.index, right.record.index
        )));
      }
    }
  }

  Ok(())
}

fn overlaps_are_allowed(left: &MbrPartitionInfo, right: &MbrPartitionInfo) -> bool {
  if left.record.role == VolumeRole::Protective || right.record.role == VolumeRole::Protective {
    return true;
  }

  (left.record.role == VolumeRole::ExtendedContainer && right.origin == MbrPartitionOrigin::Logical)
    || (right.record.role == VolumeRole::ExtendedContainer
      && left.origin == MbrPartitionOrigin::Logical)
}

fn spans_overlap(left: &MbrPartitionInfo, right: &MbrPartitionInfo) -> Result<bool> {
  let left_end = left
    .record
    .span
    .end_offset()
    .ok_or_else(|| Error::InvalidRange("left partition end offset overflow".to_string()))?;
  let right_end = right
    .record
    .span
    .end_offset()
    .ok_or_else(|| Error::InvalidRange("right partition end offset overflow".to_string()))?;

  Ok(left.record.span.byte_offset < right_end && right.record.span.byte_offset < left_end)
}
