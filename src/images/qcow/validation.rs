//! Structural validation of QCOW headers and table offsets.

use super::{constants::QCOW_VERSION_1, header::QcowHeader};
use crate::{ByteSource, Error, Result};

pub(super) fn validate_header_layout(source: &dyn ByteSource, header: &QcowHeader) -> Result<()> {
  let file_size = source.size()?;
  let cluster_size = header.cluster_size()?;
  let l2_entry_count = header.l2_entry_count()?;

  if header.l1_entry_count == 0 {
    return Err(Error::InvalidFormat(
      "qcow l1 table must contain at least one entry".to_string(),
    ));
  }
  if header.header_size < 48 {
    return Err(Error::InvalidFormat(
      "qcow header size is smaller than the base header".to_string(),
    ));
  }
  if header.virtual_size == 0 {
    return Err(Error::InvalidFormat(
      "qcow virtual size must be non-zero".to_string(),
    ));
  }

  validate_range(
    file_size,
    header.l1_table_offset,
    u64::from(header.l1_entry_count) * 8,
    "qcow l1 table",
  )?;

  if header.backing_file_size != 0 {
    if header.backing_file_offset < u64::from(header.header_size) {
      return Err(Error::InvalidFormat(
        "qcow backing file name overlaps the header".to_string(),
      ));
    }
    validate_range(
      file_size,
      header.backing_file_offset,
      u64::from(header.backing_file_size),
      "qcow backing file name",
    )?;
  }

  if header.version != QCOW_VERSION_1 {
    if header.refcount_table_clusters == 0 {
      return Err(Error::InvalidFormat(
        "qcow refcount table cluster count must be non-zero".to_string(),
      ));
    }
    validate_cluster_alignment(
      header.refcount_table_offset,
      cluster_size,
      "qcow refcount table",
    )?;
    validate_range(
      file_size,
      header.refcount_table_offset,
      u64::from(header.refcount_table_clusters)
        .checked_mul(cluster_size)
        .ok_or_else(|| Error::InvalidRange("qcow refcount table size overflow".to_string()))?,
      "qcow refcount table",
    )?;
  }

  if header.snapshot_count != 0 && header.snapshot_table_offset == 0 {
    return Err(Error::InvalidFormat(
      "qcow snapshot table offset is missing".to_string(),
    ));
  }
  if header.snapshot_count != 0 {
    validate_range(
      file_size,
      header.snapshot_table_offset,
      40,
      "qcow snapshot table",
    )?;
  }

  if l2_entry_count == 0 {
    return Err(Error::InvalidFormat(
      "qcow l2 table must contain at least one entry".to_string(),
    ));
  }

  Ok(())
}

pub(super) fn validate_cluster_alignment(
  offset: u64, cluster_size: u64, label: &str,
) -> Result<()> {
  if !offset.is_multiple_of(cluster_size) {
    return Err(Error::InvalidFormat(format!(
      "{label} offset is not cluster aligned"
    )));
  }
  Ok(())
}

pub(super) fn validate_range(file_size: u64, offset: u64, size: u64, label: &str) -> Result<()> {
  let end = offset
    .checked_add(size)
    .ok_or_else(|| Error::InvalidRange(format!("{label} range overflows")))?;
  if end > file_size {
    return Err(Error::InvalidFormat(format!(
      "{label} exceeds the source size"
    )));
  }
  Ok(())
}
