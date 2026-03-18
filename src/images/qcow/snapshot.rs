//! QCOW snapshot metadata.

use std::sync::Arc;

use super::header::QcowHeader;
use crate::{Error, Result};

/// Parsed QCOW snapshot metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QcowSnapshot {
  table_entry_size: u64,
  /// Snapshot L1 table used to resolve guest data.
  pub l1_table: Arc<[u64]>,
  /// Snapshot unique identifier.
  pub unique_id: String,
  /// Snapshot display name.
  pub name: String,
  /// Seconds since the Unix epoch.
  pub timestamp_seconds: u32,
  /// Nanoseconds within the timestamp second.
  pub timestamp_nanos: u32,
  /// Guest runtime in nanoseconds at snapshot time.
  pub guest_runtime_nanos: u64,
  /// Virtual machine state size.
  pub vm_state_size: u64,
  /// Virtual disk size represented by the snapshot.
  pub virtual_disk_size: u64,
  /// Optional instruction count.
  pub instruction_count: Option<i64>,
}

impl QcowSnapshot {
  /// Parse a sequence of snapshot headers from the qcow snapshot table region.
  pub fn parse_many(source: &dyn crate::DataSource, header: &QcowHeader) -> Result<Vec<Self>> {
    if header.snapshot_count == 0 {
      return Ok(Vec::new());
    }

    let mut snapshots = Vec::with_capacity(header.snapshot_count as usize);
    let mut offset = header.snapshot_table_offset;
    for _ in 0..header.snapshot_count {
      let snapshot = Self::read_one(source, offset)?;
      offset = offset
        .checked_add(snapshot.table_entry_size)
        .ok_or_else(|| Error::InvalidRange("qcow snapshot table offset overflow".to_string()))?;
      snapshots.push(snapshot);
    }

    Ok(snapshots)
  }

  fn read_one(source: &dyn crate::DataSource, offset: u64) -> Result<Self> {
    let fixed = source.read_bytes_at(offset, 40)?;
    let l1_table_offset = read_u64_be(&fixed, 0)?;
    let l1_entry_count = read_u32_be(&fixed, 8)?;
    let unique_id_len = usize::from(read_u16_be(&fixed, 12)?);
    let name_len = usize::from(read_u16_be(&fixed, 14)?);
    let timestamp_seconds = read_u32_be(&fixed, 16)?;
    let timestamp_nanos = read_u32_be(&fixed, 20)?;
    let guest_runtime_nanos = read_u64_be(&fixed, 24)?;
    let vm_state_size_legacy = u64::from(read_u32_be(&fixed, 32)?);
    let extra_data_size = usize::try_from(read_u32_be(&fixed, 36)?)
      .map_err(|_| Error::InvalidRange("qcow snapshot extra data size is too large".to_string()))?;

    let extra_data = source.read_bytes_at(offset + 40, extra_data_size)?;
    let mut cursor = offset
      .checked_add(40)
      .and_then(|value| value.checked_add(u64::try_from(extra_data_size).ok()?))
      .ok_or_else(|| Error::InvalidRange("qcow snapshot cursor overflow".to_string()))?;
    let unique_id = read_utf8_string(source, cursor, unique_id_len, "qcow snapshot unique id")?;
    cursor = cursor
      .checked_add(u64::try_from(unique_id_len).map_err(|_| {
        Error::InvalidRange("qcow snapshot unique id length is too large".to_string())
      })?)
      .ok_or_else(|| Error::InvalidRange("qcow snapshot unique id cursor overflow".to_string()))?;
    let name = read_utf8_string(source, cursor, name_len, "qcow snapshot name")?;
    let table_entry_size = 40u64
      .checked_add(u64::try_from(extra_data_size).map_err(|_| {
        Error::InvalidRange("qcow snapshot extra data size is too large".to_string())
      })?)
      .and_then(|size| size.checked_add(u64::try_from(unique_id_len).ok()?))
      .and_then(|size| size.checked_add(u64::try_from(name_len).ok()?))
      .ok_or_else(|| Error::InvalidRange("qcow snapshot size overflow".to_string()))?;

    let (vm_state_size, virtual_disk_size, instruction_count) =
      parse_snapshot_extra_data(&extra_data, vm_state_size_legacy)?;
    let l1_table = read_snapshot_l1_table(source, l1_table_offset, l1_entry_count)?;

    Ok(Self {
      table_entry_size,
      l1_table,
      unique_id,
      name,
      timestamp_seconds,
      timestamp_nanos,
      guest_runtime_nanos,
      vm_state_size,
      virtual_disk_size,
      instruction_count,
    })
  }
}

fn parse_snapshot_extra_data(
  data: &[u8], vm_state_size_legacy: u64,
) -> Result<(u64, u64, Option<i64>)> {
  let vm_state_size = if data.len() >= 8 {
    read_u64_be(data, 0)?
  } else {
    vm_state_size_legacy
  };
  let virtual_disk_size = if data.len() >= 16 {
    read_u64_be(data, 8)?
  } else {
    0
  };
  let instruction_count = if data.len() >= 24 {
    Some(read_i64_be(data, 16)?)
  } else {
    None
  };

  Ok((vm_state_size, virtual_disk_size, instruction_count))
}

fn read_snapshot_l1_table(
  source: &dyn crate::DataSource, offset: u64, entry_count: u32,
) -> Result<Arc<[u64]>> {
  let size = usize::try_from(u64::from(entry_count) * 8)
    .map_err(|_| Error::InvalidRange("qcow snapshot l1 table size is too large".to_string()))?;
  let raw = source.read_bytes_at(offset, size)?;
  let entries = raw
    .chunks_exact(8)
    .map(|chunk| {
      let bytes: [u8; 8] = chunk
        .try_into()
        .map_err(|_| Error::InvalidFormat("qcow snapshot l1 entry is truncated".to_string()))?;
      Ok(u64::from_be_bytes(bytes))
    })
    .collect::<Result<Vec<_>>>()?;

  Ok(Arc::from(entries))
}

fn read_utf8_string(
  source: &dyn crate::DataSource, offset: u64, len: usize, label: &str,
) -> Result<String> {
  let data = source.read_bytes_at(offset, len)?;
  String::from_utf8(data).map_err(|_| Error::InvalidFormat(format!("{label} is not valid UTF-8")))
}

fn read_u16_be(data: &[u8], offset: usize) -> Result<u16> {
  let bytes = data.get(offset..offset + 2).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "qcow snapshot field at offset {offset} is truncated"
    ))
  })?;
  Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
  let bytes = data.get(offset..offset + 4).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "qcow snapshot field at offset {offset} is truncated"
    ))
  })?;
  Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_be(data: &[u8], offset: usize) -> Result<u64> {
  let bytes = data.get(offset..offset + 8).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "qcow snapshot field at offset {offset} is truncated"
    ))
  })?;
  let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
    Error::InvalidFormat(format!(
      "qcow snapshot field at offset {offset} is truncated"
    ))
  })?;
  Ok(u64::from_be_bytes(bytes))
}

fn read_i64_be(data: &[u8], offset: usize) -> Result<i64> {
  let bytes = data.get(offset..offset + 8).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "qcow snapshot field at offset {offset} is truncated"
    ))
  })?;
  let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
    Error::InvalidFormat(format!(
      "qcow snapshot field at offset {offset} is truncated"
    ))
  })?;
  Ok(i64::from_be_bytes(bytes))
}
