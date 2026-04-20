//! EWF chunk table parsing.

use adler2::{Adler32, adler32_slice};

use super::constants::{TABLE_FOOTER_SIZE, TABLE_HEADER_SIZE};
use crate::{ByteSource, Error, Result};

const TABLE_ENTRY_SIZE: usize = 4;
const TABLE_SCAN_BUFFER_SIZE: usize = 64 * 1024;

/// Parsed EWF table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EwfTableEntry {
  /// Raw 32-bit stored offset value.
  pub raw_offset: u32,
}

impl EwfTableEntry {
  /// Return `true` when the chunk payload is zlib-compressed.
  pub const fn is_compressed(self) -> bool {
    (self.raw_offset & 0x8000_0000) != 0
  }

  /// Return the 31-bit payload offset component.
  pub const fn offset(self) -> u32 {
    self.raw_offset & 0x7FFF_FFFF
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EwfTableLayout {
  pub entry_count: u32,
  pub base_offset: u64,
  pub entry_checksum: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EwfAnalyzedTable {
  pub layout: EwfTableLayout,
  pub overflow_start_index: Option<usize>,
}

impl EwfAnalyzedTable {
  pub fn read(source: &dyn ByteSource, payload_offset: u64, payload_size: usize) -> Result<Self> {
    let layout = EwfTableLayout::read(source, payload_offset, payload_size)?;
    let overflow_start_index = validate_entries(source, payload_offset, layout)?;

    Ok(Self {
      layout,
      overflow_start_index,
    })
  }
}

impl EwfTableLayout {
  pub fn read(source: &dyn ByteSource, payload_offset: u64, payload_size: usize) -> Result<Self> {
    if payload_size < TABLE_HEADER_SIZE + TABLE_FOOTER_SIZE {
      return Err(Error::invalid_format(
        "ewf table payload is too small".to_string(),
      ));
    }

    let mut header = [0u8; TABLE_HEADER_SIZE];
    source.read_exact_at(payload_offset, &mut header)?;

    let entry_count = read_u32_le(&header, 0);
    let table_size = table_size(entry_count)?;
    if payload_size < table_size {
      return Err(Error::invalid_format(format!(
        "ewf table payload size is smaller than the entry count requires: expected at least {table_size}, got {payload_size}"
      )));
    }

    let stored_header_checksum = read_u32_le(&header, 20);
    let calculated_header_checksum = adler32_slice(&header[..20]);
    if stored_header_checksum != calculated_header_checksum {
      return Err(Error::invalid_format(format!(
        "ewf table header checksum mismatch: stored 0x{stored_header_checksum:08x}, calculated 0x{calculated_header_checksum:08x}"
      )));
    }

    let footer_offset = payload_offset
      .checked_add(
        u64::try_from(table_footer_offset(entry_count)?)
          .map_err(|_| Error::invalid_range("ewf table footer offset overflow"))?,
      )
      .ok_or_else(|| Error::invalid_range("ewf table footer offset overflow"))?;
    let mut footer = [0u8; TABLE_FOOTER_SIZE];
    source.read_exact_at(footer_offset, &mut footer)?;

    Ok(Self {
      entry_count,
      base_offset: read_u64_le(&header, 8),
      entry_checksum: read_u32_le(&footer, 0),
    })
  }
}

pub(super) fn read_entry_pair(
  source: &dyn ByteSource, entries_offset: u64, entry_count: u32, entry_index: usize,
) -> Result<(EwfTableEntry, Option<EwfTableEntry>)> {
  let entry_count = usize::try_from(entry_count)
    .map_err(|_| Error::invalid_range("ewf table entry count is too large"))?;
  if entry_index >= entry_count {
    return Err(Error::invalid_range(format!(
      "ewf table entry {entry_index} is out of bounds"
    )));
  }

  let pair_count = usize::from(entry_index + 1 < entry_count);
  let read_len = TABLE_ENTRY_SIZE * (pair_count + 1);
  let entry_offset = entries_offset
    .checked_add(
      u64::try_from(entry_index)
        .map_err(|_| Error::invalid_range("ewf table entry index is too large"))?
        .checked_mul(TABLE_ENTRY_SIZE as u64)
        .ok_or_else(|| Error::invalid_range("ewf table entry offset overflow"))?,
    )
    .ok_or_else(|| Error::invalid_range("ewf table entry offset overflow"))?;
  let mut bytes = [0u8; TABLE_ENTRY_SIZE * 2];
  source.read_exact_at(entry_offset, &mut bytes[..read_len])?;

  Ok((
    EwfTableEntry {
      raw_offset: read_u32_le(&bytes, 0),
    },
    (pair_count == 1).then_some(EwfTableEntry {
      raw_offset: read_u32_le(&bytes, TABLE_ENTRY_SIZE),
    }),
  ))
}

fn validate_entries(
  source: &dyn ByteSource, payload_offset: u64, layout: EwfTableLayout,
) -> Result<Option<usize>> {
  let entries_offset = payload_offset
    .checked_add(TABLE_HEADER_SIZE as u64)
    .ok_or_else(|| Error::invalid_range("ewf table entry offset overflow"))?;
  let entry_bytes = entry_array_size(layout.entry_count)?;
  if entry_bytes == 0 {
    return Ok(None);
  }

  let mut checksum = Adler32::new();
  let mut overflow_start_index = None;
  let mut overflow_mode = false;
  let mut previous_offset = None;
  let mut entry_index = 0usize;
  let mut buffer = vec![
    0u8;
    TABLE_SCAN_BUFFER_SIZE
      .min(entry_bytes)
      .max(TABLE_ENTRY_SIZE)
  ];
  let mut remaining = entry_bytes;
  let mut read_offset = entries_offset;

  while remaining != 0 {
    let read_len = remaining.min(buffer.len());
    source.read_exact_at(read_offset, &mut buffer[..read_len])?;
    checksum.write_slice(&buffer[..read_len]);

    for chunk in buffer[..read_len].chunks_exact(TABLE_ENTRY_SIZE) {
      let raw_offset = read_u32_le(chunk, 0);
      let mut current_offset = if overflow_mode {
        u64::from(raw_offset)
      } else {
        u64::from(raw_offset & 0x7FFF_FFFF)
      };
      if let Some(previous_offset) = previous_offset
        && current_offset < previous_offset
      {
        if overflow_mode {
          return Err(Error::invalid_format(
            "ewf chunk offsets must be monotonically increasing within a table".to_string(),
          ));
        }
        if raw_offset
          < u32::try_from(previous_offset)
            .map_err(|_| Error::invalid_range("ewf chunk offset does not fit in a table entry"))?
        {
          return Err(Error::invalid_format(
            "ewf chunk offsets must be monotonically increasing within a table".to_string(),
          ));
        }
        current_offset = u64::from(raw_offset);
        overflow_mode = true;
        overflow_start_index = Some(entry_index);
      }
      previous_offset = Some(current_offset);
      entry_index += 1;
    }

    read_offset = read_offset
      .checked_add(
        u64::try_from(read_len)
          .map_err(|_| Error::invalid_range("ewf table scan offset overflow"))?,
      )
      .ok_or_else(|| Error::invalid_range("ewf table scan offset overflow"))?;
    remaining -= read_len;
  }

  let calculated_entry_checksum = checksum.checksum();
  if calculated_entry_checksum != layout.entry_checksum {
    return Err(Error::invalid_format(format!(
      "ewf table entry checksum mismatch: stored 0x{:08x}, calculated 0x{calculated_entry_checksum:08x}",
      layout.entry_checksum
    )));
  }

  Ok(overflow_start_index)
}

fn table_size(entry_count: u32) -> Result<usize> {
  TABLE_HEADER_SIZE
    .checked_add(entry_array_size(entry_count)?)
    .and_then(|size| size.checked_add(TABLE_FOOTER_SIZE))
    .ok_or_else(|| Error::invalid_range("ewf table size overflow"))
}

fn table_footer_offset(entry_count: u32) -> Result<usize> {
  TABLE_HEADER_SIZE
    .checked_add(entry_array_size(entry_count)?)
    .ok_or_else(|| Error::invalid_range("ewf table footer offset overflow"))
}

fn entry_array_size(entry_count: u32) -> Result<usize> {
  usize::try_from(entry_count)
    .map_err(|_| Error::invalid_range("ewf table entry count is too large"))?
    .checked_mul(TABLE_ENTRY_SIZE)
    .ok_or_else(|| Error::invalid_range("ewf table entry array size overflow"))
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
  u32::from_le_bytes([
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3],
  ])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
  u64::from_le_bytes([
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3],
    data[offset + 4],
    data[offset + 5],
    data[offset + 6],
    data[offset + 7],
  ])
}

#[cfg(test)]
mod tests {
  use adler2::adler32_slice;

  use super::*;
  use crate::{ByteSourceHandle, BytesDataSource};

  #[test]
  fn analyzes_base_offset_without_materializing_the_table() {
    let payload = make_table_payload(1869, &[0x8000_004C, 0x8000_031D]);
    let source: ByteSourceHandle = std::sync::Arc::new(BytesDataSource::new(payload));

    let table = EwfAnalyzedTable::read(source.as_ref(), 0, 36).unwrap();

    assert_eq!(table.layout.base_offset, 1869);
    assert_eq!(table.layout.entry_count, 2);
    assert_eq!(table.overflow_start_index, None);
  }

  #[test]
  fn reads_table_layout_without_loading_inline_chunks() {
    let mut payload = make_table_payload(1869, &[0x8000_004C, 0x8000_0058]);
    payload.extend_from_slice(&[0u8; 16]);
    let source: ByteSourceHandle = std::sync::Arc::new(BytesDataSource::new(payload));
    let layout = EwfTableLayout::read(source.as_ref(), 0, 52).unwrap();

    assert_eq!(layout.entry_count, 2);
    assert_eq!(layout.base_offset, 1869);
    assert_eq!(
      layout.entry_checksum,
      adler32_slice(&[0x4C, 0x00, 0x00, 0x80, 0x58, 0x00, 0x00, 0x80])
    );
  }

  #[test]
  fn accepts_inline_chunk_data_after_the_footer() {
    let mut payload = make_table_payload(0, &[0x8000_004C, 0x8000_0058]);
    payload.extend_from_slice(&[0u8; 16]);
    let source: ByteSourceHandle = std::sync::Arc::new(BytesDataSource::new(payload));

    let table = EwfAnalyzedTable::read(source.as_ref(), 0, 52).unwrap();

    assert_eq!(table.layout.entry_count, 2);
  }

  #[test]
  fn detects_overflow_start_in_streaming_analysis() {
    let payload = make_table_payload(0, &[0x7FFF_F000, 0x8000_1000, 0x8000_2000]);
    let source: ByteSourceHandle = std::sync::Arc::new(BytesDataSource::new(payload));

    let table = EwfAnalyzedTable::read(source.as_ref(), 0, 40).unwrap();

    assert_eq!(table.overflow_start_index, Some(1));
  }

  #[test]
  fn reads_adjacent_entries_without_loading_the_table() {
    let payload = make_table_payload(0, &[0x8000_004C, 0x8000_0058]);
    let source: ByteSourceHandle = std::sync::Arc::new(BytesDataSource::new(payload));

    let (current, next) = read_entry_pair(source.as_ref(), 24, 2, 0).unwrap();

    assert_eq!(current.raw_offset, 0x8000_004C);
    assert_eq!(next.unwrap().raw_offset, 0x8000_0058);
  }

  fn make_table_payload(base_offset: u64, raw_offsets: &[u32]) -> Vec<u8> {
    let mut payload = vec![0u8; 24 + raw_offsets.len() * 4 + 4];
    payload[0..4].copy_from_slice(&(raw_offsets.len() as u32).to_le_bytes());
    payload[8..16].copy_from_slice(&base_offset.to_le_bytes());
    let header_checksum = adler32_slice(&payload[..20]);
    payload[20..24].copy_from_slice(&header_checksum.to_le_bytes());
    for (index, offset) in raw_offsets.iter().enumerate() {
      let start = 24 + index * 4;
      payload[start..start + 4].copy_from_slice(&offset.to_le_bytes());
    }
    let footer_offset = 24 + raw_offsets.len() * 4;
    let footer_checksum = adler32_slice(&payload[24..footer_offset]);
    payload[footer_offset..footer_offset + 4].copy_from_slice(&footer_checksum.to_le_bytes());
    payload
  }
}
