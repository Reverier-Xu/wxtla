//! EWF chunk table parsing.

use adler2::adler32_slice;

use super::constants::{TABLE_FOOTER_SIZE, TABLE_HEADER_SIZE};
use crate::{Error, Result};

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

/// Parsed EWF table section payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfTable {
  /// Base file offset used to resolve table entry offsets.
  pub base_offset: u64,
  /// Chunk table entries.
  pub entries: Vec<EwfTableEntry>,
}

impl EwfTable {
  /// Parse a table payload from bytes.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < TABLE_HEADER_SIZE + TABLE_FOOTER_SIZE {
      return Err(Error::InvalidFormat(
        "ewf table payload is too small".to_string(),
      ));
    }

    let entry_count = read_u32_le(data, 0) as usize;
    let table_size = TABLE_HEADER_SIZE
      .checked_add(
        entry_count
          .checked_mul(4)
          .ok_or_else(|| Error::InvalidRange("ewf table entry array size overflow".to_string()))?,
      )
      .and_then(|size| size.checked_add(TABLE_FOOTER_SIZE))
      .ok_or_else(|| Error::InvalidRange("ewf table size overflow".to_string()))?;
    if data.len() < table_size {
      return Err(Error::InvalidFormat(format!(
        "ewf table payload size is smaller than the entry count requires: expected at least {table_size}, got {}",
        data.len()
      )));
    }

    let stored_header_checksum = read_u32_le(data, 20);
    let calculated_header_checksum = adler32_slice(&data[..20]);
    if stored_header_checksum != calculated_header_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf table header checksum mismatch: stored 0x{stored_header_checksum:08x}, calculated 0x{calculated_header_checksum:08x}"
      )));
    }

    let footer_offset = TABLE_HEADER_SIZE + entry_count * 4;
    let stored_entry_checksum = read_u32_le(data, footer_offset);
    let calculated_entry_checksum = adler32_slice(&data[TABLE_HEADER_SIZE..footer_offset]);
    if stored_entry_checksum != calculated_entry_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf table entry checksum mismatch: stored 0x{stored_entry_checksum:08x}, calculated 0x{calculated_entry_checksum:08x}"
      )));
    }

    let mut entries = Vec::with_capacity(entry_count);
    let mut offset = TABLE_HEADER_SIZE;
    for _ in 0..entry_count {
      entries.push(EwfTableEntry {
        raw_offset: read_u32_le(data, offset),
      });
      offset += 4;
    }

    Ok(Self {
      base_offset: read_u64_le(data, 8),
      entries,
    })
  }
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

  #[test]
  fn parses_base_offset_and_entries() {
    let mut data = vec![0u8; TABLE_HEADER_SIZE + 8 + TABLE_FOOTER_SIZE];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[8..16].copy_from_slice(&1869u64.to_le_bytes());
    let header_checksum = adler32_slice(&data[..20]);
    data[20..24].copy_from_slice(&header_checksum.to_le_bytes());
    data[24..28].copy_from_slice(&0x8000_004C_u32.to_le_bytes());
    data[28..32].copy_from_slice(&0x8000_031D_u32.to_le_bytes());
    let entry_checksum = adler32_slice(&data[24..32]);
    data[32..36].copy_from_slice(&entry_checksum.to_le_bytes());

    let table = EwfTable::parse(&data).unwrap();

    assert_eq!(table.base_offset, 1869);
    assert_eq!(table.entries.len(), 2);
    assert!(table.entries[0].is_compressed());
    assert_eq!(table.entries[0].offset(), 0x4C);
  }

  #[test]
  fn accepts_inline_chunk_data_after_the_footer() {
    let mut data = vec![0u8; TABLE_HEADER_SIZE + 8 + TABLE_FOOTER_SIZE + 16];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    let header_checksum = adler32_slice(&data[..20]);
    data[20..24].copy_from_slice(&header_checksum.to_le_bytes());
    data[24..28].copy_from_slice(&0x8000_004C_u32.to_le_bytes());
    data[28..32].copy_from_slice(&0x8000_0058_u32.to_le_bytes());
    let entry_checksum = adler32_slice(&data[24..32]);
    data[32..36].copy_from_slice(&entry_checksum.to_le_bytes());

    let table = EwfTable::parse(&data).unwrap();

    assert_eq!(table.entries.len(), 2);
  }
}
