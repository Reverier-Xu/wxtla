//! EWF section-descriptor parsing.

use adler2::adler32_slice;

use super::constants::{
  SECTION_DESCRIPTOR_SIZE, SECTION_TYPE_DATA, SECTION_TYPE_DIGEST, SECTION_TYPE_DISK,
  SECTION_TYPE_DONE, SECTION_TYPE_HASH, SECTION_TYPE_HEADER, SECTION_TYPE_HEADER2,
  SECTION_TYPE_NEXT, SECTION_TYPE_SECTORS, SECTION_TYPE_TABLE, SECTION_TYPE_TABLE2,
  SECTION_TYPE_VOLUME,
};
use crate::{DataSource, Error, Result};

/// Known EWF section kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EwfSectionKind {
  Data,
  Digest,
  Disk,
  Done,
  Hash,
  Header,
  Header2,
  Next,
  Sectors,
  Table,
  Table2,
  Volume,
  Unknown,
}

/// Parsed EWF section descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfSectionDescriptor {
  /// Section kind.
  pub kind: EwfSectionKind,
  /// File offset of the section descriptor.
  pub file_offset: u64,
  /// Offset of the next section according to the descriptor.
  pub next_offset: u64,
  /// Resolved section size in bytes, including the descriptor.
  pub size: u64,
}

impl EwfSectionDescriptor {
  /// Read a section descriptor from a source offset.
  pub fn read(source: &dyn DataSource, offset: u64) -> Result<Self> {
    let data = source.read_bytes_at(offset, SECTION_DESCRIPTOR_SIZE)?;
    Self::parse(&data, offset)
  }

  /// Parse a section descriptor from 76 bytes.
  pub fn parse(data: &[u8], file_offset: u64) -> Result<Self> {
    if data.len() != SECTION_DESCRIPTOR_SIZE {
      return Err(Error::InvalidFormat(format!(
        "ewf section descriptor must be {SECTION_DESCRIPTOR_SIZE} bytes, got {}",
        data.len()
      )));
    }

    let stored_checksum = u32::from_le_bytes([data[72], data[73], data[74], data[75]]);
    let calculated_checksum = adler32_slice(&data[..72]);
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf section descriptor checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    let next_offset = u64::from_le_bytes([
      data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let declared_size = u64::from_le_bytes([
      data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
    ]);
    let kind = section_kind(&data[..16]);
    let size = resolve_section_size(kind, file_offset, next_offset, declared_size)?;

    Ok(Self {
      kind,
      file_offset,
      next_offset,
      size,
    })
  }

  /// Return the file offset directly after this section.
  pub fn end_offset(&self) -> Result<u64> {
    self
      .file_offset
      .checked_add(self.size)
      .ok_or_else(|| Error::InvalidRange("ewf section end offset overflow".to_string()))
  }
}

fn resolve_section_size(
  kind: EwfSectionKind, file_offset: u64, next_offset: u64, declared_size: u64,
) -> Result<u64> {
  if matches!(kind, EwfSectionKind::Done | EwfSectionKind::Next) {
    if declared_size == 0 {
      return Ok(SECTION_DESCRIPTOR_SIZE as u64);
    }
    return Ok(declared_size);
  }

  if declared_size != 0 {
    return Ok(declared_size);
  }
  if next_offset <= file_offset {
    return Err(Error::InvalidFormat(
      "ewf section next offset does not advance".to_string(),
    ));
  }

  Ok(next_offset - file_offset)
}

fn section_kind(raw_type: &[u8]) -> EwfSectionKind {
  let trimmed = raw_type.split(|byte| *byte == 0).next().unwrap_or(raw_type);
  match trimmed {
    SECTION_TYPE_DATA => EwfSectionKind::Data,
    SECTION_TYPE_DIGEST => EwfSectionKind::Digest,
    SECTION_TYPE_DISK => EwfSectionKind::Disk,
    SECTION_TYPE_DONE => EwfSectionKind::Done,
    SECTION_TYPE_HASH => EwfSectionKind::Hash,
    SECTION_TYPE_HEADER => EwfSectionKind::Header,
    SECTION_TYPE_HEADER2 => EwfSectionKind::Header2,
    SECTION_TYPE_NEXT => EwfSectionKind::Next,
    SECTION_TYPE_SECTORS => EwfSectionKind::Sectors,
    SECTION_TYPE_TABLE => EwfSectionKind::Table,
    SECTION_TYPE_TABLE2 => EwfSectionKind::Table2,
    SECTION_TYPE_VOLUME => EwfSectionKind::Volume,
    _ => EwfSectionKind::Unknown,
  }
}

#[cfg(test)]
mod tests {
  use adler2::adler32_slice;

  use super::*;

  #[test]
  fn parses_done_section_with_zero_size() {
    let mut data = [0u8; SECTION_DESCRIPTOR_SIZE];
    data[0..4].copy_from_slice(b"done");
    data[16..24].copy_from_slice(&100u64.to_le_bytes());
    let checksum = adler32_slice(&data[..72]);
    data[72..76].copy_from_slice(&checksum.to_le_bytes());

    let descriptor = EwfSectionDescriptor::parse(&data, 100).unwrap();

    assert_eq!(descriptor.kind, EwfSectionKind::Done);
    assert_eq!(descriptor.size, 76);
  }
}
