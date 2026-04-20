//! NTFS attribute-list parsing.

use crate::{Error, Result};

const MIN_ENTRY_SIZE: usize = 26;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAttributeListEntry {
  pub attribute_type: u32,
  pub entry_length: u16,
  pub starting_vcn: u64,
  pub base_file_record: u64,
  pub base_file_sequence: u16,
  pub attribute_id: u16,
  pub name: Option<String>,
}

impl NtfsAttributeListEntry {
  pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    if bytes.len() < MIN_ENTRY_SIZE {
      return Err(Error::invalid_format(
        "ntfs attribute-list entry is truncated".to_string(),
      ));
    }

    let entry_length = usize::from(le_u16(&bytes[4..6]));
    if entry_length < MIN_ENTRY_SIZE || entry_length > bytes.len() {
      return Err(Error::invalid_format(
        "ntfs attribute-list entry length is invalid".to_string(),
      ));
    }

    let name_length = usize::from(bytes[6]);
    let name_offset = usize::from(bytes[7]);
    let name = if name_length == 0 {
      None
    } else {
      Some(read_utf16le(
        &bytes[..entry_length],
        name_offset,
        name_length,
        "ntfs attribute-list entry name",
      )?)
    };

    Ok(Self {
      attribute_type: le_u32(&bytes[0..4]),
      entry_length: entry_length as u16,
      starting_vcn: le_u64(&bytes[8..16]),
      base_file_record: decode_file_reference(&bytes[16..24])?,
      base_file_sequence: le_u16(&bytes[22..24]),
      attribute_id: le_u16(&bytes[24..26]),
      name,
    })
  }
}

pub fn parse_attribute_list(bytes: &[u8]) -> Result<Vec<NtfsAttributeListEntry>> {
  let mut entries = Vec::new();
  let mut offset = 0usize;

  while offset < bytes.len() {
    if bytes[offset..].iter().all(|byte| *byte == 0) {
      break;
    }

    let entry = NtfsAttributeListEntry::from_bytes(&bytes[offset..])?;
    let entry_length = usize::from(entry.entry_length);
    entries.push(entry);
    offset = offset
      .checked_add(entry_length)
      .ok_or_else(|| Error::invalid_range("ntfs attribute-list offset overflow"))?;
  }

  Ok(entries)
}

fn read_utf16le(bytes: &[u8], offset: usize, chars: usize, label: &str) -> Result<String> {
  let byte_len = chars
    .checked_mul(2)
    .ok_or_else(|| Error::invalid_range(format!("{label} length overflow")))?;
  let end = offset
    .checked_add(byte_len)
    .ok_or_else(|| Error::invalid_range(format!("{label} offset overflow")))?;
  let slice = bytes
    .get(offset..end)
    .ok_or_else(|| Error::invalid_format(format!("{label} extends past the available bytes")))?;
  let units = slice
    .chunks_exact(2)
    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  String::from_utf16(&units)
    .map_err(|_| Error::invalid_format(format!("{label} is not valid UTF-16")))
}

fn decode_file_reference(bytes: &[u8]) -> Result<u64> {
  let bytes = bytes
    .get(..8)
    .ok_or_else(|| Error::invalid_format("ntfs file reference is truncated"))?;
  let mut raw = [0u8; 8];
  raw[..6].copy_from_slice(&bytes[..6]);
  Ok(u64::from_le_bytes(raw))
}

fn le_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_le_bytes(raw)
}

fn le_u32(bytes: &[u8]) -> u32 {
  let mut raw = [0u8; 4];
  raw.copy_from_slice(bytes);
  u32::from_le_bytes(raw)
}

fn le_u64(bytes: &[u8]) -> u64 {
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use super::*;

  fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("ntfs")
      .join("libfsntfs")
      .join(relative)
  }

  #[test]
  fn parses_libfsntfs_attribute_list_entry_fixture() {
    let bytes = std::fs::read(fixture_path("attribute_list_entry.1")).unwrap();
    let entry = NtfsAttributeListEntry::from_bytes(&bytes).unwrap();

    assert_eq!(entry.attribute_type, 0x80);
    assert_eq!(entry.entry_length, 40);
    assert_eq!(entry.starting_vcn, 0);
    assert_eq!(entry.base_file_record, 2248);
    assert_eq!(entry.base_file_sequence, 1);
    assert_eq!(entry.attribute_id, 0);
    assert_eq!(entry.name.as_deref(), Some("$SDS"));
  }

  #[test]
  fn parses_libfsntfs_attribute_list_fixture() {
    let bytes = std::fs::read(fixture_path("attribute_list.1")).unwrap();
    let entries = parse_attribute_list(&bytes).unwrap();

    assert_eq!(entries.len(), 9);
    assert_eq!(entries[0].attribute_type, 0x10);
    assert_eq!(entries[1].attribute_type, 0x30);
    assert_eq!(entries[2].name.as_deref(), Some("$SDS"));
    assert_eq!(entries[3].name.as_deref(), Some("$SDH"));
    assert_eq!(entries[4].name.as_deref(), Some("$SII"));
    assert_eq!(entries[5].base_file_record, 2248);
    assert_eq!(entries[8].attribute_id, 6);
  }
}
