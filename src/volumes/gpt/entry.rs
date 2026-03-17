//! GPT partition-entry parsing and metadata.

use super::{constants, guid::GptGuid};
use crate::{
  Error, Result,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan},
};

/// Raw GPT partition entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartitionEntry {
  /// Stable entry index.
  pub index: usize,
  /// Partition type GUID.
  pub type_guid: GptGuid,
  /// Unique partition GUID.
  pub unique_guid: GptGuid,
  /// First LBA owned by the partition.
  pub first_lba: u64,
  /// Last LBA owned by the partition, inclusive.
  pub last_lba: u64,
  /// GPT attribute flags.
  pub attribute_flags: u64,
  /// Decoded partition name.
  pub name: String,
}

impl GptPartitionEntry {
  /// Parse a GPT partition entry from a buffer of at least 128 bytes.
  pub fn parse(index: usize, data: &[u8]) -> Result<Self> {
    if data.len() < constants::PARTITION_ENTRY_MIN_SIZE {
      return Err(Error::InvalidFormat(format!(
        "gpt entry must be at least {} bytes, got {}",
        constants::PARTITION_ENTRY_MIN_SIZE,
        data.len()
      )));
    }

    Ok(Self {
      index,
      type_guid: GptGuid::from_le_bytes(
        &data[constants::PARTITION_TYPE_GUID_OFFSET..constants::PARTITION_GUID_OFFSET],
      )?,
      unique_guid: GptGuid::from_le_bytes(
        &data[constants::PARTITION_GUID_OFFSET..constants::FIRST_LBA_OFFSET],
      )?,
      first_lba: read_u64(data, constants::FIRST_LBA_OFFSET),
      last_lba: read_u64(data, constants::LAST_LBA_OFFSET),
      attribute_flags: read_u64(data, constants::ATTRIBUTE_FLAGS_OFFSET),
      name: decode_name(
        &data[constants::NAME_OFFSET..constants::NAME_OFFSET + constants::NAME_LEN],
      )?,
    })
  }

  /// Return `true` when the entry is unused.
  pub fn is_unused(&self) -> bool {
    self.type_guid.is_nil()
  }

  /// Convert the entry into a byte span for the given block size.
  pub fn span(&self, block_size: u32) -> Result<VolumeSpan> {
    if self.last_lba < self.first_lba {
      return Err(Error::InvalidFormat(format!(
        "gpt entry {} has an invalid lba range",
        self.index
      )));
    }

    let byte_offset = self
      .first_lba
      .checked_mul(u64::from(block_size))
      .ok_or_else(|| Error::InvalidRange("gpt partition offset overflow".to_string()))?;
    let block_count = self
      .last_lba
      .checked_sub(self.first_lba)
      .and_then(|delta| delta.checked_add(1))
      .ok_or_else(|| Error::InvalidRange("gpt partition length overflow".to_string()))?;
    let byte_size = block_count
      .checked_mul(u64::from(block_size))
      .ok_or_else(|| Error::InvalidRange("gpt partition size overflow".to_string()))?;

    Ok(VolumeSpan::new(byte_offset, byte_size))
  }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
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

/// Parsed GPT partition metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartitionInfo {
  /// Generic volume record.
  pub record: VolumeRecord,
  /// Partition type GUID.
  pub type_guid: GptGuid,
  /// Unique partition GUID.
  pub unique_guid: GptGuid,
  /// GPT attribute flags.
  pub attribute_flags: u64,
  /// First LBA owned by the partition.
  pub first_lba: u64,
  /// Last LBA owned by the partition.
  pub last_lba: u64,
}

impl GptPartitionInfo {
  /// Build partition metadata from a parsed GPT entry.
  pub fn from_entry(entry: GptPartitionEntry, block_size: u32) -> Result<Self> {
    let mut record = VolumeRecord::new(entry.index, entry.span(block_size)?, VolumeRole::Primary);
    if !entry.name.is_empty() {
      record = record.with_name(entry.name.clone());
    }

    Ok(Self {
      record,
      type_guid: entry.type_guid,
      unique_guid: entry.unique_guid,
      attribute_flags: entry.attribute_flags,
      first_lba: entry.first_lba,
      last_lba: entry.last_lba,
    })
  }
}

fn decode_name(data: &[u8]) -> Result<String> {
  if data.len() != constants::NAME_LEN {
    return Err(Error::InvalidFormat(format!(
      "gpt name field must be {} bytes, got {}",
      constants::NAME_LEN,
      data.len()
    )));
  }

  let mut code_units = Vec::with_capacity(constants::NAME_LEN / 2);
  for chunk in data.chunks_exact(2) {
    let code_unit = u16::from_le_bytes([chunk[0], chunk[1]]);
    if code_unit == 0 {
      break;
    }
    code_units.push(code_unit);
  }

  String::from_utf16(&code_units)
    .map_err(|_| Error::InvalidFormat("gpt partition name is not valid utf-16".to_string()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_entry_fields_and_name() {
    let entry = GptPartitionEntry::parse(
      1,
      &[
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4, 0x8C, 0x58, 0x25, 0x1E, 0xA9, 0x27, 0x94, 0x40, 0x86, 0x8C, 0x2F, 0x25, 0x70, 0x21,
        0xF8, 0x7B, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x69, 0x00,
        0x6E, 0x00, 0x75, 0x00, 0x78, 0x00, 0x20, 0x00, 0x66, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65,
        0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ],
    )
    .unwrap();

    assert_eq!(
      entry.type_guid.to_string(),
      "0fc63daf-8483-4772-8e79-3d69d8477de4"
    );
    assert_eq!(
      entry.unique_guid.to_string(),
      "1e25588c-27a9-4094-868c-2f257021f87b"
    );
    assert_eq!(entry.first_lba, 2048);
    assert_eq!(entry.last_lba, 2175);
    assert_eq!(entry.name, "Linux filesystem");
  }
}
