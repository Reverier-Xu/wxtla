//! Parsing of MBR and EBR boot records.

use super::{
  constants::{
    BOOT_RECORD_SIZE, BOOT_SIGNATURE, BOOT_SIGNATURE_OFFSET, DISK_SIGNATURE_OFFSET,
    PARTITION_ENTRY_COUNT, PARTITION_ENTRY_OFFSET, PARTITION_ENTRY_SIZE,
  },
  entry::MbrPartitionEntry,
};
use crate::{ByteSource, Error, Result};

/// Parsed MBR-style boot record containing four partition entries.
#[derive(Debug, Clone)]
pub struct MbrBootRecord {
  disk_signature: u32,
  entries: Vec<MbrPartitionEntry>,
}

impl MbrBootRecord {
  /// Read and parse a boot record from a source offset.
  pub fn read(source: &dyn ByteSource, offset: u64) -> Result<Self> {
    let data = source.read_bytes_at(offset, BOOT_RECORD_SIZE)?;
    Self::parse(&data)
  }

  /// Parse a boot record from exactly 512 bytes.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != BOOT_RECORD_SIZE {
      return Err(Error::invalid_format(format!(
        "mbr boot record must be {BOOT_RECORD_SIZE} bytes, got {}",
        data.len()
      )));
    }
    if data[BOOT_SIGNATURE_OFFSET..BOOT_SIGNATURE_OFFSET + 2] != BOOT_SIGNATURE {
      return Err(Error::invalid_format(
        "mbr boot record signature is missing".to_string(),
      ));
    }

    let disk_signature = u32::from_le_bytes([
      data[DISK_SIGNATURE_OFFSET],
      data[DISK_SIGNATURE_OFFSET + 1],
      data[DISK_SIGNATURE_OFFSET + 2],
      data[DISK_SIGNATURE_OFFSET + 3],
    ]);
    let mut entries = Vec::with_capacity(PARTITION_ENTRY_COUNT);

    for entry_index in 0..PARTITION_ENTRY_COUNT {
      let start = PARTITION_ENTRY_OFFSET + entry_index * PARTITION_ENTRY_SIZE;
      let end = start + PARTITION_ENTRY_SIZE;
      entries.push(MbrPartitionEntry::parse(&data[start..end])?);
    }

    Ok(Self {
      disk_signature,
      entries,
    })
  }

  /// Return the disk signature from the boot record.
  pub fn disk_signature(&self) -> u32 {
    self.disk_signature
  }

  /// Return the parsed partition entries.
  pub fn entries(&self) -> &[MbrPartitionEntry] {
    &self.entries
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_boot_record_signature_and_entries() {
    let mut data = [0u8; BOOT_RECORD_SIZE];
    data[DISK_SIGNATURE_OFFSET..DISK_SIGNATURE_OFFSET + 4]
      .copy_from_slice(&0x1A43_5B69u32.to_le_bytes());
    data[PARTITION_ENTRY_OFFSET + 4] = 0x83;
    data[PARTITION_ENTRY_OFFSET + 8..PARTITION_ENTRY_OFFSET + 12]
      .copy_from_slice(&1u32.to_le_bytes());
    data[PARTITION_ENTRY_OFFSET + 12..PARTITION_ENTRY_OFFSET + 16]
      .copy_from_slice(&2048u32.to_le_bytes());
    data[BOOT_SIGNATURE_OFFSET..BOOT_SIGNATURE_OFFSET + 2].copy_from_slice(&BOOT_SIGNATURE);

    let record = MbrBootRecord::parse(&data).unwrap();

    assert_eq!(record.disk_signature(), 0x1A43_5B69);
    assert_eq!(record.entries()[0].partition_type, 0x83);
  }
}
