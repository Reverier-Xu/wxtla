//! GPT header parsing.

use super::{constants, guid::GptGuid};
use crate::{ByteSource, Error, Result};

/// Parsed GPT header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptHeader {
  /// Header size in bytes.
  pub header_size: u32,
  /// Header CRC32 value stored on disk.
  pub header_crc32: u32,
  /// Current header LBA.
  pub current_lba: u64,
  /// Backup header LBA.
  pub backup_lba: u64,
  /// First usable LBA for partitions.
  pub first_usable_lba: u64,
  /// Last usable LBA for partitions.
  pub last_usable_lba: u64,
  /// Disk GUID.
  pub disk_guid: GptGuid,
  /// Start LBA of the partition-entry array.
  pub entry_array_start_lba: u64,
  /// Number of partition entries.
  pub entry_count: u32,
  /// Size of a single partition entry.
  pub entry_size: u32,
  /// CRC32 of the entry array.
  pub entry_array_crc32: u32,
}

impl GptHeader {
  /// Read a GPT header from the given LBA.
  pub fn read(source: &dyn ByteSource, block_size: u32, lba: u64) -> Result<Self> {
    let offset = lba
      .checked_mul(u64::from(block_size))
      .ok_or_else(|| Error::InvalidRange("gpt header offset overflow".to_string()))?;
    let block = source.read_bytes_at(offset, block_size as usize)?;
    Self::parse(&block)
  }

  /// Parse a GPT header from a block containing the header at offset 0.
  pub fn parse(block: &[u8]) -> Result<Self> {
    if block.len() < constants::HEADER_MIN_SIZE {
      return Err(Error::InvalidFormat(format!(
        "gpt header block is too small: {}",
        block.len()
      )));
    }
    if &block[0..8] != constants::HEADER_SIGNATURE {
      return Err(Error::InvalidFormat(
        "gpt header signature is missing".to_string(),
      ));
    }

    let revision = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
    if revision != constants::GPT_FORMAT_REVISION {
      return Err(Error::InvalidFormat(format!(
        "unsupported gpt revision: 0x{revision:08x}"
      )));
    }

    let header_size = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);
    if (header_size as usize) < constants::HEADER_MIN_SIZE {
      return Err(Error::InvalidFormat(format!(
        "unsupported gpt header size: {header_size}"
      )));
    }
    if (header_size as usize) > block.len() {
      return Err(Error::InvalidFormat(
        "gpt header size exceeds the block size".to_string(),
      ));
    }

    let entry_size = u32::from_le_bytes([block[84], block[85], block[86], block[87]]);
    if entry_size < constants::PARTITION_ENTRY_MIN_SIZE as u32 {
      return Err(Error::InvalidFormat(format!(
        "unsupported gpt entry size: {entry_size}"
      )));
    }

    Ok(Self {
      header_size,
      header_crc32: u32::from_le_bytes([block[16], block[17], block[18], block[19]]),
      current_lba: u64::from_le_bytes([
        block[24], block[25], block[26], block[27], block[28], block[29], block[30], block[31],
      ]),
      backup_lba: u64::from_le_bytes([
        block[32], block[33], block[34], block[35], block[36], block[37], block[38], block[39],
      ]),
      first_usable_lba: u64::from_le_bytes([
        block[40], block[41], block[42], block[43], block[44], block[45], block[46], block[47],
      ]),
      last_usable_lba: u64::from_le_bytes([
        block[48], block[49], block[50], block[51], block[52], block[53], block[54], block[55],
      ]),
      disk_guid: GptGuid::from_le_bytes(&block[56..72])?,
      entry_array_start_lba: u64::from_le_bytes([
        block[72], block[73], block[74], block[75], block[76], block[77], block[78], block[79],
      ]),
      entry_count: u32::from_le_bytes([block[80], block[81], block[82], block[83]]),
      entry_size,
      entry_array_crc32: u32::from_le_bytes([block[88], block[89], block[90], block[91]]),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_header_fields() {
    let header = GptHeader::parse(&[
      0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54, 0x00, 0x00, 0x01, 0x00, 0x5C, 0x00, 0x00,
      0x00, 0x35, 0x50, 0xDC, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xFF, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0xDE, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x65, 0x6E, 0xE8,
      0x40, 0xD8, 0x09, 0x4C, 0xAF, 0xE3, 0xA1, 0xA5, 0xF6, 0x65, 0xCF, 0x44, 0x02, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x1E, 0xF9,
      0xB8, 0xAC,
    ])
    .unwrap();

    assert_eq!(header.current_lba, 1);
    assert_eq!(header.backup_lba, 8191);
    assert_eq!(header.entry_array_start_lba, 2);
    assert_eq!(header.entry_count, 128);
    assert_eq!(header.entry_size, 128);
    assert_eq!(
      header.disk_guid.to_string(),
      "e86e657a-d840-4c09-afe3-a1a5f665cf44"
    );
  }

  #[test]
  fn accepts_larger_header_sizes() {
    let mut block = vec![0u8; 128];
    block[0..8].copy_from_slice(constants::HEADER_SIGNATURE);
    block[8..12].copy_from_slice(&constants::GPT_FORMAT_REVISION.to_le_bytes());
    block[12..16].copy_from_slice(&128u32.to_le_bytes());
    block[24..32].copy_from_slice(&1u64.to_le_bytes());
    block[32..40].copy_from_slice(&127u64.to_le_bytes());
    block[40..48].copy_from_slice(&34u64.to_le_bytes());
    block[48..56].copy_from_slice(&126u64.to_le_bytes());
    block[56..72].copy_from_slice(&[1; 16]);
    block[72..80].copy_from_slice(&2u64.to_le_bytes());
    block[80..84].copy_from_slice(&128u32.to_le_bytes());
    block[84..88].copy_from_slice(&128u32.to_le_bytes());

    let header = GptHeader::parse(&block).unwrap();

    assert_eq!(header.header_size, 128);
    assert_eq!(header.entry_count, 128);
  }
}
