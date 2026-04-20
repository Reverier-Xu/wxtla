//! GPT integrity validation helpers.

use crc32fast::Hasher;

use super::header::GptHeader;
use crate::{Error, Result};

pub(super) fn validate_header_crc(block: &[u8], header: &GptHeader) -> Result<()> {
  let header_size = usize::try_from(header.header_size)
    .map_err(|_| Error::invalid_range("gpt header size is too large"))?;
  if block.len() < header_size {
    return Err(Error::invalid_format(
      "gpt header block is shorter than the declared header size".to_string(),
    ));
  }

  let mut checksum_input = block[..header_size].to_vec();
  checksum_input[16..20].fill(0);
  let calculated = crc32(&checksum_input);
  if calculated != header.header_crc32 {
    return Err(Error::invalid_format(format!(
      "gpt header crc mismatch: stored 0x{:08x}, calculated 0x{:08x}",
      header.header_crc32, calculated
    )));
  }

  Ok(())
}

pub(super) fn validate_entry_array_crc(data: &[u8], expected_crc32: u32) -> Result<()> {
  let calculated = crc32(data);
  if calculated != expected_crc32 {
    return Err(Error::invalid_format(format!(
      "gpt entry array crc mismatch: stored 0x{:08x}, calculated 0x{:08x}",
      expected_crc32, calculated
    )));
  }

  Ok(())
}

pub(super) fn validate_header_pair(primary: &GptHeader, backup: &GptHeader) -> Result<()> {
  if backup.current_lba != primary.backup_lba {
    return Err(Error::invalid_format(
      "gpt backup header current lba does not match the primary backup lba".to_string(),
    ));
  }
  if backup.backup_lba != primary.current_lba {
    return Err(Error::invalid_format(
      "gpt backup header backup lba does not point back to the primary header".to_string(),
    ));
  }
  if backup.header_size != primary.header_size {
    return Err(Error::invalid_format(
      "gpt primary and backup header sizes differ".to_string(),
    ));
  }
  if backup.disk_guid != primary.disk_guid {
    return Err(Error::invalid_format(
      "gpt primary and backup disk guids differ".to_string(),
    ));
  }
  if backup.first_usable_lba != primary.first_usable_lba
    || backup.last_usable_lba != primary.last_usable_lba
  {
    return Err(Error::invalid_format(
      "gpt primary and backup usable ranges differ".to_string(),
    ));
  }
  if backup.entry_count != primary.entry_count || backup.entry_size != primary.entry_size {
    return Err(Error::invalid_format(
      "gpt primary and backup entry layout differs".to_string(),
    ));
  }
  if backup.entry_array_crc32 != primary.entry_array_crc32 {
    return Err(Error::invalid_format(
      "gpt primary and backup entry array checksums differ".to_string(),
    ));
  }

  Ok(())
}

pub(super) fn crc32(data: &[u8]) -> u32 {
  let mut hasher = Hasher::new();
  hasher.update(data);
  hasher.finalize()
}
