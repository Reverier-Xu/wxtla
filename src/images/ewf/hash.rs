//! EWF hash and digest section parsing.

use adler2::adler32_slice;

use super::constants::{DIGEST_DATA_SIZE, HASH_DATA_SIZE};
use crate::{Error, Result};

/// Parsed EWF hash section with an MD5 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfHashSection {
  /// MD5 hash of the media bytes.
  pub md5: [u8; 16],
}

impl EwfHashSection {
  /// Parse a 36-byte hash section payload.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != HASH_DATA_SIZE {
      return Err(Error::InvalidFormat(format!(
        "ewf hash section must be {HASH_DATA_SIZE} bytes, got {}",
        data.len()
      )));
    }

    let stored_checksum = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    let calculated_checksum = adler32_slice(&data[..32]);
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf hash checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    Ok(Self {
      md5: copy_array::<16>(&data[..16])?,
    })
  }
}

/// Parsed EWF digest section with MD5 and SHA1 digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfDigestSection {
  /// MD5 hash of the media bytes.
  pub md5: [u8; 16],
  /// SHA1 hash of the media bytes.
  pub sha1: [u8; 20],
}

impl EwfDigestSection {
  /// Parse an 80-byte digest section payload.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != DIGEST_DATA_SIZE {
      return Err(Error::InvalidFormat(format!(
        "ewf digest section must be {DIGEST_DATA_SIZE} bytes, got {}",
        data.len()
      )));
    }

    let stored_checksum = u32::from_le_bytes([data[76], data[77], data[78], data[79]]);
    let calculated_checksum = adler32_slice(&data[..76]);
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf digest checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    Ok(Self {
      md5: copy_array::<16>(&data[..16])?,
      sha1: copy_array::<20>(&data[16..36])?,
    })
  }
}

fn copy_array<const N: usize>(data: &[u8]) -> Result<[u8; N]> {
  data.try_into().map_err(|_| {
    Error::InvalidFormat(format!(
      "ewf fixed-size array conversion failed: expected {N} bytes, got {}",
      data.len()
    ))
  })
}
