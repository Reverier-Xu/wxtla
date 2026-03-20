//! UDIF trailer parsing.

use crate::{DataSource, Error, Result};

pub(super) const TRAILER_SIZE: usize = 512;
const TRAILER_MAGIC: &[u8; 4] = b"koly";

/// Parsed UDIF trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdifTrailer {
  /// Trailer flags.
  pub flags: u32,
  /// Data fork offset.
  pub data_fork_offset: u64,
  /// Data fork size.
  pub data_fork_size: u64,
  /// XML plist offset.
  pub plist_offset: u64,
  /// XML plist size.
  pub plist_size: u64,
  /// Data checksum type.
  pub data_checksum_type: u32,
  /// Data checksum bytes.
  pub data_checksum: [u8; 128],
  /// Master checksum type.
  pub master_checksum_type: u32,
  /// Master checksum bytes.
  pub master_checksum: [u8; 128],
  /// Image type identifier.
  pub image_type: u32,
  /// Total sector count.
  pub sector_count: u64,
}

impl UdifTrailer {
  pub fn read(source: &dyn DataSource) -> Result<Self> {
    let size = source.size()?;
    if size < TRAILER_SIZE as u64 {
      return Err(Error::InvalidFormat(
        "udif source is too small to contain a koly trailer".to_string(),
      ));
    }

    let offset = size - TRAILER_SIZE as u64;
    let bytes = source.read_bytes_at(offset, TRAILER_SIZE)?;
    Self::from_bytes(&bytes)
  }

  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != TRAILER_SIZE {
      return Err(Error::InvalidFormat(format!(
        "udif trailer must be {TRAILER_SIZE} bytes, got {}",
        data.len()
      )));
    }
    if &data[0..4] != TRAILER_MAGIC {
      return Err(Error::InvalidFormat(
        "udif koly trailer signature is missing".to_string(),
      ));
    }

    let _version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let trailer_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if trailer_size < TRAILER_SIZE as u32 {
      return Err(Error::InvalidFormat(format!(
        "unsupported udif trailer size: {trailer_size}"
      )));
    }

    Ok(Self {
      flags: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
      data_fork_offset: u64::from_be_bytes([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
      ]),
      data_fork_size: u64::from_be_bytes([
        data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
      ]),
      data_checksum_type: u32::from_be_bytes([data[80], data[81], data[82], data[83]]),
      data_checksum: data[88..216]
        .try_into()
        .map_err(|_| Error::InvalidFormat("udif data checksum length mismatch".to_string()))?,
      plist_offset: u64::from_be_bytes([
        data[216], data[217], data[218], data[219], data[220], data[221], data[222], data[223],
      ]),
      plist_size: u64::from_be_bytes([
        data[224], data[225], data[226], data[227], data[228], data[229], data[230], data[231],
      ]),
      master_checksum_type: u32::from_be_bytes([data[352], data[353], data[354], data[355]]),
      master_checksum: data[360..488]
        .try_into()
        .map_err(|_| Error::InvalidFormat("udif master checksum length mismatch".to_string()))?,
      image_type: u32::from_be_bytes([data[488], data[489], data[490], data[491]]),
      sector_count: u64::from_be_bytes([
        data[492], data[493], data[494], data[495], data[496], data[497], data[498], data[499],
      ]),
    })
  }

  pub fn stored_data_crc32(&self) -> Option<u32> {
    checksum_value(self.data_checksum_type, &self.data_checksum)
  }

  pub fn stored_master_crc32(&self) -> Option<u32> {
    checksum_value(self.master_checksum_type, &self.master_checksum)
  }
}

fn checksum_value(checksum_type: u32, checksum: &[u8; 128]) -> Option<u32> {
  if checksum_type != 2 {
    return None;
  }

  let value = u32::from_be_bytes([checksum[0], checksum[1], checksum[2], checksum[3]]);
  (value != 0).then_some(value)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_trailer() -> [u8; TRAILER_SIZE] {
    let mut data = [0u8; TRAILER_SIZE];
    data[0..4].copy_from_slice(TRAILER_MAGIC);
    data[4..8].copy_from_slice(&4u32.to_be_bytes());
    data[8..12].copy_from_slice(&(TRAILER_SIZE as u32).to_be_bytes());
    data[32..40].copy_from_slice(&4096u64.to_be_bytes());
    data[216..224].copy_from_slice(&4096u64.to_be_bytes());
    data[224..232].copy_from_slice(&1024u64.to_be_bytes());
    data[352..356].copy_from_slice(&2u32.to_be_bytes());
    data[360..364].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
    data[492..500].copy_from_slice(&8u64.to_be_bytes());
    data
  }

  #[test]
  fn parses_trailer_fields() {
    let trailer = UdifTrailer::from_bytes(&sample_trailer()).unwrap();

    assert_eq!(trailer.data_fork_size, 4096);
    assert_eq!(trailer.plist_offset, 4096);
    assert_eq!(trailer.plist_size, 1024);
    assert_eq!(trailer.stored_master_crc32(), Some(0xDEADBEEF));
    assert_eq!(trailer.sector_count, 8);
  }

  #[test]
  fn rejects_invalid_magic() {
    let mut data = sample_trailer();
    data[0] = 0;

    let result = UdifTrailer::from_bytes(&data);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn accepts_newer_trailer_versions_and_sizes() {
    let mut data = sample_trailer();
    data[4..8].copy_from_slice(&7u32.to_be_bytes());
    data[8..12].copy_from_slice(&(TRAILER_SIZE as u32 + 128).to_be_bytes());

    let trailer = UdifTrailer::from_bytes(&data).unwrap();

    assert_eq!(trailer.data_fork_size, 4096);
    assert_eq!(trailer.plist_size, 1024);
  }
}
