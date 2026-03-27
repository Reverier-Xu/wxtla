//! VMDK COWD sparse extent header parsing.

use super::constants;
use crate::{ByteSource, Error, Result};

/// Parsed VMDK COWD sparse extent header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmdkCowdHeader {
  /// COWD format version.
  pub format_version: u32,
  /// Header flags.
  pub flags: u32,
  /// Virtual disk capacity in sectors.
  pub capacity_sectors: u32,
  /// Grain size in sectors.
  pub sectors_per_grain: u32,
  /// Grain-directory start sector.
  pub grain_directory_start_sector: u32,
  /// Number of grain-directory entries.
  pub grain_directory_entries: u32,
  /// Next free sector marker from the header.
  pub next_free_sector: u32,
  /// Parent file name when present.
  pub parent_path: String,
  /// Parent generation number.
  pub parent_generation: u32,
  /// Current generation number.
  pub generation: u32,
  /// Saved generation number.
  pub saved_generation: u32,
  /// Dirty flag.
  pub is_dirty: bool,
}

impl VmdkCowdHeader {
  pub fn read(source: &dyn ByteSource) -> Result<Self> {
    let data = source.read_bytes_at(0, constants::COWD_HEADER_SIZE)?;
    Self::from_bytes(&data)
  }

  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != constants::COWD_HEADER_SIZE {
      return Err(Error::InvalidFormat(format!(
        "vmdk cowd header must be {} bytes, got {}",
        constants::COWD_HEADER_SIZE,
        data.len()
      )));
    }
    if &data[0..4] != constants::COWD_HEADER_MAGIC {
      return Err(Error::InvalidFormat(
        "invalid vmdk cowd header signature".to_string(),
      ));
    }

    let format_version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if format_version != 1 {
      return Err(Error::InvalidFormat(format!(
        "unsupported vmdk cowd format version: {format_version}"
      )));
    }
    let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if flags & !constants::COWD_SUPPORTED_FLAGS != 0 {
      return Err(Error::InvalidFormat(format!(
        "unsupported vmdk cowd flags: 0x{flags:08x}"
      )));
    }

    let capacity_sectors = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let sectors_per_grain = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let grain_directory_start_sector = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let grain_directory_entries = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let next_free_sector = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let parent_generation = u32::from_le_bytes([data[1056], data[1057], data[1058], data[1059]]);
    let generation = u32::from_le_bytes([data[1060], data[1061], data[1062], data[1063]]);
    let saved_generation = u32::from_le_bytes([data[1636], data[1637], data[1638], data[1639]]);
    let dirty_raw = u32::from_le_bytes([data[1648], data[1649], data[1650], data[1651]]);

    if capacity_sectors == 0 {
      return Err(Error::InvalidFormat(
        "vmdk cowd capacity must be non-zero".to_string(),
      ));
    }
    if sectors_per_grain == 0 || !sectors_per_grain.is_power_of_two() {
      return Err(Error::InvalidFormat(format!(
        "invalid vmdk cowd sectors-per-grain value: {sectors_per_grain}"
      )));
    }
    if grain_directory_start_sector == 0 {
      return Err(Error::InvalidFormat(
        "vmdk cowd grain-directory start sector must be non-zero".to_string(),
      ));
    }
    if grain_directory_entries == 0 {
      return Err(Error::InvalidFormat(
        "vmdk cowd grain-directory entry count must be non-zero".to_string(),
      ));
    }
    if dirty_raw != 0 && dirty_raw != 1 {
      return Err(Error::InvalidFormat(format!(
        "unsupported vmdk cowd dirty flag value: {dirty_raw}"
      )));
    }

    Ok(Self {
      format_version,
      flags,
      capacity_sectors,
      sectors_per_grain,
      grain_directory_start_sector,
      grain_directory_entries,
      next_free_sector,
      parent_path: extract_c_string(&data[32..1056]),
      parent_generation,
      generation,
      saved_generation,
      is_dirty: dirty_raw != 0,
    })
  }

  pub fn grain_size_bytes(&self) -> Result<u64> {
    u64::from(self.sectors_per_grain)
      .checked_mul(constants::BYTES_PER_SECTOR)
      .ok_or_else(|| Error::InvalidRange("vmdk cowd grain size overflow".to_string()))
  }

  pub fn virtual_size_bytes(&self) -> Result<u64> {
    u64::from(self.capacity_sectors)
      .checked_mul(constants::BYTES_PER_SECTOR)
      .ok_or_else(|| Error::InvalidRange("vmdk cowd virtual size overflow".to_string()))
  }
}

fn extract_c_string(data: &[u8]) -> String {
  let end = data
    .iter()
    .position(|byte| *byte == 0)
    .unwrap_or(data.len());
  String::from_utf8_lossy(&data[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_header() -> [u8; constants::COWD_HEADER_SIZE] {
    let mut data = [0u8; constants::COWD_HEADER_SIZE];
    data[0..4].copy_from_slice(constants::COWD_HEADER_MAGIC);
    data[4..8].copy_from_slice(&1u32.to_le_bytes());
    data[8..12].copy_from_slice(&3u32.to_le_bytes());
    data[12..16].copy_from_slice(&8192u32.to_le_bytes());
    data[16..20].copy_from_slice(&128u32.to_le_bytes());
    data[20..24].copy_from_slice(&21u32.to_le_bytes());
    data[24..28].copy_from_slice(&16u32.to_le_bytes());
    data[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    data
  }

  #[test]
  fn parses_cowd_header_fields() {
    let header = VmdkCowdHeader::from_bytes(&sample_header()).unwrap();

    assert_eq!(header.format_version, 1);
    assert_eq!(header.capacity_sectors, 8192);
    assert_eq!(header.sectors_per_grain, 128);
    assert_eq!(header.grain_directory_entries, 16);
    assert_eq!(header.parent_path, "");
    assert_eq!(header.virtual_size_bytes().unwrap(), 4_194_304);
  }

  #[test]
  fn rejects_invalid_grain_directory_counts() {
    let mut data = sample_header();
    data[24..28].copy_from_slice(&0u32.to_le_bytes());

    let result = VmdkCowdHeader::from_bytes(&data);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn extracts_parent_paths() {
    let mut data = sample_header();
    data[32..43].copy_from_slice(b"parent.vmdk");

    let header = VmdkCowdHeader::from_bytes(&data).unwrap();

    assert_eq!(header.parent_path, "parent.vmdk");
  }
}
