//! VMDK sparse extent header parsing.

use super::constants;
use crate::{ByteSource, Error, Result};

/// Parsed VMDK sparse-file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmdkSparseHeader {
  /// Sparse extent format version.
  pub format_version: u32,
  /// Header flags.
  pub flags: u32,
  /// Virtual disk capacity in sectors.
  pub capacity_sectors: u64,
  /// Grain size in sectors.
  pub sectors_per_grain: u64,
  /// Embedded descriptor start sector.
  pub descriptor_start_sector: u64,
  /// Embedded descriptor length in sectors.
  pub descriptor_size_sectors: u64,
  /// Number of entries in each grain table.
  pub grain_table_entries: u32,
  /// Redundant grain-directory start sector.
  pub secondary_grain_directory_start_sector: u64,
  /// Primary grain-directory start sector.
  pub primary_grain_directory_start_sector: u64,
  /// Metadata size in sectors.
  pub metadata_size_sectors: u64,
  /// Dirty flag.
  pub is_dirty: bool,
  /// Compression method identifier.
  pub compression_method: u16,
}

impl VmdkSparseHeader {
  pub fn read(source: &dyn ByteSource) -> Result<Self> {
    Self::read_at(source, 0)
  }

  pub fn read_at(source: &dyn ByteSource, offset: u64) -> Result<Self> {
    let data = source.read_bytes_at(offset, constants::SPARSE_HEADER_SIZE)?;
    Self::from_bytes(&data)
  }

  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != constants::SPARSE_HEADER_SIZE {
      return Err(Error::invalid_format(format!(
        "vmdk sparse header must be {} bytes, got {}",
        constants::SPARSE_HEADER_SIZE,
        data.len()
      )));
    }
    if &data[0..4] != constants::SPARSE_HEADER_MAGIC {
      return Err(Error::invalid_format(
        "invalid vmdk sparse header signature".to_string(),
      ));
    }
    if data[73..77] != [0x0A, 0x20, 0x0D, 0x0A] {
      return Err(Error::invalid_format(
        "invalid vmdk sparse header newline marker bytes".to_string(),
      ));
    }

    let format_version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if !(1..=3).contains(&format_version) {
      return Err(Error::invalid_format(format!(
        "unsupported vmdk sparse format version: {format_version}"
      )));
    }

    let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if flags & !constants::SUPPORTED_HEADER_FLAGS != 0 {
      return Err(Error::invalid_format(format!(
        "unsupported vmdk sparse header flags: 0x{flags:08x}"
      )));
    }
    if flags & constants::FLAG_VALID_NEWLINE_TEST == 0 {
      return Err(Error::invalid_format(
        "vmdk sparse header must enable newline validation".to_string(),
      ));
    }

    let capacity_sectors = u64::from_le_bytes([
      data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
    ]);
    let sectors_per_grain = u64::from_le_bytes([
      data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
    ]);
    let descriptor_start_sector = u64::from_le_bytes([
      data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35],
    ]);
    let descriptor_size_sectors = u64::from_le_bytes([
      data[36], data[37], data[38], data[39], data[40], data[41], data[42], data[43],
    ]);
    let grain_table_entries = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
    let secondary_grain_directory_start_sector = u64::from_le_bytes([
      data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
    ]);
    let primary_grain_directory_start_sector = u64::from_le_bytes([
      data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
    ]);
    let metadata_size_sectors = u64::from_le_bytes([
      data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
    ]);

    if capacity_sectors == 0 {
      return Err(Error::invalid_format(
        "vmdk sparse header capacity must be non-zero".to_string(),
      ));
    }
    if sectors_per_grain < 8 || !sectors_per_grain.is_power_of_two() {
      return Err(Error::invalid_format(format!(
        "invalid vmdk sectors-per-grain value: {sectors_per_grain}"
      )));
    }
    if (descriptor_start_sector == 0) != (descriptor_size_sectors == 0) {
      return Err(Error::invalid_format(
        "vmdk sparse header descriptor location must be fully specified or fully absent"
          .to_string(),
      ));
    }
    if grain_table_entries == 0 {
      return Err(Error::invalid_format(
        "vmdk sparse header grain-table entry count must be non-zero".to_string(),
      ));
    }
    let grain_table_bytes = u64::from(grain_table_entries)
      .checked_mul(4)
      .ok_or_else(|| Error::invalid_range("vmdk grain-table size overflow"))?;
    if !grain_table_bytes.is_multiple_of(constants::BYTES_PER_SECTOR) {
      return Err(Error::invalid_format(
        "vmdk grain table must occupy a whole number of sectors".to_string(),
      ));
    }
    if primary_grain_directory_start_sector == 0 {
      return Err(Error::invalid_format(
        "vmdk sparse header primary grain directory must be non-zero".to_string(),
      ));
    }
    if flags & constants::FLAG_USE_SECONDARY_GD != 0 && secondary_grain_directory_start_sector == 0
    {
      return Err(Error::invalid_format(
        "vmdk sparse header requires a non-zero secondary grain directory".to_string(),
      ));
    }
    let compression_method = u16::from_le_bytes([data[77], data[78]]);
    if compression_method > 1 {
      return Err(Error::invalid_format(format!(
        "unsupported vmdk compression method: {compression_method}"
      )));
    }
    if compression_method != 0 && flags & constants::FLAG_HAS_COMPRESSED_GRAINS == 0 {
      return Err(Error::invalid_format(
        "vmdk compression method requires the compressed-grains flag".to_string(),
      ));
    }

    Ok(Self {
      format_version,
      flags,
      capacity_sectors,
      sectors_per_grain,
      descriptor_start_sector,
      descriptor_size_sectors,
      grain_table_entries,
      secondary_grain_directory_start_sector,
      primary_grain_directory_start_sector,
      metadata_size_sectors,
      is_dirty: data[72] != 0,
      compression_method,
    })
  }

  pub fn grain_size_bytes(self) -> Result<u64> {
    self
      .sectors_per_grain
      .checked_mul(constants::BYTES_PER_SECTOR)
      .ok_or_else(|| Error::invalid_range("vmdk grain size overflow"))
  }

  pub fn virtual_size_bytes(self) -> Result<u64> {
    self
      .capacity_sectors
      .checked_mul(constants::BYTES_PER_SECTOR)
      .ok_or_else(|| Error::invalid_range("vmdk virtual size overflow"))
  }

  pub fn uses_secondary_grain_directory(self) -> bool {
    self.flags & constants::FLAG_USE_SECONDARY_GD != 0
  }

  pub fn uses_zero_grain_entries(self) -> bool {
    self.flags & constants::FLAG_USE_ZERO_GRAIN != 0
  }

  pub fn has_compressed_grains(self) -> bool {
    self.flags & constants::FLAG_HAS_COMPRESSED_GRAINS != 0
  }

  pub fn has_markers(self) -> bool {
    self.flags & constants::FLAG_HAS_MARKERS != 0
  }

  pub fn uses_gd_at_end(self) -> bool {
    self.primary_grain_directory_start_sector == constants::GD_AT_END
  }

  pub fn active_grain_directory_start_sector(self) -> u64 {
    if self.uses_secondary_grain_directory() {
      self.secondary_grain_directory_start_sector
    } else {
      self.primary_grain_directory_start_sector
    }
  }

  pub fn has_embedded_descriptor(self) -> bool {
    self.descriptor_start_sector != 0 && self.descriptor_size_sectors != 0
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_header() -> [u8; 512] {
    let mut data = [0u8; 512];
    data[0..4].copy_from_slice(constants::SPARSE_HEADER_MAGIC);
    data[4..8].copy_from_slice(&1u32.to_le_bytes());
    data[8..12].copy_from_slice(&(constants::FLAG_VALID_NEWLINE_TEST).to_le_bytes());
    data[12..20].copy_from_slice(&8192u64.to_le_bytes());
    data[20..28].copy_from_slice(&128u64.to_le_bytes());
    data[28..36].copy_from_slice(&1u64.to_le_bytes());
    data[36..44].copy_from_slice(&20u64.to_le_bytes());
    data[44..48].copy_from_slice(&512u32.to_le_bytes());
    data[48..56].copy_from_slice(&21u64.to_le_bytes());
    data[56..64].copy_from_slice(&26u64.to_le_bytes());
    data[64..72].copy_from_slice(&128u64.to_le_bytes());
    data[73..77].copy_from_slice(&[0x0A, 0x20, 0x0D, 0x0A]);
    data
  }

  #[test]
  fn parses_sparse_header_fields() {
    let header = VmdkSparseHeader::from_bytes(&sample_header()).unwrap();

    assert_eq!(header.format_version, 1);
    assert_eq!(header.capacity_sectors, 8192);
    assert_eq!(header.sectors_per_grain, 128);
    assert_eq!(header.grain_table_entries, 512);
    assert_eq!(header.active_grain_directory_start_sector(), 26);
    assert_eq!(header.virtual_size_bytes().unwrap(), 4_194_304);
  }

  #[test]
  fn rejects_invalid_newline_marker_bytes() {
    let mut data = sample_header();
    data[73] = 0x00;

    let result = VmdkSparseHeader::from_bytes(&data);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_unsupported_flag_bits() {
    let mut data = sample_header();
    data[11] = 0x80;

    let result = VmdkSparseHeader::from_bytes(&data);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
