//! NTFS boot-sector parsing and validation.

use crate::{DataSource, Error, Result};

pub(crate) const BOOT_SECTOR_SIZE: usize = 512;
pub(crate) const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsBootSector {
  pub bytes_per_sector: u16,
  pub sectors_per_cluster: u8,
  pub total_sectors: u64,
  pub mft_cluster: u64,
  pub mft_mirror_cluster: u64,
  pub clusters_per_file_record: u8,
  pub clusters_per_index_buffer: u8,
  pub volume_serial_number: u64,
}

impl NtfsBootSector {
  pub fn read(source: &dyn DataSource) -> Result<Self> {
    let bytes = source.read_bytes_at(0, BOOT_SECTOR_SIZE)?;
    Self::from_bytes(&bytes)
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    let sector: &[u8; BOOT_SECTOR_SIZE] = bytes.try_into().map_err(|_| {
      Error::InvalidFormat("ntfs boot sector must be exactly 512 bytes".to_string())
    })?;
    Self::from_sector(sector)
  }

  pub fn from_sector(sector: &[u8; BOOT_SECTOR_SIZE]) -> Result<Self> {
    if !has_valid_boot_jump(sector) {
      return Err(Error::InvalidFormat(
        "ntfs boot sector has an invalid jump instruction".to_string(),
      ));
    }
    if !has_boot_signature(sector) {
      return Err(Error::InvalidFormat(
        "ntfs boot sector is missing the 0x55aa signature".to_string(),
      ));
    }
    if &sector[3..11] != NTFS_OEM_ID {
      return Err(Error::InvalidFormat(
        "ntfs boot sector is missing the NTFS OEM identifier".to_string(),
      ));
    }

    let bytes_per_sector = le_u16(&sector[11..13]);
    if !valid_bytes_per_sector(bytes_per_sector) {
      return Err(Error::InvalidFormat(format!(
        "unsupported ntfs bytes-per-sector value: {bytes_per_sector}"
      )));
    }

    let sectors_per_cluster = sector[13];
    if !valid_sectors_per_cluster(sectors_per_cluster) {
      return Err(Error::InvalidFormat(format!(
        "unsupported ntfs sectors-per-cluster value: {sectors_per_cluster}"
      )));
    }

    let reserved_sectors = le_u16(&sector[14..16]);
    if reserved_sectors != 0 {
      return Err(Error::InvalidFormat(format!(
        "ntfs reserved sectors must be zero, got {reserved_sectors}"
      )));
    }

    let total_sectors = le_u64(&sector[40..48]);
    if total_sectors == 0 {
      return Err(Error::InvalidFormat(
        "ntfs total sector count must be non-zero".to_string(),
      ));
    }

    let mft_cluster = le_u64(&sector[48..56]);
    if mft_cluster == 0 {
      return Err(Error::InvalidFormat(
        "ntfs MFT cluster number must be non-zero".to_string(),
      ));
    }

    let mft_mirror_cluster = le_u64(&sector[56..64]);
    if mft_mirror_cluster == 0 {
      return Err(Error::InvalidFormat(
        "ntfs MFT mirror cluster number must be non-zero".to_string(),
      ));
    }

    let clusters_per_file_record = sector[64];
    if clusters_per_file_record == 0 {
      return Err(Error::InvalidFormat(
        "ntfs file-record size encoding must be non-zero".to_string(),
      ));
    }

    let clusters_per_index_buffer = sector[68];
    if clusters_per_index_buffer == 0 {
      return Err(Error::InvalidFormat(
        "ntfs index-buffer size encoding must be non-zero".to_string(),
      ));
    }

    Ok(Self {
      bytes_per_sector,
      sectors_per_cluster,
      total_sectors,
      mft_cluster,
      mft_mirror_cluster,
      clusters_per_file_record,
      clusters_per_index_buffer,
      volume_serial_number: le_u64(&sector[72..80]),
    })
  }

  pub fn cluster_size(&self) -> Result<u64> {
    u64::from(self.bytes_per_sector)
      .checked_mul(u64::from(self.sectors_per_cluster))
      .ok_or_else(|| Error::InvalidRange("ntfs cluster size overflow".to_string()))
  }

  pub fn total_size(&self) -> Result<u64> {
    u64::from(self.bytes_per_sector)
      .checked_mul(self.total_sectors)
      .ok_or_else(|| Error::InvalidRange("ntfs total size overflow".to_string()))
  }

  pub fn file_record_size(&self) -> Result<u64> {
    decode_encoded_size(
      self.clusters_per_file_record,
      self.cluster_size()?,
      "ntfs file-record size",
    )
  }

  pub fn index_buffer_size(&self) -> Result<u64> {
    decode_encoded_size(
      self.clusters_per_index_buffer,
      self.cluster_size()?,
      "ntfs index-buffer size",
    )
  }

  pub fn mft_offset(&self) -> Result<u64> {
    self
      .mft_cluster
      .checked_mul(self.cluster_size()?)
      .ok_or_else(|| Error::InvalidRange("ntfs MFT offset overflow".to_string()))
  }
}

pub(crate) fn has_valid_boot_jump(sector: &[u8; BOOT_SECTOR_SIZE]) -> bool {
  matches!(sector[0], 0xE9) || (sector[0] == 0xEB && sector[2] == 0x90)
}

pub(crate) fn has_boot_signature(sector: &[u8; BOOT_SECTOR_SIZE]) -> bool {
  sector[510] == 0x55 && sector[511] == 0xAA
}

pub(crate) fn valid_bytes_per_sector(value: u16) -> bool {
  matches!(value, 512 | 1024 | 2048 | 4096)
}

pub(crate) fn valid_sectors_per_cluster(value: u8) -> bool {
  value != 0 && value.is_power_of_two()
}

fn decode_encoded_size(encoded: u8, cluster_size: u64, label: &str) -> Result<u64> {
  if encoded == 0 {
    return Err(Error::InvalidFormat(format!(
      "{label} encoding must be non-zero"
    )));
  }

  let signed = encoded as i8;
  if signed > 0 {
    cluster_size
      .checked_mul(u64::from(encoded))
      .ok_or_else(|| Error::InvalidRange(format!("{label} overflow")))
  } else {
    1u64
      .checked_shl(u32::from(signed.unsigned_abs()))
      .ok_or_else(|| Error::InvalidRange(format!("{label} overflow")))
  }
}

fn le_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_le_bytes(raw)
}

fn le_u64(bytes: &[u8]) -> u64 {
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_sector() -> [u8; BOOT_SECTOR_SIZE] {
    let mut sector = [0u8; BOOT_SECTOR_SIZE];
    sector[0] = 0xEB;
    sector[1] = 0x52;
    sector[2] = 0x90;
    sector[3..11].copy_from_slice(NTFS_OEM_ID);
    sector[11..13].copy_from_slice(&512u16.to_le_bytes());
    sector[13] = 8;
    sector[40..48].copy_from_slice(&4096u64.to_le_bytes());
    sector[48..56].copy_from_slice(&4u64.to_le_bytes());
    sector[56..64].copy_from_slice(&8u64.to_le_bytes());
    sector[64] = 0xF6;
    sector[68] = 1;
    sector[510] = 0x55;
    sector[511] = 0xAA;
    sector
  }

  #[test]
  fn parses_valid_boot_sector() {
    let boot_sector = NtfsBootSector::from_sector(&sample_sector()).unwrap();

    assert_eq!(boot_sector.cluster_size().unwrap(), 4096);
    assert_eq!(boot_sector.file_record_size().unwrap(), 1024);
    assert_eq!(boot_sector.index_buffer_size().unwrap(), 4096);
    assert_eq!(boot_sector.mft_offset().unwrap(), 16384);
  }

  #[test]
  fn rejects_invalid_cluster_geometry() {
    let mut sector = sample_sector();
    sector[13] = 3;

    let error = NtfsBootSector::from_sector(&sector).unwrap_err();
    assert!(matches!(error, Error::InvalidFormat(_)));
  }
}
