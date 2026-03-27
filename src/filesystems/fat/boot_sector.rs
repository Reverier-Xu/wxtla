//! FAT boot-sector parsing and layout helpers.

use crate::{ByteSource, Error, Result};

pub(crate) const BOOT_SECTOR_SIZE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
  Fat12,
  Fat16,
  Fat32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatBootSector {
  pub fat_type: FatType,
  pub bytes_per_sector: u16,
  pub sectors_per_cluster: u8,
  pub reserved_sectors: u16,
  pub fat_count: u8,
  pub root_entry_count: u16,
  pub total_sectors: u32,
  pub sectors_per_fat: u32,
  pub root_cluster: u32,
  pub media_descriptor: u8,
}

impl FatBootSector {
  pub fn read(source: &dyn ByteSource) -> Result<Self> {
    let bytes = source.read_bytes_at(0, BOOT_SECTOR_SIZE)?;
    Self::from_bytes(&bytes)
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    let sector: &[u8; BOOT_SECTOR_SIZE] = bytes
      .try_into()
      .map_err(|_| Error::InvalidFormat("fat boot sector must be exactly 512 bytes".to_string()))?;
    Self::from_sector(sector)
  }

  pub fn from_sector(sector: &[u8; BOOT_SECTOR_SIZE]) -> Result<Self> {
    if !has_valid_boot_jump(sector) {
      return Err(Error::InvalidFormat(
        "fat boot sector has an invalid jump instruction".to_string(),
      ));
    }
    if !has_boot_signature(sector) {
      return Err(Error::InvalidFormat(
        "fat boot sector is missing the 0x55aa signature".to_string(),
      ));
    }

    let bytes_per_sector = le_u16(&sector[11..13]);
    if !valid_bytes_per_sector(bytes_per_sector) {
      return Err(Error::InvalidFormat(format!(
        "unsupported fat bytes-per-sector value: {bytes_per_sector}"
      )));
    }

    let sectors_per_cluster = sector[13];
    if !valid_sectors_per_cluster(sectors_per_cluster) {
      return Err(Error::InvalidFormat(format!(
        "unsupported fat sectors-per-cluster value: {sectors_per_cluster}"
      )));
    }

    let reserved_sectors = le_u16(&sector[14..16]);
    if reserved_sectors == 0 {
      return Err(Error::InvalidFormat(
        "fat reserved sector count must be non-zero".to_string(),
      ));
    }

    let fat_count = sector[16];
    if fat_count == 0 {
      return Err(Error::InvalidFormat(
        "fat must contain at least one FAT table".to_string(),
      ));
    }

    let root_entry_count = le_u16(&sector[17..19]);
    let total_sectors_16 = u32::from(le_u16(&sector[19..21]));
    let total_sectors_32 = le_u32(&sector[32..36]);
    let total_sectors = if total_sectors_16 != 0 {
      total_sectors_16
    } else {
      total_sectors_32
    };
    if total_sectors == 0 {
      return Err(Error::InvalidFormat(
        "fat total sector count must be non-zero".to_string(),
      ));
    }

    let media_descriptor = sector[21];
    if !matches!(media_descriptor, 0xF0 | 0xF8..=0xFF) {
      return Err(Error::InvalidFormat(format!(
        "unsupported fat media descriptor: 0x{media_descriptor:02x}"
      )));
    }

    let sectors_per_fat_16 = u32::from(le_u16(&sector[22..24]));
    let sectors_per_fat_32 = le_u32(&sector[36..40]);
    let sectors_per_fat = if sectors_per_fat_16 != 0 {
      sectors_per_fat_16
    } else {
      sectors_per_fat_32
    };
    if sectors_per_fat == 0 {
      return Err(Error::InvalidFormat(
        "fat sectors-per-fat must be non-zero".to_string(),
      ));
    }

    let root_dir_sectors = div_ceil_u32(
      u32::from(root_entry_count)
        .checked_mul(32)
        .ok_or_else(|| Error::InvalidRange("fat root directory size overflow".to_string()))?,
      u32::from(bytes_per_sector),
    );
    let data_sectors = total_sectors
      .checked_sub(
        u32::from(reserved_sectors)
          .checked_add(
            u32::from(fat_count)
              .checked_mul(sectors_per_fat)
              .ok_or_else(|| Error::InvalidRange("fat table area size overflow".to_string()))?,
          )
          .and_then(|value| value.checked_add(root_dir_sectors))
          .ok_or_else(|| Error::InvalidRange("fat layout size overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidFormat("fat data area is out of bounds".to_string()))?;
    let cluster_count = data_sectors / u32::from(sectors_per_cluster);
    let fat_type = if cluster_count < 4_085 {
      FatType::Fat12
    } else if cluster_count < 65_525 {
      FatType::Fat16
    } else {
      FatType::Fat32
    };

    let root_cluster = if fat_type == FatType::Fat32 {
      let root_cluster = le_u32(&sector[44..48]);
      if root_entry_count != 0 || sectors_per_fat_16 != 0 || sectors_per_fat_32 == 0 {
        return Err(Error::InvalidFormat(
          "fat32 requires a zero root-entry count and 32-bit sectors-per-fat".to_string(),
        ));
      }
      if root_cluster < 2 {
        return Err(Error::InvalidFormat(
          "fat32 root cluster must be at least 2".to_string(),
        ));
      }
      root_cluster
    } else {
      if root_entry_count == 0 || sectors_per_fat_16 == 0 {
        return Err(Error::InvalidFormat(
          "fat12/16 require a fixed root directory and 16-bit sectors-per-fat".to_string(),
        ));
      }
      0
    };

    Ok(Self {
      fat_type,
      bytes_per_sector,
      sectors_per_cluster,
      reserved_sectors,
      fat_count,
      root_entry_count,
      total_sectors,
      sectors_per_fat,
      root_cluster,
      media_descriptor,
    })
  }

  pub fn cluster_size(&self) -> Result<u64> {
    u64::from(self.bytes_per_sector)
      .checked_mul(u64::from(self.sectors_per_cluster))
      .ok_or_else(|| Error::InvalidRange("fat cluster size overflow".to_string()))
  }

  pub fn root_dir_sectors(&self) -> u32 {
    div_ceil_u32(
      u32::from(self.root_entry_count) * 32,
      u32::from(self.bytes_per_sector),
    )
  }

  pub fn fat_offset(&self, index: u8) -> Result<u64> {
    let sector_offset = u64::from(self.reserved_sectors)
      .checked_add(
        u64::from(index)
          .checked_mul(u64::from(self.sectors_per_fat))
          .ok_or_else(|| Error::InvalidRange("fat table offset overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange("fat table offset overflow".to_string()))?;
    sector_offset
      .checked_mul(u64::from(self.bytes_per_sector))
      .ok_or_else(|| Error::InvalidRange("fat table byte offset overflow".to_string()))
  }

  pub fn fat_size_bytes(&self) -> Result<usize> {
    usize::try_from(
      u64::from(self.sectors_per_fat)
        .checked_mul(u64::from(self.bytes_per_sector))
        .ok_or_else(|| Error::InvalidRange("fat table byte size overflow".to_string()))?,
    )
    .map_err(|_| Error::InvalidRange("fat table is too large to map".to_string()))
  }

  pub fn root_dir_offset(&self) -> Result<u64> {
    let sector_offset = u64::from(self.reserved_sectors)
      .checked_add(
        u64::from(self.fat_count)
          .checked_mul(u64::from(self.sectors_per_fat))
          .ok_or_else(|| Error::InvalidRange("fat root directory offset overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange("fat root directory offset overflow".to_string()))?;
    sector_offset
      .checked_mul(u64::from(self.bytes_per_sector))
      .ok_or_else(|| Error::InvalidRange("fat root directory offset overflow".to_string()))
  }

  pub fn root_dir_size_bytes(&self) -> Result<usize> {
    usize::try_from(
      u64::from(self.root_dir_sectors())
        .checked_mul(u64::from(self.bytes_per_sector))
        .ok_or_else(|| Error::InvalidRange("fat root directory size overflow".to_string()))?,
    )
    .map_err(|_| Error::InvalidRange("fat root directory is too large to map".to_string()))
  }

  pub fn data_offset(&self) -> Result<u64> {
    let data_sector = u64::from(self.reserved_sectors)
      .checked_add(
        u64::from(self.fat_count)
          .checked_mul(u64::from(self.sectors_per_fat))
          .ok_or_else(|| Error::InvalidRange("fat data offset overflow".to_string()))?,
      )
      .and_then(|value| value.checked_add(u64::from(self.root_dir_sectors())))
      .ok_or_else(|| Error::InvalidRange("fat data offset overflow".to_string()))?;
    data_sector
      .checked_mul(u64::from(self.bytes_per_sector))
      .ok_or_else(|| Error::InvalidRange("fat data offset overflow".to_string()))
  }

  pub fn cluster_offset(&self, cluster: u32) -> Result<u64> {
    if cluster < 2 {
      return Err(Error::InvalidFormat(format!(
        "fat cluster numbers start at 2, got {cluster}"
      )));
    }

    self
      .data_offset()?
      .checked_add(
        u64::from(cluster - 2)
          .checked_mul(self.cluster_size()?)
          .ok_or_else(|| Error::InvalidRange("fat cluster offset overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange("fat cluster offset overflow".to_string()))
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

fn div_ceil_u32(value: u32, divisor: u32) -> u32 {
  value.div_ceil(divisor)
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

#[cfg(test)]
mod tests {
  use std::path::Path;

  use super::*;

  fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("fat")
      .join("libfsfat")
      .join(relative)
  }

  fn build_fat32_boot_sector() -> [u8; BOOT_SECTOR_SIZE] {
    let mut sector = [0u8; BOOT_SECTOR_SIZE];
    sector[0] = 0xEB;
    sector[1] = 0x58;
    sector[2] = 0x90;
    sector[3..11].copy_from_slice(b"MSWIN4.1");
    sector[11..13].copy_from_slice(&512u16.to_le_bytes());
    sector[13] = 8;
    sector[14..16].copy_from_slice(&32u16.to_le_bytes());
    sector[16] = 2;
    sector[21] = 0xF8;
    sector[32..36].copy_from_slice(&1_048_576u32.to_le_bytes());
    sector[36..40].copy_from_slice(&1_024u32.to_le_bytes());
    sector[44..48].copy_from_slice(&2u32.to_le_bytes());
    sector[510] = 0x55;
    sector[511] = 0xAA;
    sector
  }

  #[test]
  fn parses_valid_fat32_boot_sector() {
    let boot_sector = FatBootSector::from_sector(&build_fat32_boot_sector()).unwrap();

    assert_eq!(boot_sector.fat_type, FatType::Fat32);
    assert_eq!(boot_sector.cluster_size().unwrap(), 4096);
    assert_eq!(boot_sector.root_cluster, 2);
  }

  #[test]
  fn rejects_ntfs_geometry_with_a_fat_hint() {
    let mut sector = build_fat32_boot_sector();
    sector[3..11].copy_from_slice(b"NTFS    ");
    sector[14..16].copy_from_slice(&0u16.to_le_bytes());

    let error = FatBootSector::from_sector(&sector).unwrap_err();
    assert!(matches!(error, Error::InvalidFormat(_)));
  }

  #[test]
  fn parses_libfsfat_boot_sector_fixture() {
    let bytes = std::fs::read(fixture_path("boot_sector.1")).unwrap();
    let boot_sector = FatBootSector::from_bytes(&bytes).unwrap();

    assert_eq!(boot_sector.fat_type, FatType::Fat12);
    assert_eq!(boot_sector.bytes_per_sector, 512);
    assert_eq!(boot_sector.sectors_per_cluster, 4);
    assert_eq!(boot_sector.reserved_sectors, 6);
    assert_eq!(boot_sector.fat_count, 2);
    assert_eq!(boot_sector.root_entry_count, 512);
    assert_eq!(boot_sector.total_sectors, 6016);
    assert_eq!(boot_sector.sectors_per_fat, 5);
    assert_eq!(boot_sector.media_descriptor, 0xF8);
  }
}
