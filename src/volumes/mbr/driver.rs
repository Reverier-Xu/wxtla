//! MBR driver open flow.

use super::{DESCRIPTOR, parser, system::MbrVolumeSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

/// Driver for the Master Boot Record partitioning scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct MbrDriver;

impl MbrDriver {
  /// Create a new MBR driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open an MBR source using inferred bytes-per-sector semantics.
  pub fn open(source: ByteSourceHandle) -> Result<MbrVolumeSystem> {
    parser::open(source)
  }

  /// Open an MBR source using an explicit bytes-per-sector value.
  pub fn open_with_sector_size(
    source: ByteSourceHandle, bytes_per_sector: u32,
  ) -> Result<MbrVolumeSystem> {
    parser::open_with_sector_size(source, bytes_per_sector)
  }
}

impl Driver for MbrDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(Self::open(source)?))
  }
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;
  use crate::{ByteSource, Error, Result, volumes::VolumeRole};

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl MemDataSource {
    fn from_fixture(relative_path: &str) -> Self {
      let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join(relative_path);
      Self {
        data: std::fs::read(path).unwrap(),
      }
    }
  }

  impl ByteSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = offset as usize;
      if offset >= self.data.len() {
        return Ok(0);
      }
      let read = buf.len().min(self.data.len() - offset);
      buf[..read].copy_from_slice(&self.data[offset..offset + read]);
      Ok(read)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.data.len() as u64)
    }
  }

  fn sample_source(relative_path: &str) -> ByteSourceHandle {
    Arc::new(MemDataSource::from_fixture(relative_path))
  }

  fn synthetic_source(bytes: Vec<u8>) -> ByteSourceHandle {
    Arc::new(MemDataSource { data: bytes })
  }

  fn write_partition_entry(
    sector: &mut [u8], slot: usize, boot_indicator: u8, partition_type: u8, start_lba: u32,
    sector_count: u32,
  ) {
    let offset = 446 + slot * 16;
    sector[offset] = boot_indicator;
    sector[offset + 4] = partition_type;
    sector[offset + 8..offset + 12].copy_from_slice(&start_lba.to_le_bytes());
    sector[offset + 12..offset + 16].copy_from_slice(&sector_count.to_le_bytes());
  }

  fn write_boot_signature(disk: &mut [u8], offset: usize) {
    disk[offset + 510..offset + 512].copy_from_slice(&[0x55, 0xAA]);
  }

  #[test]
  fn opens_primary_and_logical_partitions_from_fixture() {
    let system = MbrDriver::open(sample_source("mbr/mbr.raw")).unwrap();

    assert_eq!(system.bytes_per_sector(), 512);
    assert_eq!(system.partitions().len(), 3);
    assert_eq!(system.partitions()[0].record.role, VolumeRole::Primary);
    assert_eq!(system.partitions()[0].record.span.byte_offset, 512);
    assert_eq!(
      system.partitions()[1].record.role,
      VolumeRole::ExtendedContainer
    );
    assert_eq!(system.partitions()[2].record.role, VolumeRole::Logical);
    assert_eq!(system.partitions()[2].absolute_start_lba, 2051);
  }

  #[test]
  fn opens_volume_slices_from_logical_entries() {
    let system = MbrDriver::open(sample_source("mbr/mbr.raw")).unwrap();
    let volume = system.open_volume(2).unwrap();

    assert_eq!(volume.size().unwrap(), 3073 * 512);
  }

  #[test]
  fn classifies_protective_primary_entries() {
    let system = MbrDriver::open(sample_source("gpt/gpt.raw")).unwrap();

    assert_eq!(system.partitions().len(), 1);
    assert_eq!(system.partitions()[0].record.role, VolumeRole::Protective);
  }

  #[test]
  fn infers_4096_sector_size_from_extended_partition_chain() {
    let bytes_per_sector = 4096usize;
    let mut disk = vec![0u8; 64 * bytes_per_sector];

    write_partition_entry(&mut disk, 0, 0x00, 0x05, 1, 10);
    write_boot_signature(&mut disk, 0);

    let ebr_offset = bytes_per_sector;
    write_partition_entry(&mut disk[ebr_offset..ebr_offset + 512], 0, 0x00, 0x83, 1, 2);
    write_boot_signature(&mut disk, ebr_offset);

    let logical_offset = 2 * bytes_per_sector;
    disk[logical_offset + 1024 + 56..logical_offset + 1024 + 58].copy_from_slice(&[0x53, 0xEF]);

    let system = MbrDriver::open(synthetic_source(disk)).unwrap();

    assert_eq!(system.bytes_per_sector(), 4096);
    assert_eq!(system.partitions().len(), 2);
    assert_eq!(system.partitions()[1].record.role, VolumeRole::Logical);
  }

  #[test]
  fn rejects_overlapping_primary_partitions() {
    let mut disk = vec![0u8; 4096 * 4];
    write_partition_entry(&mut disk, 0, 0x00, 0x83, 1, 100);
    write_partition_entry(&mut disk, 1, 0x00, 0x07, 50, 100);
    write_boot_signature(&mut disk, 0);

    let result = MbrDriver::open_with_sector_size(synthetic_source(disk), 512);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn allows_hybrid_overlap_with_a_protective_partition() {
    let mut disk = vec![0u8; 512 * 5000];
    write_partition_entry(&mut disk, 0, 0x00, 0xEE, 1, 4000);
    write_partition_entry(&mut disk, 1, 0x80, 0xAF, 40, 200);
    write_boot_signature(&mut disk, 0);
    disk[512..520].copy_from_slice(b"EFI PART");
    disk[40 * 512 + 1024..40 * 512 + 1026].copy_from_slice(b"H+");

    let system = MbrDriver::open_with_sector_size(synthetic_source(disk), 512).unwrap();

    assert_eq!(system.partitions().len(), 2);
    assert_eq!(system.partitions()[0].record.role, VolumeRole::Protective);
    assert_eq!(system.partitions()[1].record.role, VolumeRole::Primary);
  }

  #[test]
  fn opens_logical_partitions_from_multiple_extended_containers() {
    let mut disk = vec![0u8; 512 * 128];
    write_partition_entry(&mut disk, 0, 0x00, 0x05, 1, 16);
    write_partition_entry(&mut disk, 1, 0x00, 0x0F, 32, 16);
    write_boot_signature(&mut disk, 0);

    let first_ebr_offset = 512usize;
    write_partition_entry(
      &mut disk[first_ebr_offset..first_ebr_offset + 512],
      0,
      0x00,
      0x83,
      1,
      2,
    );
    write_boot_signature(&mut disk, first_ebr_offset);

    let second_ebr_offset = 32 * 512usize;
    write_partition_entry(
      &mut disk[second_ebr_offset..second_ebr_offset + 512],
      0,
      0x00,
      0x07,
      1,
      2,
    );
    write_boot_signature(&mut disk, second_ebr_offset);

    let system = MbrDriver::open_with_sector_size(synthetic_source(disk), 512).unwrap();

    assert_eq!(system.partitions().len(), 4);
    assert_eq!(
      system.partitions()[0].record.role,
      VolumeRole::ExtendedContainer
    );
    assert_eq!(
      system.partitions()[1].record.role,
      VolumeRole::ExtendedContainer
    );
    assert_eq!(system.partitions()[2].record.role, VolumeRole::Logical);
    assert_eq!(system.partitions()[2].absolute_start_lba, 2);
    assert_eq!(system.partitions()[3].record.role, VolumeRole::Logical);
    assert_eq!(system.partitions()[3].absolute_start_lba, 33);
  }
}
