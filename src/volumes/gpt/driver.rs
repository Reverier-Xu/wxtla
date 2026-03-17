//! GPT driver open flow.

use super::{DESCRIPTOR, parser, system::GptVolumeSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  volumes::{VolumeSystem, VolumeSystemDriver},
};

/// Driver for the GUID Partition Table scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct GptDriver;

impl GptDriver {
  /// Create a new GPT driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open a GPT source using inferred logical block size.
  pub fn open(source: DataSourceHandle) -> Result<GptVolumeSystem> {
    parser::open(source)
  }

  /// Open a GPT source using an explicit logical block size.
  pub fn open_with_block_size(
    source: DataSourceHandle, block_size: u32,
  ) -> Result<GptVolumeSystem> {
    parser::open_with_block_size(source, block_size)
  }
}

impl VolumeSystemDriver for GptDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: DataSourceHandle, _hints: SourceHints<'_>,
  ) -> Result<Box<dyn VolumeSystem>> {
    Ok(Box::new(Self::open(source)?))
  }
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;
  use crate::{DataSource, Error, Result, volumes::gpt::integrity};

  const LINUX_FILESYSTEM_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
  ];
  const TEST_DISK_GUID: [u8; 16] = [
    0x7A, 0x65, 0x6E, 0xE8, 0x40, 0xD8, 0x09, 0x4C, 0xAF, 0xE3, 0xA1, 0xA5, 0xF6, 0x65, 0xCF, 0x44,
  ];

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

  impl DataSource for MemDataSource {
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

  fn sample_source(relative_path: &str) -> DataSourceHandle {
    Arc::new(MemDataSource::from_fixture(relative_path))
  }

  fn synthetic_source(bytes: Vec<u8>) -> DataSourceHandle {
    Arc::new(MemDataSource { data: bytes })
  }

  fn write_protective_mbr(disk: &mut [u8], protective_sectors: u32) {
    disk[446 + 4] = 0xEE;
    disk[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    disk[446 + 12..446 + 16].copy_from_slice(&protective_sectors.to_le_bytes());
    disk[510..512].copy_from_slice(&[0x55, 0xAA]);
  }

  fn write_hybrid_mbr(disk: &mut [u8], protective_sectors: u32) {
    write_protective_mbr(disk, protective_sectors);
    disk[462 + 4] = 0xAF;
    disk[462 + 8..462 + 12].copy_from_slice(&40u32.to_le_bytes());
    disk[462 + 12..462 + 16].copy_from_slice(&20u32.to_le_bytes());
  }

  struct TestHeaderSpec {
    offset: usize,
    current_lba: u64,
    backup_lba: u64,
    entry_array_start_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    entry_count: u32,
    entry_array_crc32: u32,
    disk_guid: [u8; 16],
  }

  fn write_header(disk: &mut [u8], spec: TestHeaderSpec) {
    let header = &mut disk[spec.offset..spec.offset + 92];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[24..32].copy_from_slice(&spec.current_lba.to_le_bytes());
    header[32..40].copy_from_slice(&spec.backup_lba.to_le_bytes());
    header[40..48].copy_from_slice(&spec.first_usable_lba.to_le_bytes());
    header[48..56].copy_from_slice(&spec.last_usable_lba.to_le_bytes());
    header[56..72].copy_from_slice(&spec.disk_guid);
    header[72..80].copy_from_slice(&spec.entry_array_start_lba.to_le_bytes());
    header[80..84].copy_from_slice(&spec.entry_count.to_le_bytes());
    header[84..88].copy_from_slice(&128u32.to_le_bytes());
    header[88..92].copy_from_slice(&spec.entry_array_crc32.to_le_bytes());
    let header_crc32 = integrity::crc32(&header_crc_input(header));
    header[16..20].copy_from_slice(&header_crc32.to_le_bytes());
  }

  fn header_crc_input(header: &[u8]) -> Vec<u8> {
    let mut input = header[..92].to_vec();
    input[16..20].fill(0);
    input
  }

  fn write_entry(
    disk: &mut [u8], offset: usize, type_guid: [u8; 16], unique_guid: [u8; 16], first_lba: u64,
    last_lba: u64, name: &str,
  ) {
    let entry = &mut disk[offset..offset + 128];
    entry[0..16].copy_from_slice(&type_guid);
    entry[16..32].copy_from_slice(&unique_guid);
    entry[32..40].copy_from_slice(&first_lba.to_le_bytes());
    entry[40..48].copy_from_slice(&last_lba.to_le_bytes());
    for (index, code_unit) in name.encode_utf16().enumerate() {
      let start = 56 + index * 2;
      entry[start..start + 2].copy_from_slice(&code_unit.to_le_bytes());
    }
  }

  fn synthetic_gpt(block_size: usize) -> Vec<u8> {
    let total_blocks = 96usize;
    let mut disk = vec![0u8; total_blocks * block_size];
    let protective_sectors = u32::try_from(total_blocks - 1).unwrap();
    write_protective_mbr(&mut disk, protective_sectors);

    let primary_entries_offset = 2 * block_size;
    write_entry(
      &mut disk,
      primary_entries_offset,
      LINUX_FILESYSTEM_GUID,
      [1; 16],
      40,
      47,
      "linux",
    );
    let primary_entry_crc32 =
      integrity::crc32(&disk[primary_entries_offset..primary_entries_offset + 128]);

    let backup_entries_lba = (total_blocks - 2) as u64;
    let backup_entries_offset = (backup_entries_lba as usize) * block_size;
    let primary_entry_bytes = disk[primary_entries_offset..primary_entries_offset + 128].to_vec();
    disk[backup_entries_offset..backup_entries_offset + 128].copy_from_slice(&primary_entry_bytes);

    write_header(
      &mut disk,
      TestHeaderSpec {
        offset: block_size,
        current_lba: 1,
        backup_lba: (total_blocks - 1) as u64,
        entry_array_start_lba: 2,
        first_usable_lba: 34,
        last_usable_lba: backup_entries_lba - 1,
        entry_count: 1,
        entry_array_crc32: primary_entry_crc32,
        disk_guid: TEST_DISK_GUID,
      },
    );
    write_header(
      &mut disk,
      TestHeaderSpec {
        offset: (total_blocks - 1) * block_size,
        current_lba: (total_blocks - 1) as u64,
        backup_lba: 1,
        entry_array_start_lba: backup_entries_lba,
        first_usable_lba: 34,
        last_usable_lba: backup_entries_lba - 1,
        entry_count: 1,
        entry_array_crc32: primary_entry_crc32,
        disk_guid: TEST_DISK_GUID,
      },
    );

    disk
  }

  #[test]
  fn opens_fixture_partitions_and_names() {
    let system = GptDriver::open(sample_source("gpt/gpt.raw")).unwrap();

    assert_eq!(system.block_size(), 512);
    assert_eq!(system.partitions().len(), 2);
    assert_eq!(
      system.partitions()[0].record.name.as_deref(),
      Some("Linux filesystem")
    );
    assert_eq!(
      system.partitions()[1].record.name.as_deref(),
      Some("Microsoft basic data")
    );
    assert_eq!(
      system.disk_guid().to_string(),
      "b182deb3-9c86-4892-9e88-9297a4909855"
    );
    assert_eq!(system.backup_header().current_lba, 8191);
  }

  #[test]
  fn opens_volume_slices_from_fixture() {
    let system = GptDriver::open(sample_source("gpt/gpt.raw")).unwrap();
    let volume = system.open_volume(1).unwrap();

    assert_eq!(volume.size().unwrap(), 3072 * 512);
  }

  #[test]
  fn infers_4096_block_size_from_valid_layout() {
    let system = GptDriver::open(synthetic_source(synthetic_gpt(4096))).unwrap();

    assert_eq!(system.block_size(), 4096);
    assert_eq!(system.partitions().len(), 1);
    assert_eq!(system.partitions()[0].record.name.as_deref(), Some("linux"));
  }

  #[test]
  fn rejects_missing_protective_mbr() {
    let mut disk = synthetic_gpt(512);
    disk[446 + 4] = 0x00;

    let result = GptDriver::open(synthetic_source(disk));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_header_crc_mismatch() {
    let mut disk = synthetic_gpt(512);
    disk[512 + 16] ^= 0xFF;

    let result = GptDriver::open(synthetic_source(disk));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_backup_header_mismatch() {
    let mut disk = synthetic_gpt(512);
    let backup_header_offset = disk.len() - 512;
    disk[backup_header_offset + 56] ^= 0x01;
    let backup_header = &mut disk[backup_header_offset..backup_header_offset + 92];
    backup_header[16..20].fill(0);
    let backup_crc32 = integrity::crc32(&header_crc_input(backup_header));
    backup_header[16..20].copy_from_slice(&backup_crc32.to_le_bytes());

    let result = GptDriver::open(synthetic_source(disk));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn allows_hybrid_protective_mbr_layouts() {
    let mut disk = synthetic_gpt(512);
    let protective_sectors = u32::try_from((disk.len() / 512) - 1).unwrap();
    write_hybrid_mbr(&mut disk, protective_sectors);

    let system = GptDriver::open(synthetic_source(disk)).unwrap();

    assert_eq!(system.partitions().len(), 1);
  }
}
