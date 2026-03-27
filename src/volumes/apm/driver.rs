//! APM driver open flow.

use super::{DESCRIPTOR, parser, system::ApmVolumeSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

/// Driver for the Apple Partition Map scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApmDriver;

impl ApmDriver {
  /// Create a new APM driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open an APM source.
  pub fn open(source: ByteSourceHandle) -> Result<ApmVolumeSystem> {
    parser::open(source)
  }
}

impl Driver for ApmDriver {
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
  use crate::{
    ByteSource, Error,
    volumes::{VolumeRole, apm::type_identifiers},
  };

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

  fn write_driver_descriptor(disk: &mut [u8], block_size: u16, block_count: u32) {
    disk[0..2].copy_from_slice(b"ER");
    disk[2..4].copy_from_slice(&block_size.to_be_bytes());
    disk[4..8].copy_from_slice(&block_count.to_be_bytes());
  }

  struct TestPartitionSpec<'a> {
    index: usize,
    total_entry_count: u32,
    start_block: u32,
    block_count: u32,
    name: &'a str,
    type_identifier: &'a str,
    status_flags: u32,
  }

  fn write_partition_entry(disk: &mut [u8], spec: TestPartitionSpec<'_>) {
    let offset = 512 + spec.index * 512;
    let entry = &mut disk[offset..offset + 512];
    entry[0..2].copy_from_slice(b"PM");
    entry[4..8].copy_from_slice(&spec.total_entry_count.to_be_bytes());
    entry[8..12].copy_from_slice(&spec.start_block.to_be_bytes());
    entry[12..16].copy_from_slice(&spec.block_count.to_be_bytes());
    entry[16..16 + spec.name.len()].copy_from_slice(spec.name.as_bytes());
    entry[48..48 + spec.type_identifier.len()].copy_from_slice(spec.type_identifier.as_bytes());
    entry[80..84].copy_from_slice(&spec.start_block.to_be_bytes());
    entry[84..88].copy_from_slice(&spec.block_count.to_be_bytes());
    entry[88..92].copy_from_slice(&spec.status_flags.to_be_bytes());
  }

  fn synthetic_apm(block_size: u16) -> Vec<u8> {
    let block_count = 128u32;
    let total_size = usize::from(block_size) * block_count as usize;
    let mut disk = vec![0u8; total_size];
    write_driver_descriptor(&mut disk, block_size, block_count);
    write_partition_entry(
      &mut disk,
      TestPartitionSpec {
        index: 0,
        total_entry_count: 2,
        start_block: 1,
        block_count: 16,
        name: "Apple",
        type_identifier: type_identifiers::PARTITION_MAP,
        status_flags: 0x0000_0003,
      },
    );
    write_partition_entry(
      &mut disk,
      TestPartitionSpec {
        index: 1,
        total_entry_count: 2,
        start_block: 17,
        block_count: 32,
        name: "Data",
        type_identifier: type_identifiers::HFS,
        status_flags: 0x4000_0033,
      },
    );
    disk
  }

  #[test]
  fn opens_partition_map_entries_from_fixture() {
    let system = ApmDriver::open(sample_source("apm/apm.dmg")).unwrap();

    assert_eq!(system.block_size(), 512);
    assert_eq!(system.driver_descriptor().block_count, 8192);
    assert_eq!(system.partitions().len(), 3);
    assert_eq!(system.partitions()[0].record.role, VolumeRole::Metadata);
    assert_eq!(
      system.partitions()[0].entry.type_identifier,
      "Apple_partition_map"
    );
    assert_eq!(
      system.partitions()[1].record.name.as_deref(),
      Some("disk image")
    );
    assert_eq!(system.partitions()[1].record.role, VolumeRole::Primary);
    assert_eq!(system.partitions()[2].record.role, VolumeRole::Unknown);
    assert_eq!(system.partitions()[2].entry.type_identifier, "Apple_Free");
  }

  #[test]
  fn opens_volume_slices_from_fixture() {
    let system = ApmDriver::open(sample_source("apm/apm.dmg")).unwrap();
    let volume = system.open_volume(1).unwrap();

    assert_eq!(volume.size().unwrap(), 8112 * 512);
  }

  #[test]
  fn honors_descriptor_block_size_for_partition_spans() {
    let system = ApmDriver::open(synthetic_source(synthetic_apm(2048))).unwrap();

    assert_eq!(system.block_size(), 2048);
    assert_eq!(system.partitions()[1].record.span.byte_offset, 17 * 2048);
    assert_eq!(system.partitions()[1].record.span.byte_size, 32 * 2048);
  }

  #[test]
  fn rejects_inconsistent_partition_entry_counts() {
    let mut disk = synthetic_apm(512);
    let second_entry = &mut disk[1024..1536];
    second_entry[4..8].copy_from_slice(&3u32.to_be_bytes());

    let result = ApmDriver::open(synthetic_source(disk));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_partition_maps_without_a_map_entry_first() {
    let mut disk = synthetic_apm(512);
    let first_entry = &mut disk[512..1024];
    first_entry[48..80].fill(0);
    first_entry[48..48 + type_identifiers::HFS.len()]
      .copy_from_slice(type_identifiers::HFS.as_bytes());

    let result = ApmDriver::open(synthetic_source(disk));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_out_of_bounds_partition_entries() {
    let mut disk = synthetic_apm(512);
    let second_entry = &mut disk[1024..1536];
    second_entry[8..12].copy_from_slice(&120u32.to_be_bytes());
    second_entry[12..16].copy_from_slice(&32u32.to_be_bytes());

    let result = ApmDriver::open(synthetic_source(disk));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_overlapping_partitions_even_when_entries_are_out_of_order() {
    let mut disk = synthetic_apm(512);
    write_partition_entry(
      &mut disk,
      TestPartitionSpec {
        index: 0,
        total_entry_count: 3,
        start_block: 1,
        block_count: 16,
        name: "Apple",
        type_identifier: type_identifiers::PARTITION_MAP,
        status_flags: 0x0000_0003,
      },
    );
    write_partition_entry(
      &mut disk,
      TestPartitionSpec {
        index: 1,
        total_entry_count: 3,
        start_block: 40,
        block_count: 8,
        name: "Data",
        type_identifier: type_identifiers::HFS,
        status_flags: 0x4000_0033,
      },
    );
    write_partition_entry(
      &mut disk,
      TestPartitionSpec {
        index: 2,
        total_entry_count: 3,
        start_block: 35,
        block_count: 12,
        name: "Overlap",
        type_identifier: type_identifiers::FREE,
        status_flags: 0,
      },
    );

    let result = ApmDriver::open(synthetic_source(disk));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
