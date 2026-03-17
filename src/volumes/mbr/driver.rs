//! MBR driver open flow.

use super::{
  DESCRIPTOR, boot_record::MbrBootRecord, constants::DEFAULT_BYTES_PER_SECTOR,
  entry::MbrPartitionInfo, system::MbrVolumeSystem,
};
use crate::{
  DataSourceHandle, Error, Result, SourceHints,
  volumes::{VolumeSystem, VolumeSystemDriver},
};

/// Driver for the Master Boot Record partitioning scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct MbrDriver;

impl MbrDriver {
  /// Create a new MBR driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open an MBR source using the default 512-byte sector size.
  pub fn open_primary(source: DataSourceHandle) -> Result<MbrVolumeSystem> {
    Self::open_with_sector_size(source, DEFAULT_BYTES_PER_SECTOR)
  }

  /// Open an MBR source using an explicit bytes-per-sector value.
  pub fn open_with_sector_size(
    source: DataSourceHandle, bytes_per_sector: u32,
  ) -> Result<MbrVolumeSystem> {
    let boot_record = MbrBootRecord::read(source.as_ref(), 0)?;
    let source_size = source.size()?;
    let mut partitions = Vec::new();

    for (index, entry) in boot_record.entries().iter().copied().enumerate() {
      if entry.is_unused() {
        continue;
      }

      let partition = MbrPartitionInfo::from_primary(index, entry, bytes_per_sector)?;
      let Some(end_offset) = partition.record.span.end_offset() else {
        return Err(Error::InvalidRange(
          "mbr partition end offset overflow".to_string(),
        ));
      };
      if end_offset > source_size {
        return Err(Error::InvalidFormat(format!(
          "mbr partition {index} exceeds source size"
        )));
      }

      partitions.push(partition);
    }

    Ok(MbrVolumeSystem::new(
      source,
      bytes_per_sector,
      boot_record.disk_signature(),
      partitions,
    ))
  }
}

impl VolumeSystemDriver for MbrDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: DataSourceHandle, _hints: SourceHints<'_>,
  ) -> Result<Box<dyn VolumeSystem>> {
    Ok(Box::new(Self::open_primary(source)?))
  }
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;
  use crate::{DataSource, Result, volumes::VolumeRole};

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

  #[test]
  fn opens_primary_partitions_from_fixture() {
    let system = MbrDriver::open_primary(sample_source("mbr/mbr.raw")).unwrap();

    assert_eq!(system.bytes_per_sector(), 512);
    assert_eq!(system.partitions().len(), 2);
    assert_eq!(system.partitions()[0].record.role, VolumeRole::Primary);
    assert_eq!(system.partitions()[0].record.span.byte_offset, 512);
    assert_eq!(
      system.partitions()[1].record.role,
      VolumeRole::ExtendedContainer
    );
  }

  #[test]
  fn opens_volume_slices_from_primary_entries() {
    let system = MbrDriver::open_primary(sample_source("mbr/mbr.raw")).unwrap();
    let volume = system.open_volume(0).unwrap();

    assert_eq!(volume.size().unwrap(), 2049 * 512);
  }

  #[test]
  fn classifies_protective_primary_entries() {
    let system = MbrDriver::open_primary(sample_source("gpt/gpt.raw")).unwrap();

    assert_eq!(system.partitions().len(), 1);
    assert_eq!(system.partitions()[0].record.role, VolumeRole::Protective);
  }
}
