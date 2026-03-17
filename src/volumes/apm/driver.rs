//! APM driver open flow.

use super::{DESCRIPTOR, parser, system::ApmVolumeSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  volumes::{VolumeSystem, VolumeSystemDriver},
};

/// Driver for the Apple Partition Map scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApmDriver;

impl ApmDriver {
  /// Create a new APM driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open an APM source.
  pub fn open(source: DataSourceHandle) -> Result<ApmVolumeSystem> {
    parser::open(source)
  }
}

impl VolumeSystemDriver for ApmDriver {
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
  use crate::DataSource;

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
  fn opens_partition_map_entries_from_fixture() {
    let system = ApmDriver::open(sample_source("apm/apm.dmg")).unwrap();

    assert_eq!(system.block_size(), 512);
    assert_eq!(system.driver_descriptor().block_count, 8192);
    assert_eq!(system.partitions().len(), 3);
    assert_eq!(
      system.partitions()[0].entry.type_identifier,
      "Apple_partition_map"
    );
    assert_eq!(
      system.partitions()[1].record.name.as_deref(),
      Some("disk image")
    );
    assert_eq!(system.partitions()[2].entry.type_identifier, "Apple_Free");
  }

  #[test]
  fn opens_volume_slices_from_fixture() {
    let system = ApmDriver::open(sample_source("apm/apm.dmg")).unwrap();
    let volume = system.open_volume(1).unwrap();

    assert_eq!(volume.size().unwrap(), 8112 * 512);
  }
}
