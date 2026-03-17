//! Core volume-system driver interfaces.

use super::VolumeRecord;
use crate::{DataSourceHandle, FormatDescriptor, Result, SourceHints};

/// Read-only volume map produced by a partition-table or volume-system driver.
pub trait VolumeSystem: Send + Sync {
  /// Return the format descriptor for this opened volume system.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the volume-system block size in bytes.
  fn block_size(&self) -> u32;

  /// Return the discovered volume records.
  fn volumes(&self) -> &[VolumeRecord];

  /// Return a volume record by index.
  fn volume(&self, index: usize) -> Option<&VolumeRecord> {
    self.volumes().get(index)
  }

  /// Open the logical byte range corresponding to a volume.
  fn open_volume(&self, index: usize) -> Result<DataSourceHandle>;
}

/// Opens a specific volume-system format into a set of logical volumes.
pub trait VolumeSystemDriver: Send + Sync {
  /// Return the format descriptor handled by this driver.
  fn descriptor(&self) -> FormatDescriptor;

  /// Open the volume system from the provided byte source.
  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>)
  -> Result<Box<dyn VolumeSystem>>;
}
