//! Core image-driver interfaces.

use crate::{DataSource, DataSourceHandle, FormatDescriptor, Result, SourceHints};

/// Read-only logical image surface exposed by an image driver.
pub trait Image: DataSource {
  /// Return the format descriptor for this opened image.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the logical sector size when the format defines one.
  fn logical_sector_size(&self) -> Option<u32> {
    None
  }

  /// Return the physical sector size when the format defines one.
  fn physical_sector_size(&self) -> Option<u32> {
    self.logical_sector_size()
  }

  /// Return `true` when the image can expose holes or zero-runs.
  fn is_sparse(&self) -> bool {
    false
  }

  /// Return `true` when the image depends on one or more backing images.
  fn has_backing_chain(&self) -> bool {
    false
  }
}

/// Opens a specific image format into a concurrent logical image surface.
pub trait ImageDriver: Send + Sync {
  /// Return the format descriptor handled by this driver.
  fn descriptor(&self) -> FormatDescriptor;

  /// Open the image format from the provided byte source.
  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>>;
}
