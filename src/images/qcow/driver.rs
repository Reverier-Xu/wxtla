//! QCOW driver open flow.

use super::{DESCRIPTOR, image::QcowImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

/// Driver for QCOW image files.
#[derive(Debug, Default, Clone, Copy)]
pub struct QcowDriver;

impl QcowDriver {
  /// Create a new QCOW driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open a QCOW image.
  pub fn open(source: DataSourceHandle) -> Result<QcowImage> {
    QcowImage::open(source)
  }
}

impl ImageDriver for QcowDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(QcowImage::open_with_hints(source, hints)?))
  }
}
