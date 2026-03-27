//! QCOW driver open flow.

use super::{DESCRIPTOR, image::QcowImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

/// Driver for QCOW image files.
#[derive(Debug, Default, Clone, Copy)]
pub struct QcowDriver;

impl QcowDriver {
  /// Create a new QCOW driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open a QCOW image.
  pub fn open(source: ByteSourceHandle) -> Result<QcowImage> {
    QcowImage::open(source)
  }
}

impl Driver for QcowDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(QcowImage::open_with_hints(source, options.hints)?))
  }
}
