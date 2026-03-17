//! EWF driver open flow.

use super::{DESCRIPTOR, image::EwfImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

/// Driver for Expert Witness Compression Format images.
#[derive(Debug, Default, Clone, Copy)]
pub struct EwfDriver;

impl EwfDriver {
  /// Create a new EWF driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open an EWF image from a single segment source.
  pub fn open(source: DataSourceHandle) -> Result<EwfImage> {
    EwfImage::open(source)
  }
}

impl ImageDriver for EwfDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(Self::open(source)?))
  }
}
