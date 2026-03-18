//! Splitraw driver open flow.

use super::{DESCRIPTOR, image::SplitRawImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct SplitRawDriver;

impl SplitRawDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<SplitRawImage> {
    SplitRawImage::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<SplitRawImage> {
    SplitRawImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for SplitRawDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(SplitRawImage::open_with_hints(source, hints)?))
  }
}
