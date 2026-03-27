//! Splitraw driver open flow.

use super::{DESCRIPTOR, image::SplitRawImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct SplitRawDriver;

impl SplitRawDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<SplitRawImage> {
    SplitRawImage::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<SplitRawImage> {
    SplitRawImage::open_with_hints(source, hints)
  }
}
impl Driver for SplitRawDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(SplitRawImage::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
