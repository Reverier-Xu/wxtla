//! Sparseimage driver open flow.

use super::{DESCRIPTOR, image::SparseImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct SparseImageDriver;

impl SparseImageDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<SparseImage> {
    SparseImage::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<SparseImage> {
    SparseImage::open_with_hints(source, hints)
  }
}

impl Driver for SparseImageDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(SparseImage::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
