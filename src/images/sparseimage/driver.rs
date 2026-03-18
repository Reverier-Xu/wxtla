//! Sparseimage driver open flow.

use super::{DESCRIPTOR, image::SparseImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct SparseImageDriver;

impl SparseImageDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<SparseImage> {
    SparseImage::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<SparseImage> {
    SparseImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for SparseImageDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(SparseImage::open_with_hints(source, hints)?))
  }
}
