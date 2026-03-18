//! Sparsebundle driver open flow.

use super::{DESCRIPTOR, image::SparseBundleImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct SparseBundleDriver;

impl SparseBundleDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<SparseBundleImage> {
    SparseBundleImage::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<SparseBundleImage> {
    SparseBundleImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for SparseBundleDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(SparseBundleImage::open_with_hints(source, hints)?))
  }
}
