//! Sparsebundle driver open flow.

use super::{DESCRIPTOR, image::SparseBundleImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct SparseBundleDriver;

impl SparseBundleDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<SparseBundleImage> {
    SparseBundleImage::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<SparseBundleImage> {
    SparseBundleImage::open_with_hints(source, hints)
  }
}
impl Driver for SparseBundleDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(SparseBundleImage::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
