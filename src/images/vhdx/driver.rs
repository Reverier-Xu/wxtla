//! VHDX driver open flow.

use super::{DESCRIPTOR, image::VhdxImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct VhdxDriver;

impl VhdxDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<VhdxImage> {
    VhdxImage::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<VhdxImage> {
    VhdxImage::open_with_hints(source, hints)
  }
}

impl Driver for VhdxDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(VhdxImage::open_with_hints(source, options.hints)?))
  }
}
