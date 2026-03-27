//! VMDK driver open flow.

use super::{DESCRIPTOR, image::VmdkImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct VmdkDriver;

impl VmdkDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<VmdkImage> {
    VmdkImage::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<VmdkImage> {
    VmdkImage::open_with_hints(source, hints)
  }
}

impl Driver for VmdkDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(VmdkImage::open_with_hints(source, options.hints)?))
  }
}
