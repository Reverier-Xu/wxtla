//! PDI driver open flow.

use super::{DESCRIPTOR, image::PdiImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct PdiDriver;

impl PdiDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<PdiImage> {
    PdiImage::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<PdiImage> {
    PdiImage::open_with_hints(source, hints)
  }
}

impl Driver for PdiDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(PdiImage::open_with_hints(source, options.hints)?))
  }
}
