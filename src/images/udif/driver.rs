//! UDIF driver open flow.

use super::{DESCRIPTOR, image::UdifImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct UdifDriver;

impl UdifDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<UdifImage> {
    UdifImage::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<UdifImage> {
    UdifImage::open_with_hints(source, hints)
  }
}

impl Driver for UdifDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(UdifImage::open_with_hints(source, options.hints)?))
  }
}
