//! HFS driver open flow.

use super::{DESCRIPTOR, filesystem::HfsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct HfsDriver;

impl HfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<HfsFileSystem> {
    HfsFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<HfsFileSystem> {
    HfsFileSystem::open_with_hints(source, hints)
  }
}
impl Driver for HfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(HfsFileSystem::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
