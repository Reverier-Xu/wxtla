//! ext-family driver open flow.

use super::{DESCRIPTOR, filesystem::ExtFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct ExtDriver;

impl ExtDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<ExtFileSystem> {
    ExtFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<ExtFileSystem> {
    ExtFileSystem::open_with_hints(source, hints)
  }
}
impl Driver for ExtDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(ExtFileSystem::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
