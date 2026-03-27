//! ReFS driver open flow.

use super::{DESCRIPTOR, filesystem::RefsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct RefsDriver;

impl RefsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<RefsFileSystem> {
    RefsFileSystem::open(source)
  }
}

impl Driver for RefsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(RefsFileSystem::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
