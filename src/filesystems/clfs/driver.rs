use super::{DESCRIPTOR, filesystem::ClfsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct ClfsDriver;

impl ClfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<ClfsFileSystem> {
    ClfsFileSystem::open(source)
  }
}

impl Driver for ClfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(ClfsFileSystem::open(source)?))
  }
}
