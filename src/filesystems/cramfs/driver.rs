use super::{DESCRIPTOR, filesystem::CramFsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct CramFsDriver;

impl CramFsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<CramFsFileSystem> {
    CramFsFileSystem::open(source)
  }
}

impl Driver for CramFsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(CramFsFileSystem::open(source)?))
  }
}
