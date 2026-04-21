use super::{DESCRIPTOR, filesystem::SquashFsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct SquashFsDriver;

impl SquashFsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<SquashFsFileSystem> {
    SquashFsFileSystem::open(source)
  }
}

impl Driver for SquashFsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(SquashFsFileSystem::open(source)?))
  }
}
