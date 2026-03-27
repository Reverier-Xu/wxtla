use super::{DESCRIPTOR, filesystem::XfsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct XfsDriver;

impl XfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<XfsFileSystem> {
    XfsFileSystem::open(source)
  }
}

impl Driver for XfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(XfsFileSystem::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
