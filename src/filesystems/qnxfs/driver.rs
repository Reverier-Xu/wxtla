use super::{DESCRIPTOR, filesystem::QnxFsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct QnxFsDriver;

impl QnxFsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<QnxFsFileSystem> {
    QnxFsFileSystem::open(source)
  }
}

impl Driver for QnxFsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(QnxFsFileSystem::open(source)?))
  }
}
