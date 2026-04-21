use super::{DESCRIPTOR, filesystem::VmfsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct VmfsDriver;

impl VmfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<VmfsFileSystem> {
    VmfsFileSystem::open(source)
  }
}

impl Driver for VmfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(VmfsFileSystem::open(source)?))
  }
}
