use super::{DESCRIPTOR, filesystem::Jffs2FileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct Jffs2Driver;

impl Jffs2Driver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<Jffs2FileSystem> {
    Jffs2FileSystem::open(source)
  }
}

impl Driver for Jffs2Driver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(Jffs2FileSystem::open(source)?))
  }
}
