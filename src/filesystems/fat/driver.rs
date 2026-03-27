//! FAT driver open flow.

use super::{DESCRIPTOR, filesystem::FatFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct FatDriver;

impl FatDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<FatFileSystem> {
    FatFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<FatFileSystem> {
    FatFileSystem::open_with_hints(source, hints)
  }
}
impl Driver for FatDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(FatFileSystem::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
