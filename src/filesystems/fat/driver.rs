//! FAT driver open flow.

use super::{DESCRIPTOR, filesystem::FatFileSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  filesystems::{FileSystem, FileSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct FatDriver;

impl FatDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<FatFileSystem> {
    FatFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<FatFileSystem> {
    FatFileSystem::open_with_hints(source, hints)
  }
}

impl FileSystemDriver for FatDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn FileSystem>> {
    Ok(Box::new(FatFileSystem::open_with_hints(source, hints)?))
  }
}
