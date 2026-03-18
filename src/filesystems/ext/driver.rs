//! ext-family driver open flow.

use super::{DESCRIPTOR, filesystem::ExtFileSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  filesystems::{FileSystem, FileSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct ExtDriver;

impl ExtDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<ExtFileSystem> {
    ExtFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<ExtFileSystem> {
    ExtFileSystem::open_with_hints(source, hints)
  }
}

impl FileSystemDriver for ExtDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn FileSystem>> {
    Ok(Box::new(ExtFileSystem::open_with_hints(source, hints)?))
  }
}
