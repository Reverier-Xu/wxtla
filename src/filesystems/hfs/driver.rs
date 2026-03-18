//! HFS driver open flow.

use super::{DESCRIPTOR, filesystem::HfsFileSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  filesystems::{FileSystem, FileSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct HfsDriver;

impl HfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<HfsFileSystem> {
    HfsFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<HfsFileSystem> {
    HfsFileSystem::open_with_hints(source, hints)
  }
}

impl FileSystemDriver for HfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn FileSystem>> {
    Ok(Box::new(HfsFileSystem::open_with_hints(source, hints)?))
  }
}
