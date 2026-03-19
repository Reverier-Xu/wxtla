//! ReFS driver open flow.

use super::{DESCRIPTOR, filesystem::RefsFileSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  filesystems::{FileSystem, FileSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct RefsDriver;

impl RefsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<RefsFileSystem> {
    RefsFileSystem::open(source)
  }
}

impl FileSystemDriver for RefsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn FileSystem>> {
    Ok(Box::new(RefsFileSystem::open_with_hints(source, hints)?))
  }
}
