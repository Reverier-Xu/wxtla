//! NTFS driver open flow.

use super::{DESCRIPTOR, filesystem::NtfsFileSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  filesystems::{FileSystem, FileSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct NtfsDriver;

impl NtfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<NtfsFileSystem> {
    NtfsFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<NtfsFileSystem> {
    NtfsFileSystem::open_with_hints(source, hints)
  }
}

impl FileSystemDriver for NtfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn FileSystem>> {
    Ok(Box::new(NtfsFileSystem::open_with_hints(source, hints)?))
  }
}
