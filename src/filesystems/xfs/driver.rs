use super::{DESCRIPTOR, filesystem::XfsFileSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  filesystems::{FileSystem, FileSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct XfsDriver;

impl XfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<XfsFileSystem> {
    XfsFileSystem::open(source)
  }
}

impl FileSystemDriver for XfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn FileSystem>> {
    Ok(Box::new(XfsFileSystem::open_with_hints(source, hints)?))
  }
}
