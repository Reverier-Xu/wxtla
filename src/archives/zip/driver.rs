//! ZIP driver open flow.

use super::{DESCRIPTOR, archive::ZipArchive};
use crate::{
  DataSourceHandle, Result, SourceHints,
  archives::{Archive, ArchiveDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct ZipDriver;

impl ZipDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<ZipArchive> {
    ZipArchive::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<ZipArchive> {
    ZipArchive::open_with_hints(source, hints)
  }
}

impl ArchiveDriver for ZipDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Archive>> {
    Ok(Box::new(ZipArchive::open_with_hints(source, hints)?))
  }
}
