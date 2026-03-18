//! 7z driver open flow.

use super::{DESCRIPTOR, archive::SevenZipArchive};
use crate::{
  DataSourceHandle, Result, SourceHints,
  archives::{Archive, ArchiveDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct SevenZipDriver;

impl SevenZipDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<SevenZipArchive> {
    SevenZipArchive::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<SevenZipArchive> {
    SevenZipArchive::open_with_hints(source, hints)
  }
}

impl ArchiveDriver for SevenZipDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Archive>> {
    Ok(Box::new(SevenZipArchive::open_with_hints(source, hints)?))
  }
}
