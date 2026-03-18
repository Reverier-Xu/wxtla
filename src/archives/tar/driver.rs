//! TAR driver open flow.

use super::{DESCRIPTOR, archive::TarArchive};
use crate::{
  DataSourceHandle, Result, SourceHints,
  archives::{Archive, ArchiveDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct TarDriver;

impl TarDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<TarArchive> {
    TarArchive::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<TarArchive> {
    TarArchive::open_with_hints(source, hints)
  }
}

impl ArchiveDriver for TarDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Archive>> {
    Ok(Box::new(TarArchive::open_with_hints(source, hints)?))
  }
}
