//! RAR driver open flow.

use super::{DESCRIPTOR, archive::RarArchive};
use crate::{
  DataSourceHandle, Result, SourceHints,
  archives::{Archive, ArchiveDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct RarDriver;

impl RarDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<RarArchive> {
    RarArchive::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<RarArchive> {
    RarArchive::open_with_hints(source, hints)
  }
}

impl ArchiveDriver for RarDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Archive>> {
    Ok(Box::new(RarArchive::open_with_hints(source, hints)?))
  }
}
