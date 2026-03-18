//! AD1 driver open flow.

use super::{DESCRIPTOR, archive::AdfArchive};
use crate::{
  DataSourceHandle, Result, SourceHints,
  archives::{Archive, ArchiveDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct AdfDriver;

impl AdfDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<AdfArchive> {
    AdfArchive::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<AdfArchive> {
    AdfArchive::open_with_hints(source, hints)
  }
}

impl ArchiveDriver for AdfDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Archive>> {
    Ok(Box::new(AdfArchive::open_with_hints(source, hints)?))
  }
}
