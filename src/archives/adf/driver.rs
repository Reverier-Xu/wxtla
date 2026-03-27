//! AD1 driver open flow.

use super::{DESCRIPTOR, archive::AdfArchive};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct AdfDriver;

impl AdfDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<AdfArchive> {
    AdfArchive::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<AdfArchive> {
    AdfArchive::open_with_hints(source, hints)
  }
}

impl Driver for AdfDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(AdfArchive::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
