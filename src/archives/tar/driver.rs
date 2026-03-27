//! TAR driver open flow.

use super::{DESCRIPTOR, archive::TarArchive};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct TarDriver;

impl TarDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<TarArchive> {
    TarArchive::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<TarArchive> {
    TarArchive::open_with_hints(source, hints)
  }
}

impl Driver for TarDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(TarArchive::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
