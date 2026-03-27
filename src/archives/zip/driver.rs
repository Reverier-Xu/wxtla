//! ZIP driver open flow.

use super::{DESCRIPTOR, archive::ZipArchive};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct ZipDriver;

impl ZipDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<ZipArchive> {
    ZipArchive::open(source)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<ZipArchive> {
    ZipArchive::open_with_hints(source, hints)
  }
}

impl Driver for ZipDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(ZipArchive::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
