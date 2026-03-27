//! 7z driver open flow.

use super::{DESCRIPTOR, archive::SevenZipArchive};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct SevenZipDriver;

impl SevenZipDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<SevenZipArchive> {
    SevenZipArchive::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<SevenZipArchive> {
    SevenZipArchive::open_with_hints(source, hints)
  }
}
impl Driver for SevenZipDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(SevenZipArchive::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
