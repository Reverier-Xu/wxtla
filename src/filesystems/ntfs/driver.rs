//! NTFS driver open flow.

use super::{DESCRIPTOR, filesystem::NtfsFileSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct NtfsDriver;

impl NtfsDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<NtfsFileSystem> {
    NtfsFileSystem::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<NtfsFileSystem> {
    NtfsFileSystem::open_with_hints(source, hints)
  }
}
impl Driver for NtfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(NtfsFileSystem::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
