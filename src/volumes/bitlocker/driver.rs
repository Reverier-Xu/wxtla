//! BitLocker driver open flow.

use super::{DESCRIPTOR, system::BitlockerVolumeSystem};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result, SourceHints};

#[derive(Debug, Default, Clone, Copy)]
pub struct BitlockerDriver;

impl BitlockerDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<BitlockerVolumeSystem> {
    BitlockerVolumeSystem::open(source)
  }

  pub fn open_with_hints(
    source: ByteSourceHandle, hints: SourceHints<'_>,
  ) -> Result<BitlockerVolumeSystem> {
    BitlockerVolumeSystem::open_with_hints(source, hints)
  }
}
impl Driver for BitlockerDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(BitlockerVolumeSystem::open_with_hints(
      source,
      options.hints,
    )?))
  }
}
