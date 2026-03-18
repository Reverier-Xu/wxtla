//! BitLocker driver open flow.

use super::{DESCRIPTOR, system::BitlockerVolumeSystem};
use crate::{
  DataSourceHandle, Result, SourceHints,
  volumes::{VolumeSystem, VolumeSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct BitlockerDriver;

impl BitlockerDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<BitlockerVolumeSystem> {
    BitlockerVolumeSystem::open(source)
  }

  pub fn open_with_hints(
    source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<BitlockerVolumeSystem> {
    BitlockerVolumeSystem::open_with_hints(source, hints)
  }
}

impl VolumeSystemDriver for BitlockerDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<Box<dyn VolumeSystem>> {
    Ok(Box::new(BitlockerVolumeSystem::open_with_hints(
      source, hints,
    )?))
  }
}
