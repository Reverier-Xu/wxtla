//! PDI driver open flow.

use super::{DESCRIPTOR, image::PdiImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct PdiDriver;

impl PdiDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<PdiImage> {
    PdiImage::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<PdiImage> {
    PdiImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for PdiDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(PdiImage::open_with_hints(source, hints)?))
  }
}
