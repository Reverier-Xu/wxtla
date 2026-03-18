//! VHDX driver open flow.

use super::{DESCRIPTOR, image::VhdxImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct VhdxDriver;

impl VhdxDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<VhdxImage> {
    VhdxImage::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<VhdxImage> {
    VhdxImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for VhdxDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(VhdxImage::open_with_hints(source, hints)?))
  }
}
