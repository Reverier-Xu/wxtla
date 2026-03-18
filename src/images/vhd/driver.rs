//! VHD driver open flow.

use super::{DESCRIPTOR, image::VhdImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct VhdDriver;

impl VhdDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<VhdImage> {
    VhdImage::open(source)
  }
}

impl ImageDriver for VhdDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(VhdImage::open_with_hints(source, hints)?))
  }
}
