//! VHD driver open flow.

use super::{DESCRIPTOR, image::VhdImage};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

#[derive(Debug, Default, Clone, Copy)]
pub struct VhdDriver;

impl VhdDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: ByteSourceHandle) -> Result<VhdImage> {
    VhdImage::open(source)
  }
}

impl Driver for VhdDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(VhdImage::open_with_hints(source, options.hints)?))
  }
}
