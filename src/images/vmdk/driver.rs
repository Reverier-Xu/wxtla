//! VMDK driver open flow.

use super::{DESCRIPTOR, image::VmdkImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct VmdkDriver;

impl VmdkDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<VmdkImage> {
    VmdkImage::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<VmdkImage> {
    VmdkImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for VmdkDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(VmdkImage::open_with_hints(source, hints)?))
  }
}
