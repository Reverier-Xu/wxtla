//! UDIF driver open flow.

use super::{DESCRIPTOR, image::UdifImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct UdifDriver;

impl UdifDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<UdifImage> {
    UdifImage::open(source)
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<UdifImage> {
    UdifImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for UdifDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(UdifImage::open_with_hints(source, hints)?))
  }
}
