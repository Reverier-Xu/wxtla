//! APFS driver open flow.

use super::{DESCRIPTOR, container::ApfsContainer};
use crate::{ByteSourceHandle, DataSource, Driver, OpenOptions, Result};

/// Driver for Apple File System containers.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApfsDriver;

impl ApfsDriver {
  /// Create a new APFS driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open an APFS container from a byte source.
  pub fn open(source: ByteSourceHandle) -> Result<ApfsContainer> {
    ApfsContainer::open(source)
  }
}

impl Driver for ApfsDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    let container = ApfsContainer::open(source)?;
    if let Some(selector) = options.view {
      return container.open_view(&selector, options);
    }
    Ok(Box::new(container))
  }
}
