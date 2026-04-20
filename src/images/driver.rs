//! Internal image helpers shared by concrete image drivers.

use crate::{ByteSource, DataSource, FormatDescriptor};

/// Internal read-only logical image surface exposed by a concrete image type.
#[allow(dead_code)]
pub(crate) trait Image: ByteSource {
  /// Return the format descriptor for this opened image.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the logical sector size when the format defines one.
  fn logical_sector_size(&self) -> Option<u32> {
    None
  }

  /// Return the physical sector size when the format defines one.
  fn physical_sector_size(&self) -> Option<u32> {
    self.logical_sector_size()
  }

  /// Return `true` when the image can expose holes or zero-runs.
  fn is_sparse(&self) -> bool {
    false
  }

  /// Return `true` when the image depends on one or more backing images.
  fn has_backing_chain(&self) -> bool {
    false
  }

  /// Enumerate child views exposed by the image.
  fn views(&self) -> crate::Result<Vec<crate::DataViewRecord>> {
    Ok(Vec::new())
  }

  /// Open a child view exposed by the image.
  fn open_view(
    &self, selector: &crate::DataViewSelector<'_>, options: crate::OpenOptions<'_>,
  ) -> crate::Result<Box<dyn DataSource>> {
    let _ = (selector, options);
    Err(crate::Error::unsupported(format!(
      "{} does not expose image child views",
      self.descriptor().id
    )))
  }
}

macro_rules! impl_image_data_source {
  ($ty:ty) => {
    impl crate::DataSource for $ty {
      fn descriptor(&self) -> crate::FormatDescriptor {
        crate::images::driver::Image::descriptor(self)
      }

      fn facets(&self) -> crate::DataSourceFacets {
        let facets = crate::DataSourceFacets::bytes();
        if crate::images::driver::Image::views(self)
          .map(|views| !views.is_empty())
          .unwrap_or(false)
        {
          facets.with_views()
        } else {
          facets
        }
      }

      fn byte_source(&self) -> Option<&dyn crate::ByteSource> {
        Some(self)
      }

      fn views(&self) -> crate::Result<Vec<crate::DataViewRecord>> {
        crate::images::driver::Image::views(self)
      }

      fn open_view(
        &self, selector: &crate::DataViewSelector<'_>, options: crate::OpenOptions<'_>,
      ) -> crate::Result<Box<dyn crate::DataSource>> {
        crate::images::driver::Image::open_view(self, selector, options)
      }
    }
  };
}

pub(crate) use impl_image_data_source;
