//! Internal volume-system helpers shared by concrete volume drivers.

use super::{VolumeRecord, VolumeRole};
use crate::{
  ByteSourceHandle, DataSourceFacets, DataViewId, DataViewKind, DataViewRecord, FormatDescriptor,
  Result,
};

/// Internal read-only volume map produced by a concrete volume-system parser.
#[allow(dead_code)]
pub(crate) trait VolumeSystem: Send + Sync {
  /// Return the format descriptor for this opened volume system.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the volume-system block size in bytes.
  fn block_size(&self) -> u32;

  /// Return the discovered volume records.
  fn volumes(&self) -> &[VolumeRecord];

  /// Return a volume record by index.
  fn volume(&self, index: usize) -> Option<&VolumeRecord> {
    self.volumes().get(index)
  }

  /// Open the logical byte range corresponding to a volume.
  fn open_volume(&self, index: usize) -> Result<ByteSourceHandle>;
}

macro_rules! impl_volume_system_data_source {
  ($ty:ty) => {
    impl crate::DataSource for $ty {
      fn descriptor(&self) -> crate::FormatDescriptor {
        crate::volumes::driver::VolumeSystem::descriptor(self)
      }

      fn facets(&self) -> crate::DataSourceFacets {
        crate::DataSourceFacets::none().with_views()
      }

      fn views(&self) -> crate::Result<Vec<crate::DataViewRecord>> {
        Ok(
          crate::volumes::driver::VolumeSystem::volumes(self)
            .iter()
            .map(crate::volumes::driver::volume_record_to_view)
            .collect(),
        )
      }

      fn open_view(
        &self, selector: &crate::DataViewSelector<'_>, _options: crate::OpenOptions<'_>,
      ) -> crate::Result<Box<dyn crate::DataSource>> {
        let index = crate::volumes::driver::VolumeSystem::volumes(self)
          .iter()
          .position(|volume| {
            selector.matches(&crate::volumes::driver::volume_record_to_view(volume))
          })
          .ok_or_else(|| {
            crate::Error::not_found(format!(
              "{} child view was not found for selector {selector:?}",
              crate::volumes::driver::VolumeSystem::descriptor(self).id
            ))
          })?;
        Ok(Box::new(crate::ByteViewSource::new(
          crate::volumes::driver::VolumeSystem::descriptor(self),
          crate::volumes::driver::VolumeSystem::open_volume(self, index)?,
        )))
      }
    }
  };
}

pub(crate) use impl_volume_system_data_source;

pub(crate) fn volume_record_to_view(record: &VolumeRecord) -> DataViewRecord {
  let kind = match record.role {
    VolumeRole::Primary | VolumeRole::Logical => DataViewKind::Volume,
    VolumeRole::ExtendedContainer
    | VolumeRole::Protective
    | VolumeRole::Metadata
    | VolumeRole::Unknown => DataViewKind::Partition,
  };

  let mut view = DataViewRecord::new(
    DataViewId::from_u64(record.index as u64),
    kind,
    DataSourceFacets::bytes(),
  )
  .with_tag("index", record.index.to_string())
  .with_tag("byte_offset", record.span.byte_offset.to_string())
  .with_tag("byte_size", record.span.byte_size.to_string())
  .with_tag("role", format!("{:?}", record.role).to_lowercase());
  if let Some(name) = &record.name {
    view = view.with_name(name.clone());
  }
  view
}
