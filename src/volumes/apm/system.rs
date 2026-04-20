//! Open APM volume-system state.

use std::sync::Arc;

use super::{DESCRIPTOR, descriptor::ApmDriverDescriptor, entry::ApmPartitionInfo};
use crate::{
  ByteSourceHandle, Error, Result, SliceDataSource,
  volumes::{VolumeRecord, VolumeSystem},
};

/// Open APM volume system.
pub struct ApmVolumeSystem {
  source: ByteSourceHandle,
  driver_descriptor: ApmDriverDescriptor,
  volumes: Vec<VolumeRecord>,
  partitions: Vec<ApmPartitionInfo>,
}

impl ApmVolumeSystem {
  /// Create a new open APM volume system.
  pub fn new(
    source: ByteSourceHandle, driver_descriptor: ApmDriverDescriptor,
    partitions: Vec<ApmPartitionInfo>,
  ) -> Self {
    let volumes = partitions
      .iter()
      .map(|partition| partition.record.clone())
      .collect();

    Self {
      source,
      driver_descriptor,
      volumes,
      partitions,
    }
  }

  /// Return the parsed driver descriptor block.
  pub fn driver_descriptor(&self) -> &ApmDriverDescriptor {
    &self.driver_descriptor
  }

  /// Return the parsed APM partition metadata.
  pub fn partitions(&self) -> &[ApmPartitionInfo] {
    &self.partitions
  }

  /// Return the volume-system block size in bytes.
  pub fn block_size(&self) -> u32 {
    u32::from(self.driver_descriptor.block_size)
  }

  /// Return the discovered volume records.
  pub fn volumes(&self) -> &[VolumeRecord] {
    &self.volumes
  }

  /// Open the logical byte range corresponding to a volume.
  pub fn open_volume(&self, index: usize) -> Result<ByteSourceHandle> {
    let volume = self
      .volumes
      .get(index)
      .ok_or_else(|| Error::not_found(format!("apm volume index {index} is out of bounds")))?;
    Ok(Arc::new(SliceDataSource::new(
      self.source.clone(),
      volume.span.byte_offset,
      volume.span.byte_size,
    )))
  }
}

impl VolumeSystem for ApmVolumeSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn block_size(&self) -> u32 {
    self.block_size()
  }

  fn volumes(&self) -> &[VolumeRecord] {
    self.volumes()
  }

  fn open_volume(&self, index: usize) -> Result<ByteSourceHandle> {
    self.open_volume(index)
  }
}

crate::volumes::driver::impl_volume_system_data_source!(ApmVolumeSystem);
