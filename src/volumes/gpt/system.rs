//! Open GPT volume-system state.

use std::sync::Arc;

use super::{DESCRIPTOR, entry::GptPartitionInfo, guid::GptGuid, header::GptHeader};
use crate::{
  DataSourceHandle, Error, Result, SliceDataSource,
  volumes::{VolumeRecord, VolumeSystem},
};

/// Open GPT volume system.
pub struct GptVolumeSystem {
  source: DataSourceHandle,
  block_size: u32,
  header: GptHeader,
  volumes: Vec<VolumeRecord>,
  partitions: Vec<GptPartitionInfo>,
}

impl GptVolumeSystem {
  /// Create a new open GPT volume system.
  pub fn new(
    source: DataSourceHandle, block_size: u32, header: GptHeader, partitions: Vec<GptPartitionInfo>,
  ) -> Self {
    let volumes = partitions
      .iter()
      .map(|partition| partition.record.clone())
      .collect();

    Self {
      source,
      block_size,
      header,
      volumes,
      partitions,
    }
  }

  /// Return the parsed primary header.
  pub fn header(&self) -> &GptHeader {
    &self.header
  }

  /// Return the GPT disk GUID.
  pub fn disk_guid(&self) -> GptGuid {
    self.header.disk_guid
  }

  /// Return the parsed GPT partition metadata.
  pub fn partitions(&self) -> &[GptPartitionInfo] {
    &self.partitions
  }
}

impl VolumeSystem for GptVolumeSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn block_size(&self) -> u32 {
    self.block_size
  }

  fn volumes(&self) -> &[VolumeRecord] {
    &self.volumes
  }

  fn open_volume(&self, index: usize) -> Result<DataSourceHandle> {
    let volume = self
      .volumes
      .get(index)
      .ok_or_else(|| Error::NotFound(format!("gpt volume index {index} is out of bounds")))?;
    Ok(Arc::new(SliceDataSource::new(
      self.source.clone(),
      volume.span.byte_offset,
      volume.span.byte_size,
    )))
  }
}
