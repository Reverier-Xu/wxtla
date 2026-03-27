//! Open GPT volume-system state.

use std::sync::Arc;

use super::{DESCRIPTOR, entry::GptPartitionInfo, guid::GptGuid, header::GptHeader};
use crate::{
  ByteSourceHandle, Error, Result, SliceDataSource,
  volumes::{VolumeRecord, VolumeSystem},
};

/// Which GPT header was used to open the volume system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptHeaderLocation {
  /// The primary header at LBA 1.
  Primary,
  /// The backup header at the end of the device.
  Backup,
}

/// Open GPT volume system.
pub struct GptVolumeSystem {
  source: ByteSourceHandle,
  block_size: u32,
  active_header_location: GptHeaderLocation,
  active_header: GptHeader,
  primary_header: Option<GptHeader>,
  backup_header: Option<GptHeader>,
  volumes: Vec<VolumeRecord>,
  partitions: Vec<GptPartitionInfo>,
}

impl GptVolumeSystem {
  /// Create a new open GPT volume system.
  pub fn new(
    source: ByteSourceHandle, block_size: u32, active_header_location: GptHeaderLocation,
    primary_header: Option<GptHeader>, backup_header: Option<GptHeader>,
    partitions: Vec<GptPartitionInfo>,
  ) -> Result<Self> {
    let volumes = partitions
      .iter()
      .map(|partition| partition.record.clone())
      .collect();
    let active_header = match active_header_location {
      GptHeaderLocation::Primary => primary_header
        .clone()
        .ok_or_else(|| Error::InvalidFormat("gpt active primary header is missing".to_string()))?,
      GptHeaderLocation::Backup => backup_header
        .clone()
        .ok_or_else(|| Error::InvalidFormat("gpt active backup header is missing".to_string()))?,
    };

    Ok(Self {
      source,
      block_size,
      active_header_location,
      active_header,
      primary_header,
      backup_header,
      volumes,
      partitions,
    })
  }

  /// Return which header was used to open the volume system.
  pub fn active_header_location(&self) -> GptHeaderLocation {
    self.active_header_location
  }

  /// Return the active header used for parsing.
  pub fn header(&self) -> &GptHeader {
    &self.active_header
  }

  /// Return the parsed primary header.
  pub fn primary_header(&self) -> Option<&GptHeader> {
    self.primary_header.as_ref()
  }

  /// Return the parsed backup header.
  pub fn backup_header(&self) -> Option<&GptHeader> {
    self.backup_header.as_ref()
  }

  /// Return the GPT disk GUID.
  pub fn disk_guid(&self) -> GptGuid {
    self.header().disk_guid
  }

  /// Return the volume-system block size in bytes.
  pub fn block_size(&self) -> u32 {
    self.block_size
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
      .ok_or_else(|| Error::NotFound(format!("gpt volume index {index} is out of bounds")))?;
    Ok(Arc::new(SliceDataSource::new(
      self.source.clone(),
      volume.span.byte_offset,
      volume.span.byte_size,
    )))
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
    self.block_size()
  }

  fn volumes(&self) -> &[VolumeRecord] {
    self.volumes()
  }

  fn open_volume(&self, index: usize) -> Result<ByteSourceHandle> {
    self.open_volume(index)
  }
}

crate::volumes::driver::impl_volume_system_data_source!(GptVolumeSystem);
