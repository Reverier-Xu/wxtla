//! Open MBR volume-system state.

use std::sync::Arc;

use super::{DESCRIPTOR, entry::MbrPartitionInfo};
use crate::{
  ByteSourceHandle, Error, Result, SliceDataSource,
  volumes::{VolumeRecord, VolumeSystem},
};

/// Open MBR volume system.
pub struct MbrVolumeSystem {
  source: ByteSourceHandle,
  bytes_per_sector: u32,
  disk_signature: u32,
  volumes: Vec<VolumeRecord>,
  partitions: Vec<MbrPartitionInfo>,
}

impl MbrVolumeSystem {
  /// Create a new open MBR volume system.
  pub fn new(
    source: ByteSourceHandle, bytes_per_sector: u32, disk_signature: u32,
    partitions: Vec<MbrPartitionInfo>,
  ) -> Self {
    let volumes = partitions
      .iter()
      .map(|partition| partition.record.clone())
      .collect();

    Self {
      source,
      bytes_per_sector,
      disk_signature,
      volumes,
      partitions,
    }
  }

  /// Return the MBR disk signature.
  pub fn disk_signature(&self) -> u32 {
    self.disk_signature
  }

  /// Return the parsed MBR partition metadata.
  pub fn partitions(&self) -> &[MbrPartitionInfo] {
    &self.partitions
  }

  /// Return the bytes-per-sector value used to map LBAs.
  pub fn bytes_per_sector(&self) -> u32 {
    self.bytes_per_sector
  }

  /// Return the volume-system block size in bytes.
  pub fn block_size(&self) -> u32 {
    self.bytes_per_sector
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
      .ok_or_else(|| Error::NotFound(format!("mbr volume index {index} is out of bounds")))?;
    let slice: ByteSourceHandle = Arc::new(SliceDataSource::new(
      self.source.clone(),
      volume.span.byte_offset,
      volume.span.byte_size,
    ));

    Ok(slice)
  }
}

impl VolumeSystem for MbrVolumeSystem {
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

crate::volumes::driver::impl_volume_system_data_source!(MbrVolumeSystem);
