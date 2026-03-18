//! Open BitLocker volume-system state.

use std::sync::Arc;

use super::{
  DESCRIPTOR,
  header::BitlockerVolumeHeader,
  metadata::{BitlockerMetadataBlockHeader, BitlockerMetadataHeader},
};
use crate::{
  DataSourceHandle, Error, Result, SliceDataSource,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan, VolumeSystem},
};

pub struct BitlockerVolumeSystem {
  source: DataSourceHandle,
  header: BitlockerVolumeHeader,
  metadata_block_header: BitlockerMetadataBlockHeader,
  metadata_header: BitlockerMetadataHeader,
  volumes: Vec<VolumeRecord>,
}

impl BitlockerVolumeSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, crate::SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: crate::SourceHints<'_>) -> Result<Self> {
    let header = BitlockerVolumeHeader::from_bytes(&source.read_bytes_at(0, 512)?)?;
    let metadata_offset = header
      .metadata_offsets
      .iter()
      .copied()
      .find(|offset| *offset != 0)
      .ok_or_else(|| Error::InvalidFormat("bitlocker metadata offsets are missing".to_string()))?;
    let block_header =
      BitlockerMetadataBlockHeader::from_bytes(&source.read_bytes_at(metadata_offset, 64)?)?;
    let metadata_header =
      BitlockerMetadataHeader::from_bytes(&source.read_bytes_at(metadata_offset + 64, 48)?)?;
    let volume_size = source.size()?;
    let volumes = vec![
      VolumeRecord::new(0, VolumeSpan::new(0, volume_size), VolumeRole::Primary)
        .with_name("bitlocker"),
    ];

    Ok(Self {
      source,
      header,
      metadata_block_header: block_header,
      metadata_header,
      volumes,
    })
  }

  pub fn header(&self) -> &BitlockerVolumeHeader {
    &self.header
  }

  pub fn metadata_block_header(&self) -> &BitlockerMetadataBlockHeader {
    &self.metadata_block_header
  }

  pub fn metadata_header(&self) -> &BitlockerMetadataHeader {
    &self.metadata_header
  }
}

impl VolumeSystem for BitlockerVolumeSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn block_size(&self) -> u32 {
    u32::from(self.header.bytes_per_sector)
  }

  fn volumes(&self) -> &[VolumeRecord] {
    &self.volumes
  }

  fn open_volume(&self, index: usize) -> Result<DataSourceHandle> {
    let volume = self
      .volumes
      .get(index)
      .ok_or_else(|| Error::NotFound(format!("bitlocker volume index {index} is out of bounds")))?;
    Ok(Arc::new(SliceDataSource::new(
      self.source.clone(),
      volume.span.byte_offset,
      volume.span.byte_size,
    )) as DataSourceHandle)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::DataSource;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = usize::try_from(offset)
        .map_err(|_| Error::InvalidRange("test read offset is too large".to_string()))?;
      if offset >= self.data.len() {
        return Ok(0);
      }
      let read = buf.len().min(self.data.len() - offset);
      buf[..read].copy_from_slice(&self.data[offset..offset + read]);
      Ok(read)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.data.len() as u64)
    }
  }

  fn synthetic_volume() -> Vec<u8> {
    let mut data = vec![0u8; 0x3000];
    let volume_size = data.len() as u64;
    data[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    data[3..11].copy_from_slice(b"-FVE-FS-");
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[13] = 8;
    data[176..184].copy_from_slice(&0x1000u64.to_le_bytes());
    data[184..192].copy_from_slice(&0x1800u64.to_le_bytes());
    data[192..200].copy_from_slice(&0x2000u64.to_le_bytes());
    data[510..512].copy_from_slice(&[0x55, 0xAA]);

    data[0x1000..0x1008].copy_from_slice(b"-FVE-FS-");
    data[0x100A..0x100C].copy_from_slice(&2u16.to_le_bytes());
    data[0x1010..0x1018].copy_from_slice(&volume_size.to_le_bytes());
    data[0x101C..0x1020].copy_from_slice(&16u32.to_le_bytes());
    data[0x1020..0x1028].copy_from_slice(&0x1000u64.to_le_bytes());
    data[0x1028..0x1030].copy_from_slice(&0x1800u64.to_le_bytes());
    data[0x1030..0x1038].copy_from_slice(&0x2000u64.to_le_bytes());
    data[0x1038..0x1040].copy_from_slice(&0x4000u64.to_le_bytes());

    data[0x1040..0x1044].copy_from_slice(&48u32.to_le_bytes());
    data[0x1044..0x1048].copy_from_slice(&1u32.to_le_bytes());
    data[0x1048..0x104C].copy_from_slice(&48u32.to_le_bytes());
    data[0x1064..0x1068].copy_from_slice(&0x8000u32.to_le_bytes());

    data
  }

  #[test]
  fn opens_synthetic_bitlocker_volume() {
    let source = Arc::new(MemDataSource {
      data: synthetic_volume(),
    }) as DataSourceHandle;
    let system = BitlockerVolumeSystem::open(source.clone()).unwrap();

    assert_eq!(system.block_size(), 512);
    assert_eq!(system.volumes().len(), 1);
    assert_eq!(system.metadata_block_header().version, 2);
    assert_eq!(system.metadata_header().encryption_method, 0x8000);
    assert_eq!(
      system.open_volume(0).unwrap().size().unwrap(),
      source.size().unwrap()
    );
  }

  #[test]
  fn rejects_missing_metadata_blocks() {
    let mut data = synthetic_volume();
    data[176..200].fill(0);
    let result = BitlockerVolumeSystem::open(Arc::new(MemDataSource { data }) as DataSourceHandle);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
