use std::{
  cmp::min,
  collections::HashMap,
  sync::{Arc, Mutex, OnceLock},
};

use super::{
  DESCRIPTOR,
  model::{
    LvmChunk, LvmLogicalVolumeInfo, MetadataLogicalVolume, PhysicalVolumeLabel,
    build_logical_volume_info, logical_volume_size,
  },
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, Error, Result,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan, VolumeSystem},
};

pub struct LvmVolumeSystem {
  source: ByteSourceHandle,
  label: PhysicalVolumeLabel,
  current_pv_name: String,
  current_pv_pe_start: Option<u64>,
  extent_size_bytes: u64,
  vg_name: String,
  logical_volumes: Vec<MetadataLogicalVolume>,
  logical_volume_infos: OnceLock<Vec<LvmLogicalVolumeInfo>>,
  volume_sources: Mutex<HashMap<usize, ByteSourceHandle>>,
  volumes: Vec<VolumeRecord>,
}

impl LvmVolumeSystem {
  pub(super) fn new(
    source: ByteSourceHandle, label: PhysicalVolumeLabel, current_pv_name: String,
    current_pv_pe_start: Option<u64>, vg_name: String, extent_size_bytes: u64,
    logical_volumes: Vec<MetadataLogicalVolume>,
  ) -> Result<Self> {
    let mut volumes = Vec::with_capacity(logical_volumes.len());
    for (index, logical_volume) in logical_volumes.iter().enumerate() {
      let size = logical_volume_size(
        &label,
        extent_size_bytes,
        &current_pv_name,
        current_pv_pe_start,
        logical_volume,
      )?;
      volumes.push(
        VolumeRecord::new(index, VolumeSpan::new(0, size), VolumeRole::Logical)
          .with_name(logical_volume.name.clone()),
      );
    }

    Ok(Self {
      source,
      label,
      current_pv_name,
      current_pv_pe_start,
      extent_size_bytes,
      vg_name,
      logical_volumes,
      logical_volume_infos: OnceLock::new(),
      volume_sources: Mutex::new(HashMap::new()),
      volumes,
    })
  }

  pub fn vg_name(&self) -> &str {
    &self.vg_name
  }

  pub fn logical_volumes_info(&self) -> &[LvmLogicalVolumeInfo] {
    self.logical_volume_infos.get_or_init(|| {
      self
        .logical_volumes
        .iter()
        .map(|logical_volume| {
          build_logical_volume_info(
            &self.label,
            self.extent_size_bytes,
            &self.current_pv_name,
            self.current_pv_pe_start,
            logical_volume,
          )
          .expect("validated when the LVM volume system was created")
        })
        .collect()
    })
  }

  pub fn block_size(&self) -> u32 {
    u32::try_from(self.extent_size_bytes).unwrap_or(512)
  }

  pub fn volumes(&self) -> &[VolumeRecord] {
    &self.volumes
  }

  pub fn open_volume(&self, index: usize) -> Result<ByteSourceHandle> {
    if let Some(cached) = self
      .volume_sources
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&index)
      .cloned()
    {
      return Ok(cached);
    }

    let logical_volume = self.logical_volumes.get(index).ok_or_else(|| {
      Error::NotFound(format!("lvm logical volume index {index} is out of bounds"))
    })?;
    let (chunks, size) = if let Some(infos) = self.logical_volume_infos.get() {
      let info = infos.get(index).ok_or_else(|| {
        Error::NotFound(format!("lvm logical volume index {index} is out of bounds"))
      })?;
      (info.chunks.clone(), info.size)
    } else {
      let info = build_logical_volume_info(
        &self.label,
        self.extent_size_bytes,
        &self.current_pv_name,
        self.current_pv_pe_start,
        logical_volume,
      )?;
      (info.chunks, info.size)
    };
    let built = Arc::new(LvmLogicalVolumeSource {
      source: self.source.clone(),
      chunks,
      size,
    }) as ByteSourceHandle;

    let mut cached = self
      .volume_sources
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cached.get(&index).cloned() {
      return Ok(existing);
    }
    cached.insert(index, built.clone());

    Ok(built)
  }
}

impl VolumeSystem for LvmVolumeSystem {
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

struct LvmLogicalVolumeSource {
  source: ByteSourceHandle,
  chunks: Vec<LvmChunk>,
  size: u64,
}

impl LvmLogicalVolumeSource {
  fn chunk_index_for_offset(&self, offset: u64) -> Option<usize> {
    let index = self
      .chunks
      .partition_point(|chunk| chunk.logical_offset <= offset)
      .checked_sub(1)?;
    let chunk = self.chunks.get(index)?;
    let chunk_end = chunk.logical_offset.checked_add(chunk.size)?;

    (offset < chunk_end).then_some(index)
  }

  fn next_chunk_start(&self, offset: u64) -> u64 {
    self
      .chunks
      .get(
        self
          .chunks
          .partition_point(|chunk| chunk.logical_offset <= offset),
      )
      .map_or(self.size, |chunk| chunk.logical_offset)
  }
}

impl ByteSource for LvmLogicalVolumeSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.size || buf.is_empty() {
      return Ok(0);
    }

    let mut total = min(buf.len() as u64, self.size - offset) as usize;
    let mut out_offset = 0usize;
    let mut current = offset;
    while total > 0 {
      let Some(chunk_index) = self.chunk_index_for_offset(current) else {
        let next_start = self.next_chunk_start(current);
        let span = min(total as u64, next_start.saturating_sub(current)) as usize;
        buf[out_offset..out_offset + span].fill(0);
        out_offset += span;
        current += span as u64;
        total -= span;
        continue;
      };

      let chunk = self.chunks[chunk_index];
      let chunk_inner = current - chunk.logical_offset;
      let span = min(total as u64, chunk.size - chunk_inner) as usize;
      if let Some(physical_offset) = chunk.physical_offset {
        self.source.read_exact_at(
          physical_offset + chunk_inner,
          &mut buf[out_offset..out_offset + span],
        )?;
      } else {
        buf[out_offset..out_offset + span].fill(0);
      }
      out_offset += span;
      current += span as u64;
      total -= span;
    }

    Ok(out_offset)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    "volume.lvm.logical"
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::BytesDataSource;

  #[test]
  fn chunk_lookup_handles_sparse_gaps_with_binary_search() {
    let source = LvmLogicalVolumeSource {
      source: Arc::new(BytesDataSource::new(vec![0u8; 32])),
      chunks: vec![
        LvmChunk {
          logical_offset: 0,
          size: 4,
          physical_offset: Some(0),
        },
        LvmChunk {
          logical_offset: 8,
          size: 4,
          physical_offset: Some(8),
        },
      ],
      size: 12,
    };

    assert_eq!(source.chunk_index_for_offset(0), Some(0));
    assert_eq!(source.chunk_index_for_offset(3), Some(0));
    assert_eq!(source.chunk_index_for_offset(4), None);
    assert_eq!(source.next_chunk_start(4), 8);
    assert_eq!(source.chunk_index_for_offset(9), Some(1));
  }

  #[test]
  fn reads_fragmented_logical_volumes_across_sparse_gaps() {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(b"ABCD");
    bytes[8..12].copy_from_slice(b"WXYZ");
    let source = LvmLogicalVolumeSource {
      source: Arc::new(BytesDataSource::new(bytes)),
      chunks: vec![
        LvmChunk {
          logical_offset: 0,
          size: 4,
          physical_offset: Some(0),
        },
        LvmChunk {
          logical_offset: 8,
          size: 4,
          physical_offset: Some(8),
        },
      ],
      size: 12,
    };
    let mut out = [0u8; 8];

    let read = source.read_at(2, &mut out).unwrap();

    assert_eq!(read, out.len());
    assert_eq!(&out, b"CD\0\0\0\0WX");
  }
}

crate::volumes::driver::impl_volume_system_data_source!(LvmVolumeSystem);
