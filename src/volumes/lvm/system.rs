use std::{cmp::min, sync::Arc};

use super::{
  DESCRIPTOR,
  model::{LvmChunk, LvmLogicalVolumeInfo},
};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, Error, Result,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan, VolumeSystem},
};

pub struct LvmVolumeSystem {
  source: DataSourceHandle,
  extent_size_bytes: u64,
  vg_name: String,
  logical_volumes: Vec<LvmLogicalVolumeInfo>,
  volumes: Vec<VolumeRecord>,
}

impl LvmVolumeSystem {
  pub fn new(
    source: DataSourceHandle, vg_name: String, extent_size_bytes: u64,
    logical_volumes: Vec<LvmLogicalVolumeInfo>,
  ) -> Self {
    let volumes = logical_volumes
      .iter()
      .enumerate()
      .map(|(index, logical_volume)| {
        VolumeRecord::new(
          index,
          VolumeSpan::new(0, logical_volume.size),
          VolumeRole::Logical,
        )
        .with_name(logical_volume.name.clone())
      })
      .collect();

    Self {
      source,
      extent_size_bytes,
      vg_name,
      logical_volumes,
      volumes,
    }
  }

  pub fn vg_name(&self) -> &str {
    &self.vg_name
  }

  pub fn logical_volumes_info(&self) -> &[LvmLogicalVolumeInfo] {
    &self.logical_volumes
  }
}

impl VolumeSystem for LvmVolumeSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn block_size(&self) -> u32 {
    u32::try_from(self.extent_size_bytes).unwrap_or(512)
  }

  fn volumes(&self) -> &[VolumeRecord] {
    &self.volumes
  }

  fn open_volume(&self, index: usize) -> Result<DataSourceHandle> {
    let logical_volume = self.logical_volumes.get(index).ok_or_else(|| {
      Error::NotFound(format!("lvm logical volume index {index} is out of bounds"))
    })?;
    Ok(Arc::new(LvmLogicalVolumeSource {
      source: self.source.clone(),
      chunks: logical_volume.chunks.clone(),
      size: logical_volume.size,
    }) as DataSourceHandle)
  }
}

struct LvmLogicalVolumeSource {
  source: DataSourceHandle,
  chunks: Vec<LvmChunk>,
  size: u64,
}

impl DataSource for LvmLogicalVolumeSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.size || buf.is_empty() {
      return Ok(0);
    }

    let mut total = min(buf.len() as u64, self.size - offset) as usize;
    let mut out_offset = 0usize;
    let mut current = offset;
    while total > 0 {
      let Some(chunk_index) = self.chunks.iter().position(|chunk| {
        current >= chunk.logical_offset && current < chunk.logical_offset + chunk.size
      }) else {
        let next_start = self
          .chunks
          .iter()
          .filter(|chunk| chunk.logical_offset > current)
          .map(|chunk| chunk.logical_offset)
          .min()
          .unwrap_or(self.size);
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

  fn capabilities(&self) -> DataSourceCapabilities {
    self.source.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    "volume.lvm.logical"
  }
}
