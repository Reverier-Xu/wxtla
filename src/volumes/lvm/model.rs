use crate::{Error, Result};

#[derive(Clone, Copy)]
pub(super) struct AreaDescriptor {
  pub(super) offset: u64,
  pub(super) size: u64,
}

#[derive(Clone, Copy)]
pub(super) struct RawLocation {
  pub(super) offset: u64,
  pub(super) size: u64,
  pub(super) checksum: u32,
}

pub(super) struct PhysicalVolumeLabel {
  pub(super) pv_identifier: String,
  pub(super) data_areas: Vec<AreaDescriptor>,
  pub(super) metadata_areas: Vec<AreaDescriptor>,
}

pub struct LvmParsedImage {
  pub(super) label: PhysicalVolumeLabel,
  pub(super) metadata: ParsedMetadata,
  pub(super) current_pv_name: String,
}

pub(super) struct ParsedMetadata {
  pub(super) vg_name: String,
  pub(super) seqno: u64,
  pub(super) extent_size_bytes: u64,
  pub(super) physical_volumes: Vec<MetadataPhysicalVolume>,
  pub(super) logical_volumes: Vec<MetadataLogicalVolume>,
}

pub(super) struct MetadataPhysicalVolume {
  pub(super) name: String,
  pub(super) id: Option<String>,
  pub(super) pe_start_bytes: Option<u64>,
}

pub(super) struct MetadataLogicalVolume {
  pub(super) name: String,
  pub(super) id: Option<String>,
  pub(super) segments: Vec<MetadataSegment>,
}

pub(super) struct MetadataSegment {
  pub(super) start_extent: u64,
  pub(super) extent_count: u64,
  pub(super) stripe_size_bytes: Option<u64>,
  pub(super) stripes: Vec<MetadataStripe>,
}

pub(super) struct MetadataStripe {
  pub(super) pv_name: String,
  pub(super) start_extent: u64,
}

#[derive(Clone)]
pub struct LvmLogicalVolumeInfo {
  pub name: String,
  pub id: Option<String>,
  pub size: u64,
  pub chunks: Vec<LvmChunk>,
}

#[derive(Clone, Copy)]
pub struct LvmChunk {
  pub logical_offset: u64,
  pub size: u64,
  pub physical_offset: Option<u64>,
}

pub(super) fn build_logical_volume_info(
  label: &PhysicalVolumeLabel, extent_size_bytes: u64, current_pv_name: &str,
  current_pv_pe_start: Option<u64>, logical_volume: &MetadataLogicalVolume,
) -> Result<LvmLogicalVolumeInfo> {
  let lv_name = logical_volume.name.clone();
  let mut chunks = Vec::new();
  let mut size = 0u64;

  for segment in &logical_volume.segments {
    let segment_chunks = build_segment_chunks(
      label,
      extent_size_bytes,
      current_pv_name,
      current_pv_pe_start,
      segment,
    )?;
    for chunk in segment_chunks {
      let chunk_end = chunk
        .logical_offset
        .checked_add(chunk.size)
        .ok_or_else(|| Error::InvalidRange("LVM logical volume size overflow".to_string()))?;
      chunks.push(chunk);
      size = size.max(chunk_end);
    }
  }

  chunks.sort_by_key(|chunk| chunk.logical_offset);
  Ok(LvmLogicalVolumeInfo {
    name: lv_name,
    id: logical_volume.id.clone(),
    size,
    chunks,
  })
}

pub(super) fn logical_volume_size(
  label: &PhysicalVolumeLabel, extent_size_bytes: u64, current_pv_name: &str,
  current_pv_pe_start: Option<u64>, logical_volume: &MetadataLogicalVolume,
) -> Result<u64> {
  let mut size = 0u64;

  for segment in &logical_volume.segments {
    let segment_chunks = build_segment_chunks(
      label,
      extent_size_bytes,
      current_pv_name,
      current_pv_pe_start,
      segment,
    )?;
    for chunk in segment_chunks {
      let chunk_end = chunk
        .logical_offset
        .checked_add(chunk.size)
        .ok_or_else(|| Error::InvalidRange("LVM logical volume size overflow".to_string()))?;
      size = size.max(chunk_end);
    }
  }

  Ok(size)
}

pub(super) fn resolve_current_pv_name(
  metadata: &ParsedMetadata, pv_identifier: &str,
) -> Option<String> {
  let normalized_target = normalize_lvm_id(pv_identifier);
  for pv in &metadata.physical_volumes {
    if let Some(id) = &pv.id
      && normalize_lvm_id(id) == normalized_target
    {
      return Some(pv.name.clone());
    }
  }

  if metadata.physical_volumes.len() == 1 {
    return Some(metadata.physical_volumes[0].name.clone());
  }
  None
}

pub(super) fn resolve_pv_pe_start(
  physical_volumes: &[MetadataPhysicalVolume], pv_name: &str,
) -> Option<u64> {
  physical_volumes
    .iter()
    .find(|pv| pv.name == pv_name)
    .and_then(|pv| pv.pe_start_bytes)
}

fn resolve_data_area_offset(data_areas: &[AreaDescriptor], mut offset: u64) -> Option<u64> {
  for area in data_areas {
    if area.size == 0 {
      return area.offset.checked_add(offset);
    }
    if offset < area.size {
      return area.offset.checked_add(offset);
    }
    offset -= area.size;
  }
  None
}

fn build_segment_chunks(
  label: &PhysicalVolumeLabel, extent_size_bytes: u64, current_pv_name: &str,
  current_pv_pe_start: Option<u64>, segment: &MetadataSegment,
) -> Result<Vec<LvmChunk>> {
  let logical_offset = segment
    .start_extent
    .checked_mul(extent_size_bytes)
    .ok_or_else(|| Error::InvalidRange("LVM logical offset overflow".to_string()))?;
  let segment_size = segment
    .extent_count
    .checked_mul(extent_size_bytes)
    .ok_or_else(|| Error::InvalidRange("LVM segment size overflow".to_string()))?;

  if segment.stripes.len() == 1 {
    let stripe = &segment.stripes[0];
    let physical_offset = if stripe.pv_name == current_pv_name {
      let stripe_rel = stripe
        .start_extent
        .checked_mul(extent_size_bytes)
        .ok_or_else(|| Error::InvalidRange("LVM stripe offset overflow".to_string()))?;
      match resolve_data_area_offset(&label.data_areas, stripe_rel) {
        Some(offset) => {
          if let Some(pe_start) = current_pv_pe_start {
            if offset < pe_start {
              Some(
                pe_start
                  .checked_add(stripe_rel)
                  .ok_or_else(|| Error::InvalidRange("LVM physical offset overflow".to_string()))?,
              )
            } else {
              Some(offset)
            }
          } else {
            Some(offset)
          }
        }
        None => {
          if let Some(pe_start) = current_pv_pe_start {
            Some(
              pe_start
                .checked_add(stripe_rel)
                .ok_or_else(|| Error::InvalidRange("LVM physical offset overflow".to_string()))?,
            )
          } else {
            Some(stripe_rel)
          }
        }
      }
    } else {
      None
    };

    return Ok(vec![LvmChunk {
      logical_offset,
      size: segment_size,
      physical_offset,
    }]);
  }

  let stripe_size = segment.stripe_size_bytes.ok_or_else(|| {
    Error::InvalidFormat("LVM striped segments require an explicit stripe size".to_string())
  })?;
  if stripe_size == 0 {
    return Err(Error::InvalidFormat(
      "LVM striped segments require a non-zero stripe size".to_string(),
    ));
  }

  let stripe_count = u64::try_from(segment.stripes.len())
    .map_err(|_| Error::InvalidRange("LVM stripe count is too large".to_string()))?;
  let chunk_count = segment_size.div_ceil(stripe_size);
  let mut chunks = Vec::with_capacity(usize::try_from(chunk_count).unwrap_or(0));
  for chunk_index in 0..chunk_count {
    let stripe_index = usize::try_from(chunk_index % stripe_count)
      .map_err(|_| Error::InvalidRange("LVM stripe index is too large".to_string()))?;
    let row = chunk_index / stripe_count;
    let chunk_logical_offset = logical_offset
      .checked_add(
        chunk_index
          .checked_mul(stripe_size)
          .ok_or_else(|| Error::InvalidRange("LVM stripe logical offset overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange("LVM stripe logical offset overflow".to_string()))?;
    let remaining = segment_size - chunk_index * stripe_size;
    let chunk_size = remaining.min(stripe_size);
    let stripe = &segment.stripes[stripe_index];
    let physical_offset = if stripe.pv_name == current_pv_name {
      let stripe_rel = stripe
        .start_extent
        .checked_mul(extent_size_bytes)
        .and_then(|offset| offset.checked_add(row * stripe_size))
        .ok_or_else(|| Error::InvalidRange("LVM stripe offset overflow".to_string()))?;
      match resolve_data_area_offset(&label.data_areas, stripe_rel) {
        Some(offset) => {
          if let Some(pe_start) = current_pv_pe_start {
            if offset < pe_start {
              Some(
                pe_start
                  .checked_add(stripe_rel)
                  .ok_or_else(|| Error::InvalidRange("LVM physical offset overflow".to_string()))?,
              )
            } else {
              Some(offset)
            }
          } else {
            Some(offset)
          }
        }
        None => {
          if let Some(pe_start) = current_pv_pe_start {
            Some(
              pe_start
                .checked_add(stripe_rel)
                .ok_or_else(|| Error::InvalidRange("LVM physical offset overflow".to_string()))?,
            )
          } else {
            Some(stripe_rel)
          }
        }
      }
    } else {
      None
    };
    chunks.push(LvmChunk {
      logical_offset: chunk_logical_offset,
      size: chunk_size,
      physical_offset,
    });
  }

  Ok(chunks)
}

fn normalize_lvm_id(value: &str) -> String {
  value
    .chars()
    .filter(|character| character.is_ascii_alphanumeric())
    .map(|character| character.to_ascii_lowercase())
    .collect()
}
