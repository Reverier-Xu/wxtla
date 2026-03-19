//! Parsing of VHDX metadata tables and BAT state.

use std::collections::HashSet;

use super::{
  constants,
  header::{VhdxImageHeader, VhdxRegionTable, VhdxRegionTableEntry, validate_file_identifier},
  metadata::{VhdxDiskType, VhdxMetadata},
};
use crate::{DataSource, DataSourceHandle, Error, Result};

pub(super) struct ParsedVhdx {
  pub image_header: VhdxImageHeader,
  pub metadata: VhdxMetadata,
  pub block_allocation_table: VhdxBatLayout,
  pub payload_block_count: u64,
  pub entries_per_chunk: u64,
  pub sector_bitmap_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VhdxBatLayout {
  pub file_offset: u64,
  pub entry_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct BatLayout {
  payload_block_count: u64,
  entries_per_chunk: u64,
  sector_bitmap_size: u64,
  entry_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VhdxPayloadBlockState {
  NotPresent,
  Undefined,
  Zero,
  Unmapped,
  FullyPresent,
  PartiallyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VhdxSectorBitmapState {
  NotPresent,
  Present,
}

pub(super) fn parse(source: DataSourceHandle) -> Result<ParsedVhdx> {
  validate_file_identifier(source.as_ref())?;
  let source_size = source.size()?;
  let image_header = read_active_image_header(source.as_ref())?;
  if !image_header.log_identifier.is_nil() || image_header.log_version != 0 {
    return Err(Error::InvalidFormat(
      "vhdx log replay is not supported".to_string(),
    ));
  }
  let region_table = read_region_table_pair(source.as_ref())?;
  let metadata_region = require_known_region(&region_table, constants::METADATA_REGION_GUID)?;
  let bat_region = require_known_region(&region_table, constants::BAT_REGION_GUID)?;
  validate_region_bounds(source_size, metadata_region, "metadata")?;
  validate_region_bounds(source_size, bat_region, "BAT")?;

  let metadata_region_size = usize::try_from(metadata_region.length)
    .map_err(|_| Error::InvalidRange("vhdx metadata region length is too large".to_string()))?;
  let metadata_bytes = source.read_bytes_at(metadata_region.file_offset, metadata_region_size)?;
  let metadata = VhdxMetadata::from_region(&metadata_bytes)?;
  let payload_block_count = metadata
    .virtual_disk_size
    .div_ceil(u64::from(metadata.block_size));
  let entries_per_chunk = compute_entries_per_chunk(&metadata)?;
  let sector_bitmap_size = compute_sector_bitmap_size(entries_per_chunk)?;
  let layout = BatLayout {
    payload_block_count,
    entries_per_chunk,
    sector_bitmap_size,
    entry_count: compute_bat_entry_count(&metadata, payload_block_count, entries_per_chunk)?,
  };
  let block_allocation_table = read_bat_layout(bat_region, &layout)?;
  validate_bat_entries(
    source.as_ref(),
    &block_allocation_table,
    &metadata,
    source_size,
    &layout,
  )?;

  Ok(ParsedVhdx {
    image_header,
    metadata,
    block_allocation_table,
    payload_block_count: layout.payload_block_count,
    entries_per_chunk: layout.entries_per_chunk,
    sector_bitmap_size: layout.sector_bitmap_size,
  })
}

pub(super) fn payload_bat_index(
  disk_type: VhdxDiskType, block_index: u64, entries_per_chunk: u64,
) -> Result<usize> {
  let raw_index = match disk_type {
    VhdxDiskType::Fixed => block_index,
    VhdxDiskType::Dynamic | VhdxDiskType::Differential => {
      let chunk_index = block_index / entries_per_chunk;
      let within_chunk = block_index % entries_per_chunk;
      chunk_index
        .checked_mul(entries_per_chunk + 1)
        .and_then(|value| value.checked_add(within_chunk))
        .ok_or_else(|| Error::InvalidRange("vhdx BAT payload index overflow".to_string()))?
    }
  };

  usize::try_from(raw_index)
    .map_err(|_| Error::InvalidRange("vhdx BAT payload index is too large".to_string()))
}

pub(super) fn sector_bitmap_bat_index(chunk_index: u64, entries_per_chunk: u64) -> Result<usize> {
  let raw_index = (chunk_index + 1)
    .checked_mul(entries_per_chunk + 1)
    .and_then(|value| value.checked_sub(1))
    .ok_or_else(|| Error::InvalidRange("vhdx BAT sector bitmap index overflow".to_string()))?;
  usize::try_from(raw_index)
    .map_err(|_| Error::InvalidRange("vhdx BAT sector bitmap index is too large".to_string()))
}

pub(super) fn bat_file_offset(entry: u64) -> Result<u64> {
  let reserved = (entry >> 3) & 0x1_FFFF;
  if reserved != 0 {
    return Err(Error::InvalidFormat(format!(
      "vhdx BAT entry reserved bits are not zero: 0x{entry:016x}"
    )));
  }

  let offset_units = entry >> 20;
  offset_units
    .checked_mul(constants::VHDX_ALIGNMENT)
    .ok_or_else(|| Error::InvalidRange("vhdx BAT file offset overflow".to_string()))
}

pub(super) fn payload_block_state(entry: u64) -> Result<VhdxPayloadBlockState> {
  match entry & 0x7 {
    0 => Ok(VhdxPayloadBlockState::NotPresent),
    1 => Ok(VhdxPayloadBlockState::Undefined),
    2 => Ok(VhdxPayloadBlockState::Zero),
    3 => Ok(VhdxPayloadBlockState::Unmapped),
    6 => Ok(VhdxPayloadBlockState::FullyPresent),
    7 => Ok(VhdxPayloadBlockState::PartiallyPresent),
    state => Err(Error::InvalidFormat(format!(
      "unsupported vhdx payload BAT state: {state}"
    ))),
  }
}

pub(super) fn sector_bitmap_state(entry: u64) -> Result<VhdxSectorBitmapState> {
  match entry & 0x7 {
    0 => Ok(VhdxSectorBitmapState::NotPresent),
    6 => Ok(VhdxSectorBitmapState::Present),
    state => Err(Error::InvalidFormat(format!(
      "unsupported vhdx sector bitmap BAT state: {state}"
    ))),
  }
}

fn read_active_image_header(source: &dyn DataSource) -> Result<VhdxImageHeader> {
  let primary = VhdxImageHeader::read(source, constants::PRIMARY_IMAGE_HEADER_OFFSET);
  let secondary = VhdxImageHeader::read(source, constants::SECONDARY_IMAGE_HEADER_OFFSET);

  match (primary, secondary) {
    (Ok(left), Ok(right)) => Ok(if left.sequence_number >= right.sequence_number {
      left
    } else {
      right
    }),
    (Ok(header), Err(_)) | (Err(_), Ok(header)) => Ok(header),
    (Err(_), Err(_)) => Err(Error::InvalidFormat(
      "no valid vhdx image header copy was found".to_string(),
    )),
  }
}

fn read_region_table_pair(source: &dyn DataSource) -> Result<VhdxRegionTable> {
  let primary = VhdxRegionTable::read(source, constants::PRIMARY_REGION_TABLE_OFFSET);
  let secondary = VhdxRegionTable::read(source, constants::SECONDARY_REGION_TABLE_OFFSET);

  match (primary, secondary) {
    (Ok(left), Ok(right)) => {
      validate_known_required_regions(&left)?;
      validate_known_required_regions(&right)?;
      if left.entries() != right.entries() {
        return Err(Error::InvalidFormat(
          "primary and secondary vhdx region tables differ".to_string(),
        ));
      }
      Ok(left)
    }
    (Ok(table), Err(_)) | (Err(_), Ok(table)) => {
      validate_known_required_regions(&table)?;
      Ok(table)
    }
    (Err(_), Err(_)) => Err(Error::InvalidFormat(
      "no valid vhdx region table copy was found".to_string(),
    )),
  }
}

fn validate_known_required_regions(table: &VhdxRegionTable) -> Result<()> {
  for entry in table.entries() {
    let is_known = matches!(
      entry.type_identifier,
      constants::BAT_REGION_GUID | constants::METADATA_REGION_GUID
    );
    if entry.is_required && !is_known {
      return Err(Error::InvalidFormat(format!(
        "unsupported required vhdx region: {}",
        entry.type_identifier
      )));
    }
  }

  if table.entry(constants::BAT_REGION_GUID).is_none() {
    return Err(Error::InvalidFormat("missing vhdx BAT region".to_string()));
  }
  if table.entry(constants::METADATA_REGION_GUID).is_none() {
    return Err(Error::InvalidFormat(
      "missing vhdx metadata region".to_string(),
    ));
  }

  Ok(())
}

fn require_known_region(
  table: &VhdxRegionTable, type_identifier: super::guid::VhdxGuid,
) -> Result<&VhdxRegionTableEntry> {
  table
    .entry(type_identifier)
    .ok_or_else(|| Error::InvalidFormat(format!("missing required vhdx region: {type_identifier}")))
}

fn validate_region_bounds(
  source_size: u64, region: &VhdxRegionTableEntry, label: &str,
) -> Result<()> {
  let end = region
    .file_offset
    .checked_add(u64::from(region.length))
    .ok_or_else(|| Error::InvalidRange(format!("vhdx {label} region end overflow")))?;
  if end > source_size {
    return Err(Error::InvalidFormat(format!(
      "vhdx {label} region exceeds the source size"
    )));
  }
  Ok(())
}

fn compute_entries_per_chunk(metadata: &VhdxMetadata) -> Result<u64> {
  let numerator = constants::SECTORS_PER_BITMAP_BLOCK
    .checked_mul(u64::from(metadata.logical_sector_size))
    .ok_or_else(|| Error::InvalidRange("vhdx entries-per-chunk overflow".to_string()))?;
  let denominator = u64::from(metadata.block_size);
  let entries_per_chunk = numerator / denominator;
  if entries_per_chunk == 0 || !numerator.is_multiple_of(denominator) {
    return Err(Error::InvalidFormat(
      "vhdx block geometry does not produce integral chunk entries".to_string(),
    ));
  }
  Ok(entries_per_chunk)
}

fn compute_sector_bitmap_size(entries_per_chunk: u64) -> Result<u64> {
  if !constants::SECTOR_BITMAP_BLOCK_SIZE.is_multiple_of(entries_per_chunk) {
    return Err(Error::InvalidFormat(
      "vhdx sector bitmap size is not integral".to_string(),
    ));
  }
  Ok(constants::SECTOR_BITMAP_BLOCK_SIZE / entries_per_chunk)
}

fn compute_bat_entry_count(
  metadata: &VhdxMetadata, payload_block_count: u64, entries_per_chunk: u64,
) -> Result<usize> {
  let raw_count = match metadata.disk_type {
    VhdxDiskType::Fixed => payload_block_count,
    VhdxDiskType::Dynamic | VhdxDiskType::Differential => {
      let chunk_count = payload_block_count.div_ceil(entries_per_chunk);
      chunk_count
        .checked_mul(entries_per_chunk + 1)
        .ok_or_else(|| Error::InvalidRange("vhdx BAT entry count overflow".to_string()))?
    }
  };

  usize::try_from(raw_count)
    .map_err(|_| Error::InvalidRange("vhdx BAT entry count is too large".to_string()))
}

fn read_bat_layout(bat_region: &VhdxRegionTableEntry, layout: &BatLayout) -> Result<VhdxBatLayout> {
  let table_bytes = layout
    .entry_count
    .checked_mul(8)
    .ok_or_else(|| Error::InvalidRange("vhdx BAT byte length overflow".to_string()))?;
  if u64::from(bat_region.length) < u64::try_from(table_bytes).unwrap_or(u64::MAX) {
    return Err(Error::InvalidFormat(
      "vhdx BAT region is too small for the expected entry count".to_string(),
    ));
  }

  Ok(VhdxBatLayout {
    file_offset: bat_region.file_offset,
    entry_count: layout.entry_count,
  })
}

fn validate_bat_entries(
  source: &dyn DataSource, bat: &VhdxBatLayout, metadata: &VhdxMetadata, source_size: u64,
  layout: &BatLayout,
) -> Result<()> {
  let mut chunks_with_partial_blocks = HashSet::new();
  for block_index in 0..layout.payload_block_count {
    let entry = read_bat_entry(
      source,
      bat,
      payload_bat_index(metadata.disk_type, block_index, layout.entries_per_chunk)?,
    )?;
    let state = payload_block_state(entry)?;
    if matches!(metadata.disk_type, VhdxDiskType::Fixed)
      && !matches!(state, VhdxPayloadBlockState::FullyPresent)
    {
      return Err(Error::InvalidFormat(
        "fixed vhdx images must map every payload block in-file".to_string(),
      ));
    }
    if matches!(metadata.disk_type, VhdxDiskType::Dynamic)
      && matches!(state, VhdxPayloadBlockState::PartiallyPresent)
    {
      return Err(Error::InvalidFormat(
        "dynamic vhdx images cannot contain partially-present payload blocks".to_string(),
      ));
    }

    let file_offset = bat_file_offset(entry)?;
    match state {
      VhdxPayloadBlockState::FullyPresent | VhdxPayloadBlockState::PartiallyPresent => {
        if file_offset < constants::VHDX_ALIGNMENT {
          return Err(Error::InvalidFormat(
            "vhdx BAT payload block offset is below the minimum alignment".to_string(),
          ));
        }
        let end = file_offset
          .checked_add(u64::from(metadata.block_size))
          .ok_or_else(|| Error::InvalidRange("vhdx payload block end overflow".to_string()))?;
        if end > source_size {
          return Err(Error::InvalidFormat(
            "vhdx BAT payload block exceeds the source size".to_string(),
          ));
        }
        if matches!(state, VhdxPayloadBlockState::PartiallyPresent) {
          chunks_with_partial_blocks.insert(block_index / layout.entries_per_chunk);
        }
      }
      VhdxPayloadBlockState::NotPresent
      | VhdxPayloadBlockState::Undefined
      | VhdxPayloadBlockState::Zero
      | VhdxPayloadBlockState::Unmapped => {
        if file_offset != 0 {
          return Err(Error::InvalidFormat(
            "vhdx sparse BAT entries must not carry a file offset".to_string(),
          ));
        }
      }
    }
  }

  if matches!(metadata.disk_type, VhdxDiskType::Fixed) {
    return Ok(());
  }

  let chunk_count = layout
    .payload_block_count
    .div_ceil(layout.entries_per_chunk);
  for chunk_index in 0..chunk_count {
    let entry = read_bat_entry(
      source,
      bat,
      sector_bitmap_bat_index(chunk_index, layout.entries_per_chunk)?,
    )?;
    let state = sector_bitmap_state(entry)?;
    if chunks_with_partial_blocks.contains(&chunk_index) && state != VhdxSectorBitmapState::Present
    {
      return Err(Error::InvalidFormat(
        "vhdx partially-present payload blocks require a sector bitmap".to_string(),
      ));
    }
    if matches!(state, VhdxSectorBitmapState::Present) {
      let file_offset = bat_file_offset(entry)?;
      if file_offset < constants::VHDX_ALIGNMENT {
        return Err(Error::InvalidFormat(
          "vhdx sector bitmap offset is below the minimum alignment".to_string(),
        ));
      }
      let end = file_offset
        .checked_add(constants::SECTOR_BITMAP_BLOCK_SIZE)
        .ok_or_else(|| Error::InvalidRange("vhdx sector bitmap end overflow".to_string()))?;
      if end > source_size {
        return Err(Error::InvalidFormat(
          "vhdx sector bitmap block exceeds the source size".to_string(),
        ));
      }
      if layout.sector_bitmap_size == 0 {
        return Err(Error::InvalidFormat(
          "vhdx sector bitmap slices must be non-zero".to_string(),
        ));
      }
    }
  }

  Ok(())
}

pub(super) fn read_bat_entry(
  source: &dyn DataSource, bat: &VhdxBatLayout, index: usize,
) -> Result<u64> {
  if index >= bat.entry_count {
    return Err(Error::InvalidFormat(format!(
      "vhdx BAT entry {index} is out of bounds"
    )));
  }
  let entry_offset = bat
    .file_offset
    .checked_add(
      u64::try_from(index)
        .map_err(|_| Error::InvalidRange("vhdx BAT entry index is too large".to_string()))?
        .checked_mul(8)
        .ok_or_else(|| Error::InvalidRange("vhdx BAT entry offset overflow".to_string()))?,
    )
    .ok_or_else(|| Error::InvalidRange("vhdx BAT entry offset overflow".to_string()))?;
  let mut data = [0u8; 8];
  source.read_exact_at(entry_offset, &mut data)?;

  Ok(u64::from_le_bytes(data))
}
