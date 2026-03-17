//! EWF metadata parsing and chunk-map construction.

use super::{
  constants::{
    DIGEST_DATA_SIZE, E01_VOLUME_DATA_SIZE, HASH_DATA_SIZE, MAX_SECTION_DATA_SIZE,
    SECTION_DESCRIPTOR_SIZE,
  },
  file_header::EwfFileHeader,
  hash::{EwfDigestSection, EwfHashSection},
  section::{EwfSectionDescriptor, EwfSectionKind},
  table::EwfTable,
  types::{EwfChunkDescriptor, EwfChunkEncoding},
  volume::EwfVolumeInfo,
};
use crate::{DataSource, Error, Result};

/// Parsed single-segment EWF metadata required to open an image surface.
#[derive(Debug, Clone)]
pub struct ParsedEwf {
  /// Segment number encoded in the source file header.
  pub segment_number: u16,
  /// Volume geometry and media metadata.
  pub volume: EwfVolumeInfo,
  /// Chunk mapping for logical media reads.
  pub chunks: Vec<EwfChunkDescriptor>,
  /// Optional MD5 hash stored in the image metadata.
  pub md5_hash: Option<[u8; 16]>,
  /// Optional SHA1 hash stored in the image metadata.
  pub sha1_hash: Option<[u8; 20]>,
}

/// Parse a single-segment EWF image source.
pub fn parse(source: &dyn DataSource) -> Result<ParsedEwf> {
  let file_header = EwfFileHeader::read(source)?;
  let file_size = source.size()?;

  let mut section_offset = 13u64;
  let mut volume: Option<EwfVolumeInfo> = None;
  let mut md5_hash = None;
  let mut sha1_hash = None;
  let mut chunks = Vec::new();
  let mut last_sectors_section: Option<EwfSectionDescriptor> = None;
  let mut last_table: Option<EwfTable> = None;

  while section_offset < file_size {
    let section = EwfSectionDescriptor::read(source, section_offset)?;
    let section_end = section.end_offset()?;
    if section_end > file_size {
      return Err(Error::InvalidFormat(
        "ewf section extends beyond the segment file".to_string(),
      ));
    }

    let payload_size = usize::try_from(section.size)
      .map_err(|_| Error::InvalidRange("ewf section size is too large".to_string()))?
      .checked_sub(SECTION_DESCRIPTOR_SIZE)
      .ok_or_else(|| Error::InvalidRange("ewf section payload size underflow".to_string()))?;
    if payload_size > MAX_SECTION_DATA_SIZE {
      return Err(Error::InvalidFormat(format!(
        "ewf section payload is too large: {payload_size}"
      )));
    }
    let payload_offset = section_offset + SECTION_DESCRIPTOR_SIZE as u64;

    match section.kind {
      EwfSectionKind::Volume | EwfSectionKind::Data | EwfSectionKind::Disk => {
        if payload_size != E01_VOLUME_DATA_SIZE {
          return Err(Error::InvalidFormat(format!(
            "unsupported ewf volume/data payload size: {payload_size}"
          )));
        }
        let parsed_volume =
          EwfVolumeInfo::parse_e01(&source.read_bytes_at(payload_offset, payload_size)?)?;
        if let Some(existing) = &volume {
          if existing != &parsed_volume {
            return Err(Error::InvalidFormat(
              "ewf volume/data sections are inconsistent".to_string(),
            ));
          }
        } else {
          volume = Some(parsed_volume);
        }
      }
      EwfSectionKind::Sectors => {
        last_sectors_section = Some(section.clone());
      }
      EwfSectionKind::Table => {
        let volume = volume.as_ref().ok_or_else(|| {
          Error::InvalidFormat("ewf chunk table appears before the volume metadata".to_string())
        })?;
        let table = EwfTable::parse(&source.read_bytes_at(payload_offset, payload_size)?)?;
        append_table_chunks(&mut chunks, volume, &table, &last_sectors_section, &section)?;
        last_table = Some(table);
      }
      EwfSectionKind::Table2 => {
        let table = EwfTable::parse(&source.read_bytes_at(payload_offset, payload_size)?)?;
        if let Some(previous_table) = &last_table
          && previous_table != &table
        {
          return Err(Error::InvalidFormat(
            "ewf table2 does not mirror the preceding table section".to_string(),
          ));
        }
      }
      EwfSectionKind::Hash => {
        if payload_size != HASH_DATA_SIZE {
          return Err(Error::InvalidFormat(format!(
            "unsupported ewf hash payload size: {payload_size}"
          )));
        }
        md5_hash =
          Some(EwfHashSection::parse(&source.read_bytes_at(payload_offset, payload_size)?)?.md5);
      }
      EwfSectionKind::Digest => {
        if payload_size != DIGEST_DATA_SIZE {
          return Err(Error::InvalidFormat(format!(
            "unsupported ewf digest payload size: {payload_size}"
          )));
        }
        let digest = EwfDigestSection::parse(&source.read_bytes_at(payload_offset, payload_size)?)?;
        md5_hash = Some(digest.md5);
        sha1_hash = Some(digest.sha1);
      }
      EwfSectionKind::Header
      | EwfSectionKind::Header2
      | EwfSectionKind::Next
      | EwfSectionKind::Done
      | EwfSectionKind::Unknown => {}
    }

    section_offset = section_end;
    if matches!(section.kind, EwfSectionKind::Done | EwfSectionKind::Next) {
      break;
    }
  }

  let volume = volume
    .ok_or_else(|| Error::InvalidFormat("ewf image is missing volume metadata".to_string()))?;
  if chunks.len() != volume.chunk_count as usize {
    return Err(Error::InvalidFormat(format!(
      "ewf chunk count mismatch: expected {}, parsed {}",
      volume.chunk_count,
      chunks.len()
    )));
  }

  Ok(ParsedEwf {
    segment_number: file_header.segment_number,
    volume,
    chunks,
    md5_hash,
    sha1_hash,
  })
}

fn append_table_chunks(
  chunks: &mut Vec<EwfChunkDescriptor>, volume: &EwfVolumeInfo, table: &EwfTable,
  sectors_section: &Option<EwfSectionDescriptor>, table_section: &EwfSectionDescriptor,
) -> Result<()> {
  if table.entries.is_empty() {
    return Err(Error::InvalidFormat(
      "ewf table section does not contain chunk entries".to_string(),
    ));
  }

  let chunk_size = volume.chunk_size()?;
  for (entry_index, entry) in table.entries.iter().enumerate() {
    let chunk_index = u32::try_from(chunks.len())
      .map_err(|_| Error::InvalidRange("ewf chunk index overflow".to_string()))?;
    let media_offset = u64::from(chunk_index)
      .checked_mul(u64::from(chunk_size))
      .ok_or_else(|| Error::InvalidRange("ewf chunk media offset overflow".to_string()))?;
    let remaining_media_size = volume
      .media_size()?
      .checked_sub(media_offset)
      .ok_or_else(|| Error::InvalidRange("ewf chunk media range underflow".to_string()))?;
    let logical_size = remaining_media_size.min(u64::from(chunk_size)) as u32;
    let current_offset = entry.offset();
    let stored_offset = table
      .base_offset
      .checked_add(u64::from(current_offset))
      .ok_or_else(|| Error::InvalidRange("ewf chunk file offset overflow".to_string()))?;
    let next_offset = if let Some(next_entry) = table.entries.get(entry_index + 1) {
      let next_offset = next_entry.offset();
      if next_offset < current_offset {
        return Err(Error::InvalidFormat(
          "ewf chunk offsets must be monotonically increasing within a table".to_string(),
        ));
      }
      u64::from(next_offset)
    } else {
      let data_end_offset = match sectors_section {
        Some(section) => section.next_offset,
        None => table_section.next_offset,
      };
      data_end_offset
        .checked_sub(table.base_offset)
        .ok_or_else(|| Error::InvalidRange("ewf chunk end offset underflow".to_string()))?
    };
    let stored_size = u32::try_from(
      next_offset
        .checked_sub(u64::from(current_offset))
        .ok_or_else(|| Error::InvalidRange("ewf chunk stored size underflow".to_string()))?,
    )
    .map_err(|_| Error::InvalidRange("ewf chunk stored size overflow".to_string()))?;
    if stored_size == 0 {
      return Err(Error::InvalidFormat(
        "ewf chunk stored size must be non-zero".to_string(),
      ));
    }

    chunks.push(EwfChunkDescriptor {
      chunk_index,
      media_offset,
      logical_size,
      stored_offset,
      stored_size,
      encoding: if entry.is_compressed() {
        EwfChunkEncoding::Compressed
      } else {
        EwfChunkEncoding::Stored
      },
    });
  }

  Ok(())
}
