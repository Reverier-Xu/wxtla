//! EWF metadata parsing and chunk-map construction.

use std::collections::HashMap;

use super::{
  constants::{
    DIGEST_DATA_SIZE, E01_VOLUME_DATA_SIZE, HASH_DATA_SIZE, MAX_SECTION_DATA_SIZE,
    SECTION_DESCRIPTOR_SIZE,
  },
  file_header::EwfFileHeader,
  hash::{EwfDigestSection, EwfHashSection},
  naming::EwfSegmentPathInfo,
  section::{EwfSectionDescriptor, EwfSectionKind},
  table::EwfTable,
  types::{EwfChunkDescriptor, EwfChunkEncoding},
  volume::EwfVolumeInfo,
};
use crate::{
  DataSource, DataSourceHandle, Error, RelatedSourcePurpose, RelatedSourceRequest, Result,
  SourceHints,
};

/// Parsed EWF metadata required to open an image surface.
#[derive(Debug, Clone)]
pub struct ParsedEwf {
  /// Segment number encoded in the first segment file header.
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

/// Parsed EWF metadata alongside the segment sources used to construct it.
pub struct ParsedEwfSources {
  /// Parsed EWF metadata.
  pub parsed: ParsedEwf,
  /// Segment sources keyed by segment number.
  pub segment_sources: HashMap<u16, DataSourceHandle>,
}

#[derive(Debug, Default)]
struct ParseState {
  volume: Option<EwfVolumeInfo>,
  md5_hash: Option<[u8; 16]>,
  sha1_hash: Option<[u8; 20]>,
  chunks: Vec<EwfChunkDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentTermination {
  Done,
  Next,
}

/// Parse a single-segment EWF image source.
pub fn parse(source: DataSourceHandle) -> Result<ParsedEwfSources> {
  parse_with_hints(source, SourceHints::new())
}

/// Parse an EWF image source using source hints for segment resolution.
pub fn parse_with_hints(
  source: DataSourceHandle, hints: SourceHints<'_>,
) -> Result<ParsedEwfSources> {
  let naming_info = hints
    .source_identity()
    .map(EwfSegmentPathInfo::from_identity)
    .transpose()?;
  let mut current_source = resolve_initial_source(source, hints, naming_info.as_ref())?;
  let mut segment_sources = HashMap::new();
  let mut state = ParseState::default();
  let mut expected_segment_number = 1u16;
  let mut first_signature = None;

  loop {
    let parsed_segment = parse_segment(current_source.as_ref(), &mut state)?;
    if parsed_segment.file_header.segment_number != expected_segment_number {
      return Err(Error::InvalidFormat(format!(
        "ewf segment sequence mismatch: expected segment {expected_segment_number}, found {}",
        parsed_segment.file_header.segment_number
      )));
    }
    if let Some(signature) = first_signature {
      if parsed_segment.file_header.signature != signature {
        return Err(Error::InvalidFormat(
          "ewf segment file signatures are inconsistent".to_string(),
        ));
      }
    } else {
      first_signature = Some(parsed_segment.file_header.signature);
    }

    segment_sources.insert(
      parsed_segment.file_header.segment_number,
      current_source.clone(),
    );

    match parsed_segment.termination {
      SegmentTermination::Done => break,
      SegmentTermination::Next => {
        expected_segment_number = expected_segment_number
          .checked_add(1)
          .ok_or_else(|| Error::InvalidRange("ewf segment number overflow".to_string()))?;
        current_source = resolve_next_source(hints, naming_info.as_ref(), expected_segment_number)?;
      }
    }
  }

  let volume = state
    .volume
    .ok_or_else(|| Error::InvalidFormat("ewf image is missing volume metadata".to_string()))?;
  if state.chunks.len() != volume.chunk_count as usize {
    return Err(Error::InvalidFormat(format!(
      "ewf chunk count mismatch: expected {}, parsed {}",
      volume.chunk_count,
      state.chunks.len()
    )));
  }

  Ok(ParsedEwfSources {
    parsed: ParsedEwf {
      segment_number: 1,
      volume,
      chunks: state.chunks,
      md5_hash: state.md5_hash,
      sha1_hash: state.sha1_hash,
    },
    segment_sources,
  })
}

fn resolve_initial_source(
  source: DataSourceHandle, hints: SourceHints<'_>, naming_info: Option<&EwfSegmentPathInfo>,
) -> Result<DataSourceHandle> {
  match (naming_info, hints.resolver()) {
    (Some(info), Some(resolver)) if info.segment_number != 1 => {
      let segment_one_name = info.file_name_for_segment(1)?;
      let path = hints
        .source_identity()
        .expect("source identity must exist when naming info exists")
        .sibling_path(segment_one_name)?;
      resolver
        .resolve(&RelatedSourceRequest::new(
          RelatedSourcePurpose::Segment,
          path,
        ))?
        .ok_or_else(|| Error::NotFound("unable to resolve the first ewf segment".to_string()))
    }
    _ => Ok(source),
  }
}

fn resolve_next_source(
  hints: SourceHints<'_>, naming_info: Option<&EwfSegmentPathInfo>, segment_number: u16,
) -> Result<DataSourceHandle> {
  let resolver = hints.resolver().ok_or_else(|| {
    Error::InvalidSourceReference(
      "ewf multi-segment images require a related-source resolver".to_string(),
    )
  })?;
  let identity = hints.source_identity().ok_or_else(|| {
    Error::InvalidSourceReference(
      "ewf multi-segment images require a source identity hint".to_string(),
    )
  })?;
  let naming_info = naming_info.ok_or_else(|| {
    Error::InvalidSourceReference(
      "unable to derive ewf segment naming information from the source identity".to_string(),
    )
  })?;
  let segment_name = naming_info.file_name_for_segment(segment_number)?;
  let path = identity.sibling_path(segment_name)?;

  resolver
    .resolve(&RelatedSourceRequest::new(
      RelatedSourcePurpose::Segment,
      path,
    ))?
    .ok_or_else(|| Error::NotFound(format!("missing ewf segment {segment_number}")))
}

fn parse_segment(source: &dyn DataSource, state: &mut ParseState) -> Result<ParsedSegment> {
  let file_header = EwfFileHeader::read(source)?;
  let file_size = source.size()?;
  let mut section_offset = 13u64;
  let mut last_sectors_section: Option<EwfSectionDescriptor> = None;
  let mut last_table: Option<EwfTable> = None;
  let mut termination = SegmentTermination::Done;

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
        let parsed_volume = parse_volume_payload(source, payload_offset, payload_size)?;
        if let Some(existing) = &state.volume {
          if existing != &parsed_volume {
            return Err(Error::InvalidFormat(
              "ewf volume/data sections are inconsistent".to_string(),
            ));
          }
        } else {
          state.volume = Some(parsed_volume);
        }
      }
      EwfSectionKind::Sectors => {
        last_sectors_section = Some(section.clone());
      }
      EwfSectionKind::Table => {
        let volume = state.volume.as_ref().ok_or_else(|| {
          Error::InvalidFormat("ewf chunk table appears before the volume metadata".to_string())
        })?;
        let table = EwfTable::parse(&source.read_bytes_at(payload_offset, payload_size)?)?;
        append_table_chunks(
          &mut state.chunks,
          volume,
          file_header.segment_number,
          &table,
          &last_sectors_section,
          &section,
        )?;
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
        state.md5_hash =
          Some(EwfHashSection::parse(&source.read_bytes_at(payload_offset, payload_size)?)?.md5);
      }
      EwfSectionKind::Digest => {
        if payload_size != DIGEST_DATA_SIZE {
          return Err(Error::InvalidFormat(format!(
            "unsupported ewf digest payload size: {payload_size}"
          )));
        }
        let digest = EwfDigestSection::parse(&source.read_bytes_at(payload_offset, payload_size)?)?;
        state.md5_hash = Some(digest.md5);
        state.sha1_hash = Some(digest.sha1);
      }
      EwfSectionKind::Next => {
        termination = SegmentTermination::Next;
      }
      EwfSectionKind::Done => {
        termination = SegmentTermination::Done;
      }
      EwfSectionKind::Header | EwfSectionKind::Header2 | EwfSectionKind::Unknown => {}
    }

    section_offset = section_end;
    if matches!(section.kind, EwfSectionKind::Done | EwfSectionKind::Next) {
      break;
    }
  }

  Ok(ParsedSegment {
    file_header,
    termination,
  })
}

fn parse_volume_payload(
  source: &dyn DataSource, payload_offset: u64, payload_size: usize,
) -> Result<EwfVolumeInfo> {
  let payload = source.read_bytes_at(payload_offset, payload_size)?;

  match payload_size {
    E01_VOLUME_DATA_SIZE => EwfVolumeInfo::parse_e01(&payload),
    _ => Err(Error::InvalidFormat(format!(
      "unsupported ewf volume/data payload size: {payload_size}"
    ))),
  }
}

fn append_table_chunks(
  chunks: &mut Vec<EwfChunkDescriptor>, volume: &EwfVolumeInfo, segment_number: u16,
  table: &EwfTable, sectors_section: &Option<EwfSectionDescriptor>,
  table_section: &EwfSectionDescriptor,
) -> Result<()> {
  if table.entries.is_empty() {
    return Err(Error::InvalidFormat(
      "ewf table section does not contain chunk entries".to_string(),
    ));
  }

  let chunk_size = volume.chunk_size()?;
  let media_size = volume.media_size()?;
  for (entry_index, entry) in table.entries.iter().enumerate() {
    let chunk_index = u32::try_from(chunks.len())
      .map_err(|_| Error::InvalidRange("ewf chunk index overflow".to_string()))?;
    let media_offset = u64::from(chunk_index)
      .checked_mul(u64::from(chunk_size))
      .ok_or_else(|| Error::InvalidRange("ewf chunk media offset overflow".to_string()))?;
    let remaining_media_size = media_size
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
      segment_number,
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

struct ParsedSegment {
  file_header: EwfFileHeader,
  termination: SegmentTermination,
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, sync::Arc};

  use super::*;
  use crate::{
    DataSource, DataSourceHandle, RelatedSourceRequest, RelatedSourceResolver, SourceHints,
    SourceIdentity,
  };

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = offset as usize;
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

  struct Resolver {
    data: HashMap<String, DataSourceHandle>,
  }

  impl RelatedSourceResolver for Resolver {
    fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<DataSourceHandle>> {
      Ok(self.data.get(&request.path.to_string()).cloned())
    }
  }

  #[test]
  fn parses_segment_file_name_info() {
    let identity = SourceIdentity::from_relative_path("images/ext2.E01").unwrap();
    let info = EwfSegmentPathInfo::from_identity(&identity).unwrap();

    assert_eq!(info.segment_number, 1);
    assert_eq!(info.file_name_for_segment(100).unwrap(), "ext2.EAA");
  }

  #[test]
  fn resolves_first_segment_from_a_later_numeric_segment() {
    let first: DataSourceHandle = Arc::new(MemDataSource { data: vec![] });
    let resolver = Resolver {
      data: HashMap::from([("images/ext2.E01".to_string(), first.clone())]),
    };
    let source: DataSourceHandle = Arc::new(MemDataSource { data: vec![] });
    let identity = SourceIdentity::from_relative_path("images/ext2.E02").unwrap();

    let resolved = resolve_initial_source(
      source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
      Some(&EwfSegmentPathInfo::from_identity(&identity).unwrap()),
    )
    .unwrap();

    assert!(Arc::ptr_eq(&resolved, &first));
  }
}
