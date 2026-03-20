//! EWF metadata parsing and lazy chunk-table discovery.

use std::collections::HashMap;

use super::{
  constants::{
    DIGEST_DATA_SIZE, E01_VOLUME_DATA_SIZE, FILE_HEADER_SIZE, HASH_DATA_SIZE, S01_VOLUME_DATA_SIZE,
    SECTION_DESCRIPTOR_SIZE, TABLE_HEADER_SIZE,
  },
  error2::{EwfErrorRange, EwfErrorSection},
  file_header::EwfFileHeader,
  hash::{EwfDigestSection, EwfHashSection},
  metadata::EwfMetadataSection,
  naming::EwfSegmentPathInfo,
  section::{EwfSectionDescriptor, EwfSectionKind},
  table::{EwfAnalyzedTable, EwfTableLayout},
  volume::EwfVolumeInfo,
};
use crate::{
  DataSource, DataSourceHandle, Error, RelatedSourcePurpose, RelatedSourceRequest, Result,
  SourceHints,
};

/// Parsed EWF metadata required to open an image surface.
#[derive(Debug, Clone)]
pub(super) struct ParsedEwf {
  /// Segment number encoded in the first segment file header.
  pub segment_number: u16,
  /// Volume geometry and media metadata.
  pub volume: EwfVolumeInfo,
  /// Chunk table descriptors used to resolve logical chunks lazily.
  pub chunk_tables: Vec<EwfChunkTableDescriptor>,
  /// Parsed ASCII `header` sections from the image set.
  pub header_sections: Vec<EwfMetadataSection>,
  /// Parsed UTF-16 `header2` sections from the image set.
  pub header2_sections: Vec<EwfMetadataSection>,
  /// Error ranges reported by the image set.
  pub error_ranges: Vec<EwfErrorRange>,
  /// Optional MD5 hash stored in the image metadata.
  pub md5_hash: Option<[u8; 16]>,
  /// Optional SHA1 hash stored in the image metadata.
  pub sha1_hash: Option<[u8; 20]>,
}

/// Parsed EWF metadata alongside the segment sources used to construct it.
pub(super) struct ParsedEwfSources {
  /// Parsed EWF metadata.
  pub parsed: ParsedEwf,
  /// Segment sources keyed by segment number.
  pub segment_sources: HashMap<u16, DataSourceHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EwfChunkTableDescriptor {
  pub segment_number: u16,
  pub start_chunk_index: u32,
  pub entry_count: u32,
  pub entries_offset: u64,
  pub base_offset: u64,
  pub overflow_start_index: Option<usize>,
  pub data_end_offset: u64,
}

impl EwfChunkTableDescriptor {
  pub fn contains_chunk(&self, chunk_index: u32) -> bool {
    let end_chunk_index = self.start_chunk_index.saturating_add(self.entry_count);
    (self.start_chunk_index..end_chunk_index).contains(&chunk_index)
  }

  pub fn local_chunk_index(&self, chunk_index: u32) -> Result<usize> {
    usize::try_from(
      chunk_index
        .checked_sub(self.start_chunk_index)
        .ok_or_else(|| Error::InvalidRange("ewf chunk table index underflow".to_string()))?,
    )
    .map_err(|_| Error::InvalidRange("ewf chunk table index is too large".to_string()))
  }

  pub fn is_overflow_index(&self, entry_index: usize) -> bool {
    self
      .overflow_start_index
      .is_some_and(|start_index| entry_index >= start_index)
  }
}

#[derive(Debug, Default)]
struct ParseState {
  volume: Option<EwfVolumeInfo>,
  header_sections: Vec<EwfMetadataSection>,
  header2_sections: Vec<EwfMetadataSection>,
  error_ranges: Vec<EwfErrorRange>,
  md5_hash: Option<[u8; 16]>,
  sha1_hash: Option<[u8; 20]>,
  chunk_tables: Vec<EwfChunkTableDescriptor>,
  chunk_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentTermination {
  Done,
  Next,
}

struct ParsedSegment {
  file_header: EwfFileHeader,
  termination: SegmentTermination,
}

/// Parse a single-segment EWF image source.
pub(super) fn parse(source: DataSourceHandle) -> Result<ParsedEwfSources> {
  parse_with_hints(source, SourceHints::new())
}

/// Parse an EWF image source using source hints for segment resolution.
pub(super) fn parse_with_hints(
  source: DataSourceHandle, hints: SourceHints<'_>,
) -> Result<ParsedEwfSources> {
  let current_file_header = EwfFileHeader::read(source.as_ref())?;
  let naming_info = hints
    .source_identity()
    .map(|identity| {
      EwfSegmentPathInfo::from_identity(identity)
        .or_else(|_| EwfSegmentPathInfo::from_identity_and_header(identity, &current_file_header))
    })
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
  if state.chunk_count != volume.chunk_count {
    return Err(Error::InvalidFormat(format!(
      "ewf chunk count mismatch: expected {}, parsed {}",
      volume.chunk_count, state.chunk_count
    )));
  }

  Ok(ParsedEwfSources {
    parsed: ParsedEwf {
      segment_number: 1,
      volume,
      chunk_tables: state.chunk_tables,
      header_sections: state.header_sections,
      header2_sections: state.header2_sections,
      error_ranges: state.error_ranges,
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
      let identity = hints.source_identity().ok_or_else(|| {
        Error::InvalidSourceReference(
          "ewf source identity is missing while resolving the first segment".to_string(),
        )
      })?;
      let path = identity.sibling_path(segment_one_name)?;
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
  let mut section_offset = FILE_HEADER_SIZE as u64;
  let mut pending_sectors_section: Option<EwfSectionDescriptor> = None;
  let mut last_table_layout: Option<EwfTableLayout> = None;
  let mut termination = SegmentTermination::Done;

  while section_offset < file_size {
    let section = EwfSectionDescriptor::read(source, section_offset)?;
    let section_end = section.end_offset()?;
    if section_end > file_size {
      return Err(Error::InvalidFormat(
        "ewf section extends beyond the segment file".to_string(),
      ));
    }

    let payload_size = section_payload_size(&section)?;
    let payload_offset = section_payload_offset(&section)?;

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
      EwfSectionKind::Header => {
        let section =
          EwfMetadataSection::parse_header(&source.read_bytes_at(payload_offset, payload_size)?)?;
        if !state.header_sections.contains(&section) {
          state.header_sections.push(section);
        }
      }
      EwfSectionKind::Header2 => {
        let section =
          EwfMetadataSection::parse_header2(&source.read_bytes_at(payload_offset, payload_size)?)?;
        if !state.header2_sections.contains(&section) {
          state.header2_sections.push(section);
        }
      }
      EwfSectionKind::Error2 => {
        let section = EwfErrorSection::parse(&source.read_bytes_at(payload_offset, payload_size)?)?;
        state.error_ranges.extend(section.ranges);
      }
      EwfSectionKind::Sectors => {
        pending_sectors_section = Some(section.clone());
      }
      EwfSectionKind::Table => {
        let volume = state.volume.as_ref().ok_or_else(|| {
          Error::InvalidFormat("ewf chunk table appears before the volume metadata".to_string())
        })?;
        let analyzed_table = EwfAnalyzedTable::read(source, payload_offset, payload_size)?;
        if analyzed_table.layout.entry_count == 0 {
          return Err(Error::InvalidFormat(
            "ewf table section does not contain chunk entries".to_string(),
          ));
        }
        let start_chunk_index = state.chunk_count;
        state.chunk_count = state
          .chunk_count
          .checked_add(analyzed_table.layout.entry_count)
          .ok_or_else(|| Error::InvalidRange("ewf chunk count overflow".to_string()))?;
        if state.chunk_count > volume.chunk_count {
          return Err(Error::InvalidFormat(
            "ewf table entries exceed the declared chunk count".to_string(),
          ));
        }
        let sectors_section = pending_sectors_section.take();
        state.chunk_tables.push(EwfChunkTableDescriptor {
          segment_number: file_header.segment_number,
          start_chunk_index,
          entry_count: analyzed_table.layout.entry_count,
          entries_offset: payload_offset
            .checked_add(TABLE_HEADER_SIZE as u64)
            .ok_or_else(|| Error::InvalidRange("ewf table entry offset overflow".to_string()))?,
          base_offset: analyzed_table.layout.base_offset,
          overflow_start_index: analyzed_table.overflow_start_index,
          data_end_offset: sectors_section
            .as_ref()
            .map_or(section.next_offset, |sectors| sectors.next_offset),
        });
        last_table_layout = Some(analyzed_table.layout);
      }
      EwfSectionKind::Table2 => {
        let table_layout = EwfTableLayout::read(source, payload_offset, payload_size)?;
        if let Some(previous_layout) = &last_table_layout
          && previous_layout != &table_layout
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
        if payload_size < DIGEST_DATA_SIZE {
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
      EwfSectionKind::Unknown => {}
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

fn section_payload_offset(section: &EwfSectionDescriptor) -> Result<u64> {
  section
    .file_offset
    .checked_add(SECTION_DESCRIPTOR_SIZE as u64)
    .ok_or_else(|| Error::InvalidRange("ewf section payload offset overflow".to_string()))
}

fn section_payload_size(section: &EwfSectionDescriptor) -> Result<usize> {
  usize::try_from(section.size)
    .map_err(|_| Error::InvalidRange("ewf section size is too large".to_string()))?
    .checked_sub(SECTION_DESCRIPTOR_SIZE)
    .ok_or_else(|| Error::InvalidRange("ewf section payload size underflow".to_string()))
}

fn parse_volume_payload(
  source: &dyn DataSource, payload_offset: u64, payload_size: usize,
) -> Result<EwfVolumeInfo> {
  let payload = source.read_bytes_at(payload_offset, payload_size)?;

  if payload_size >= E01_VOLUME_DATA_SIZE {
    EwfVolumeInfo::parse_e01(&payload)
  } else if payload_size >= S01_VOLUME_DATA_SIZE {
    EwfVolumeInfo::parse_s01(&payload)
  } else {
    Err(Error::InvalidFormat(format!(
      "unsupported ewf volume/data payload size: {payload_size}"
    )))
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, sync::Arc};

  use adler2::adler32_slice;

  use super::*;
  use crate::{
    DataSource, DataSourceHandle, RelatedSourceRequest, RelatedSourceResolver, SourceHints,
    SourceIdentity, images::ewf::constants::FILE_HEADER_MAGIC,
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

  #[derive(Default)]
  struct SparseDataSource {
    size: u64,
    regions: Vec<(u64, Vec<u8>)>,
  }

  impl SparseDataSource {
    fn with_region(mut self, offset: u64, bytes: Vec<u8>) -> Self {
      self.regions.push((offset, bytes));
      self
    }
  }

  impl DataSource for SparseDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      if offset >= self.size || buf.is_empty() {
        return Ok(0);
      }

      let available = usize::try_from(self.size - offset)
        .map_err(|_| Error::InvalidRange("test sparse read is too large".to_string()))?
        .min(buf.len());
      buf[..available].fill(0);
      for (region_offset, region) in &self.regions {
        let region_end = region_offset.saturating_add(region.len() as u64);
        let read_end = offset + available as u64;
        let overlap_start = offset.max(*region_offset);
        let overlap_end = read_end.min(region_end);
        if overlap_start >= overlap_end {
          continue;
        }

        let dst_start = usize::try_from(overlap_start - offset)
          .map_err(|_| Error::InvalidRange("test sparse overlap is too large".to_string()))?;
        let src_start = usize::try_from(overlap_start - region_offset)
          .map_err(|_| Error::InvalidRange("test sparse overlap is too large".to_string()))?;
        let overlap_len = usize::try_from(overlap_end - overlap_start)
          .map_err(|_| Error::InvalidRange("test sparse overlap is too large".to_string()))?;
        buf[dst_start..dst_start + overlap_len]
          .copy_from_slice(&region[src_start..src_start + overlap_len]);
      }

      Ok(available)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.size)
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

  #[test]
  fn parses_alpha_segment_file_name_info_with_header_context() {
    let identity = SourceIdentity::from_relative_path("images/ext2.EAA").unwrap();
    let info = EwfSegmentPathInfo::from_identity_and_header(
      &identity,
      &EwfFileHeader {
        signature: super::super::file_header::EwfFileSignature::Evf,
        segment_number: 100,
      },
    )
    .unwrap();

    assert_eq!(info.segment_number, 100);
    assert_eq!(info.file_name_for_segment(1).unwrap(), "ext2.E01");
  }

  #[test]
  fn resolves_first_segment_from_a_later_alpha_segment() {
    let volume_payload = make_e01_volume_payload(0, 1, 512);
    let volume_offset = FILE_HEADER_SIZE as u64;
    let volume_section = make_section("volume", &volume_payload, volume_offset);
    let done_offset = volume_offset + volume_section.len() as u64;
    let done_section = make_descriptor("done", done_offset, SECTION_DESCRIPTOR_SIZE as u64);
    let first_segment = [make_file_header(1), volume_section, done_section].concat();
    let resolver = Resolver {
      data: HashMap::from([(
        "images/ext2.E01".to_string(),
        Arc::new(MemDataSource {
          data: first_segment.clone(),
        }) as DataSourceHandle,
      )]),
    };
    let source: DataSourceHandle = Arc::new(MemDataSource {
      data: make_file_header(100),
    });
    let identity = SourceIdentity::from_relative_path("images/ext2.EAA").unwrap();

    let parsed = parse_with_hints(
      source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(parsed.parsed.segment_number, 1);
    assert_eq!(parsed.parsed.volume.chunk_count, 0);
    assert!(parsed.segment_sources.contains_key(&1));
  }

  #[test]
  fn accepts_large_sectors_sections_without_loading_the_payload() {
    let large_payload_size = (16 * 1024 * 1024) as u64 + 1;
    let volume_payload = make_e01_volume_payload(1, 1, 512);
    let volume_offset = FILE_HEADER_SIZE as u64;
    let volume_section = make_section("volume", &volume_payload, volume_offset);
    let sectors_offset = volume_offset + volume_section.len() as u64;
    let sectors_size = SECTION_DESCRIPTOR_SIZE as u64 + large_payload_size;
    let sectors_section = make_descriptor("sectors", sectors_offset + sectors_size, sectors_size);
    let table_offset = sectors_offset + sectors_size;
    let table_payload = make_table_payload(sectors_offset, &[0x8000_004C]);
    let table_section = make_section("table", &table_payload, table_offset);
    let table2_offset = table_offset + table_section.len() as u64;
    let table2_section = make_section("table2", &table_payload, table2_offset);
    let done_offset = table2_offset + table2_section.len() as u64;
    let done_section = make_descriptor("done", done_offset, SECTION_DESCRIPTOR_SIZE as u64);
    let source: DataSourceHandle = Arc::new(
      SparseDataSource {
        size: done_offset + done_section.len() as u64,
        ..SparseDataSource::default()
      }
      .with_region(0, make_file_header(1))
      .with_region(volume_offset, volume_section)
      .with_region(sectors_offset, sectors_section)
      .with_region(table_offset, table_section)
      .with_region(table2_offset, table2_section)
      .with_region(done_offset, done_section),
    );

    let parsed = parse(source).unwrap();

    assert_eq!(parsed.parsed.volume.chunk_count, 1);
    assert_eq!(parsed.parsed.chunk_tables.len(), 1);
    assert_eq!(parsed.parsed.chunk_tables[0].entry_count, 1);
  }

  #[test]
  fn accepts_volume_sections_with_trailing_bytes() {
    let mut volume_payload = make_e01_volume_payload(0, 1, 512);
    volume_payload.extend_from_slice(&[0xAA; 32]);
    let volume_offset = FILE_HEADER_SIZE as u64;
    let volume_section = make_section("volume", &volume_payload, volume_offset);
    let done_offset = volume_offset + volume_section.len() as u64;
    let done_section = make_descriptor("done", done_offset, SECTION_DESCRIPTOR_SIZE as u64);
    let source: DataSourceHandle = Arc::new(MemDataSource {
      data: [make_file_header(1), volume_section, done_section].concat(),
    });

    let parsed = parse(source).unwrap();

    assert_eq!(parsed.parsed.volume.chunk_count, 0);
    assert_eq!(parsed.parsed.volume.bytes_per_sector, 512);
  }

  #[test]
  fn accepts_digest_sections_with_trailing_bytes() {
    let volume_payload = make_e01_volume_payload(0, 1, 512);
    let mut digest_payload = vec![0u8; DIGEST_DATA_SIZE + 16];
    digest_payload[..16].copy_from_slice(&[0x11; 16]);
    digest_payload[16..36].copy_from_slice(&[0x22; 20]);
    let checksum = adler32_slice(&digest_payload[..76]);
    digest_payload[76..80].copy_from_slice(&checksum.to_le_bytes());
    let volume_offset = FILE_HEADER_SIZE as u64;
    let volume_section = make_section("volume", &volume_payload, volume_offset);
    let digest_offset = volume_offset + volume_section.len() as u64;
    let digest_section = make_section("digest", &digest_payload, digest_offset);
    let done_offset = digest_offset + digest_section.len() as u64;
    let done_section = make_descriptor("done", done_offset, SECTION_DESCRIPTOR_SIZE as u64);
    let source: DataSourceHandle = Arc::new(MemDataSource {
      data: [
        make_file_header(1),
        volume_section,
        digest_section,
        done_section,
      ]
      .concat(),
    });

    let parsed = parse(source).unwrap();

    assert_eq!(parsed.parsed.md5_hash, Some([0x11; 16]));
    assert_eq!(parsed.parsed.sha1_hash, Some([0x22; 20]));
  }

  fn make_file_header(segment_number: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(FILE_HEADER_SIZE);
    data.extend_from_slice(FILE_HEADER_MAGIC);
    data.push(0x01);
    data.extend_from_slice(&segment_number.to_le_bytes());
    data.extend_from_slice(&[0x00, 0x00]);
    data
  }

  fn make_descriptor(kind: &str, next_offset: u64, size: u64) -> Vec<u8> {
    let mut descriptor = vec![0u8; SECTION_DESCRIPTOR_SIZE];
    descriptor[..kind.len()].copy_from_slice(kind.as_bytes());
    descriptor[16..24].copy_from_slice(&next_offset.to_le_bytes());
    if !matches!(kind, "done" | "next") {
      descriptor[24..32].copy_from_slice(&size.to_le_bytes());
    }
    let checksum = adler32_slice(&descriptor[..72]);
    descriptor[72..76].copy_from_slice(&checksum.to_le_bytes());
    descriptor
  }

  fn make_section(kind: &str, payload: &[u8], offset: u64) -> Vec<u8> {
    let size = SECTION_DESCRIPTOR_SIZE as u64 + payload.len() as u64;
    let next_offset = offset + size;
    let mut section = make_descriptor(kind, next_offset, size);
    section.extend_from_slice(payload);
    section
  }

  fn make_e01_volume_payload(
    chunk_count: u32, sectors_per_chunk: u32, bytes_per_sector: u32,
  ) -> Vec<u8> {
    let mut payload = vec![0u8; E01_VOLUME_DATA_SIZE];
    payload[0] = 0x01;
    payload[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    payload[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    payload[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    let sector_count = u64::from(chunk_count) * u64::from(sectors_per_chunk);
    payload[16..24].copy_from_slice(&sector_count.to_le_bytes());
    payload[36] = 0x01;
    payload[52] = 0x01;
    payload[56..60].copy_from_slice(&64u32.to_le_bytes());
    payload[64..80].copy_from_slice(&[0x11; 16]);
    let checksum = adler32_slice(&payload[..1048]);
    payload[1048..1052].copy_from_slice(&checksum.to_le_bytes());
    payload
  }

  fn make_table_payload(base_offset: u64, raw_offsets: &[u32]) -> Vec<u8> {
    let mut payload = vec![0u8; 24 + raw_offsets.len() * 4 + 4];
    payload[0..4].copy_from_slice(&(raw_offsets.len() as u32).to_le_bytes());
    payload[8..16].copy_from_slice(&base_offset.to_le_bytes());
    let header_checksum = adler32_slice(&payload[..20]);
    payload[20..24].copy_from_slice(&header_checksum.to_le_bytes());
    for (index, offset) in raw_offsets.iter().enumerate() {
      let start = 24 + index * 4;
      payload[start..start + 4].copy_from_slice(&offset.to_le_bytes());
    }
    let footer_offset = 24 + raw_offsets.len() * 4;
    let footer_checksum = adler32_slice(&payload[24..footer_offset]);
    payload[footer_offset..footer_offset + 4].copy_from_slice(&footer_checksum.to_le_bytes());
    payload
  }
}
