//! Read-only EWF image surface.

use std::{collections::HashMap, io::Read, sync::Arc};

use adler2::adler32_slice;
use flate2::read::ZlibDecoder;

use super::{
  DESCRIPTOR,
  cache::EwfChunkCache,
  constants::DEFAULT_CHUNK_CACHE_CAPACITY,
  error2::EwfErrorRange,
  metadata::EwfMetadataSection,
  parser::{EwfChunkTableDescriptor, ParsedEwfSources, parse, parse_with_hints},
  table::read_entry_pair,
  types::{EwfChunkDescriptor, EwfChunkEncoding, EwfMediaType},
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

const CHUNK_CACHE_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Read-only EWF image surface.
pub struct EwfImage {
  segment_sources: HashMap<u16, ByteSourceHandle>,
  segment_number: u16,
  media_type: EwfMediaType,
  chunk_count: u32,
  chunk_size: u32,
  sectors_per_chunk: u32,
  bytes_per_sector: u32,
  media_size: u64,
  header_sections: Vec<EwfMetadataSection>,
  header2_sections: Vec<EwfMetadataSection>,
  error_ranges: Vec<EwfErrorRange>,
  md5_hash: Option<[u8; 16]>,
  sha1_hash: Option<[u8; 20]>,
  chunk_tables: Arc<[EwfChunkTableDescriptor]>,
  chunk_cache: EwfChunkCache,
}

impl EwfImage {
  /// Open an EWF image from a single segment source.
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::from_parsed(parse(source)?)
  }

  /// Open an EWF image using source hints for multi-segment resolution.
  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    Self::from_parsed(parse_with_hints(source, hints)?)
  }

  fn from_parsed(parsed: ParsedEwfSources) -> Result<Self> {
    let ParsedEwfSources {
      parsed,
      segment_sources,
    } = parsed;
    let media_size = parsed.volume.media_size()?;
    let chunk_size = parsed.volume.chunk_size()?;
    let chunk_cache_capacity = bounded_cache_capacity(
      usize::try_from(chunk_size)
        .map_err(|_| Error::InvalidRange("ewf chunk size is too large".to_string()))?,
      CHUNK_CACHE_BUDGET_BYTES,
      DEFAULT_CHUNK_CACHE_CAPACITY,
    );

    Ok(Self {
      segment_sources,
      segment_number: parsed.segment_number,
      media_type: parsed.volume.media_type,
      chunk_count: parsed.volume.chunk_count,
      chunk_size,
      sectors_per_chunk: parsed.volume.sectors_per_chunk,
      bytes_per_sector: parsed.volume.bytes_per_sector,
      media_size,
      header_sections: parsed.header_sections,
      header2_sections: parsed.header2_sections,
      error_ranges: parsed.error_ranges,
      md5_hash: parsed.md5_hash,
      sha1_hash: parsed.sha1_hash,
      chunk_tables: Arc::from(parsed.chunk_tables),
      chunk_cache: EwfChunkCache::new(chunk_cache_capacity),
    })
  }

  /// Return the EWF segment number of the first segment source.
  pub fn segment_number(&self) -> u16 {
    self.segment_number
  }

  /// Return the number of resolved segment sources.
  pub fn segment_count(&self) -> usize {
    self.segment_sources.len()
  }

  /// Return the parsed media type.
  pub fn media_type(&self) -> EwfMediaType {
    self.media_type
  }

  /// Return the number of logical chunks.
  pub fn chunk_count(&self) -> u32 {
    self.chunk_count
  }

  /// Return the number of sectors per chunk.
  pub fn sectors_per_chunk(&self) -> u32 {
    self.sectors_per_chunk
  }

  /// Return the number of bytes per sector.
  pub fn bytes_per_sector(&self) -> u32 {
    self.bytes_per_sector
  }

  /// Return parsed ASCII `header` sections.
  pub fn header_sections(&self) -> &[EwfMetadataSection] {
    &self.header_sections
  }

  /// Return parsed UTF-16 `header2` sections.
  pub fn header2_sections(&self) -> &[EwfMetadataSection] {
    &self.header2_sections
  }

  /// Return the media error ranges reported by `error2` sections.
  pub fn error_ranges(&self) -> &[EwfErrorRange] {
    &self.error_ranges
  }

  /// Return the optional MD5 hash from the metadata.
  pub fn md5_hash(&self) -> Option<[u8; 16]> {
    self.md5_hash
  }

  /// Return the optional SHA1 hash from the metadata.
  pub fn sha1_hash(&self) -> Option<[u8; 20]> {
    self.sha1_hash
  }

  fn find_chunk_table(&self, chunk_index: u32) -> Result<&EwfChunkTableDescriptor> {
    let table_index = self
      .chunk_tables
      .partition_point(|table| table.start_chunk_index <= chunk_index)
      .checked_sub(1)
      .ok_or_else(|| {
        Error::InvalidRange(format!("ewf chunk index {chunk_index} is out of bounds"))
      })?;
    let table = self.chunk_tables.get(table_index).ok_or_else(|| {
      Error::InvalidRange(format!("ewf chunk index {chunk_index} is out of bounds"))
    })?;
    if !table.contains_chunk(chunk_index) {
      return Err(Error::InvalidRange(format!(
        "ewf chunk index {chunk_index} is out of bounds"
      )));
    }

    Ok(table)
  }

  fn read_chunk(&self, chunk_index: u32) -> Result<Arc<[u8]>> {
    self.chunk_cache.get_or_load(chunk_index, || {
      let chunk = self.resolve_chunk_descriptor(chunk_index)?;
      self.load_chunk(&chunk)
    })
  }

  fn resolve_chunk_descriptor(&self, chunk_index: u32) -> Result<EwfChunkDescriptor> {
    let table_descriptor = self.find_chunk_table(chunk_index)?;
    let local_index = table_descriptor.local_chunk_index(chunk_index)?;
    let source = self
      .segment_sources
      .get(&table_descriptor.segment_number)
      .ok_or_else(|| {
        Error::NotFound(format!(
          "ewf segment {} is missing for chunk {}",
          table_descriptor.segment_number, chunk_index
        ))
      })?;
    let (entry, next_entry) = read_entry_pair(
      source.as_ref(),
      table_descriptor.entries_offset,
      table_descriptor.entry_count,
      local_index,
    )?;
    let overflow_offsets = table_descriptor.is_overflow_index(local_index);
    let current_offset = if overflow_offsets {
      entry.raw_offset
    } else {
      entry.offset()
    };
    let next_offset = if let Some(next_entry) = next_entry {
      let next_offset = if table_descriptor.is_overflow_index(local_index + 1) {
        next_entry.raw_offset
      } else {
        next_entry.offset()
      };
      if next_offset < current_offset {
        if table_descriptor.is_overflow_index(local_index + 1)
          || next_entry.raw_offset < current_offset
        {
          return Err(Error::InvalidFormat(
            "ewf chunk offsets must be monotonically increasing within a table".to_string(),
          ));
        }
        u64::from(next_entry.raw_offset)
      } else {
        u64::from(next_offset)
      }
    } else {
      table_descriptor
        .data_end_offset
        .checked_sub(table_descriptor.base_offset)
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

    let chunk_size = u64::from(self.chunk_size);
    let media_offset = u64::from(chunk_index)
      .checked_mul(chunk_size)
      .ok_or_else(|| Error::InvalidRange("ewf chunk media offset overflow".to_string()))?;
    let remaining_media_size = self
      .media_size
      .checked_sub(media_offset)
      .ok_or_else(|| Error::InvalidRange("ewf chunk media range underflow".to_string()))?;
    let logical_size = remaining_media_size.min(chunk_size) as u32;
    let stored_offset = table_descriptor
      .base_offset
      .checked_add(u64::from(current_offset))
      .ok_or_else(|| Error::InvalidRange("ewf chunk file offset overflow".to_string()))?;

    Ok(EwfChunkDescriptor {
      chunk_index,
      segment_number: table_descriptor.segment_number,
      media_offset,
      logical_size,
      stored_offset,
      stored_size,
      encoding: if overflow_offsets {
        EwfChunkEncoding::Stored
      } else if entry.is_compressed() {
        EwfChunkEncoding::Compressed
      } else {
        EwfChunkEncoding::Stored
      },
    })
  }

  fn load_chunk(&self, chunk: &EwfChunkDescriptor) -> Result<Arc<[u8]>> {
    let source = self
      .segment_sources
      .get(&chunk.segment_number)
      .ok_or_else(|| {
        Error::NotFound(format!(
          "ewf segment {} is missing for chunk {}",
          chunk.segment_number, chunk.chunk_index
        ))
      })?;
    let stored = source.read_bytes_at(chunk.stored_offset, chunk.stored_size as usize)?;

    match chunk.encoding {
      EwfChunkEncoding::Compressed => self.decompress_chunk(chunk, &stored),
      EwfChunkEncoding::Stored => self.read_stored_chunk(chunk, &stored),
    }
  }

  fn decompress_chunk(&self, chunk: &EwfChunkDescriptor, stored: &[u8]) -> Result<Arc<[u8]>> {
    let mut decoder = ZlibDecoder::new(stored);
    let mut data = vec![0u8; chunk.logical_size as usize];
    decoder.read_exact(&mut data).map_err(Error::Io)?;

    Ok(Arc::from(data))
  }

  fn read_stored_chunk(&self, chunk: &EwfChunkDescriptor, stored: &[u8]) -> Result<Arc<[u8]>> {
    let expected_stored_size = chunk
      .logical_size
      .checked_add(4)
      .ok_or_else(|| Error::InvalidRange("ewf stored chunk size overflow".to_string()))?
      as usize;
    if stored.len() != expected_stored_size {
      return Err(Error::InvalidFormat(format!(
        "ewf stored chunk size mismatch: expected {expected_stored_size}, got {}",
        stored.len()
      )));
    }

    let data_len = chunk.logical_size as usize;
    let stored_checksum = u32::from_le_bytes([
      stored[data_len],
      stored[data_len + 1],
      stored[data_len + 2],
      stored[data_len + 3],
    ]);
    let calculated_checksum = adler32_slice(&stored[..data_len]);
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf stored chunk checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    Ok(Arc::from(stored[..data_len].to_vec()))
  }
}

fn bounded_cache_capacity(entry_size: usize, byte_budget: usize, max_entries: usize) -> usize {
  if entry_size == 0 || max_entries == 0 {
    return 1;
  }

  (byte_budget / entry_size).max(1).min(max_entries)
}

impl ByteSource for EwfImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("ewf read offset overflow".to_string()))?;
      if absolute_offset >= self.media_size {
        break;
      }

      let chunk_size = u64::from(self.chunk_size);
      let chunk_index = u32::try_from(absolute_offset / chunk_size)
        .map_err(|_| Error::InvalidRange("ewf chunk index overflow".to_string()))?;
      let chunk_offset = usize::try_from(absolute_offset % chunk_size)
        .map_err(|_| Error::InvalidRange("ewf chunk offset overflow".to_string()))?;
      let chunk = self.read_chunk(chunk_index)?;
      let available = (chunk.len() - chunk_offset).min(buf.len() - copied);
      buf[copied..copied + available]
        .copy_from_slice(&chunk[chunk_offset..chunk_offset + available]);
      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size((self.sectors_per_chunk * self.bytes_per_sector) as usize)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.ewf"
  }
}

impl Image for EwfImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(self.bytes_per_sector)
  }
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;
  use crate::ByteSource;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl MemDataSource {
    fn from_fixture(relative_path: &str) -> Self {
      let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join(relative_path);
      Self {
        data: std::fs::read(path).unwrap(),
      }
    }
  }

  impl ByteSource for MemDataSource {
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

  fn sample_source(relative_path: &str) -> ByteSourceHandle {
    Arc::new(MemDataSource::from_fixture(relative_path))
  }

  #[test]
  fn scales_chunk_cache_capacity_to_the_chunk_budget() {
    assert_eq!(
      bounded_cache_capacity(32 * 1024, CHUNK_CACHE_BUDGET_BYTES, 64),
      64
    );
    assert_eq!(
      bounded_cache_capacity(128 * 1024 * 1024, CHUNK_CACHE_BUDGET_BYTES, 64),
      1
    );
  }

  #[test]
  fn opens_sample_metadata() {
    let image = EwfImage::open(sample_source("ewf/ext2.E01")).unwrap();

    assert_eq!(image.segment_number(), 1);
    assert_eq!(image.segment_count(), 1);
    assert_eq!(image.media_type(), EwfMediaType::Fixed);
    assert_eq!(image.chunk_count(), 128);
    assert_eq!(image.sectors_per_chunk(), 64);
    assert_eq!(image.bytes_per_sector(), 512);
    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(image.header_sections().len(), 1);
    assert_eq!(image.header_sections()[0].main_field("c"), Some("case"));
    assert_eq!(image.header_sections()[0].main_field("n"), Some("evidence"));
    assert_eq!(
      image.header_sections()[0].main_field("a"),
      Some("description")
    );
    assert_eq!(image.header2_sections().len(), 1);
    assert_eq!(
      image.header2_sections()[0].main_field("a"),
      Some("description")
    );
    assert!(image.error_ranges().is_empty());
    assert_eq!(
      image.md5_hash().unwrap(),
      [
        0xB1, 0x76, 0x0D, 0x0B, 0x35, 0xA5, 0x12, 0xEF, 0x56, 0x97, 0x0D, 0xF4, 0xE6, 0xF8, 0xC5,
        0xD6,
      ]
    );
  }

  #[test]
  fn reads_all_media_bytes_matching_the_raw_fixture() {
    let image = EwfImage::open(sample_source("ewf/ext2.E01")).unwrap();
    let raw = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("ext/ext2.raw"),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), raw);
  }

  #[test]
  fn reads_across_chunk_boundaries() {
    let image = EwfImage::open(sample_source("ewf/ext2.E01")).unwrap();
    let raw = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("ext/ext2.raw"),
    )
    .unwrap();
    let mut buf = vec![0u8; 1024];

    image.read_exact_at(32_700, &mut buf).unwrap();

    assert_eq!(&buf, &raw[32_700..32_700 + 1024]);
  }
}

crate::images::driver::impl_image_data_source!(EwfImage);
