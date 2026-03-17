//! EWF driver open flow.

use super::{DESCRIPTOR, image::EwfImage};
use crate::{
  DataSourceHandle, Result, SourceHints,
  images::{Image, ImageDriver},
};

/// Driver for Expert Witness Compression Format images.
#[derive(Debug, Default, Clone, Copy)]
pub struct EwfDriver;

impl EwfDriver {
  /// Create a new EWF driver.
  pub const fn new() -> Self {
    Self
  }

  /// Open an EWF image from a single segment source.
  pub fn open(source: DataSourceHandle) -> Result<EwfImage> {
    EwfImage::open(source)
  }

  /// Open an EWF image using source hints for multi-segment resolution.
  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<EwfImage> {
    EwfImage::open_with_hints(source, hints)
  }
}

impl ImageDriver for EwfDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Image>> {
    Ok(Box::new(Self::open_with_hints(source, hints)?))
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, io::Write, sync::Arc};

  use adler2::adler32_slice;
  use flate2::{Compression, write::ZlibEncoder};

  use super::*;
  use crate::{
    DataSource, RelatedSourceRequest, RelatedSourceResolver, SourceIdentity,
    images::ewf::constants::{
      E01_VOLUME_DATA_SIZE, FILE_HEADER_MAGIC, FILE_HEADER_MAGIC_LVF, S01_VOLUME_DATA_SIZE,
      SECTION_DESCRIPTOR_SIZE,
    },
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
    files: HashMap<String, DataSourceHandle>,
  }

  impl RelatedSourceResolver for Resolver {
    fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<DataSourceHandle>> {
      Ok(self.files.get(&request.path.to_string()).cloned())
    }
  }

  struct TestSection<'a> {
    kind: &'a str,
    payload: Vec<u8>,
    zero_sized: bool,
  }

  #[test]
  fn opens_a_multi_segment_e01_image_via_resolver_hints() {
    let chunk0 = repeat_byte(0x11, 512);
    let chunk1 = repeat_byte(0x22, 512);
    let chunk2 = repeat_byte(0x33, 512);
    let volume_payload = make_e01_volume_payload(3, 1, 512);

    let mut segment1_sections = vec![TestSection {
      kind: "volume",
      payload: volume_payload.clone(),
      zero_sized: false,
    }];
    segment1_sections.extend(chunk_sections(vec![
      (compress_chunk(&chunk0), true),
      (store_chunk(&chunk1), false),
    ]));
    segment1_sections.push(TestSection {
      kind: "next",
      payload: vec![],
      zero_sized: true,
    });
    let segment1 = build_segment(1, FILE_HEADER_MAGIC, segment1_sections);

    let mut segment2_sections = vec![TestSection {
      kind: "data",
      payload: volume_payload,
      zero_sized: false,
    }];
    segment2_sections.extend(chunk_sections(vec![(compress_chunk(&chunk2), true)]));
    segment2_sections.push(TestSection {
      kind: "done",
      payload: vec![],
      zero_sized: true,
    });
    let segment2 = build_segment(2, FILE_HEADER_MAGIC, segment2_sections);

    let resolver = Resolver {
      files: HashMap::from([
        (
          "images/demo.E01".to_string(),
          Arc::new(MemDataSource {
            data: segment1.clone(),
          }) as DataSourceHandle,
        ),
        (
          "images/demo.E02".to_string(),
          Arc::new(MemDataSource {
            data: segment2.clone(),
          }) as DataSourceHandle,
        ),
      ]),
    };
    let identity = SourceIdentity::from_relative_path("images/demo.E01").unwrap();
    let source: DataSourceHandle = Arc::new(MemDataSource { data: segment1 });
    let image = EwfDriver::open_with_hints(
      source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.segment_count(), 2);
    assert_eq!(image.chunk_count(), 3);
    assert_eq!(image.read_all().unwrap(), [chunk0, chunk1, chunk2].concat());
  }

  #[test]
  fn resolves_back_to_the_first_numeric_segment() {
    let chunk0 = repeat_byte(0xAA, 512);
    let chunk1 = repeat_byte(0xBB, 512);
    let volume_payload = make_e01_volume_payload(2, 1, 512);
    let mut segment1_sections = vec![TestSection {
      kind: "volume",
      payload: volume_payload.clone(),
      zero_sized: false,
    }];
    segment1_sections.extend(chunk_sections(vec![(compress_chunk(&chunk0), true)]));
    segment1_sections.push(TestSection {
      kind: "next",
      payload: vec![],
      zero_sized: true,
    });
    let segment1 = build_segment(1, FILE_HEADER_MAGIC, segment1_sections);

    let mut segment2_sections = vec![TestSection {
      kind: "data",
      payload: volume_payload,
      zero_sized: false,
    }];
    segment2_sections.extend(chunk_sections(vec![(compress_chunk(&chunk1), true)]));
    segment2_sections.push(TestSection {
      kind: "done",
      payload: vec![],
      zero_sized: true,
    });
    let segment2 = build_segment(2, FILE_HEADER_MAGIC, segment2_sections);

    let resolver = Resolver {
      files: HashMap::from([
        (
          "images/demo.E01".to_string(),
          Arc::new(MemDataSource {
            data: segment1.clone(),
          }) as DataSourceHandle,
        ),
        (
          "images/demo.E02".to_string(),
          Arc::new(MemDataSource {
            data: segment2.clone(),
          }) as DataSourceHandle,
        ),
      ]),
    };
    let identity = SourceIdentity::from_relative_path("images/demo.E02").unwrap();
    let source: DataSourceHandle = Arc::new(MemDataSource { data: segment2 });
    let image = EwfDriver::open_with_hints(
      source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.segment_number(), 1);
    assert_eq!(image.segment_count(), 2);
    assert_eq!(image.read_all().unwrap(), [chunk0, chunk1].concat());
  }

  #[test]
  fn opens_single_segment_lvf_images() {
    let chunk = repeat_byte(0x44, 512);
    let volume_payload = make_logical_evidence_volume_payload(1, 1, 512);
    let mut sections = vec![TestSection {
      kind: "volume",
      payload: volume_payload,
      zero_sized: false,
    }];
    sections.extend(chunk_sections(vec![(compress_chunk(&chunk), true)]));
    sections.push(TestSection {
      kind: "done",
      payload: vec![],
      zero_sized: true,
    });
    let source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_segment(1, FILE_HEADER_MAGIC_LVF, sections),
    });

    let image = EwfDriver::open(source).unwrap();

    assert_eq!(
      image.media_type(),
      super::super::types::EwfMediaType::LogicalEvidence
    );
    assert_eq!(image.read_all().unwrap(), chunk);
  }

  #[test]
  fn opens_s01_style_inline_table_chunks() {
    let chunk0 = repeat_byte(0x55, 512);
    let chunk1 = repeat_byte(0x66, 512);
    let volume_payload = make_s01_volume_payload(2, 1, 512);
    let table_section = inline_table_section(vec![
      (compress_chunk(&chunk0), true),
      (compress_chunk(&chunk1), true),
    ]);
    let source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_segment(
        1,
        FILE_HEADER_MAGIC,
        vec![
          TestSection {
            kind: "volume",
            payload: volume_payload,
            zero_sized: false,
          },
          table_section,
          TestSection {
            kind: "done",
            payload: vec![],
            zero_sized: true,
          },
        ],
      ),
    });

    let image = EwfDriver::open(source).unwrap();

    assert_eq!(image.read_all().unwrap(), [chunk0, chunk1].concat());
  }

  fn repeat_byte(byte: u8, size: usize) -> Vec<u8> {
    vec![byte; size]
  }

  fn compress_chunk(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
  }

  fn store_chunk(data: &[u8]) -> Vec<u8> {
    let mut stored = data.to_vec();
    stored.extend_from_slice(&adler32_slice(data).to_le_bytes());
    stored
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

  fn make_logical_evidence_volume_payload(
    chunk_count: u32, sectors_per_chunk: u32, bytes_per_sector: u32,
  ) -> Vec<u8> {
    let mut payload = make_e01_volume_payload(chunk_count, sectors_per_chunk, bytes_per_sector);
    payload[0] = 0x0E;
    let checksum = adler32_slice(&payload[..1048]);
    payload[1048..1052].copy_from_slice(&checksum.to_le_bytes());
    payload
  }

  fn make_s01_volume_payload(
    chunk_count: u32, sectors_per_chunk: u32, bytes_per_sector: u32,
  ) -> Vec<u8> {
    let mut payload = vec![0u8; S01_VOLUME_DATA_SIZE];
    payload[0..4].copy_from_slice(&1u32.to_le_bytes());
    payload[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    payload[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    payload[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    payload[16..20].copy_from_slice(&(chunk_count * sectors_per_chunk).to_le_bytes());
    payload[85..90].copy_from_slice(b"SMART");
    let checksum = adler32_slice(&payload[..90]);
    payload[90..94].copy_from_slice(&checksum.to_le_bytes());
    payload
  }

  fn chunk_sections(chunks: Vec<(Vec<u8>, bool)>) -> Vec<TestSection<'static>> {
    let mut sectors_payload = Vec::new();
    let mut raw_offsets = Vec::with_capacity(chunks.len());
    let mut next_offset = SECTION_DESCRIPTOR_SIZE as u32;

    for (chunk, compressed) in &chunks {
      let raw_offset = if *compressed {
        0x8000_0000 | next_offset
      } else {
        next_offset
      };
      raw_offsets.push(raw_offset);
      sectors_payload.extend_from_slice(chunk);
      next_offset = next_offset
        .checked_add(u32::try_from(chunk.len()).unwrap())
        .unwrap();
    }

    let sectors_section = TestSection {
      kind: "sectors",
      payload: sectors_payload.clone(),
      zero_sized: false,
    };
    let table_payload = make_table_payload(&raw_offsets);
    let table2_payload = table_payload.clone();

    let table_section = TestSection {
      kind: "table",
      payload: table_payload,
      zero_sized: false,
    };
    let table2_section = TestSection {
      kind: "table2",
      payload: table2_payload,
      zero_sized: false,
    };

    vec![sectors_section, table_section, table2_section]
  }

  fn inline_table_section(chunks: Vec<(Vec<u8>, bool)>) -> TestSection<'static> {
    let mut table_payload = vec![0u8; 24 + chunks.len() * 4 + 4];
    table_payload[0..4].copy_from_slice(&(chunks.len() as u32).to_le_bytes());
    let header_checksum = adler32_slice(&table_payload[..20]);
    table_payload[20..24].copy_from_slice(&header_checksum.to_le_bytes());

    let section_base = 13u32 + SECTION_DESCRIPTOR_SIZE as u32 + S01_VOLUME_DATA_SIZE as u32;
    let table_start = section_base + SECTION_DESCRIPTOR_SIZE as u32;
    let mut chunk_offset = table_start + u32::try_from(table_payload.len()).unwrap();
    for (index, (chunk, compressed)) in chunks.iter().enumerate() {
      let raw_offset = if *compressed {
        0x8000_0000 | chunk_offset
      } else {
        chunk_offset
      };
      let start = 24 + index * 4;
      table_payload[start..start + 4].copy_from_slice(&raw_offset.to_le_bytes());
      chunk_offset = chunk_offset
        .checked_add(u32::try_from(chunk.len()).unwrap())
        .unwrap();
    }
    let footer_offset = 24 + chunks.len() * 4;
    let footer_checksum = adler32_slice(&table_payload[24..footer_offset]);
    table_payload[footer_offset..footer_offset + 4].copy_from_slice(&footer_checksum.to_le_bytes());

    for (chunk, _) in chunks {
      table_payload.extend_from_slice(&chunk);
    }

    TestSection {
      kind: "table",
      payload: table_payload,
      zero_sized: false,
    }
  }

  fn make_table_payload(raw_offsets: &[u32]) -> Vec<u8> {
    let mut payload = vec![0u8; 24 + raw_offsets.len() * 4 + 4];
    payload[0..4].copy_from_slice(&(raw_offsets.len() as u32).to_le_bytes());
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

  fn build_segment(
    segment_number: u16, magic: &[u8], sections: Vec<TestSection<'static>>,
  ) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(magic);
    data.push(0x01);
    data.extend_from_slice(&segment_number.to_le_bytes());
    data.extend_from_slice(&[0x00, 0x00]);

    let mut offset = 13u64;
    let built_sections: Vec<Vec<u8>> = sections
      .into_iter()
      .map(|section| {
        let size = if section.zero_sized {
          SECTION_DESCRIPTOR_SIZE
        } else {
          SECTION_DESCRIPTOR_SIZE + section.payload.len()
        };
        let next_offset = if matches!(section.kind, "next" | "done") {
          offset
        } else {
          offset + size as u64
        };
        let mut section_bytes = vec![0u8; size];
        section_bytes[..16].copy_from_slice(padded_type(section.kind));
        section_bytes[16..24].copy_from_slice(&next_offset.to_le_bytes());
        if !section.zero_sized {
          section_bytes[24..32].copy_from_slice(&(size as u64).to_le_bytes());
          section_bytes[76..].copy_from_slice(&section.payload);
        }
        let checksum = adler32_slice(&section_bytes[..72]);
        section_bytes[72..76].copy_from_slice(&checksum.to_le_bytes());
        offset += size as u64;
        section_bytes
      })
      .collect();

    // fix table base offsets after section locations are known
    let mut rebuilt = Vec::new();
    let mut absolute_offset = 13u64;
    let mut pending_sector_base = None;
    for mut section in built_sections {
      let kind = section[..16].split(|byte| *byte == 0).next().unwrap();
      match kind {
        b"sectors" => {
          pending_sector_base = Some(absolute_offset);
        }
        b"table" | b"table2" => {
          if let Some(base_offset) = pending_sector_base {
            section[76 + 8..76 + 16].copy_from_slice(&base_offset.to_le_bytes());
            let checksum = adler32_slice(&section[76..76 + 20]);
            section[76 + 20..76 + 24].copy_from_slice(&checksum.to_le_bytes());
          }
        }
        _ => {}
      }
      absolute_offset += section.len() as u64;
      rebuilt.extend_from_slice(&section);
    }
    data.extend_from_slice(&rebuilt);
    data
  }

  fn padded_type(name: &str) -> &'static [u8; 16] {
    let mut value = [0u8; 16];
    let bytes = name.as_bytes();
    value[..bytes.len()].copy_from_slice(bytes);
    Box::leak(Box::new(value))
  }
}
