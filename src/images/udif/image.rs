//! Read-only UDIF image surface.

use std::{io::Read, sync::Arc};

use adc::AdcDecoder;
use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use xz2::read::XzDecoder;

use super::{
  DESCRIPTOR,
  block_map::{SECTOR_SIZE, UdifCompressionMethod, UdifRange, UdifRangeKind},
  cache::UdifCache,
  parser::parse,
  trailer::UdifTrailer,
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

const MAX_DECOMPRESSED_CACHE_ENTRIES: usize = 8;
const MAX_CACHED_DECOMPRESSED_RANGE_SIZE: usize = 8 * 1024 * 1024;

#[allow(dead_code)]
pub struct UdifImage {
  source: ByteSourceHandle,
  trailer: UdifTrailer,
  media_size: u64,
  ranges: Arc<[UdifRange]>,
  compression_method: UdifCompressionMethod,
  has_sparse_ranges: bool,
  decompressed_cache: UdifCache<Vec<u8>>,
}

impl UdifImage {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let parsed = parse(source.clone())?;

    Ok(Self {
      source,
      trailer: parsed.trailer,
      media_size: parsed.media_size,
      ranges: parsed.ranges,
      compression_method: parsed.compression_method,
      has_sparse_ranges: parsed.has_sparse_ranges,
      decompressed_cache: UdifCache::new(MAX_DECOMPRESSED_CACHE_ENTRIES),
    })
  }

  pub fn trailer(&self) -> &UdifTrailer {
    &self.trailer
  }

  pub fn compression_method(&self) -> UdifCompressionMethod {
    self.compression_method
  }

  fn find_range_index(&self, offset: u64) -> Option<usize> {
    let index = self
      .ranges
      .partition_point(|range| range.media_offset <= offset);
    if index == 0 {
      return None;
    }

    let candidate_index = index - 1;
    let candidate = &self.ranges[candidate_index];
    let end = candidate.media_offset.checked_add(candidate.size)?;
    (offset < end).then_some(candidate_index)
  }

  fn read_decompressed_range(&self, index: usize, range: &UdifRange) -> Result<Arc<Vec<u8>>> {
    let expected_size = usize::try_from(range.size)
      .map_err(|_| Error::InvalidRange("udif range size is too large".to_string()))?;
    let load_range = || self.decompress_range(index, range, expected_size);

    if should_cache_decompressed_range(expected_size) {
      self
        .decompressed_cache
        .get_or_load(range.media_offset, load_range)
    } else {
      load_range()
    }
  }

  fn decompress_range(
    &self, index: usize, range: &UdifRange, expected_size: usize,
  ) -> Result<Arc<Vec<u8>>> {
    let compressed = self.source.read_bytes_at(
      range.data_offset,
      usize::try_from(range.data_size)
        .map_err(|_| Error::InvalidRange("udif compressed range is too large".to_string()))?,
    )?;
    let mut output = vec![0u8; expected_size];

    match range.kind {
      UdifRangeKind::Adc => {
        let mut decoder = AdcDecoder::new(compressed.as_slice());
        read_full(&mut decoder, &mut output)?;
      }
      UdifRangeKind::Zlib => {
        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        read_full(&mut decoder, &mut output)?;
      }
      UdifRangeKind::Bzip2 => {
        let mut decoder = BzDecoder::new(compressed.as_slice());
        read_full(&mut decoder, &mut output)?;
      }
      UdifRangeKind::Lzfse => {
        let output_len = expected_size
          .checked_add(1)
          .ok_or_else(|| Error::InvalidRange("udif lzfse buffer overflow".to_string()))?;
        let mut decoded = vec![0u8; output_len];
        let decoded_size = lzfse::decode_buffer(&compressed, &mut decoded).map_err(|error| {
          Error::InvalidFormat(format!("unable to decompress udif lzfse block: {error:?}"))
        })?;
        if decoded_size != expected_size {
          return Err(Error::InvalidFormat(
            "udif lzfse block does not expand to the expected size".to_string(),
          ));
        }
        output.copy_from_slice(&decoded[..expected_size]);
      }
      UdifRangeKind::Lzma => {
        let mut decoder = XzDecoder::new(compressed.as_slice());
        read_full(&mut decoder, &mut output)?;
      }
      UdifRangeKind::Raw | UdifRangeKind::Sparse => {
        return Err(Error::InvalidFormat(format!(
          "udif range {index} does not require decompression"
        )));
      }
    }

    Ok(Arc::new(output))
  }
}

fn should_cache_decompressed_range(expected_size: usize) -> bool {
  expected_size <= MAX_CACHED_DECOMPRESSED_RANGE_SIZE
}

impl ByteSource for UdifImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("udif read offset overflow".to_string()))?;
      if absolute_offset >= self.media_size {
        break;
      }

      let remaining = usize::try_from(self.media_size - absolute_offset)
        .map_err(|_| Error::InvalidRange("udif remaining size is too large".to_string()))?;
      if let Some(range_index) = self.find_range_index(absolute_offset) {
        let range = &self.ranges[range_index];
        let within_range = absolute_offset - range.media_offset;
        let available = usize::try_from(range.size - within_range)
          .map_err(|_| Error::InvalidRange("udif range size is too large".to_string()))?
          .min(buf.len() - copied)
          .min(remaining);

        match range.kind {
          UdifRangeKind::Sparse => {
            buf[copied..copied + available].fill(0);
          }
          UdifRangeKind::Raw => {
            if within_range >= range.data_size {
              buf[copied..copied + available].fill(0);
            } else {
              let readable = usize::try_from(range.data_size - within_range)
                .map_err(|_| Error::InvalidRange("udif raw payload is too large".to_string()))?
                .min(available);
              self.source.read_exact_at(
                range.data_offset + within_range,
                &mut buf[copied..copied + readable],
              )?;
              if readable < available {
                buf[copied + readable..copied + available].fill(0);
              }
            }
          }
          UdifRangeKind::Adc
          | UdifRangeKind::Zlib
          | UdifRangeKind::Bzip2
          | UdifRangeKind::Lzfse
          | UdifRangeKind::Lzma => {
            let range_data = self.read_decompressed_range(range_index, range)?;
            let range_offset = usize::try_from(within_range)
              .map_err(|_| Error::InvalidRange("udif range offset is too large".to_string()))?;
            buf[copied..copied + available]
              .copy_from_slice(&range_data[range_offset..range_offset + available]);
          }
        }

        copied += available;
      } else {
        let next_offset = self
          .ranges
          .iter()
          .find(|range| range.media_offset > absolute_offset)
          .map(|range| range.media_offset)
          .unwrap_or(self.media_size);
        let gap = usize::try_from(next_offset - absolute_offset)
          .map_err(|_| Error::InvalidRange("udif gap size is too large".to_string()))?
          .min(buf.len() - copied)
          .min(remaining);
        buf[copied..copied + gap].fill(0);
        copied += gap;
      }
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size(64 * 1024)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.udif"
  }
}

impl Image for UdifImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(SECTOR_SIZE as u32)
  }

  fn physical_sector_size(&self) -> Option<u32> {
    self.logical_sector_size()
  }

  fn is_sparse(&self) -> bool {
    self.has_sparse_ranges
  }
}

fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
  let mut total = 0usize;
  while total < buf.len() {
    match reader.read(&mut buf[total..]) {
      Ok(0) => break,
      Ok(read_count) => total += read_count,
      Err(error) => return Err(Error::Io(error)),
    }
  }

  Ok(total)
}

#[cfg(test)]
mod tests {
  use std::{
    io::Write,
    path::Path,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
  };

  use flate2::{Compression, write::ZlibEncoder};

  use super::*;
  use crate::images::udif::trailer::UdifTrailer;

  struct MemDataSource {
    data: Vec<u8>,
  }

  struct CountingDataSource {
    data: Vec<u8>,
    reads: AtomicUsize,
  }

  impl ByteSource for MemDataSource {
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

  impl ByteSource for CountingDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      self.reads.fetch_add(1, Ordering::Relaxed);
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

  fn sample_source(relative_path: &str) -> ByteSourceHandle {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Arc::new(MemDataSource {
      data: std::fs::read(path).unwrap(),
    })
  }

  fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
  }

  fn synthetic_raw_udif(payload: &[u8]) -> Vec<u8> {
    let sector_count = payload.len().div_ceil(SECTOR_SIZE as usize);
    let mut image = vec![0u8; payload.len() + 512];
    image[..payload.len()].copy_from_slice(payload);
    let trailer = &mut image[payload.len()..payload.len() + 512];
    trailer[0..4].copy_from_slice(b"koly");
    trailer[4..8].copy_from_slice(&4u32.to_be_bytes());
    trailer[8..12].copy_from_slice(&512u32.to_be_bytes());
    trailer[24..32].copy_from_slice(&0u64.to_be_bytes());
    trailer[32..40].copy_from_slice(&(payload.len() as u64).to_be_bytes());
    trailer[488..492].copy_from_slice(&1u32.to_be_bytes());
    trailer[492..500].copy_from_slice(&(sector_count as u64).to_be_bytes());
    image
  }

  fn compress_zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
  }

  fn synthetic_trailer(data_size: u64, sector_count: u64) -> UdifTrailer {
    UdifTrailer {
      flags: 0,
      data_fork_offset: 0,
      data_fork_size: data_size,
      plist_offset: 0,
      plist_size: 0,
      data_checksum_type: 0,
      data_checksum: [0; 128],
      master_checksum_type: 0,
      master_checksum: [0; 128],
      image_type: 1,
      sector_count,
    }
  }

  #[test]
  fn opens_udif_fixture_metadata() {
    let image = UdifImage::open(sample_source("udif/hfsplus_zlib.dmg")).unwrap();

    assert_eq!(image.size().unwrap(), 1_964_032);
    assert_eq!(image.logical_sector_size(), Some(512));
    assert_eq!(image.compression_method(), UdifCompressionMethod::Zlib);
    assert!(image.is_sparse());
  }

  #[test]
  fn reads_full_udif_fixture_variants() {
    let cases = [
      (
        "udif/hfsplus_zlib.dmg",
        UdifCompressionMethod::Zlib,
        "399bfcc39637bde7e43eb86fcc8565ae",
      ),
      (
        "udif/hfsplus_bzip2.dmg",
        UdifCompressionMethod::Bzip2,
        "7ec785450bbc17de417be373fd5d2159",
      ),
      (
        "udif/hfsplus_lzfse.dmg",
        UdifCompressionMethod::Lzfse,
        "c2c160c788676641725fd1a4b8da733b",
      ),
      (
        "udif/hfsplus_lzma.dmg",
        UdifCompressionMethod::Lzma,
        "ee3b14a7a0824c9d06bfeab97c614767",
      ),
      (
        "udif/hfsplus_adc.dmg",
        UdifCompressionMethod::Adc,
        "08c32fd5d0fc1c2274d1c2d34185312a",
      ),
    ];

    for (path, method, expected_md5) in cases {
      let image = UdifImage::open(sample_source(path)).unwrap();

      assert_eq!(image.compression_method(), method, "fixture {path}");
      assert_eq!(
        md5_hex(&image.read_all().unwrap()),
        expected_md5,
        "fixture {path}"
      );
    }
  }

  #[test]
  fn reads_raw_udif_without_a_plist() {
    let payload = vec![0x5A; 4096];
    let image = UdifImage::open(Arc::new(MemDataSource {
      data: synthetic_raw_udif(&payload),
    }))
    .unwrap();

    assert_eq!(image.compression_method(), UdifCompressionMethod::None);
    assert_eq!(image.read_all().unwrap()[..payload.len()], payload[..]);
  }

  #[test]
  fn large_decompressed_ranges_bypass_the_cache() {
    let payload = vec![0xA5; MAX_CACHED_DECOMPRESSED_RANGE_SIZE + 1];
    let compressed = compress_zlib(&payload);
    let source = Arc::new(CountingDataSource {
      data: compressed.clone(),
      reads: AtomicUsize::new(0),
    });
    let image = UdifImage {
      source: source.clone(),
      trailer: synthetic_trailer(
        compressed.len() as u64,
        (payload.len() as u64).div_ceil(SECTOR_SIZE),
      ),
      media_size: payload.len() as u64,
      ranges: Arc::from(vec![UdifRange {
        media_offset: 0,
        size: payload.len() as u64,
        data_offset: 0,
        data_size: compressed.len() as u64,
        kind: UdifRangeKind::Zlib,
      }]),
      compression_method: UdifCompressionMethod::Zlib,
      has_sparse_ranges: false,
      decompressed_cache: UdifCache::new(MAX_DECOMPRESSED_CACHE_ENTRIES),
    };
    let mut buf = vec![0u8; 4096];

    image.read_exact_at(0, &mut buf).unwrap();
    let reads_after_first = source.reads.load(Ordering::Relaxed);
    image.read_exact_at(0, &mut buf).unwrap();

    assert_eq!(&buf[..], &payload[..buf.len()]);
    assert!(source.reads.load(Ordering::Relaxed) > reads_after_first);
  }

  #[test]
  fn rejects_invalid_trailer_magic() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("udif/hfsplus_zlib.dmg"),
    )
    .unwrap();
    let trailer_offset = data.len() - 512;
    data[trailer_offset] = 0;

    let result = UdifImage::open(Arc::new(MemDataSource { data }));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_corrupted_master_checksums() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("udif/hfsplus_zlib.dmg"),
    )
    .unwrap();
    let trailer_offset = data.len() - 512;
    data[trailer_offset + 360] ^= 0xFF;

    let result = UdifImage::open(Arc::new(MemDataSource { data }));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}

crate::images::driver::impl_image_data_source!(UdifImage);
