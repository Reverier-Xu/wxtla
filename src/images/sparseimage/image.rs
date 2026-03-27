//! Read-only sparseimage surface.

use std::sync::Arc;

use super::{DESCRIPTOR, header::SparseImageHeader, parser::parse};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

#[allow(dead_code)]
pub struct SparseImage {
  source: ByteSourceHandle,
  header: SparseImageHeader,
  media_size: u64,
  band_size: u64,
  guest_to_file_offsets: Arc<[Option<u64>]>,
  has_sparse_bands: bool,
}

impl SparseImage {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let parsed = parse(source.clone())?;

    Ok(Self {
      source,
      header: parsed.header,
      media_size: parsed.media_size,
      band_size: parsed.band_size,
      guest_to_file_offsets: parsed.guest_to_file_offsets,
      has_sparse_bands: parsed.has_sparse_bands,
    })
  }

  pub fn header(&self) -> &SparseImageHeader {
    &self.header
  }

  pub fn band_size(&self) -> u64 {
    self.band_size
  }
}

impl ByteSource for SparseImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("sparseimage read offset overflow".to_string()))?;
      if absolute_offset >= self.media_size {
        break;
      }

      let band_index = usize::try_from(absolute_offset / self.band_size)
        .map_err(|_| Error::InvalidRange("sparseimage band index is too large".to_string()))?;
      let within_band = absolute_offset % self.band_size;
      let available = usize::try_from(
        (self.band_size - within_band)
          .min(self.media_size - absolute_offset)
          .min((buf.len() - copied) as u64),
      )
      .map_err(|_| Error::InvalidRange("sparseimage read chunk is too large".to_string()))?;

      match self
        .guest_to_file_offsets
        .get(band_index)
        .copied()
        .flatten()
      {
        Some(file_offset) => {
          self.source.read_exact_at(
            file_offset + within_band,
            &mut buf[copied..copied + available],
          )?;
        }
        None => {
          buf[copied..copied + available].fill(0);
        }
      }

      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    let preferred_chunk_size = usize::try_from(self.band_size).unwrap_or(1024 * 1024);
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size(preferred_chunk_size)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.sparseimage"
  }
}

impl Image for SparseImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(512)
  }

  fn physical_sector_size(&self) -> Option<u32> {
    self.logical_sector_size()
  }

  fn is_sparse(&self) -> bool {
    self.has_sparse_bands
  }
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use super::*;

  struct MemDataSource {
    data: Vec<u8>,
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

  fn synthetic_sparseimage() -> Vec<u8> {
    let sectors_per_band = 4u32;
    let sector_count = 8u32;
    let band_size = usize::try_from(u64::from(sectors_per_band) * 512).unwrap();
    let mut image = vec![0u8; 4096 + band_size];
    image[0..4].copy_from_slice(b"sprs");
    image[4..8].copy_from_slice(&3u32.to_be_bytes());
    image[8..12].copy_from_slice(&sectors_per_band.to_be_bytes());
    image[12..16].copy_from_slice(&1u32.to_be_bytes());
    image[16..20].copy_from_slice(&sector_count.to_be_bytes());
    image[64..68].copy_from_slice(&2u32.to_be_bytes());
    image[4096..4096 + band_size].fill(0xA5);
    image
  }

  #[test]
  fn opens_sparseimage_fixture_metadata() {
    let image = SparseImage::open(sample_source("sparseimage/hfsplus.sparseimage")).unwrap();

    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(image.band_size(), 1_048_576);
    assert_eq!(image.logical_sector_size(), Some(512));
  }

  #[test]
  fn reads_full_sparseimage_fixture() {
    let image = SparseImage::open(sample_source("sparseimage/hfsplus.sparseimage")).unwrap();

    assert_eq!(
      md5_hex(&image.read_all().unwrap()),
      "22c35335e6fafcbfc2ef21f1839f228d"
    );
  }

  #[test]
  fn reads_sparse_bands_as_zeroes() {
    let image = SparseImage::open(Arc::new(MemDataSource {
      data: synthetic_sparseimage(),
    }))
    .unwrap();

    let mut expected = vec![0u8; 2048];
    expected.extend_from_slice(&vec![0xA5; 2048]);
    assert_eq!(image.read_all().unwrap(), expected);
    assert!(image.is_sparse());
  }

  #[test]
  fn rejects_duplicate_band_numbers() {
    let mut image = synthetic_sparseimage();
    image[68..72].copy_from_slice(&2u32.to_be_bytes());

    let result = SparseImage::open(Arc::new(MemDataSource { data: image }));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}

crate::images::driver::impl_image_data_source!(SparseImage);
