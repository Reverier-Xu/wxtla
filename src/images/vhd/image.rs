//! Read-only VHD image surface.

use std::sync::Arc;

use super::{
  DESCRIPTOR,
  cache::VhdCache,
  constants::DEFAULT_SECTOR_SIZE,
  dynamic_header::VhdDynamicHeader,
  footer::{VhdDiskType, VhdFooter},
  parser::{ParsedVhd, parse},
};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

pub struct VhdImage {
  source: DataSourceHandle,
  footer: VhdFooter,
  dynamic_header: Option<VhdDynamicHeader>,
  bat: Arc<[u32]>,
  bitmap_cache: VhdCache<Vec<u8>>,
  block_cache: VhdCache<Vec<u8>>,
}

impl VhdImage {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    let parsed = parse(source.clone())?;
    Self::from_parsed(source, parsed)
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    Self::open(source)
  }

  fn from_parsed(source: DataSourceHandle, parsed: ParsedVhd) -> Result<Self> {
    Ok(Self {
      source,
      footer: parsed.footer,
      dynamic_header: parsed.dynamic_header,
      bat: parsed.block_allocation_table,
      bitmap_cache: VhdCache::new(64),
      block_cache: VhdCache::new(64),
    })
  }

  pub fn footer(&self) -> &VhdFooter {
    &self.footer
  }

  pub fn dynamic_header(&self) -> Option<&VhdDynamicHeader> {
    self.dynamic_header.as_ref()
  }

  fn read_bitmap(&self, block_index: u64) -> Result<Arc<Vec<u8>>> {
    let header = self
      .dynamic_header
      .as_ref()
      .ok_or_else(|| Error::InvalidFormat("vhd dynamic header is missing".to_string()))?;
    let sector_bitmap_size = usize::try_from(header.sector_bitmap_size()?)
      .map_err(|_| Error::InvalidRange("vhd sector bitmap size is too large".to_string()))?;
    let bat_entry = *self
      .bat
      .get(
        usize::try_from(block_index)
          .map_err(|_| Error::InvalidRange("vhd block index conversion overflow".to_string()))?,
      )
      .ok_or_else(|| {
        Error::InvalidRange(format!("vhd block index {block_index} is out of bounds"))
      })?;
    if bat_entry == u32::MAX {
      return Err(Error::InvalidFormat(
        "vhd sparse block bitmap was requested".to_string(),
      ));
    }
    let bitmap_offset = u64::from(bat_entry)
      .checked_mul(u64::from(DEFAULT_SECTOR_SIZE))
      .ok_or_else(|| Error::InvalidRange("vhd bitmap offset overflow".to_string()))?;

    self.bitmap_cache.get_or_load(block_index, || {
      let data = self
        .source
        .read_bytes_at(bitmap_offset, sector_bitmap_size)?;
      Ok(Arc::new(data))
    })
  }

  fn read_block(&self, block_index: u64) -> Result<Option<Arc<Vec<u8>>>> {
    let header = self
      .dynamic_header
      .as_ref()
      .ok_or_else(|| Error::InvalidFormat("vhd dynamic header is missing".to_string()))?;
    let bat_entry = *self
      .bat
      .get(
        usize::try_from(block_index)
          .map_err(|_| Error::InvalidRange("vhd block index conversion overflow".to_string()))?,
      )
      .ok_or_else(|| {
        Error::InvalidRange(format!("vhd block index {block_index} is out of bounds"))
      })?;
    if bat_entry == u32::MAX {
      return Ok(None);
    }
    let sector_bitmap_size = header.sector_bitmap_size()?;
    let block_offset = u64::from(bat_entry)
      .checked_mul(u64::from(DEFAULT_SECTOR_SIZE))
      .and_then(|offset| offset.checked_add(sector_bitmap_size))
      .ok_or_else(|| Error::InvalidRange("vhd block offset overflow".to_string()))?;
    let block_size = usize::try_from(header.block_size)
      .map_err(|_| Error::InvalidRange("vhd block size is too large".to_string()))?;

    self
      .block_cache
      .get_or_load(block_index, || {
        let data = self.source.read_bytes_at(block_offset, block_size)?;
        Ok(Arc::new(data))
      })
      .map(Some)
  }
}

impl DataSource for VhdImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.footer.current_size || buf.is_empty() {
      return Ok(0);
    }

    if self.footer.disk_type == VhdDiskType::Fixed {
      let max = usize::try_from(self.footer.current_size - offset)
        .map_err(|_| Error::InvalidRange("vhd remaining size is too large".to_string()))?
        .min(buf.len());
      return self.source.read_at(offset, &mut buf[..max]);
    }

    let header = self
      .dynamic_header
      .as_ref()
      .ok_or_else(|| Error::InvalidFormat("vhd dynamic header is missing".to_string()))?;
    let block_size = u64::from(header.block_size);
    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("vhd read offset overflow".to_string()))?;
      if absolute_offset >= self.footer.current_size {
        break;
      }

      let block_index = absolute_offset / block_size;
      let within_block = absolute_offset % block_size;
      let block_available = usize::try_from(
        block_size
          .checked_sub(within_block)
          .ok_or_else(|| Error::InvalidRange("vhd block range underflow".to_string()))?,
      )
      .map_err(|_| Error::InvalidRange("vhd block size is too large".to_string()))?
      .min(
        usize::try_from(self.footer.current_size - absolute_offset)
          .map_err(|_| Error::InvalidRange("vhd remaining size is too large".to_string()))?,
      );
      let sector_available = usize::try_from(
        u64::from(DEFAULT_SECTOR_SIZE) - (within_block % u64::from(DEFAULT_SECTOR_SIZE)),
      )
      .map_err(|_| Error::InvalidRange("vhd sector size is too large".to_string()))?;
      let available = block_available
        .min(buf.len() - copied)
        .min(sector_available);

      let block = match self.read_block(block_index)? {
        Some(block) => block,
        None => {
          buf[copied..copied + available].fill(0);
          copied += available;
          continue;
        }
      };
      let bitmap = self.read_bitmap(block_index)?;
      let sector_index = usize::try_from(within_block / u64::from(DEFAULT_SECTOR_SIZE))
        .map_err(|_| Error::InvalidRange("vhd sector index overflow".to_string()))?;
      let sector_present = {
        let byte = *bitmap.get(sector_index / 8).ok_or_else(|| {
          Error::InvalidFormat("vhd sector bitmap does not cover the requested sector".to_string())
        })?;
        let bit = 7 - (sector_index % 8);
        (byte & (1 << bit)) != 0
      };

      if !sector_present {
        buf[copied..copied + available].fill(0);
        copied += available;
        continue;
      }

      let block_offset = usize::try_from(within_block)
        .map_err(|_| Error::InvalidRange("vhd block offset is too large".to_string()))?;
      buf[copied..copied + available]
        .copy_from_slice(&block[block_offset..block_offset + available]);

      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.footer.current_size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    let mut capabilities = DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap);
    if let Some(header) = &self.dynamic_header
      && let Ok(size) = usize::try_from(header.block_size)
    {
      capabilities = capabilities.with_preferred_chunk_size(size);
    }
    capabilities
  }

  fn telemetry_name(&self) -> &'static str {
    "image.vhd"
  }
}

impl Image for VhdImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(DEFAULT_SECTOR_SIZE)
  }

  fn is_sparse(&self) -> bool {
    matches!(
      self.footer.disk_type,
      VhdDiskType::Dynamic | VhdDiskType::Differential
    )
  }

  fn has_backing_chain(&self) -> bool {
    self.footer.disk_type == VhdDiskType::Differential
  }
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;

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

  fn sample_source(relative_path: &str) -> DataSourceHandle {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Arc::new(MemDataSource {
      data: std::fs::read(path).unwrap(),
    })
  }

  #[test]
  fn opens_dynamic_vhd_metadata() {
    let image = VhdImage::open(sample_source("vhd/ext2.vhd")).unwrap();

    assert_eq!(image.footer().disk_type, VhdDiskType::Dynamic);
    assert_eq!(image.size().unwrap(), 4_212_736);
    assert_eq!(image.dynamic_header().unwrap().block_count, 3);
  }

  #[test]
  fn reads_full_ext2_dynamic_vhd_fixture() {
    let image = VhdImage::open(sample_source("vhd/ext2.vhd")).unwrap();
    let mut raw = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("ext/ext2.raw"),
    )
    .unwrap();
    raw.resize(image.size().unwrap() as usize, 0);

    assert_eq!(image.read_all().unwrap(), raw);
  }

  #[test]
  fn reads_full_ntfs_dynamic_vhd_fixture() {
    let image = VhdImage::open(sample_source("vhd/ntfs-dynamic.vhd")).unwrap();
    let mut mbr_signature = [0u8; 2];
    let mut ntfs_oem = [0u8; 8];

    image.read_exact_at(510, &mut mbr_signature).unwrap();
    image.read_exact_at(128 * 512 + 3, &mut ntfs_oem).unwrap();

    assert_eq!(&mbr_signature, &[0x55, 0xAA]);
    assert_eq!(&ntfs_oem, b"NTFS    ");
  }
}
