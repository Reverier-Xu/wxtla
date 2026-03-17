//! Read-only QCOW image surface.

use std::sync::Arc;

use super::{
  DESCRIPTOR,
  cache::QcowCache,
  constants::{
    DEFAULT_CLUSTER_CACHE_CAPACITY, DEFAULT_L2_CACHE_CAPACITY, QCOW_OFFSET_MASK,
    QCOW_OFLAG_COMPRESSED, QCOW_OFLAG_COPIED,
  },
  header::QcowHeader,
  parser::{ParsedQcow, parse},
};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

/// Read-only QCOW image surface.
pub struct QcowImage {
  source: DataSourceHandle,
  header: QcowHeader,
  backing_file_name: Option<String>,
  l1_table: Arc<[u64]>,
  l2_cache: QcowCache<Vec<u64>>,
  cluster_cache: QcowCache<Vec<u8>>,
}

impl QcowImage {
  /// Open a QCOW image from a single-file source.
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    let parsed = parse(source.clone())?;
    Self::from_parsed(source, parsed)
  }

  /// Open a QCOW image using source hints.
  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    Self::open(source)
  }

  fn from_parsed(source: DataSourceHandle, parsed: ParsedQcow) -> Result<Self> {
    Ok(Self {
      source,
      header: parsed.header,
      backing_file_name: parsed.backing_file_name,
      l1_table: parsed.l1_table,
      l2_cache: QcowCache::new(DEFAULT_L2_CACHE_CAPACITY),
      cluster_cache: QcowCache::new(DEFAULT_CLUSTER_CACHE_CAPACITY),
    })
  }

  /// Return the parsed QCOW header.
  pub fn header(&self) -> &QcowHeader {
    &self.header
  }

  /// Return the optional backing file name.
  pub fn backing_file_name(&self) -> Option<&str> {
    self.backing_file_name.as_deref()
  }

  fn cluster_size(&self) -> Result<u64> {
    self.header.cluster_size()
  }

  fn l2_entries_per_table(&self) -> Result<u64> {
    self.header.l2_entry_count()
  }

  fn read_l2_table(&self, l1_index: u64) -> Result<Option<Arc<Vec<u64>>>> {
    let raw_l1 = *self
      .l1_table
      .get(
        usize::try_from(l1_index)
          .map_err(|_| Error::InvalidRange("qcow l1 index conversion overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange(format!("qcow l1 index {l1_index} is out of bounds")))?;
    let l2_offset = raw_l1 & QCOW_OFFSET_MASK;
    if l2_offset == 0 {
      return Ok(None);
    }

    self
      .l2_cache
      .get_or_load(l1_index, || {
        let table_bytes = usize::try_from(self.cluster_size()?)
          .map_err(|_| Error::InvalidRange("qcow l2 table size is too large".to_string()))?;
        let raw = self.source.read_bytes_at(l2_offset, table_bytes)?;
        let entries = raw
          .chunks_exact(8)
          .map(|chunk| {
            Ok(u64::from_be_bytes([
              chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]))
          })
          .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(entries))
      })
      .map(Some)
  }

  fn read_cluster(&self, cluster_offset: u64) -> Result<Arc<Vec<u8>>> {
    self.cluster_cache.get_or_load(cluster_offset, || {
      let cluster_size = usize::try_from(self.cluster_size()?)
        .map_err(|_| Error::InvalidRange("qcow cluster size is too large".to_string()))?;
      let cluster = self.source.read_bytes_at(cluster_offset, cluster_size)?;
      Ok(Arc::new(cluster))
    })
  }

  fn read_l2_entry(&self, cluster_index: u64) -> Result<Option<u64>> {
    let l2_entries_per_table = self.l2_entries_per_table()?;
    let l1_index = cluster_index / l2_entries_per_table;
    let l2_index = cluster_index % l2_entries_per_table;
    let l2_table = match self.read_l2_table(l1_index)? {
      Some(table) => table,
      None => return Ok(None),
    };
    let raw = *l2_table
      .get(
        usize::try_from(l2_index)
          .map_err(|_| Error::InvalidRange("qcow l2 index conversion overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange(format!("qcow l2 index {l2_index} is out of bounds")))?;

    Ok(Some(raw))
  }
}

impl DataSource for QcowImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.header.virtual_size || buf.is_empty() {
      return Ok(0);
    }

    let cluster_size = self.cluster_size()?;
    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("qcow read offset overflow".to_string()))?;
      if absolute_offset >= self.header.virtual_size {
        break;
      }

      let cluster_index = absolute_offset / cluster_size;
      let within_cluster = absolute_offset % cluster_size;
      let cluster_offset = usize::try_from(within_cluster)
        .map_err(|_| Error::InvalidRange("qcow cluster offset overflow".to_string()))?;
      let available = usize::try_from(
        cluster_size
          .checked_sub(within_cluster)
          .ok_or_else(|| Error::InvalidRange("qcow cluster range underflow".to_string()))?,
      )
      .map_err(|_| Error::InvalidRange("qcow available size overflow".to_string()))?
      .min(buf.len() - copied)
      .min(
        usize::try_from(
          self
            .header
            .virtual_size
            .checked_sub(absolute_offset)
            .ok_or_else(|| Error::InvalidRange("qcow image range underflow".to_string()))?,
        )
        .map_err(|_| Error::InvalidRange("qcow remaining image size is too large".to_string()))?,
      );

      match self.read_l2_entry(cluster_index)? {
        None => {
          buf[copied..copied + available].fill(0);
        }
        Some(raw_l2_entry) => {
          if raw_l2_entry == 0 {
            buf[copied..copied + available].fill(0);
          } else if (raw_l2_entry & QCOW_OFLAG_COMPRESSED) != 0 {
            return Err(Error::InvalidFormat(
              "compressed qcow clusters are not supported in this stage".to_string(),
            ));
          } else {
            let cluster_data_offset = raw_l2_entry & QCOW_OFFSET_MASK;
            let cluster = self.read_cluster(cluster_data_offset)?;
            buf[copied..copied + available]
              .copy_from_slice(&cluster[cluster_offset..cluster_offset + available]);
          }
          let _ = raw_l2_entry & QCOW_OFLAG_COPIED;
        }
      }

      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.header.virtual_size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    let mut capabilities = DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap);
    if let Ok(cluster_size) = self.cluster_size()
      && let Ok(cluster_size) = usize::try_from(cluster_size)
    {
      capabilities = capabilities.with_preferred_chunk_size(cluster_size);
    }
    capabilities
  }

  fn telemetry_name(&self) -> &'static str {
    "image.qcow"
  }
}

impl Image for QcowImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(512)
  }

  fn has_backing_chain(&self) -> bool {
    self.backing_file_name.is_some()
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
  fn opens_qcow_fixture_metadata() {
    let image = QcowImage::open(sample_source("qcow/ext2.qcow2")).unwrap();

    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(image.header().version, 3);
    assert_eq!(image.backing_file_name(), None);
  }

  #[test]
  fn reads_full_ext2_qcow_fixture() {
    let image = QcowImage::open(sample_source("qcow/ext2.qcow2")).unwrap();
    let raw = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("ext/ext2.raw"),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), raw);
  }

  #[test]
  fn exposes_fat_boot_markers_from_qcow_fixtures() {
    let fat16 = QcowImage::open(sample_source("qcow/fat16.qcow2")).unwrap();
    let fat32 = QcowImage::open(sample_source("qcow/fat32.qcow2")).unwrap();
    let mut fat16_marker = [0u8; 8];
    let mut fat32_marker = [0u8; 8];

    fat16.read_exact_at(54, &mut fat16_marker).unwrap();
    fat32.read_exact_at(82, &mut fat32_marker).unwrap();

    assert_eq!(&fat16_marker, b"FAT16   ");
    assert_eq!(&fat32_marker, b"FAT32   ");
  }
}
