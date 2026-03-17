//! Read-only QCOW image surface.

use std::{io::Read, sync::Arc};

use flate2::read::DeflateDecoder;

use super::{
  DESCRIPTOR,
  cache::QcowCache,
  constants::{
    DEFAULT_CLUSTER_CACHE_CAPACITY, DEFAULT_L2_CACHE_CAPACITY, QCOW_OFLAG_COMPRESSED,
    QCOW_OFLAG_COPIED,
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
  backing_image: Option<DataSourceHandle>,
  l1_table: Arc<[u64]>,
  l2_cache: QcowCache<Vec<u64>>,
  cluster_cache: QcowCache<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedL2Entry {
  Sparse,
  Zero,
  Standard {
    cluster_offset: u64,
  },
  Compressed {
    host_offset: u64,
    stored_size: usize,
  },
}

impl QcowImage {
  /// Open a QCOW image from a single-file source.
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    let parsed = parse(source.clone())?;
    Self::from_parsed(source, parsed, None)
  }

  /// Open a QCOW image using source hints.
  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    let parsed = parse(source.clone())?;
    let backing_image = if let Some(backing_file_name) = parsed.backing_file_name.as_deref() {
      let resolver = hints.resolver().ok_or_else(|| {
        Error::InvalidSourceReference(
          "qcow backing files require a related-source resolver".to_string(),
        )
      })?;
      let identity = hints.source_identity().ok_or_else(|| {
        Error::InvalidSourceReference(
          "qcow backing files require a source identity hint".to_string(),
        )
      })?;
      let backing_path = identity.sibling_path(backing_file_name)?;
      let backing_identity = crate::SourceIdentity::new(backing_path.clone());
      let backing_source = resolver
        .resolve(&crate::RelatedSourceRequest::new(
          crate::RelatedSourcePurpose::BackingFile,
          backing_path,
        ))?
        .ok_or_else(|| {
          Error::NotFound(format!("missing qcow backing file: {backing_file_name}"))
        })?;
      Some(Arc::new(Self::open_with_hints(
        backing_source,
        SourceHints::new()
          .with_resolver(resolver)
          .with_source_identity(&backing_identity),
      )?) as DataSourceHandle)
    } else {
      None
    };

    Self::from_parsed(source, parsed, backing_image)
  }

  fn from_parsed(
    source: DataSourceHandle, parsed: ParsedQcow, backing_image: Option<DataSourceHandle>,
  ) -> Result<Self> {
    Ok(Self {
      source,
      header: parsed.header,
      backing_file_name: parsed.backing_file_name,
      backing_image,
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

  fn l1_offset_mask(&self) -> u64 {
    if self.header.version == super::constants::QCOW_VERSION_1 {
      (1u64 << 63) - 1
    } else {
      0x00FF_FFFF_FFFF_FE00
    }
  }

  fn l2_standard_offset_mask(&self) -> u64 {
    if self.header.version == super::constants::QCOW_VERSION_1 {
      (1u64 << 63) - 1
    } else {
      0x00FF_FFFF_FFFF_FE00
    }
  }

  fn read_l2_table(&self, l1_index: u64) -> Result<Option<Arc<Vec<u64>>>> {
    let raw_l1 = *self
      .l1_table
      .get(
        usize::try_from(l1_index)
          .map_err(|_| Error::InvalidRange("qcow l1 index conversion overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange(format!("qcow l1 index {l1_index} is out of bounds")))?;
    let l2_offset = raw_l1 & self.l1_offset_mask();
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

  fn read_l2_entry(&self, cluster_index: u64) -> Result<ParsedL2Entry> {
    let l2_entries_per_table = self.l2_entries_per_table()?;
    let l1_index = cluster_index / l2_entries_per_table;
    let l2_index = cluster_index % l2_entries_per_table;
    let l2_table = match self.read_l2_table(l1_index)? {
      Some(table) => table,
      None => return Ok(ParsedL2Entry::Sparse),
    };
    let raw = *l2_table
      .get(
        usize::try_from(l2_index)
          .map_err(|_| Error::InvalidRange("qcow l2 index conversion overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange(format!("qcow l2 index {l2_index} is out of bounds")))?;

    self.parse_l2_entry(raw)
  }

  fn parse_l2_entry(&self, raw: u64) -> Result<ParsedL2Entry> {
    if raw == 0 {
      return Ok(ParsedL2Entry::Sparse);
    }

    let zero = (raw & 1) != 0;
    let compressed = if self.header.version == super::constants::QCOW_VERSION_1 {
      (raw & QCOW_OFLAG_COPIED) != 0
    } else {
      (raw & QCOW_OFLAG_COMPRESSED) != 0
    };

    if compressed {
      let cluster_bits = self.header.cluster_bits;
      let host_offset_bits = if self.header.version == super::constants::QCOW_VERSION_1 {
        63u32.checked_sub(cluster_bits).ok_or_else(|| {
          Error::InvalidFormat("qcow v1 compressed cluster bits are invalid".to_string())
        })?
      } else {
        70u32.checked_sub(cluster_bits).ok_or_else(|| {
          Error::InvalidFormat("qcow compressed cluster bits are invalid".to_string())
        })?
      };
      if host_offset_bits == 0 || host_offset_bits >= 62 {
        return Err(Error::InvalidFormat(
          "qcow compressed cluster offset bit count is invalid".to_string(),
        ));
      }
      let host_offset_mask = (1u64 << host_offset_bits) - 1;
      let descriptor = if self.header.version == super::constants::QCOW_VERSION_1 {
        raw & !QCOW_OFLAG_COPIED
      } else {
        raw & !QCOW_OFLAG_COPIED & !QCOW_OFLAG_COMPRESSED
      };
      let host_offset = descriptor & host_offset_mask;
      let stored_size = if self.header.version == super::constants::QCOW_VERSION_1 {
        usize::try_from(descriptor >> host_offset_bits).map_err(|_| {
          Error::InvalidRange("qcow compressed cluster size is too large".to_string())
        })?
      } else {
        let additional_sectors = descriptor >> host_offset_bits;
        usize::try_from(
          u64::from(512u16)
            .checked_mul(additional_sectors.saturating_add(1))
            .ok_or_else(|| {
              Error::InvalidRange("qcow compressed cluster size overflow".to_string())
            })?,
        )
        .map_err(|_| Error::InvalidRange("qcow compressed cluster size is too large".to_string()))?
      };
      if stored_size == 0 {
        return Err(Error::InvalidFormat(
          "qcow compressed cluster size must be non-zero".to_string(),
        ));
      }

      return Ok(ParsedL2Entry::Compressed {
        host_offset,
        stored_size,
      });
    }

    let cluster_offset = raw & self.l2_standard_offset_mask();
    if cluster_offset == 0 && zero {
      return Ok(ParsedL2Entry::Zero);
    }
    if cluster_offset == 0 {
      return Ok(ParsedL2Entry::Sparse);
    }

    Ok(ParsedL2Entry::Standard { cluster_offset })
  }

  fn read_compressed_cluster(&self, host_offset: u64, stored_size: usize) -> Result<Arc<Vec<u8>>> {
    let compressed = self.source.read_bytes_at(host_offset, stored_size)?;
    let cluster_size = usize::try_from(self.cluster_size()?)
      .map_err(|_| Error::InvalidRange("qcow cluster size is too large".to_string()))?;
    let mut decoder = DeflateDecoder::new(compressed.as_slice());
    let mut cluster = vec![0u8; cluster_size];
    decoder.read_exact(&mut cluster).map_err(Error::Io)?;

    Ok(Arc::new(cluster))
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
        ParsedL2Entry::Sparse => {
          if let Some(backing_image) = &self.backing_image {
            backing_image.read_exact_at(absolute_offset, &mut buf[copied..copied + available])?;
          } else {
            buf[copied..copied + available].fill(0);
          }
        }
        ParsedL2Entry::Zero => {
          buf[copied..copied + available].fill(0);
        }
        ParsedL2Entry::Standard {
          cluster_offset: host_cluster_offset,
        } => {
          let cluster = self.read_cluster(host_cluster_offset)?;
          buf[copied..copied + available]
            .copy_from_slice(&cluster[cluster_offset..cluster_offset + available]);
        }
        ParsedL2Entry::Compressed {
          host_offset,
          stored_size,
        } => {
          let cluster = self.read_compressed_cluster(host_offset, stored_size)?;
          buf[copied..copied + available]
            .copy_from_slice(&cluster[cluster_offset..cluster_offset + available]);
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
  use std::{collections::HashMap, io::Write, path::Path, sync::Arc};

  use flate2::{Compression, write::DeflateEncoder};

  use super::{super::constants, *};
  use crate::{RelatedSourceRequest, RelatedSourceResolver, SourceIdentity};

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

  #[test]
  fn reads_from_a_backing_file_when_overlay_clusters_are_unallocated() {
    let base_data = repeat_byte(0xAB, 65_536);
    let base_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow(Some(&base_data), None),
    });
    let overlay_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow(None, Some("base.qcow2")),
    });
    let resolver = Resolver {
      files: HashMap::from([("images/base.qcow2".to_string(), base_source)]),
    };
    let identity = SourceIdentity::from_relative_path("images/overlay.qcow2").unwrap();

    let image = QcowImage::open_with_hints(
      overlay_source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.backing_file_name(), Some("base.qcow2"));
    assert_eq!(image.read_all().unwrap(), base_data);
  }

  #[test]
  fn overlay_clusters_override_backing_file_data() {
    let base_data = repeat_byte(0x10, 65_536);
    let overlay_data = repeat_byte(0xEF, 65_536);
    let base_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow(Some(&base_data), None),
    });
    let overlay_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow(Some(&overlay_data), Some("base.qcow2")),
    });
    let resolver = Resolver {
      files: HashMap::from([("images/base.qcow2".to_string(), base_source)]),
    };
    let identity = SourceIdentity::from_relative_path("images/overlay.qcow2").unwrap();

    let image = QcowImage::open_with_hints(
      overlay_source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), overlay_data);
  }

  #[test]
  fn reads_compressed_clusters_from_synthetic_qcow() {
    let cluster = repeat_byte(0x7E, 65_536);
    let image = QcowImage::open(Arc::new(MemDataSource {
      data: build_synthetic_qcow_from_cluster(SyntheticCluster::Compressed(&cluster), None),
    }))
    .unwrap();

    assert_eq!(image.read_all().unwrap(), cluster);
  }

  #[test]
  fn reads_version_one_qcow_clusters() {
    let cluster = repeat_byte(0x42, 65_536);
    let image = QcowImage::open(Arc::new(MemDataSource {
      data: build_synthetic_qcow_v1(SyntheticCluster::Standard(&cluster)),
    }))
    .unwrap();

    assert_eq!(image.header().version, constants::QCOW_VERSION_1);
    assert_eq!(image.read_all().unwrap(), cluster);
  }

  #[test]
  fn reads_version_one_compressed_qcow_clusters() {
    let cluster = repeat_byte(0x24, 65_536);
    let image = QcowImage::open(Arc::new(MemDataSource {
      data: build_synthetic_qcow_v1(SyntheticCluster::Compressed(&cluster)),
    }))
    .unwrap();

    assert_eq!(image.read_all().unwrap(), cluster);
  }

  fn repeat_byte(byte: u8, size: usize) -> Vec<u8> {
    vec![byte; size]
  }

  enum SyntheticCluster<'a> {
    Sparse,
    Standard(&'a [u8]),
    Compressed(&'a [u8]),
  }

  fn build_synthetic_qcow(cluster_data: Option<&[u8]>, backing_name: Option<&str>) -> Vec<u8> {
    let cluster = match cluster_data {
      Some(data) => SyntheticCluster::Standard(data),
      None => SyntheticCluster::Sparse,
    };
    build_synthetic_qcow_from_cluster(cluster, backing_name)
  }

  fn build_synthetic_qcow_from_cluster(
    cluster: SyntheticCluster<'_>, backing_name: Option<&str>,
  ) -> Vec<u8> {
    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS;
    const VIRTUAL_SIZE: u64 = CLUSTER_SIZE as u64;
    const L1_OFFSET: u64 = 0x0003_0000;
    const L2_OFFSET: u64 = 0x0004_0000;
    const DATA_OFFSET: u64 = 0x0005_0000;
    const REFCOUNT_TABLE_OFFSET: u64 = 0x0001_0000;
    let mut data = vec![0u8; 0x0006_0000];

    let backing_name_bytes = backing_name.unwrap_or("").as_bytes();
    data[0..4].copy_from_slice(b"QFI\xfb");
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    if backing_name.is_some() {
      data[8..16].copy_from_slice(&112u64.to_be_bytes());
      data[16..20].copy_from_slice(&(backing_name_bytes.len() as u32).to_be_bytes());
    }
    data[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
    data[24..32].copy_from_slice(&VIRTUAL_SIZE.to_be_bytes());
    data[32..36].copy_from_slice(&0u32.to_be_bytes());
    data[36..40].copy_from_slice(&1u32.to_be_bytes());
    data[40..48].copy_from_slice(&L1_OFFSET.to_be_bytes());
    data[48..56].copy_from_slice(&REFCOUNT_TABLE_OFFSET.to_be_bytes());
    data[56..60].copy_from_slice(&1u32.to_be_bytes());
    data[60..64].copy_from_slice(&0u32.to_be_bytes());
    data[64..72].copy_from_slice(&0u64.to_be_bytes());
    data[72..80].copy_from_slice(&0u64.to_be_bytes());
    data[80..88].copy_from_slice(&0u64.to_be_bytes());
    data[88..96].copy_from_slice(&0u64.to_be_bytes());
    data[96..100].copy_from_slice(&4u32.to_be_bytes());
    data[100..104].copy_from_slice(&112u32.to_be_bytes());
    data[104] = 0;
    if backing_name.is_some() {
      let name_start = 112usize;
      let name_end = name_start + backing_name_bytes.len();
      data[name_start..name_end].copy_from_slice(backing_name_bytes);
    }

    data[L1_OFFSET as usize..L1_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0004_0000u64).to_be_bytes());
    let l2_entry = match cluster {
      SyntheticCluster::Sparse => 0,
      SyntheticCluster::Standard(_) => 0x8000_0000_0005_0000u64,
      SyntheticCluster::Compressed(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        let compressed_sectors = compressed.len().div_ceil(512);
        let additional_sectors = compressed_sectors.saturating_sub(1);
        data[72..80].copy_from_slice(&constants::QCOW_INCOMPAT_COMPRESSION.to_be_bytes());
        constants::QCOW_OFLAG_COMPRESSED
          | ((u64::try_from(additional_sectors).unwrap()) << (70 - CLUSTER_BITS))
          | DATA_OFFSET
      }
    };
    data[L2_OFFSET as usize..L2_OFFSET as usize + 8].copy_from_slice(&l2_entry.to_be_bytes());
    match cluster {
      SyntheticCluster::Sparse => {}
      SyntheticCluster::Standard(cluster_data) => {
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + cluster_data.len()]
          .copy_from_slice(cluster_data);
      }
      SyntheticCluster::Compressed(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + compressed.len()]
          .copy_from_slice(&compressed);
      }
    }

    data
  }

  fn deflate_cluster(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
  }

  fn build_synthetic_qcow_v1(cluster: SyntheticCluster<'_>) -> Vec<u8> {
    const CLUSTER_BITS: u8 = 16;
    const L2_BITS: u8 = 13;
    const CLUSTER_SIZE: usize = 1 << (CLUSTER_BITS as usize);
    const VIRTUAL_SIZE: u64 = CLUSTER_SIZE as u64;
    const L1_OFFSET: u64 = 0x0003_0000;
    const L2_OFFSET: u64 = 0x0004_0000;
    const DATA_OFFSET: u64 = 0x0005_0000;
    let mut data = vec![0u8; 0x0006_0000];

    data[0..4].copy_from_slice(b"QFI\xfb");
    data[4..8].copy_from_slice(&1u32.to_be_bytes());
    data[20..24].copy_from_slice(&0u32.to_be_bytes());
    data[24..32].copy_from_slice(&VIRTUAL_SIZE.to_be_bytes());
    data[32] = CLUSTER_BITS;
    data[33] = L2_BITS;
    data[36..40].copy_from_slice(&0u32.to_be_bytes());
    data[40..48].copy_from_slice(&L1_OFFSET.to_be_bytes());

    data[L1_OFFSET as usize..L1_OFFSET as usize + 8].copy_from_slice(&L2_OFFSET.to_be_bytes());
    let l2_entry = match cluster {
      SyntheticCluster::Sparse => 0,
      SyntheticCluster::Standard(_) => DATA_OFFSET,
      SyntheticCluster::Compressed(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        let shift = 63 - u32::from(CLUSTER_BITS);
        let stored_size = u64::try_from(compressed.len()).unwrap();
        (1u64 << 63) | (stored_size << shift) | DATA_OFFSET
      }
    };
    data[L2_OFFSET as usize..L2_OFFSET as usize + 8].copy_from_slice(&l2_entry.to_be_bytes());
    match cluster {
      SyntheticCluster::Sparse => {}
      SyntheticCluster::Standard(cluster_data) => {
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + cluster_data.len()]
          .copy_from_slice(cluster_data);
      }
      SyntheticCluster::Compressed(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + compressed.len()]
          .copy_from_slice(&compressed);
      }
    }

    data
  }
}
