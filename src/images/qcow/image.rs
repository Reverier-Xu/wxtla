//! Read-only QCOW image surface.

use std::{io::Read, sync::Arc};

use flate2::read::DeflateDecoder;
use zstd::stream::Decoder as ZstdDecoder;

use super::{
  DESCRIPTOR,
  cache::QcowCache,
  constants::{
    DEFAULT_CLUSTER_CACHE_CAPACITY, DEFAULT_L2_CACHE_CAPACITY, QCOW_OFLAG_COMPRESSED,
    QCOW_OFLAG_COPIED,
  },
  extension::QcowHeaderExtension,
  header::QcowHeader,
  parser::{ParsedQcow, parse},
  snapshot::QcowSnapshot,
};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceSeekCost, Error, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, RelatedSourceResolver, Result, SourceHints,
  SourceIdentity, images::Image,
};

/// Read-only QCOW image surface.
pub struct QcowImage {
  source: DataSourceHandle,
  header: QcowHeader,
  virtual_size: u64,
  backing_file_name: Option<String>,
  backing_file_format: Option<String>,
  external_data_path: Option<String>,
  backing_image: Option<DataSourceHandle>,
  external_data_source: Option<DataSourceHandle>,
  header_extensions: Arc<[QcowHeaderExtension]>,
  snapshots: Arc<[QcowSnapshot]>,
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
  Extended {
    cluster_offset: u64,
    allocation_bitmap: u32,
    zero_bitmap: u32,
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
    if parsed.header.uses_external_data_file() {
      return Err(Error::InvalidSourceReference(
        "qcow external data files require source hints and a related-source resolver".to_string(),
      ));
    }
    Self::from_parsed(source, parsed, None, None, None, None)
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
      let (backing_source, backing_path) = resolve_named_source(
        resolver,
        identity,
        backing_file_name,
        RelatedSourcePurpose::BackingFile,
      )?
      .ok_or_else(|| Error::NotFound(format!("missing qcow backing file: {backing_file_name}")))?;
      if &backing_path == identity.logical_path() {
        return Err(Error::InvalidFormat(
          "qcow backing file hint resolves to the same image".to_string(),
        ));
      }
      let backing_identity = crate::SourceIdentity::new(backing_path.clone());
      Some(Arc::new(Self::open_with_hints(
        backing_source,
        SourceHints::new()
          .with_resolver(resolver)
          .with_source_identity(&backing_identity),
      )?) as DataSourceHandle)
    } else {
      None
    };

    let external_data_source =
      if let Some(external_data_path) = parsed.external_data_path.as_deref() {
        let resolver = hints.resolver().ok_or_else(|| {
          Error::InvalidSourceReference(
            "qcow external data files require a related-source resolver".to_string(),
          )
        })?;
        let identity = hints.source_identity().ok_or_else(|| {
          Error::InvalidSourceReference(
            "qcow external data files require a source identity hint".to_string(),
          )
        })?;
        let (external_source, external_path) = resolve_named_source(
          resolver,
          identity,
          external_data_path,
          RelatedSourcePurpose::Extent,
        )?
        .ok_or_else(|| {
          Error::NotFound(format!(
            "missing qcow external data file: {external_data_path}"
          ))
        })?;
        if &external_path == identity.logical_path() {
          return Err(Error::InvalidFormat(
            "qcow external data path resolves to the same image".to_string(),
          ));
        }
        Some(external_source)
      } else {
        None
      };

    Self::from_parsed(
      source,
      parsed,
      backing_image,
      external_data_source,
      None,
      None,
    )
  }

  fn from_parsed(
    source: DataSourceHandle, parsed: ParsedQcow, backing_image: Option<DataSourceHandle>,
    external_data_source: Option<DataSourceHandle>, l1_table_override: Option<Arc<[u64]>>,
    virtual_size_override: Option<u64>,
  ) -> Result<Self> {
    Ok(Self {
      source,
      virtual_size: virtual_size_override.unwrap_or(parsed.header.virtual_size),
      header: parsed.header,
      backing_file_name: parsed.backing_file_name,
      backing_file_format: parsed.backing_file_format,
      external_data_path: parsed.external_data_path,
      backing_image,
      external_data_source,
      header_extensions: Arc::from(parsed.header_extensions),
      snapshots: Arc::from(parsed.snapshots),
      l1_table: l1_table_override.unwrap_or(parsed.l1_table),
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

  /// Return the optional backing file format extension string.
  pub fn backing_file_format(&self) -> Option<&str> {
    self.backing_file_format.as_deref()
  }

  /// Return the optional external data path extension string.
  pub fn external_data_path(&self) -> Option<&str> {
    self.external_data_path.as_deref()
  }

  /// Return `true` when the image reads guest clusters from an external data
  /// source.
  pub fn uses_external_data_file(&self) -> bool {
    self.external_data_source.is_some()
  }

  /// Return parsed QCOW header extensions.
  pub fn header_extensions(&self) -> &[QcowHeaderExtension] {
    &self.header_extensions
  }

  /// Return parsed internal snapshots.
  pub fn snapshots(&self) -> &[QcowSnapshot] {
    &self.snapshots
  }

  /// Open a snapshot view as a read-only image surface.
  pub fn open_snapshot(&self, index: usize) -> Result<Self> {
    let snapshot = self
      .snapshots
      .get(index)
      .ok_or_else(|| Error::NotFound(format!("qcow snapshot index {index} is out of bounds")))?;
    let parsed = ParsedQcow {
      header: self.header.clone(),
      l1_table: self.l1_table.clone(),
      backing_file_name: self.backing_file_name.clone(),
      backing_file_format: self.backing_file_format.clone(),
      external_data_path: self.external_data_path.clone(),
      header_extensions: self.header_extensions.as_ref().to_vec(),
      snapshots: self.snapshots.as_ref().to_vec(),
    };

    Self::from_parsed(
      self.source.clone(),
      parsed,
      self.backing_image.clone(),
      self.external_data_source.clone(),
      Some(snapshot.l1_table.clone()),
      Some(if snapshot.virtual_disk_size != 0 {
        snapshot.virtual_disk_size
      } else {
        self.virtual_size
      }),
    )
  }

  fn cluster_size(&self) -> Result<u64> {
    self.header.cluster_size()
  }

  fn l2_entries_per_table(&self) -> Result<u64> {
    if self.header.uses_extended_l2() {
      self
        .cluster_size()?
        .checked_div(16)
        .ok_or_else(|| Error::InvalidRange("qcow extended l2 entry count overflow".to_string()))
    } else {
      self.header.l2_entry_count()
    }
  }

  fn subcluster_size(&self) -> Result<u64> {
    self
      .cluster_size()?
      .checked_div(32)
      .ok_or_else(|| Error::InvalidRange("qcow subcluster size overflow".to_string()))
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
      let storage = if self.header.uses_external_data_file() {
        self
          .external_data_source
          .as_ref()
          .ok_or_else(|| Error::NotFound("qcow external data source is missing".to_string()))?
      } else {
        &self.source
      };
      let cluster = storage.read_bytes_at(cluster_offset, cluster_size)?;
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
    if self.header.uses_extended_l2() {
      let pair_index = usize::try_from(l2_index)
        .map_err(|_| Error::InvalidRange("qcow l2 index conversion overflow".to_string()))?
        .checked_mul(2)
        .ok_or_else(|| Error::InvalidRange("qcow extended l2 index overflow".to_string()))?;
      let descriptor = *l2_table
        .get(pair_index)
        .ok_or_else(|| Error::InvalidRange(format!("qcow l2 index {l2_index} is out of bounds")))?;
      let bitmap = *l2_table
        .get(pair_index + 1)
        .ok_or_else(|| Error::InvalidRange(format!("qcow l2 index {l2_index} is out of bounds")))?;

      return self.parse_extended_l2_entry(descriptor, bitmap);
    }

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
    if cluster_offset == 0 && self.header.uses_external_data_file() {
      return Ok(ParsedL2Entry::Standard { cluster_offset: 0 });
    }
    if cluster_offset == 0 {
      return Ok(ParsedL2Entry::Sparse);
    }

    Ok(ParsedL2Entry::Standard { cluster_offset })
  }

  fn parse_extended_l2_entry(&self, descriptor: u64, bitmap: u64) -> Result<ParsedL2Entry> {
    if descriptor == 0 && bitmap == 0 {
      return Ok(ParsedL2Entry::Sparse);
    }

    let compressed = (descriptor & QCOW_OFLAG_COMPRESSED) != 0;
    if compressed {
      if bitmap != 0 {
        return Err(Error::InvalidFormat(
          "qcow extended compressed l2 entries must not carry a subcluster bitmap".to_string(),
        ));
      }

      return self.parse_l2_entry(descriptor);
    }
    if (descriptor & 1) != 0 {
      return Err(Error::InvalidFormat(
        "qcow extended l2 descriptors must not set the legacy zero flag".to_string(),
      ));
    }

    let cluster_offset = descriptor & self.l2_standard_offset_mask();
    let allocation_bitmap = bitmap as u32;
    let zero_bitmap = (bitmap >> 32) as u32;
    if allocation_bitmap & zero_bitmap != 0 {
      return Err(Error::InvalidFormat(
        "qcow extended l2 subclusters cannot be both allocated and zero".to_string(),
      ));
    }
    if cluster_offset == 0 && allocation_bitmap != 0 && !self.header.uses_external_data_file() {
      return Err(Error::InvalidFormat(
        "qcow extended allocated subclusters require a host cluster offset".to_string(),
      ));
    }
    if allocation_bitmap == 0 && zero_bitmap == u32::MAX {
      return Ok(ParsedL2Entry::Zero);
    }
    if allocation_bitmap == 0 && zero_bitmap == 0 {
      return Ok(ParsedL2Entry::Sparse);
    }
    if allocation_bitmap == u32::MAX && zero_bitmap == 0 {
      return Ok(ParsedL2Entry::Standard { cluster_offset });
    }

    Ok(ParsedL2Entry::Extended {
      cluster_offset,
      allocation_bitmap,
      zero_bitmap,
    })
  }

  fn read_compressed_cluster(&self, host_offset: u64, stored_size: usize) -> Result<Arc<Vec<u8>>> {
    let compressed = self.source.read_bytes_at(host_offset, stored_size)?;
    let cluster_size = usize::try_from(self.cluster_size()?)
      .map_err(|_| Error::InvalidRange("qcow cluster size is too large".to_string()))?;
    let mut cluster = vec![0u8; cluster_size];
    match self.header.compression_method {
      super::constants::QCOW_COMPRESSION_ZLIB => {
        let mut decoder = DeflateDecoder::new(compressed.as_slice());
        decoder.read_exact(&mut cluster).map_err(Error::Io)?;
      }
      super::constants::QCOW_COMPRESSION_ZSTD => {
        let mut decoder = ZstdDecoder::new(compressed.as_slice()).map_err(Error::Io)?;
        decoder.read_exact(&mut cluster).map_err(Error::Io)?;
      }
      method => {
        return Err(Error::InvalidFormat(format!(
          "unsupported qcow compressed cluster method: {method}"
        )));
      }
    }

    Ok(Arc::new(cluster))
  }
}

impl DataSource for QcowImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.virtual_size || buf.is_empty() {
      return Ok(0);
    }

    let cluster_size = self.cluster_size()?;
    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("qcow read offset overflow".to_string()))?;
      if absolute_offset >= self.virtual_size {
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
        ParsedL2Entry::Extended {
          cluster_offset: host_cluster_offset,
          allocation_bitmap,
          zero_bitmap,
        } => {
          let subcluster_size = self.subcluster_size()?;
          let subcluster_index = usize::try_from(within_cluster / subcluster_size)
            .map_err(|_| Error::InvalidRange("qcow subcluster index overflow".to_string()))?;
          let within_subcluster = within_cluster % subcluster_size;
          let subcluster_available = usize::try_from(
            subcluster_size
              .checked_sub(within_subcluster)
              .ok_or_else(|| Error::InvalidRange("qcow subcluster range underflow".to_string()))?,
          )
          .map_err(|_| Error::InvalidRange("qcow subcluster size overflow".to_string()))?;
          let available = available.min(subcluster_available);
          let subcluster_bit = 1u32
            .checked_shl(u32::try_from(subcluster_index).unwrap_or(u32::MAX))
            .ok_or_else(|| Error::InvalidRange("qcow subcluster bit overflow".to_string()))?;

          if (allocation_bitmap & subcluster_bit) != 0 {
            let cluster = self.read_cluster(host_cluster_offset)?;
            buf[copied..copied + available]
              .copy_from_slice(&cluster[cluster_offset..cluster_offset + available]);
          } else if (zero_bitmap & subcluster_bit) != 0 {
            buf[copied..copied + available].fill(0);
          } else if let Some(backing_image) = &self.backing_image {
            backing_image.read_exact_at(absolute_offset, &mut buf[copied..copied + available])?;
          } else {
            buf[copied..copied + available].fill(0);
          }

          copied += available;
          continue;
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
    Ok(self.virtual_size)
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

fn resolve_named_source(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, name: &str,
  purpose: RelatedSourcePurpose,
) -> Result<Option<(DataSourceHandle, RelatedPathBuf)>> {
  if let Ok(relative) = RelatedPathBuf::from_relative_path(name)
    && let Some(parent) = identity.logical_path().parent()
  {
    let joined = parent.join(&relative);
    if let Some(source) = resolver.resolve(&RelatedSourceRequest::new(purpose, joined.clone()))? {
      return Ok(Some((source, joined)));
    }
  }

  let file_name = name.rsplit(['\\', '/']).next().unwrap_or(name);
  let sibling = identity.sibling_path(file_name)?;
  Ok(
    resolver
      .resolve(&RelatedSourceRequest::new(purpose, sibling.clone()))?
      .map(|source| (source, sibling)),
  )
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
  fn resolves_relative_backing_file_paths() {
    let base_data = repeat_byte(0x3C, 65_536);
    let base_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow(Some(&base_data), None),
    });
    let overlay_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow(None, Some("../base/base.qcow2")),
    });
    let resolver = Resolver {
      files: HashMap::from([("images/overlay/../base/base.qcow2".to_string(), base_source)]),
    };
    let identity = SourceIdentity::from_relative_path("images/overlay/child.qcow2").unwrap();

    let image = QcowImage::open_with_hints(
      overlay_source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.backing_file_name(), Some("../base/base.qcow2"));
    assert_eq!(image.read_all().unwrap(), base_data);
  }

  #[test]
  fn reads_compressed_clusters_from_synthetic_qcow() {
    let cluster = repeat_byte(0x7E, 65_536);
    let image = QcowImage::open(Arc::new(MemDataSource {
      data: build_synthetic_qcow_from_cluster(SyntheticCluster::CompressedZlib(&cluster), None),
    }))
    .unwrap();

    assert_eq!(image.read_all().unwrap(), cluster);
  }

  #[test]
  fn reads_extended_l2_subclusters_from_synthetic_qcow() {
    let image = QcowImage::open(Arc::new(MemDataSource {
      data: build_synthetic_qcow_extended_l2(),
    }))
    .unwrap();
    let data = image.read_all().unwrap();

    assert!(data[..512].iter().all(|byte| *byte == 0xAB));
    assert!(data[512..].iter().all(|byte| *byte == 0));
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
      data: build_synthetic_qcow_v1(SyntheticCluster::CompressedZlib(&cluster)),
    }))
    .unwrap();

    assert_eq!(image.read_all().unwrap(), cluster);
  }

  #[test]
  fn reads_zstd_compressed_clusters_from_synthetic_qcow() {
    let cluster = repeat_byte(0x19, 65_536);
    let image = QcowImage::open(Arc::new(MemDataSource {
      data: build_synthetic_qcow_from_cluster(SyntheticCluster::CompressedZstd(&cluster), None),
    }))
    .unwrap();

    assert_eq!(image.read_all().unwrap(), cluster);
  }

  #[test]
  fn reads_from_external_data_files() {
    let external_cluster = repeat_byte(0xCC, 65_536);
    let metadata_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow_external_data("disk.raw"),
    });
    let external_source: DataSourceHandle = Arc::new(MemDataSource {
      data: external_cluster.clone(),
    });
    let resolver = Resolver {
      files: HashMap::from([("images/disk.raw".to_string(), external_source)]),
    };
    let identity = SourceIdentity::from_relative_path("images/disk.qcow2").unwrap();

    let image = QcowImage::open_with_hints(
      metadata_source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert!(image.uses_external_data_file());
    assert_eq!(image.read_all().unwrap(), external_cluster);
  }

  #[test]
  fn resolves_relative_external_data_paths() {
    let external_cluster = repeat_byte(0x5A, 65_536);
    let metadata_source: DataSourceHandle = Arc::new(MemDataSource {
      data: build_synthetic_qcow_external_data("../data/disk.raw"),
    });
    let external_source: DataSourceHandle = Arc::new(MemDataSource {
      data: external_cluster.clone(),
    });
    let resolver = Resolver {
      files: HashMap::from([("images/meta/../data/disk.raw".to_string(), external_source)]),
    };
    let identity = SourceIdentity::from_relative_path("images/meta/disk.qcow2").unwrap();

    let image = QcowImage::open_with_hints(
      metadata_source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.external_data_path(), Some("../data/disk.raw"));
    assert_eq!(image.read_all().unwrap(), external_cluster);
  }

  #[test]
  fn opens_snapshot_views_and_header_extensions() {
    let active_cluster = repeat_byte(0xAA, 65_536);
    let snapshot_cluster = repeat_byte(0x55, 65_536);
    let image = QcowImage::open(Arc::new(MemDataSource {
      data: build_synthetic_qcow_with_snapshot_and_extension(&active_cluster, &snapshot_cluster),
    }))
    .unwrap();

    assert_eq!(image.backing_file_format(), Some("raw"));
    assert_eq!(image.header_extensions().len(), 2);
    assert_eq!(image.snapshots().len(), 1);
    assert_eq!(image.snapshots()[0].name, "snapshot");

    let snapshot_view = image.open_snapshot(0).unwrap();

    assert_eq!(snapshot_view.read_all().unwrap(), snapshot_cluster);
    assert_eq!(image.read_all().unwrap(), active_cluster);
  }

  fn repeat_byte(byte: u8, size: usize) -> Vec<u8> {
    vec![byte; size]
  }

  enum SyntheticCluster<'a> {
    Sparse,
    Standard(&'a [u8]),
    CompressedZlib(&'a [u8]),
    CompressedZstd(&'a [u8]),
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
      SyntheticCluster::CompressedZlib(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        let compressed_sectors = compressed.len().div_ceil(512);
        let additional_sectors = compressed_sectors.saturating_sub(1);
        constants::QCOW_OFLAG_COMPRESSED
          | ((u64::try_from(additional_sectors).unwrap()) << (70 - CLUSTER_BITS))
          | DATA_OFFSET
      }
      SyntheticCluster::CompressedZstd(cluster_data) => {
        let compressed = zstd_cluster(cluster_data);
        let compressed_sectors = compressed.len().div_ceil(512);
        let additional_sectors = compressed_sectors.saturating_sub(1);
        data[72..80].copy_from_slice(&constants::QCOW_INCOMPAT_COMPRESSION.to_be_bytes());
        data[104] = constants::QCOW_COMPRESSION_ZSTD;
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
      SyntheticCluster::CompressedZlib(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + compressed.len()]
          .copy_from_slice(&compressed);
      }
      SyntheticCluster::CompressedZstd(cluster_data) => {
        let compressed = zstd_cluster(cluster_data);
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + compressed.len()]
          .copy_from_slice(&compressed);
      }
    }

    data
  }

  fn build_synthetic_qcow_extended_l2() -> Vec<u8> {
    const CLUSTER_BITS: u32 = 14;
    const CLUSTER_SIZE: usize = 1 << (CLUSTER_BITS as usize);
    const VIRTUAL_SIZE: u64 = CLUSTER_SIZE as u64;
    const SUBCLUSTER_SIZE: usize = CLUSTER_SIZE / 32;
    const REFCOUNT_TABLE_OFFSET: u64 = 0x0000_4000;
    const L1_OFFSET: u64 = 0x0000_8000;
    const L2_OFFSET: u64 = 0x0000_C000;
    const DATA_OFFSET: u64 = 0x0001_0000;
    let mut data = vec![0u8; 0x0001_4000];

    data[0..4].copy_from_slice(b"QFI\xfb");
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
    data[24..32].copy_from_slice(&VIRTUAL_SIZE.to_be_bytes());
    data[32..36].copy_from_slice(&0u32.to_be_bytes());
    data[36..40].copy_from_slice(&1u32.to_be_bytes());
    data[40..48].copy_from_slice(&L1_OFFSET.to_be_bytes());
    data[48..56].copy_from_slice(&REFCOUNT_TABLE_OFFSET.to_be_bytes());
    data[56..60].copy_from_slice(&1u32.to_be_bytes());
    data[60..64].copy_from_slice(&0u32.to_be_bytes());
    data[64..72].copy_from_slice(&0u64.to_be_bytes());
    data[72..80].copy_from_slice(&constants::QCOW_INCOMPAT_EXTL2.to_be_bytes());
    data[80..88].copy_from_slice(&0u64.to_be_bytes());
    data[88..96].copy_from_slice(&0u64.to_be_bytes());
    data[96..100].copy_from_slice(&4u32.to_be_bytes());
    data[100..104].copy_from_slice(&112u32.to_be_bytes());
    data[104] = 0;

    data[L1_OFFSET as usize..L1_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0000_C000u64).to_be_bytes());
    data[L2_OFFSET as usize..L2_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0001_0000u64).to_be_bytes());
    data[L2_OFFSET as usize + 8..L2_OFFSET as usize + 16].copy_from_slice(&1u64.to_be_bytes());
    data[DATA_OFFSET as usize..DATA_OFFSET as usize + SUBCLUSTER_SIZE].fill(0xAB);

    data
  }

  fn deflate_cluster(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
  }

  fn zstd_cluster(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 1).unwrap()
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
      SyntheticCluster::CompressedZlib(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        let shift = 63 - u32::from(CLUSTER_BITS);
        let stored_size = u64::try_from(compressed.len()).unwrap();
        (1u64 << 63) | (stored_size << shift) | DATA_OFFSET
      }
      SyntheticCluster::CompressedZstd(_) => unreachable!("qcow v1 only uses zlib compression"),
    };
    data[L2_OFFSET as usize..L2_OFFSET as usize + 8].copy_from_slice(&l2_entry.to_be_bytes());
    match cluster {
      SyntheticCluster::Sparse => {}
      SyntheticCluster::Standard(cluster_data) => {
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + cluster_data.len()]
          .copy_from_slice(cluster_data);
      }
      SyntheticCluster::CompressedZlib(cluster_data) => {
        let compressed = deflate_cluster(cluster_data);
        data[DATA_OFFSET as usize..DATA_OFFSET as usize + compressed.len()]
          .copy_from_slice(&compressed);
      }
      SyntheticCluster::CompressedZstd(_) => unreachable!("qcow v1 only uses zlib compression"),
    }

    data
  }

  fn build_synthetic_qcow_with_snapshot_and_extension(
    active_cluster: &[u8], snapshot_cluster: &[u8],
  ) -> Vec<u8> {
    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << (CLUSTER_BITS as usize);
    const VIRTUAL_SIZE: u64 = CLUSTER_SIZE as u64;
    const L1_OFFSET: u64 = 0x0003_0000;
    const SNAPSHOT_TABLE_OFFSET: u64 = 0x0002_0000;
    const ACTIVE_L2_OFFSET: u64 = 0x0004_0000;
    const SNAPSHOT_L1_OFFSET: u64 = 0x0003_8000;
    const SNAPSHOT_L2_OFFSET: u64 = 0x0004_8000;
    const ACTIVE_DATA_OFFSET: u64 = 0x0005_0000;
    const SNAPSHOT_DATA_OFFSET: u64 = 0x0006_0000;
    const REFCOUNT_TABLE_OFFSET: u64 = 0x0001_0000;
    let mut data = vec![0u8; 0x0007_0000];

    data[0..4].copy_from_slice(b"QFI\xfb");
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
    data[24..32].copy_from_slice(&VIRTUAL_SIZE.to_be_bytes());
    data[32..36].copy_from_slice(&0u32.to_be_bytes());
    data[36..40].copy_from_slice(&1u32.to_be_bytes());
    data[40..48].copy_from_slice(&L1_OFFSET.to_be_bytes());
    data[48..56].copy_from_slice(&REFCOUNT_TABLE_OFFSET.to_be_bytes());
    data[56..60].copy_from_slice(&1u32.to_be_bytes());
    data[60..64].copy_from_slice(&1u32.to_be_bytes());
    data[64..72].copy_from_slice(&SNAPSHOT_TABLE_OFFSET.to_be_bytes());
    data[72..80].copy_from_slice(&0u64.to_be_bytes());
    data[80..88].copy_from_slice(&0u64.to_be_bytes());
    data[88..96].copy_from_slice(&0u64.to_be_bytes());
    data[96..100].copy_from_slice(&4u32.to_be_bytes());
    data[100..104].copy_from_slice(&112u32.to_be_bytes());
    data[104] = 0;

    let ext_offset = 112usize;
    data[ext_offset..ext_offset + 4].copy_from_slice(&0xE2792ACAu32.to_be_bytes());
    data[ext_offset + 4..ext_offset + 8].copy_from_slice(&3u32.to_be_bytes());
    data[ext_offset + 8..ext_offset + 11].copy_from_slice(b"raw");
    let end_offset = ext_offset + 16;
    data[end_offset..end_offset + 8].fill(0);

    data[L1_OFFSET as usize..L1_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0004_0000u64).to_be_bytes());
    data[ACTIVE_L2_OFFSET as usize..ACTIVE_L2_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0005_0000u64).to_be_bytes());
    data[ACTIVE_DATA_OFFSET as usize..ACTIVE_DATA_OFFSET as usize + active_cluster.len()]
      .copy_from_slice(active_cluster);

    let snapshot_entry_offset = SNAPSHOT_TABLE_OFFSET as usize;
    data[snapshot_entry_offset..snapshot_entry_offset + 8]
      .copy_from_slice(&SNAPSHOT_L1_OFFSET.to_be_bytes());
    data[snapshot_entry_offset + 8..snapshot_entry_offset + 12]
      .copy_from_slice(&1u32.to_be_bytes());
    data[snapshot_entry_offset + 12..snapshot_entry_offset + 14]
      .copy_from_slice(&5u16.to_be_bytes());
    data[snapshot_entry_offset + 14..snapshot_entry_offset + 16]
      .copy_from_slice(&8u16.to_be_bytes());
    data[snapshot_entry_offset + 16..snapshot_entry_offset + 20]
      .copy_from_slice(&123u32.to_be_bytes());
    data[snapshot_entry_offset + 20..snapshot_entry_offset + 24]
      .copy_from_slice(&456u32.to_be_bytes());
    data[snapshot_entry_offset + 24..snapshot_entry_offset + 32]
      .copy_from_slice(&789u64.to_be_bytes());
    data[snapshot_entry_offset + 32..snapshot_entry_offset + 36]
      .copy_from_slice(&0u32.to_be_bytes());
    data[snapshot_entry_offset + 36..snapshot_entry_offset + 40]
      .copy_from_slice(&24u32.to_be_bytes());
    data[snapshot_entry_offset + 40..snapshot_entry_offset + 48]
      .copy_from_slice(&0u64.to_be_bytes());
    data[snapshot_entry_offset + 48..snapshot_entry_offset + 56]
      .copy_from_slice(&VIRTUAL_SIZE.to_be_bytes());
    data[snapshot_entry_offset + 56..snapshot_entry_offset + 64]
      .copy_from_slice(&12345i64.to_be_bytes());
    data[snapshot_entry_offset + 64..snapshot_entry_offset + 69].copy_from_slice(b"snap1");
    data[snapshot_entry_offset + 69..snapshot_entry_offset + 77].copy_from_slice(b"snapshot");

    data[SNAPSHOT_L1_OFFSET as usize..SNAPSHOT_L1_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0004_8000u64).to_be_bytes());
    data[SNAPSHOT_L2_OFFSET as usize..SNAPSHOT_L2_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0006_0000u64).to_be_bytes());
    data[SNAPSHOT_DATA_OFFSET as usize..SNAPSHOT_DATA_OFFSET as usize + snapshot_cluster.len()]
      .copy_from_slice(snapshot_cluster);

    data
  }

  fn build_synthetic_qcow_external_data(external_name: &str) -> Vec<u8> {
    const CLUSTER_BITS: u32 = 16;
    const CLUSTER_SIZE: usize = 1 << (CLUSTER_BITS as usize);
    const VIRTUAL_SIZE: u64 = CLUSTER_SIZE as u64;
    const L1_OFFSET: u64 = 0x0003_0000;
    const L2_OFFSET: u64 = 0x0004_0000;
    const REFCOUNT_TABLE_OFFSET: u64 = 0x0001_0000;
    let mut data = vec![0u8; 0x0005_0000];

    data[0..4].copy_from_slice(b"QFI\xfb");
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
    data[24..32].copy_from_slice(&VIRTUAL_SIZE.to_be_bytes());
    data[32..36].copy_from_slice(&0u32.to_be_bytes());
    data[36..40].copy_from_slice(&1u32.to_be_bytes());
    data[40..48].copy_from_slice(&L1_OFFSET.to_be_bytes());
    data[48..56].copy_from_slice(&REFCOUNT_TABLE_OFFSET.to_be_bytes());
    data[56..60].copy_from_slice(&1u32.to_be_bytes());
    data[60..64].copy_from_slice(&0u32.to_be_bytes());
    data[64..72].copy_from_slice(&0u64.to_be_bytes());
    data[72..80].copy_from_slice(&constants::QCOW_INCOMPAT_DATA_FILE.to_be_bytes());
    data[80..88].copy_from_slice(&0u64.to_be_bytes());
    data[88..96].copy_from_slice(&0u64.to_be_bytes());
    data[96..100].copy_from_slice(&4u32.to_be_bytes());
    data[100..104].copy_from_slice(&112u32.to_be_bytes());
    data[104] = 0;

    let ext_offset = 112usize;
    data[ext_offset..ext_offset + 4].copy_from_slice(&0x44415441u32.to_be_bytes());
    data[ext_offset + 4..ext_offset + 8]
      .copy_from_slice(&(external_name.len() as u32).to_be_bytes());
    data[ext_offset + 8..ext_offset + 8 + external_name.len()]
      .copy_from_slice(external_name.as_bytes());
    let ext_end = ext_offset + 8 + external_name.len();
    let ext_aligned_end = ext_end + (8 - (ext_end % 8)) % 8;
    data[ext_aligned_end..ext_aligned_end + 8].fill(0);

    data[L1_OFFSET as usize..L1_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0004_0000u64).to_be_bytes());
    data[L2_OFFSET as usize..L2_OFFSET as usize + 8]
      .copy_from_slice(&(0x8000_0000_0000_0000u64).to_be_bytes());

    data
  }
}
