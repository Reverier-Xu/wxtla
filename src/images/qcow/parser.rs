//! QCOW header and table parsing.

use std::sync::Arc;

use super::{
  constants::{
    QCOW_COMPRESSION_ZLIB, QCOW_COMPRESSION_ZSTD, QCOW_CRYPT_NONE, QCOW_INCOMPAT_COMPRESSION,
  },
  extension::QcowHeaderExtension,
  header::QcowHeader,
  snapshot::QcowSnapshot,
  validation::{validate_cluster_alignment, validate_header_layout, validate_range},
};
use crate::{ByteSource, ByteSourceHandle, Error, Result};

/// Parsed QCOW metadata required to open an image surface.
pub struct ParsedQcow {
  /// Parsed QCOW header.
  pub header: QcowHeader,
  /// Parsed L1 table entries.
  pub l1_table: Arc<[u64]>,
  /// Optional backing file name from the header.
  pub backing_file_name: Option<String>,
  /// Optional backing file format from header extensions.
  pub backing_file_format: Option<String>,
  /// Optional external data path from header extensions.
  pub external_data_path: Option<String>,
  /// Parsed header extensions.
  pub header_extensions: Vec<QcowHeaderExtension>,
  /// Parsed internal snapshots.
  pub snapshots: Vec<QcowSnapshot>,
}

/// Parse a QCOW image source.
pub fn parse(source: ByteSourceHandle) -> Result<ParsedQcow> {
  let header = QcowHeader::read(source.as_ref())?;
  validate_supported_features(&header)?;
  validate_header_layout(source.as_ref(), &header)?;
  let backing_file_name = read_backing_file_name(source.as_ref(), &header)?;
  let header_extensions = read_header_extensions(source.as_ref(), &header)?;
  let backing_file_format = find_extension_string(&header_extensions, true)?;
  let external_data_path = find_extension_string(&header_extensions, false)?;
  let snapshots = QcowSnapshot::parse_many(source.as_ref(), &header)?;
  let l1_table = read_l1_table(source.as_ref(), &header)?;

  Ok(ParsedQcow {
    header,
    l1_table,
    backing_file_name,
    backing_file_format,
    external_data_path,
    header_extensions,
    snapshots,
  })
}

fn validate_supported_features(header: &QcowHeader) -> Result<()> {
  if header.encryption_method != QCOW_CRYPT_NONE {
    return Err(Error::invalid_format(
      "encrypted qcow images are not supported yet".to_string(),
    ));
  }
  if header.uses_extended_l2() && header.cluster_bits < 14 {
    return Err(Error::invalid_format(
      "qcow extended l2 entries require cluster sizes of at least 16384 bytes".to_string(),
    ));
  }
  if (header.incompatible_features & QCOW_INCOMPAT_COMPRESSION) != 0
    && header.compression_method != QCOW_COMPRESSION_ZSTD
  {
    return Err(Error::invalid_format(format!(
      "unsupported qcow compressed-cluster method: {}",
      header.compression_method
    )));
  }
  if (header.incompatible_features & QCOW_INCOMPAT_COMPRESSION) == 0
    && header.compression_method != QCOW_COMPRESSION_ZLIB
  {
    return Err(Error::invalid_format(
      "qcow default compression mode must use zlib".to_string(),
    ));
  }
  if header.uses_external_data_file() {
    if header.snapshot_count != 0 {
      return Err(Error::invalid_format(
        "qcow images with an external data file must not contain internal snapshots".to_string(),
      ));
    }
    if header.uses_non_default_compression() {
      return Err(Error::invalid_format(
        "qcow images with an external data file must not use compressed clusters".to_string(),
      ));
    }
  }

  Ok(())
}

fn read_backing_file_name(source: &dyn ByteSource, header: &QcowHeader) -> Result<Option<String>> {
  if header.backing_file_size == 0 {
    return Ok(None);
  }

  let data = source.read_bytes_at(
    header.backing_file_offset,
    usize::try_from(header.backing_file_size)
      .map_err(|_| Error::invalid_range("qcow backing file name is too large"))?,
  )?;
  let backing_file_name = String::from_utf8(data)
    .map_err(|_| Error::invalid_format("qcow backing file name is not valid UTF-8"))?;

  Ok(Some(backing_file_name))
}

fn read_l1_table(source: &dyn ByteSource, header: &QcowHeader) -> Result<Arc<[u64]>> {
  let entry_count = usize::try_from(header.l1_entry_count)
    .map_err(|_| Error::invalid_range("qcow l1 entry count is too large"))?;
  let table_bytes = entry_count
    .checked_mul(8)
    .ok_or_else(|| Error::invalid_range("qcow l1 table size overflow"))?;
  let raw = source.read_bytes_at(header.l1_table_offset, table_bytes)?;

  let entries = raw
    .chunks_exact(8)
    .enumerate()
    .map(|(index, chunk)| {
      let raw_entry = u64::from_be_bytes([
        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
      ]);
      let offset_mask = if header.version == 1 {
        (1u64 << 63) - 1
      } else {
        0x00FF_FFFF_FFFF_FE00
      };
      if header.version != 1 {
        let reserved_bits = raw_entry & !(offset_mask | (1u64 << 63));
        if reserved_bits != 0 {
          return Err(Error::invalid_format(format!(
            "qcow l1 entry {index} uses reserved bits"
          )));
        }
      }
      let l2_offset = raw_entry & offset_mask;
      if l2_offset != 0 {
        validate_cluster_alignment(l2_offset, header.cluster_size()?, "qcow l2 table")?;
        validate_range(
          source.size()?,
          l2_offset,
          header.cluster_size()?,
          &format!("qcow l2 table {index}"),
        )?;
      }

      Ok(raw_entry)
    })
    .collect::<Result<Vec<_>>>()?;

  Ok(Arc::from(entries))
}

fn read_header_extensions(
  source: &dyn ByteSource, header: &QcowHeader,
) -> Result<Vec<QcowHeaderExtension>> {
  let mut start = u64::from(header.header_size);
  if header.backing_file_size != 0 {
    let backing_file_end = header
      .backing_file_offset
      .checked_add(u64::from(header.backing_file_size))
      .ok_or_else(|| Error::invalid_range("qcow backing file name range overflow"))?;
    let aligned_backing_file_end = backing_file_end
      .checked_add((8 - (backing_file_end % 8)) % 8)
      .ok_or_else(|| Error::invalid_range("qcow backing file name alignment overflow"))?;
    start = start.max(aligned_backing_file_end);
  }
  if start == 0 {
    return Ok(Vec::new());
  }
  let end = header.l1_table_offset.min(source.size()?);
  if end <= start {
    return Ok(Vec::new());
  }
  let size = usize::try_from(end - start)
    .map_err(|_| Error::invalid_range("qcow header extension region is too large"))?;
  let data = source.read_bytes_at(start, size)?;

  QcowHeaderExtension::parse_many(&data)
}

fn find_extension_string(
  extensions: &[QcowHeaderExtension], backing_format: bool,
) -> Result<Option<String>> {
  let kind = if backing_format {
    super::extension::QcowHeaderExtensionKind::BackingFileFormat
  } else {
    super::extension::QcowHeaderExtensionKind::ExternalDataPath
  };

  for extension in extensions {
    if extension.kind == kind {
      return extension.utf8_string();
    }
  }

  Ok(None)
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;

  struct MemDataSource {
    data: Vec<u8>,
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
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Arc::new(MemDataSource {
      data: std::fs::read(path).unwrap(),
    })
  }

  #[test]
  fn parses_qcow_fixture_header_and_l1() {
    let parsed = parse(sample_source("qcow/ext2.qcow2")).unwrap();

    assert_eq!(parsed.header.version, 3);
    assert_eq!(parsed.header.virtual_size, 4_194_304);
    assert_eq!(parsed.l1_table.len(), 1);
    assert_eq!(parsed.backing_file_name, None);
  }

  #[test]
  fn accepts_dirty_qcow_images_for_read_only_parsing() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("qcow/ext2.qcow2"),
    )
    .unwrap();
    let incompatible = u64::from_be_bytes(data[72..80].try_into().unwrap())
      | super::super::constants::QCOW_INCOMPAT_DIRTY;
    data[72..80].copy_from_slice(&incompatible.to_be_bytes());

    let parsed = parse(Arc::new(MemDataSource { data })).unwrap();

    assert_eq!(
      parsed.header.incompatible_features & super::super::constants::QCOW_INCOMPAT_DIRTY,
      super::super::constants::QCOW_INCOMPAT_DIRTY
    );
  }

  #[test]
  fn accepts_corrupt_qcow_images_for_best_effort_read_only_parsing() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("qcow/ext2.qcow2"),
    )
    .unwrap();
    let incompatible = u64::from_be_bytes(data[72..80].try_into().unwrap())
      | super::super::constants::QCOW_INCOMPAT_CORRUPT;
    data[72..80].copy_from_slice(&incompatible.to_be_bytes());

    let parsed = parse(Arc::new(MemDataSource { data })).unwrap();

    assert!(parsed.header.is_marked_corrupt());
  }

  #[test]
  fn rejects_misaligned_l2_offsets() {
    let source: ByteSourceHandle = Arc::new(MemDataSource {
      data: build_invalid_v3_qcow(0x40001, 1),
    });

    let result = parse(source);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_missing_refcount_clusters_in_qcow2() {
    let source: ByteSourceHandle = Arc::new(MemDataSource {
      data: build_invalid_v3_qcow(0x40000, 0),
    });

    let result = parse(source);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  fn build_invalid_v3_qcow(l2_offset: u64, refcount_table_clusters: u32) -> Vec<u8> {
    let mut data = vec![0u8; 0x0006_0000];
    data[0..4].copy_from_slice(b"QFI\xfb");
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[20..24].copy_from_slice(&16u32.to_be_bytes());
    data[24..32].copy_from_slice(&65_536u64.to_be_bytes());
    data[32..36].copy_from_slice(&0u32.to_be_bytes());
    data[36..40].copy_from_slice(&1u32.to_be_bytes());
    data[40..48].copy_from_slice(&0x0003_0000u64.to_be_bytes());
    data[48..56].copy_from_slice(&0x0001_0000u64.to_be_bytes());
    data[56..60].copy_from_slice(&refcount_table_clusters.to_be_bytes());
    data[60..64].copy_from_slice(&0u32.to_be_bytes());
    data[64..72].copy_from_slice(&0u64.to_be_bytes());
    data[72..80].copy_from_slice(&0u64.to_be_bytes());
    data[80..88].copy_from_slice(&0u64.to_be_bytes());
    data[88..96].copy_from_slice(&0u64.to_be_bytes());
    data[96..100].copy_from_slice(&4u32.to_be_bytes());
    data[100..104].copy_from_slice(&112u32.to_be_bytes());
    data[104] = 0;
    data[0x0003_0000..0x0003_0008].copy_from_slice(&l2_offset.to_be_bytes());
    data
  }
}
