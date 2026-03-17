//! QCOW header and table parsing.

use std::sync::Arc;

use super::{
  constants::{
    QCOW_COMPRESSION_ZLIB, QCOW_CRYPT_NONE, QCOW_INCOMPAT_COMPRESSION, QCOW_INCOMPAT_CORRUPT,
    QCOW_INCOMPAT_DATA_FILE, QCOW_INCOMPAT_DIRTY, QCOW_INCOMPAT_EXTL2,
  },
  header::QcowHeader,
};
use crate::{DataSource, DataSourceHandle, Error, Result};

/// Parsed QCOW metadata required to open an image surface.
pub struct ParsedQcow {
  /// Parsed QCOW header.
  pub header: QcowHeader,
  /// Parsed L1 table entries.
  pub l1_table: Arc<[u64]>,
  /// Optional backing file name from the header.
  pub backing_file_name: Option<String>,
}

/// Parse a QCOW image source.
pub fn parse(source: DataSourceHandle) -> Result<ParsedQcow> {
  let header = QcowHeader::read(source.as_ref())?;
  validate_supported_features(&header)?;
  let backing_file_name = read_backing_file_name(source.as_ref(), &header)?;
  let l1_table = read_l1_table(source.as_ref(), &header)?;

  Ok(ParsedQcow {
    header,
    l1_table,
    backing_file_name,
  })
}

fn validate_supported_features(header: &QcowHeader) -> Result<()> {
  if header.encryption_method != QCOW_CRYPT_NONE {
    return Err(Error::InvalidFormat(
      "encrypted qcow images are not supported yet".to_string(),
    ));
  }
  if header.snapshot_count != 0 {
    return Err(Error::InvalidFormat(
      "qcow snapshots are not supported yet".to_string(),
    ));
  }
  if (header.incompatible_features & QCOW_INCOMPAT_DATA_FILE) != 0 {
    return Err(Error::InvalidFormat(
      "qcow external data files are not supported yet".to_string(),
    ));
  }
  if (header.incompatible_features & QCOW_INCOMPAT_EXTL2) != 0 {
    return Err(Error::InvalidFormat(
      "qcow extended l2 entries are not supported yet".to_string(),
    ));
  }
  if (header.incompatible_features & QCOW_INCOMPAT_COMPRESSION) != 0
    && header.compression_method != QCOW_COMPRESSION_ZLIB
  {
    return Err(Error::InvalidFormat(format!(
      "unsupported qcow compressed-cluster method: {}",
      header.compression_method
    )));
  }
  if (header.incompatible_features & QCOW_INCOMPAT_DIRTY) != 0 {
    return Err(Error::InvalidFormat(
      "qcow dirty images are not supported yet".to_string(),
    ));
  }
  if (header.incompatible_features & QCOW_INCOMPAT_CORRUPT) != 0 {
    return Err(Error::InvalidFormat(
      "qcow images marked corrupt are not supported".to_string(),
    ));
  }

  Ok(())
}

fn read_backing_file_name(source: &dyn DataSource, header: &QcowHeader) -> Result<Option<String>> {
  if header.backing_file_size == 0 {
    return Ok(None);
  }

  let data = source.read_bytes_at(
    header.backing_file_offset,
    usize::try_from(header.backing_file_size)
      .map_err(|_| Error::InvalidRange("qcow backing file name is too large".to_string()))?,
  )?;
  let backing_file_name = String::from_utf8(data)
    .map_err(|_| Error::InvalidFormat("qcow backing file name is not valid UTF-8".to_string()))?;

  Ok(Some(backing_file_name))
}

fn read_l1_table(source: &dyn DataSource, header: &QcowHeader) -> Result<Arc<[u64]>> {
  let entry_count = usize::try_from(header.l1_entry_count)
    .map_err(|_| Error::InvalidRange("qcow l1 entry count is too large".to_string()))?;
  let table_bytes = entry_count
    .checked_mul(8)
    .ok_or_else(|| Error::InvalidRange("qcow l1 table size overflow".to_string()))?;
  let raw = source.read_bytes_at(header.l1_table_offset, table_bytes)?;

  let entries = raw
    .chunks_exact(8)
    .map(|chunk| {
      Ok(u64::from_be_bytes([
        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
      ]))
    })
    .collect::<Result<Vec<_>>>()?;

  Ok(Arc::from(entries))
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
  fn parses_qcow_fixture_header_and_l1() {
    let parsed = parse(sample_source("qcow/ext2.qcow2")).unwrap();

    assert_eq!(parsed.header.version, 3);
    assert_eq!(parsed.header.virtual_size, 4_194_304);
    assert_eq!(parsed.l1_table.len(), 1);
    assert_eq!(parsed.backing_file_name, None);
  }
}
