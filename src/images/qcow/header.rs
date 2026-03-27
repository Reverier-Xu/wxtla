//! QCOW header parsing.

use super::constants::{
  QCOW_COMPRESSION_ZLIB, QCOW_COMPRESSION_ZSTD, QCOW_CRYPT_NONE, QCOW_INCOMPAT_CORRUPT,
  QCOW_INCOMPAT_DATA_FILE, QCOW_INCOMPAT_DIRTY, QCOW_INCOMPAT_EXTL2, QCOW_V1_HEADER_SIZE,
  QCOW_V2_HEADER_SIZE, QCOW_V3_HEADER_MIN_SIZE, QCOW_V3_HEADER_WITH_COMPRESSION, QCOW_VERSION_1,
  QCOW_VERSION_2, QCOW_VERSION_3, SUPPORTED_CLUSTER_BITS, SUPPORTED_REFCOUNT_ORDER,
};
use crate::{ByteSource, Error, Result};

/// Parsed QCOW2/3 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QcowHeader {
  /// QCOW format version.
  pub version: u32,
  /// Size of the on-disk header.
  pub header_size: u32,
  /// Backing file name offset.
  pub backing_file_offset: u64,
  /// Backing file name size.
  pub backing_file_size: u32,
  /// Cluster bit count.
  pub cluster_bits: u32,
  /// Virtual image size.
  pub virtual_size: u64,
  /// Number of level 2 table bits.
  pub l2_table_bits: u32,
  /// Encryption method.
  pub encryption_method: u32,
  /// Number of L1 entries.
  pub l1_entry_count: u32,
  /// L1 table offset.
  pub l1_table_offset: u64,
  /// Refcount table offset.
  pub refcount_table_offset: u64,
  /// Number of refcount table clusters.
  pub refcount_table_clusters: u32,
  /// Number of snapshots.
  pub snapshot_count: u32,
  /// Snapshot table offset.
  pub snapshot_table_offset: u64,
  /// Incompatible feature flags.
  pub incompatible_features: u64,
  /// Compatible feature flags.
  pub compatible_features: u64,
  /// Auto-clear feature flags.
  pub autoclear_features: u64,
  /// Refcount order.
  pub refcount_order: u32,
  /// Compression method.
  pub compression_method: u8,
}

impl QcowHeader {
  /// Read a QCOW header from the start of a source.
  pub fn read(source: &dyn ByteSource) -> Result<Self> {
    let prefix = source.read_bytes_at(0, QCOW_V3_HEADER_WITH_COMPRESSION)?;
    Self::parse(&prefix)
  }

  /// Parse a QCOW header from an in-memory prefix.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < QCOW_V1_HEADER_SIZE {
      return Err(Error::InvalidFormat(format!(
        "qcow header is too small: {}",
        data.len()
      )));
    }
    if &data[0..4] != super::constants::FILE_HEADER_MAGIC {
      return Err(Error::InvalidFormat(
        "qcow file header signature is missing".to_string(),
      ));
    }

    let version = read_u32_be(data, 4)?;
    if version != QCOW_VERSION_1 && version != QCOW_VERSION_2 && version != QCOW_VERSION_3 {
      return Err(Error::InvalidFormat(format!(
        "unsupported qcow version: {version}"
      )));
    }

    let header_size = if version == QCOW_VERSION_1 {
      QCOW_V1_HEADER_SIZE as u32
    } else if version == QCOW_VERSION_2 {
      QCOW_V2_HEADER_SIZE as u32
    } else {
      read_u32_be(data, 100)?
    };
    let header_size_usize = usize::try_from(header_size)
      .map_err(|_| Error::InvalidRange("qcow header size is too large".to_string()))?;
    if header_size_usize > data.len() {
      return Err(Error::InvalidFormat(format!(
        "unsupported qcow header size: {header_size}"
      )));
    }
    if version == QCOW_VERSION_3 && header_size_usize < QCOW_V3_HEADER_MIN_SIZE {
      return Err(Error::InvalidFormat(format!(
        "unsupported qcow header size: {header_size}"
      )));
    }

    let cluster_bits = if version == QCOW_VERSION_1 {
      u32::from(*data.get(32).ok_or_else(|| {
        Error::InvalidFormat("qcow v1 header is missing cluster bits".to_string())
      })?)
    } else {
      read_u32_be(data, 20)?
    };
    if !SUPPORTED_CLUSTER_BITS.contains(&cluster_bits) {
      return Err(Error::InvalidFormat(format!(
        "unsupported qcow cluster bit count: {cluster_bits}"
      )));
    }

    let l2_table_bits = if version == QCOW_VERSION_1 {
      u32::from(*data.get(33).ok_or_else(|| {
        Error::InvalidFormat("qcow v1 header is missing l2 table bits".to_string())
      })?)
    } else {
      cluster_bits
        .checked_sub(3)
        .ok_or_else(|| Error::InvalidFormat("qcow cluster bits are too small".to_string()))?
    };

    let encryption_method = if version == QCOW_VERSION_1 {
      read_u32_be(data, 36)?
    } else {
      read_u32_be(data, 32)?
    };
    if encryption_method != QCOW_CRYPT_NONE {
      return Err(Error::InvalidFormat(format!(
        "unsupported qcow encryption method: {encryption_method}"
      )));
    }

    let compression_method =
      if version == QCOW_VERSION_3 && header_size_usize >= QCOW_V3_HEADER_WITH_COMPRESSION {
        data[104]
      } else {
        QCOW_COMPRESSION_ZLIB
      };
    if compression_method != QCOW_COMPRESSION_ZLIB && compression_method != QCOW_COMPRESSION_ZSTD {
      return Err(Error::InvalidFormat(format!(
        "unsupported qcow compression method: {compression_method}"
      )));
    }

    let refcount_order = if version == QCOW_VERSION_3 {
      read_u32_be(data, 96)?
    } else {
      SUPPORTED_REFCOUNT_ORDER
    };
    if refcount_order != SUPPORTED_REFCOUNT_ORDER {
      return Err(Error::InvalidFormat(format!(
        "unsupported qcow refcount order: {refcount_order}"
      )));
    }

    Ok(Self {
      version,
      header_size,
      backing_file_offset: read_u64_be(data, 8)?,
      backing_file_size: read_u32_be(data, 16)?,
      cluster_bits,
      virtual_size: read_u64_be(data, 24)?,
      l2_table_bits,
      encryption_method,
      l1_entry_count: if version == QCOW_VERSION_1 {
        compute_v1_l1_entry_count(read_u64_be(data, 24)?, cluster_bits, l2_table_bits)?
      } else {
        read_u32_be(data, 36)?
      },
      l1_table_offset: read_u64_be(data, 40)?,
      refcount_table_offset: if version == QCOW_VERSION_1 {
        0
      } else {
        read_u64_be(data, 48)?
      },
      refcount_table_clusters: if version == QCOW_VERSION_1 {
        0
      } else {
        read_u32_be(data, 56)?
      },
      snapshot_count: if version == QCOW_VERSION_1 {
        0
      } else {
        read_u32_be(data, 60)?
      },
      snapshot_table_offset: if version == QCOW_VERSION_1 {
        0
      } else {
        read_u64_be(data, 64)?
      },
      incompatible_features: if version == QCOW_VERSION_3 {
        read_u64_be(data, 72)?
      } else {
        0
      },
      compatible_features: if version == QCOW_VERSION_3 {
        read_u64_be(data, 80)?
      } else {
        0
      },
      autoclear_features: if version == QCOW_VERSION_3 {
        read_u64_be(data, 88)?
      } else {
        0
      },
      refcount_order,
      compression_method,
    })
  }

  /// Return the cluster size in bytes.
  pub fn cluster_size(&self) -> Result<u64> {
    1u64
      .checked_shl(self.cluster_bits)
      .ok_or_else(|| Error::InvalidRange("qcow cluster size overflow".to_string()))
  }

  /// Return the number of L2 entries per table for standard 8-byte entries.
  pub fn l2_entry_count(&self) -> Result<u64> {
    1u64
      .checked_shl(self.l2_table_bits)
      .ok_or_else(|| Error::InvalidRange("qcow l2 entry count overflow".to_string()))
  }

  /// Return `true` when the image uses an external data file.
  pub const fn uses_external_data_file(&self) -> bool {
    (self.incompatible_features & QCOW_INCOMPAT_DATA_FILE) != 0
  }

  /// Return `true` when the image declares an alternate compression type.
  pub const fn uses_non_default_compression(&self) -> bool {
    (self.incompatible_features & super::constants::QCOW_INCOMPAT_COMPRESSION) != 0
  }

  /// Return `true` when the image still has the dirty refcount flag set.
  pub const fn is_dirty(&self) -> bool {
    (self.incompatible_features & QCOW_INCOMPAT_DIRTY) != 0
  }

  /// Return `true` when the image is marked corrupt.
  pub const fn is_marked_corrupt(&self) -> bool {
    (self.incompatible_features & QCOW_INCOMPAT_CORRUPT) != 0
  }

  /// Return `true` when level-2 tables use the extended entry format.
  pub const fn uses_extended_l2(&self) -> bool {
    (self.incompatible_features & QCOW_INCOMPAT_EXTL2) != 0
  }

  /// Return `true` when the raw-external-data auto-clear bit is set.
  pub const fn raw_external_data(&self) -> bool {
    (self.autoclear_features & 0x0000_0002) != 0
  }
}

fn compute_v1_l1_entry_count(
  virtual_size: u64, cluster_bits: u32, l2_table_bits: u32,
) -> Result<u32> {
  let cluster_size = 1u64
    .checked_shl(cluster_bits)
    .ok_or_else(|| Error::InvalidRange("qcow v1 cluster size overflow".to_string()))?;
  let l2_entry_count = 1u64
    .checked_shl(l2_table_bits)
    .ok_or_else(|| Error::InvalidRange("qcow v1 l2 entry count overflow".to_string()))?;
  let guest_size_per_l1_entry = cluster_size
    .checked_mul(l2_entry_count)
    .ok_or_else(|| Error::InvalidRange("qcow v1 l1 coverage overflow".to_string()))?;
  let l1_entry_count = virtual_size.div_ceil(guest_size_per_l1_entry);

  u32::try_from(l1_entry_count)
    .map_err(|_| Error::InvalidRange("qcow v1 l1 entry count is too large".to_string()))
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
  let bytes = data
    .get(offset..offset + 4)
    .ok_or_else(|| Error::InvalidFormat(format!("qcow field at offset {offset} is truncated")))?;
  Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_be(data: &[u8], offset: usize) -> Result<u64> {
  let bytes = data
    .get(offset..offset + 8)
    .ok_or_else(|| Error::InvalidFormat(format!("qcow field at offset {offset} is truncated")))?;
  Ok(u64::from_be_bytes([
    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
  ]))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_version_three_header() {
    let mut data = vec![
      0x51, 0x46, 0x49, 0xFB, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x70, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    data.resize(112, 0);
    let header = QcowHeader::parse(&data).unwrap();

    assert_eq!(header.version, 3);
    assert_eq!(header.cluster_size().unwrap(), 65_536);
    assert_eq!(header.l2_entry_count().unwrap(), 8_192);
    assert_eq!(header.refcount_order, 4);
  }

  #[test]
  fn parses_version_one_header() {
    let mut data = vec![0u8; 48];
    data[0..4].copy_from_slice(b"QFI\xfb");
    data[4..8].copy_from_slice(&1u32.to_be_bytes());
    data[20..24].copy_from_slice(&0x6633_916Au32.to_be_bytes());
    data[24..32].copy_from_slice(&65_536u64.to_be_bytes());
    data[32] = 16;
    data[33] = 13;
    data[36..40].copy_from_slice(&0u32.to_be_bytes());
    data[40..48].copy_from_slice(&0x0000_0000_0003_0000u64.to_be_bytes());
    let header = QcowHeader::parse(&data).unwrap();

    assert_eq!(header.version, 1);
    assert_eq!(header.virtual_size, 65_536);
    assert_eq!(header.cluster_bits, 16);
    assert_eq!(header.l2_table_bits, 13);
    assert_eq!(header.l1_entry_count, 1);
    assert_eq!(header.l1_table_offset, 0x30000);
  }
}
