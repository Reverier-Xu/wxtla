//! VHDX top-level header and region-table parsing.

use super::{constants, guid::VhdxGuid};
use crate::{ByteSource, Error, Result};

/// Parsed VHDX image header copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdxImageHeader {
  /// Monotonic sequence number used to pick the active header.
  pub sequence_number: u64,
  /// File write identifier.
  pub file_write_identifier: VhdxGuid,
  /// Data write identifier.
  pub data_write_identifier: VhdxGuid,
  /// Active log identifier.
  pub log_identifier: VhdxGuid,
  /// Log format version.
  pub log_version: u16,
  /// VHDX format version.
  pub format_version: u16,
  /// Log length in bytes.
  pub log_length: u32,
  /// Log start offset in bytes.
  pub log_offset: u64,
}

/// Parsed VHDX region-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdxRegionTableEntry {
  /// Region type GUID.
  pub type_identifier: VhdxGuid,
  /// Absolute file offset of the region.
  pub file_offset: u64,
  /// Region length in bytes.
  pub length: u32,
  /// Whether the region is marked as required.
  pub is_required: bool,
}

/// Parsed VHDX region table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxRegionTable {
  entries: Vec<VhdxRegionTableEntry>,
}

impl VhdxImageHeader {
  pub fn read(source: &dyn ByteSource, offset: u64) -> Result<Self> {
    let data = source.read_bytes_at(offset, constants::IMAGE_HEADER_SIZE)?;
    Self::from_bytes(&data)
  }

  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != constants::IMAGE_HEADER_SIZE {
      return Err(Error::InvalidFormat(format!(
        "vhdx image header must be {} bytes, got {}",
        constants::IMAGE_HEADER_SIZE,
        data.len()
      )));
    }
    if &data[0..4] != constants::IMAGE_HEADER_SIGNATURE {
      return Err(Error::InvalidFormat(
        "invalid vhdx image header signature".to_string(),
      ));
    }
    verify_crc32c(data, 4, "vhdx image header")?;

    let format_version = u16::from_le_bytes([data[66], data[67]]);
    if format_version != 1 {
      return Err(Error::InvalidFormat(format!(
        "unsupported vhdx format version: {format_version}"
      )));
    }
    let log_length = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
    if log_length == 0 || !u64::from(log_length).is_multiple_of(constants::VHDX_ALIGNMENT) {
      return Err(Error::InvalidFormat(format!(
        "invalid vhdx log length: {log_length}"
      )));
    }
    let log_offset = u64::from_le_bytes([
      data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
    ]);
    if log_offset < constants::VHDX_ALIGNMENT
      || !log_offset.is_multiple_of(constants::VHDX_ALIGNMENT)
    {
      return Err(Error::InvalidFormat(format!(
        "invalid vhdx log offset: {log_offset}"
      )));
    }
    if data[80..].iter().any(|&byte| byte != 0) {
      return Err(Error::InvalidFormat(
        "vhdx image header reserved bytes are not zero".to_string(),
      ));
    }

    Ok(Self {
      sequence_number: u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
      ]),
      file_write_identifier: VhdxGuid::from_le_bytes(&data[16..32])?,
      data_write_identifier: VhdxGuid::from_le_bytes(&data[32..48])?,
      log_identifier: VhdxGuid::from_le_bytes(&data[48..64])?,
      log_version: u16::from_le_bytes([data[64], data[65]]),
      format_version,
      log_length,
      log_offset,
    })
  }
}

impl VhdxRegionTable {
  pub fn read(source: &dyn ByteSource, offset: u64) -> Result<Self> {
    let data = source.read_bytes_at(offset, constants::REGION_TABLE_SIZE)?;
    Self::from_bytes(&data)
  }

  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != constants::REGION_TABLE_SIZE {
      return Err(Error::InvalidFormat(format!(
        "vhdx region table must be {} bytes, got {}",
        constants::REGION_TABLE_SIZE,
        data.len()
      )));
    }
    if &data[0..4] != constants::REGION_TABLE_SIGNATURE {
      return Err(Error::InvalidFormat(
        "invalid vhdx region table signature".to_string(),
      ));
    }
    verify_crc32c(data, 4, "vhdx region table")?;

    let entry_count =
      usize::try_from(u32::from_le_bytes([data[8], data[9], data[10], data[11]]))
        .map_err(|_| Error::InvalidRange("vhdx region entry count is too large".to_string()))?;
    if entry_count > constants::VHDX_MAX_TABLE_ENTRIES {
      return Err(Error::InvalidFormat(format!(
        "vhdx region table contains too many entries: {entry_count}"
      )));
    }
    if data[12..16] != [0, 0, 0, 0] {
      return Err(Error::InvalidFormat(
        "vhdx region table reserved field is not zero".to_string(),
      ));
    }

    let mut entries: Vec<VhdxRegionTableEntry> = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
      let entry_offset = 16usize
        .checked_add(
          index
            .checked_mul(32)
            .ok_or_else(|| Error::InvalidRange("vhdx region entry offset overflow".to_string()))?,
        )
        .ok_or_else(|| Error::InvalidRange("vhdx region entry offset overflow".to_string()))?;
      let entry_end = entry_offset
        .checked_add(32)
        .ok_or_else(|| Error::InvalidRange("vhdx region entry end overflow".to_string()))?;
      let entry_data = data.get(entry_offset..entry_end).ok_or_else(|| {
        Error::InvalidFormat("vhdx region table ends inside an entry".to_string())
      })?;
      let type_identifier = VhdxGuid::from_le_bytes(&entry_data[0..16])?;
      let file_offset = u64::from_le_bytes([
        entry_data[16],
        entry_data[17],
        entry_data[18],
        entry_data[19],
        entry_data[20],
        entry_data[21],
        entry_data[22],
        entry_data[23],
      ]);
      let length = u32::from_le_bytes([
        entry_data[24],
        entry_data[25],
        entry_data[26],
        entry_data[27],
      ]);
      let required_raw = u32::from_le_bytes([
        entry_data[28],
        entry_data[29],
        entry_data[30],
        entry_data[31],
      ]);
      if file_offset < constants::VHDX_ALIGNMENT
        || !file_offset.is_multiple_of(constants::VHDX_ALIGNMENT)
      {
        return Err(Error::InvalidFormat(format!(
          "vhdx region {type_identifier} has an invalid offset: {file_offset}"
        )));
      }
      if length == 0 || !u64::from(length).is_multiple_of(constants::VHDX_ALIGNMENT) {
        return Err(Error::InvalidFormat(format!(
          "vhdx region {type_identifier} has an invalid size: {length}"
        )));
      }
      let is_required = match required_raw {
        0 => false,
        1 => true,
        _ => {
          return Err(Error::InvalidFormat(format!(
            "vhdx region {type_identifier} has an invalid required flag: {required_raw}"
          )));
        }
      };

      let entry = VhdxRegionTableEntry {
        type_identifier,
        file_offset,
        length,
        is_required,
      };
      if entries
        .iter()
        .any(|existing| existing.type_identifier == type_identifier)
      {
        return Err(Error::InvalidFormat(format!(
          "duplicate vhdx region table entry: {type_identifier}"
        )));
      }
      entries.push(entry);
    }

    Ok(Self { entries })
  }

  pub fn entry(&self, type_identifier: VhdxGuid) -> Option<&VhdxRegionTableEntry> {
    self
      .entries
      .iter()
      .find(|entry| entry.type_identifier == type_identifier)
  }

  pub fn entries(&self) -> &[VhdxRegionTableEntry] {
    &self.entries
  }
}

pub(super) fn validate_file_identifier(source: &dyn ByteSource) -> Result<()> {
  let data = source.read_bytes_at(
    constants::FILE_IDENTIFIER_OFFSET,
    constants::FILE_IDENTIFIER_SIZE,
  )?;
  if &data[0..8] != constants::FILE_IDENTIFIER_SIGNATURE {
    return Err(Error::InvalidFormat(
      "invalid vhdx file identifier signature".to_string(),
    ));
  }
  Ok(())
}

fn verify_crc32c(data: &[u8], checksum_offset: usize, label: &str) -> Result<()> {
  let checksum_end = checksum_offset
    .checked_add(4)
    .ok_or_else(|| Error::InvalidRange(format!("{label} checksum offset overflow")))?;
  let stored_checksum = u32::from_le_bytes([
    data[checksum_offset],
    data[checksum_offset + 1],
    data[checksum_offset + 2],
    data[checksum_offset + 3],
  ]);
  let mut checksum = crc32c::crc32c_append(0, &data[..checksum_offset]);
  checksum = crc32c::crc32c_append(checksum, &[0; 4]);
  checksum = crc32c::crc32c_append(checksum, &data[checksum_end..]);

  if stored_checksum != 0 && stored_checksum != checksum {
    return Err(Error::InvalidFormat(format!(
      "mismatch between stored and calculated {label} checksum: 0x{stored_checksum:08x} != 0x{checksum:08x}"
    )));
  }

  Ok(())
}
