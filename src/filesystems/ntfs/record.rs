//! NTFS file-record parsing.

use std::sync::Arc;

use super::{
  attribute_list::{NtfsAttributeListEntry, parse_attribute_list},
  reparse::{NtfsReparsePointInfo, parse_reparse_point},
};
use crate::{Error, Result};

const FILE_RECORD_SIGNATURE: &[u8; 4] = b"FILE";
const FILE_RECORD_FLAG_IN_USE: u16 = 0x0001;
const FILE_RECORD_FLAG_DIRECTORY: u16 = 0x0002;

const ATTRIBUTE_TYPE_ATTRIBUTE_LIST: u32 = 0x0000_0020;
const ATTRIBUTE_TYPE_FILE_NAME: u32 = 0x0000_0030;
const ATTRIBUTE_TYPE_DATA: u32 = 0x0000_0080;
const ATTRIBUTE_TYPE_REPARSE_POINT: u32 = 0x0000_00C0;
const ATTRIBUTE_TYPE_END: u32 = 0xFFFF_FFFF;

const ATTRIBUTE_FLAG_ENCRYPTED: u16 = 0x4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NtfsFileNameAttribute {
  pub attribute_id: u16,
  pub parent_record_number: u64,
  pub name: String,
  pub namespace: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NtfsNonResidentAttribute {
  pub first_vcn: u64,
  pub last_vcn: u64,
  pub data_size: u64,
  pub valid_data_size: u64,
  pub runlist: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NtfsDataAttributeValue {
  Resident(Arc<[u8]>),
  NonResident(NtfsNonResidentAttribute),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NtfsDataAttribute {
  pub attribute_id: u16,
  pub name: Option<String>,
  pub data_flags: u16,
  pub value: NtfsDataAttributeValue,
}

#[derive(Debug, Clone)]
pub(crate) struct NtfsFileRecord {
  pub flags: u16,
  pub base_record_number: Option<u64>,
  pub file_names: Vec<NtfsFileNameAttribute>,
  pub data_attributes: Vec<NtfsDataAttribute>,
  pub attribute_list_entries: Vec<NtfsAttributeListEntry>,
  pub reparse_point: Option<NtfsReparsePointInfo>,
  pub has_attribute_list: bool,
  pub has_reparse_point: bool,
}

impl NtfsFileRecord {
  pub fn is_directory(&self) -> bool {
    self.flags & FILE_RECORD_FLAG_DIRECTORY != 0
  }

  pub fn preferred_name(&self) -> Option<&NtfsFileNameAttribute> {
    self
      .file_names
      .iter()
      .min_by_key(|file_name| namespace_priority(file_name.namespace))
  }
}

pub(crate) fn parse_file_record(raw: &[u8], record_number: u64) -> Result<Option<NtfsFileRecord>> {
  if raw.iter().all(|byte| *byte == 0) {
    return Ok(None);
  }

  let fixed = apply_update_sequence(raw)?;
  if &fixed[0..4] != FILE_RECORD_SIGNATURE {
    return Err(Error::InvalidFormat(format!(
      "ntfs file record {record_number} has an invalid signature"
    )));
  }

  let used_size = usize::try_from(le_u32(&fixed[24..28]))
    .map_err(|_| Error::InvalidRange("ntfs file record used size is too large".to_string()))?;
  let flags = le_u16(&fixed[22..24]);
  if flags & FILE_RECORD_FLAG_IN_USE == 0 || used_size == 0 {
    return Ok(None);
  }
  if used_size > fixed.len() {
    return Err(Error::InvalidFormat(format!(
      "ntfs file record {record_number} extends past its allocated size"
    )));
  }

  let base_reference = decode_file_reference(&fixed[32..40])?;
  let base_record_number = if base_reference == 0 {
    None
  } else {
    Some(base_reference)
  };
  let attributes_offset = usize::from(le_u16(&fixed[20..22]));
  if attributes_offset > used_size {
    return Err(Error::InvalidFormat(format!(
      "ntfs file record {record_number} attributes start outside the used region"
    )));
  }

  let mut file_names = Vec::new();
  let mut data_attributes = Vec::new();
  let mut attribute_list_entries = Vec::new();
  let mut reparse_point = None;
  let mut has_attribute_list = false;
  let mut has_reparse_point = false;
  let mut cursor = attributes_offset;
  let used = &fixed[..used_size];

  while cursor + 8 <= used.len() {
    let attribute_type = le_u32(&used[cursor..cursor + 4]);
    if attribute_type == ATTRIBUTE_TYPE_END {
      break;
    }

    let attribute_size = usize::try_from(le_u32(&used[cursor + 4..cursor + 8])).map_err(|_| {
      Error::InvalidRange(format!(
        "ntfs file record {record_number} attribute size is too large"
      ))
    })?;
    if attribute_size < 16 {
      return Err(Error::InvalidFormat(format!(
        "ntfs file record {record_number} contains a truncated attribute"
      )));
    }
    let attribute_end = cursor
      .checked_add(attribute_size)
      .ok_or_else(|| Error::InvalidRange("ntfs attribute end offset overflow".to_string()))?;
    if attribute_end > used.len() {
      return Err(Error::InvalidFormat(format!(
        "ntfs file record {record_number} attribute exceeds the used region"
      )));
    }

    let attribute = &used[cursor..attribute_end];
    let non_resident = attribute[8] != 0;
    let name_length = usize::from(attribute[9]);
    let name_offset = usize::from(le_u16(&attribute[10..12]));
    let data_flags = le_u16(&attribute[12..14]);
    let attribute_id = le_u16(&attribute[14..16]);
    let attribute_name = if name_length == 0 {
      None
    } else {
      Some(read_utf16le(
        attribute,
        name_offset,
        name_length,
        "ntfs attribute name",
      )?)
    };

    match attribute_type {
      ATTRIBUTE_TYPE_ATTRIBUTE_LIST => {
        if non_resident {
          return Err(Error::InvalidFormat(format!(
            "ntfs file record {record_number} stores $ATTRIBUTE_LIST as non-resident"
          )));
        }
        attribute_list_entries.extend(parse_attribute_list(resident_attribute_data(
          attribute,
          "ntfs $ATTRIBUTE_LIST",
        )?)?);
        has_attribute_list = true;
      }
      ATTRIBUTE_TYPE_FILE_NAME => {
        if non_resident {
          return Err(Error::InvalidFormat(format!(
            "ntfs file record {record_number} stores $FILE_NAME as non-resident"
          )));
        }
        file_names.push(parse_file_name_attribute(attribute, attribute_id)?);
      }
      ATTRIBUTE_TYPE_DATA => {
        if data_flags & ATTRIBUTE_FLAG_ENCRYPTED != 0 {
          return Err(Error::InvalidFormat(format!(
            "ntfs encrypted data attributes are not supported in record {record_number}"
          )));
        }
        data_attributes.push(parse_data_attribute(
          attribute,
          attribute_name,
          attribute_id,
          record_number,
        )?);
      }
      ATTRIBUTE_TYPE_REPARSE_POINT => {
        if non_resident {
          return Err(Error::InvalidFormat(format!(
            "ntfs file record {record_number} stores $REPARSE_POINT as non-resident"
          )));
        }
        reparse_point = Some(parse_reparse_point(resident_attribute_data(
          attribute,
          "ntfs $REPARSE_POINT",
        )?)?);
        has_reparse_point = true;
      }
      _ => {}
    }

    cursor = attribute_end;
  }

  Ok(Some(NtfsFileRecord {
    flags,
    base_record_number,
    file_names,
    data_attributes,
    attribute_list_entries,
    reparse_point,
    has_attribute_list,
    has_reparse_point,
  }))
}

fn apply_update_sequence(raw: &[u8]) -> Result<Vec<u8>> {
  if raw.len() < 48 {
    return Err(Error::InvalidFormat(
      "ntfs file record is too small".to_string(),
    ));
  }

  let mut fixed = raw.to_vec();
  let update_sequence_offset = usize::from(le_u16(&fixed[4..6]));
  let update_sequence_count = usize::from(le_u16(&fixed[6..8]));
  if update_sequence_count == 0 {
    return Err(Error::InvalidFormat(
      "ntfs update-sequence array must contain at least one element".to_string(),
    ));
  }
  let array_size = update_sequence_count
    .checked_mul(2)
    .ok_or_else(|| Error::InvalidRange("ntfs update-sequence array overflow".to_string()))?;
  let update_sequence_end = update_sequence_offset
    .checked_add(array_size)
    .ok_or_else(|| Error::InvalidRange("ntfs update-sequence array overflow".to_string()))?;
  if update_sequence_end > fixed.len() {
    return Err(Error::InvalidFormat(
      "ntfs update-sequence array exceeds the file record".to_string(),
    ));
  }

  let sequence = [
    fixed[update_sequence_offset],
    fixed[update_sequence_offset + 1],
  ];
  for index in 1..update_sequence_count {
    let sector_tail = index
      .checked_mul(512)
      .and_then(|value| value.checked_sub(2))
      .ok_or_else(|| Error::InvalidRange("ntfs sector-tail offset overflow".to_string()))?;
    if sector_tail + 2 > fixed.len() {
      return Err(Error::InvalidFormat(
        "ntfs update-sequence array references data past the file record".to_string(),
      ));
    }
    let replacement_offset = update_sequence_offset + index * 2;
    let (prefix, suffix) = fixed.split_at_mut(sector_tail);
    let sector_tail_bytes = &mut suffix[..2];
    if *sector_tail_bytes != sequence {
      return Err(Error::InvalidFormat(
        "ntfs file record fixup verification failed".to_string(),
      ));
    }
    let replacement = [prefix[replacement_offset], prefix[replacement_offset + 1]];
    sector_tail_bytes.copy_from_slice(&replacement);
  }

  Ok(fixed)
}

fn parse_file_name_attribute(attribute: &[u8], attribute_id: u16) -> Result<NtfsFileNameAttribute> {
  let data = resident_attribute_data(attribute, "ntfs $FILE_NAME")?;
  if data.len() < 66 {
    return Err(Error::InvalidFormat(
      "ntfs $FILE_NAME attribute is too small".to_string(),
    ));
  }

  let name_length = usize::from(data[64]);
  let namespace = data[65];
  Ok(NtfsFileNameAttribute {
    attribute_id,
    parent_record_number: decode_file_reference(&data[0..8])?,
    name: read_utf16le(data, 66, name_length, "ntfs $FILE_NAME string")?,
    namespace,
  })
}

fn parse_data_attribute(
  attribute: &[u8], name: Option<String>, attribute_id: u16, record_number: u64,
) -> Result<NtfsDataAttribute> {
  let data_flags = le_u16(&attribute[12..14]);
  let value = if attribute[8] == 0 {
    NtfsDataAttributeValue::Resident(Arc::from(resident_attribute_data(attribute, "ntfs $DATA")?))
  } else {
    if attribute.len() < 64 {
      return Err(Error::InvalidFormat(format!(
        "ntfs non-resident $DATA attribute in record {record_number} is truncated"
      )));
    }
    let first_vcn = le_u64(&attribute[16..24]);
    let last_vcn = le_u64(&attribute[24..32]);
    if last_vcn < first_vcn {
      return Err(Error::InvalidFormat(format!(
        "ntfs non-resident $DATA attribute in record {record_number} has an invalid VCN range"
      )));
    }
    let runlist_offset = usize::from(le_u16(&attribute[32..34]));
    if runlist_offset > attribute.len() {
      return Err(Error::InvalidFormat(format!(
        "ntfs non-resident $DATA attribute in record {record_number} has an invalid runlist offset"
      )));
    }
    let compression_unit = le_u16(&attribute[34..36]);
    if compression_unit != 0 || data_flags & 0x00FF != 0 {
      return Err(Error::InvalidFormat(format!(
        "compressed ntfs data attributes are not supported in record {record_number}"
      )));
    }

    NtfsDataAttributeValue::NonResident(NtfsNonResidentAttribute {
      first_vcn,
      last_vcn,
      data_size: le_u64(&attribute[48..56]),
      valid_data_size: le_u64(&attribute[56..64]),
      runlist: Arc::from(&attribute[runlist_offset..]),
    })
  };

  Ok(NtfsDataAttribute {
    attribute_id,
    name,
    data_flags,
    value,
  })
}

fn resident_attribute_data<'a>(attribute: &'a [u8], label: &str) -> Result<&'a [u8]> {
  if attribute.len() < 24 {
    return Err(Error::InvalidFormat(format!("{label} header is truncated")));
  }

  let data_length = usize::try_from(le_u32(&attribute[16..20]))
    .map_err(|_| Error::InvalidRange(format!("{label} data length is too large")))?;
  let data_offset = usize::from(le_u16(&attribute[20..22]));
  let data_end = data_offset
    .checked_add(data_length)
    .ok_or_else(|| Error::InvalidRange(format!("{label} data offset overflow")))?;
  if data_end > attribute.len() {
    return Err(Error::InvalidFormat(format!(
      "{label} data extends past the attribute boundary"
    )));
  }

  Ok(&attribute[data_offset..data_end])
}

fn read_utf16le(bytes: &[u8], offset: usize, chars: usize, label: &str) -> Result<String> {
  let byte_len = chars
    .checked_mul(2)
    .ok_or_else(|| Error::InvalidRange(format!("{label} length overflow")))?;
  let end = offset
    .checked_add(byte_len)
    .ok_or_else(|| Error::InvalidRange(format!("{label} offset overflow")))?;
  let slice = bytes
    .get(offset..end)
    .ok_or_else(|| Error::InvalidFormat(format!("{label} extends past the available bytes")))?;
  let units = slice
    .chunks_exact(2)
    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  String::from_utf16(&units)
    .map_err(|_| Error::InvalidFormat(format!("{label} is not valid UTF-16")))
}

fn decode_file_reference(bytes: &[u8]) -> Result<u64> {
  let bytes = bytes
    .get(..8)
    .ok_or_else(|| Error::InvalidFormat("ntfs file reference is truncated".to_string()))?;
  let mut raw = [0u8; 8];
  raw[..6].copy_from_slice(&bytes[..6]);
  Ok(u64::from_le_bytes(raw))
}

fn namespace_priority(namespace: u8) -> u8 {
  match namespace {
    1 | 3 => 0,
    0 => 1,
    2 => 2,
    other => other.saturating_add(3),
  }
}

fn le_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_le_bytes(raw)
}

fn le_u32(bytes: &[u8]) -> u32 {
  let mut raw = [0u8; 4];
  raw.copy_from_slice(bytes);
  u32::from_le_bytes(raw)
}

fn le_u64(bytes: &[u8]) -> u64 {
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn decodes_file_reference_record_number() {
    let reference = [0x34, 0x12, 0, 0, 0, 0, 0x78, 0x56];

    assert_eq!(decode_file_reference(&reference).unwrap(), 0x1234);
  }
}
