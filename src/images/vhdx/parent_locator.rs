//! VHDX parent locator metadata.

use super::{constants, guid::VhdxGuid};
use crate::{Error, Result};

/// One key-value entry inside a VHDX parent locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxParentLocatorEntry {
  /// Entry key.
  pub key: String,
  /// Entry value.
  pub value: String,
}

/// Parsed VHDX parent locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxParentLocator {
  parent_identifier: Option<VhdxGuid>,
  entries: Vec<VhdxParentLocatorEntry>,
}

impl VhdxParentLocator {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < 20 {
      return Err(Error::InvalidFormat(
        "vhdx parent locator is too small".to_string(),
      ));
    }

    let locator_type = VhdxGuid::from_le_bytes(&data[0..16])?;
    if locator_type != constants::PARENT_LOCATOR_TYPE_GUID {
      return Err(Error::InvalidFormat(format!(
        "unsupported vhdx parent locator type: {locator_type}"
      )));
    }

    if data[16..18] != [0, 0] {
      return Err(Error::InvalidFormat(
        "vhdx parent locator reserved field is not zero".to_string(),
      ));
    }

    let entry_count = usize::from(u16::from_le_bytes([data[18], data[19]]));
    let table_size = 20usize
      .checked_add(entry_count.checked_mul(12).ok_or_else(|| {
        Error::InvalidRange("vhdx parent locator table size overflow".to_string())
      })?)
      .ok_or_else(|| Error::InvalidRange("vhdx parent locator table size overflow".to_string()))?;
    if table_size > data.len() {
      return Err(Error::InvalidFormat(
        "vhdx parent locator table exceeds the metadata item".to_string(),
      ));
    }

    let mut entries = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
      let entry_offset = 20 + index * 12;
      let key_offset = usize::try_from(u32::from_le_bytes([
        data[entry_offset],
        data[entry_offset + 1],
        data[entry_offset + 2],
        data[entry_offset + 3],
      ]))
      .map_err(|_| {
        Error::InvalidRange("vhdx parent locator key offset is too large".to_string())
      })?;
      let value_offset = usize::try_from(u32::from_le_bytes([
        data[entry_offset + 4],
        data[entry_offset + 5],
        data[entry_offset + 6],
        data[entry_offset + 7],
      ]))
      .map_err(|_| {
        Error::InvalidRange("vhdx parent locator value offset is too large".to_string())
      })?;
      let key_length = usize::from(u16::from_le_bytes([
        data[entry_offset + 8],
        data[entry_offset + 9],
      ]));
      let value_length = usize::from(u16::from_le_bytes([
        data[entry_offset + 10],
        data[entry_offset + 11],
      ]));

      let key = decode_utf16_le_string(read_entry_bytes(data, key_offset, key_length, "key")?)?;
      let value =
        decode_utf16_le_string(read_entry_bytes(data, value_offset, value_length, "value")?)?;
      entries.push(VhdxParentLocatorEntry { key, value });
    }

    let parent_identifier = ["parent_linkage", "parent_linkage2"]
      .into_iter()
      .find_map(|key| {
        entries
          .iter()
          .find(|entry| entry.key == key)
          .map(|entry| entry.value.as_str())
      })
      .map(VhdxGuid::parse_display)
      .transpose()?;
    let parent_identifier = match parent_identifier {
      Some(identifier) if identifier.is_nil() => None,
      other => other,
    };

    Ok(Self {
      parent_identifier,
      entries,
    })
  }

  /// Return the parent linkage identifier when one is present.
  pub fn parent_identifier(&self) -> Option<VhdxGuid> {
    self.parent_identifier
  }

  /// Return a named parent-locator value.
  pub fn entry(&self, key: &str) -> Option<&str> {
    self
      .entries
      .iter()
      .find(|entry| entry.key == key)
      .map(|entry| entry.value.as_str())
  }

  /// Return all parsed parent-locator entries.
  pub fn entries(&self) -> &[VhdxParentLocatorEntry] {
    &self.entries
  }

  pub(crate) fn candidate_paths(&self) -> impl Iterator<Item = &str> {
    ["relative_path", "absolute_win32_path", "volume_path"]
      .into_iter()
      .filter_map(|key| self.entry(key))
  }
}

fn read_entry_bytes<'a>(
  data: &'a [u8], offset: usize, length: usize, label: &str,
) -> Result<&'a [u8]> {
  let end = offset
    .checked_add(length)
    .ok_or_else(|| Error::InvalidRange(format!("vhdx parent locator {label} range overflow")))?;
  data.get(offset..end).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "vhdx parent locator {label} range exceeds the item"
    ))
  })
}

fn decode_utf16_le_string(data: &[u8]) -> Result<String> {
  if !data.len().is_multiple_of(2) {
    return Err(Error::InvalidFormat(
      "vhdx parent locator string has an odd byte count".to_string(),
    ));
  }

  let mut code_units = Vec::with_capacity(data.len() / 2);
  for chunk in data.chunks_exact(2) {
    code_units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
  }

  String::from_utf16(&code_units)
    .map_err(|_| Error::InvalidFormat("vhdx parent locator string is not valid UTF-16".to_string()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_parent_locator_guid_with_braces() {
    let guid = VhdxGuid::parse_display("{7584f8fb-36d3-4091-afb5-b1afe587bfa8}").unwrap();

    assert_eq!(guid.to_string(), "7584f8fb-36d3-4091-afb5-b1afe587bfa8");
  }
}
