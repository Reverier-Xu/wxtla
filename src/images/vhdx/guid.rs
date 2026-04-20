//! VHDX GUID parsing helpers.

use std::fmt;

use crate::{Error, Result};

/// GUID value stored in VHDX metadata and tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VhdxGuid {
  part1: u32,
  part2: u16,
  part3: u16,
  part4: [u8; 8],
}

impl VhdxGuid {
  /// Nil GUID.
  pub const NIL: Self = Self {
    part1: 0,
    part2: 0,
    part3: 0,
    part4: [0; 8],
  };

  /// Construct a GUID from already-normalized fields.
  pub const fn from_fields(part1: u32, part2: u16, part3: u16, part4: [u8; 8]) -> Self {
    Self {
      part1,
      part2,
      part3,
      part4,
    }
  }

  /// Parse a VHDX GUID from 16 little-endian on-disk bytes.
  pub fn from_le_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != 16 {
      return Err(Error::invalid_format(format!(
        "vhdx guid must be 16 bytes, got {}",
        data.len()
      )));
    }

    Ok(Self {
      part1: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
      part2: u16::from_le_bytes([data[4], data[5]]),
      part3: u16::from_le_bytes([data[6], data[7]]),
      part4: [
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
      ],
    })
  }

  /// Parse a canonical GUID string, optionally wrapped in braces.
  pub fn parse_display(value: &str) -> Result<Self> {
    let value = value.trim();
    let value = value
      .strip_prefix('{')
      .and_then(|inner| inner.strip_suffix('}'))
      .unwrap_or(value);
    let mut parts = value.split('-');
    let Some(part1) = parts.next() else {
      return Err(Error::invalid_format(
        "vhdx guid string is empty".to_string(),
      ));
    };
    let Some(part2) = parts.next() else {
      return Err(Error::invalid_format(format!(
        "vhdx guid string is missing fields: {value}"
      )));
    };
    let Some(part3) = parts.next() else {
      return Err(Error::invalid_format(format!(
        "vhdx guid string is missing fields: {value}"
      )));
    };
    let Some(part4) = parts.next() else {
      return Err(Error::invalid_format(format!(
        "vhdx guid string is missing fields: {value}"
      )));
    };
    let Some(part5) = parts.next() else {
      return Err(Error::invalid_format(format!(
        "vhdx guid string is missing fields: {value}"
      )));
    };
    if parts.next().is_some() {
      return Err(Error::invalid_format(format!(
        "vhdx guid string has too many fields: {value}"
      )));
    }

    if part1.len() != 8
      || part2.len() != 4
      || part3.len() != 4
      || part4.len() != 4
      || part5.len() != 12
    {
      return Err(Error::invalid_format(format!(
        "vhdx guid string has invalid field widths: {value}"
      )));
    }

    let mut tail = [0u8; 8];
    tail[0] = parse_hex_byte(&part4[0..2])?;
    tail[1] = parse_hex_byte(&part4[2..4])?;
    for (index, chunk_start) in (0..12).step_by(2).enumerate() {
      tail[index + 2] = parse_hex_byte(&part5[chunk_start..chunk_start + 2])?;
    }

    Ok(Self::from_fields(
      parse_hex_u32(part1)?,
      parse_hex_u16(part2)?,
      parse_hex_u16(part3)?,
      tail,
    ))
  }

  /// Return the on-disk little-endian byte representation of this GUID.
  pub const fn to_le_bytes(self) -> [u8; 16] {
    let part1 = self.part1.to_le_bytes();
    let part2 = self.part2.to_le_bytes();
    let part3 = self.part3.to_le_bytes();

    [
      part1[0],
      part1[1],
      part1[2],
      part1[3],
      part2[0],
      part2[1],
      part3[0],
      part3[1],
      self.part4[0],
      self.part4[1],
      self.part4[2],
      self.part4[3],
      self.part4[4],
      self.part4[5],
      self.part4[6],
      self.part4[7],
    ]
  }

  /// Return `true` when the GUID is nil.
  pub fn is_nil(self) -> bool {
    self == Self::NIL
  }
}

impl fmt::Display for VhdxGuid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
      self.part1,
      self.part2,
      self.part3,
      self.part4[0],
      self.part4[1],
      self.part4[2],
      self.part4[3],
      self.part4[4],
      self.part4[5],
      self.part4[6],
      self.part4[7],
    )
  }
}

fn parse_hex_u32(value: &str) -> Result<u32> {
  u32::from_str_radix(value, 16)
    .map_err(|_| Error::invalid_format(format!("invalid vhdx guid field: {value}")))
}

fn parse_hex_u16(value: &str) -> Result<u16> {
  u16::from_str_radix(value, 16)
    .map_err(|_| Error::invalid_format(format!("invalid vhdx guid field: {value}")))
}

fn parse_hex_byte(value: &str) -> Result<u8> {
  u8::from_str_radix(value, 16)
    .map_err(|_| Error::invalid_format(format!("invalid vhdx guid field: {value}")))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_guid_from_little_endian_bytes() {
    let guid = VhdxGuid::from_le_bytes(&[
      0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A,
      0x08,
    ])
    .unwrap();

    assert_eq!(guid.to_string(), "2dc27766-f623-4200-9d64-115e9bfd4a08");
    assert!(!guid.is_nil());
  }

  #[test]
  fn parses_braced_guid_strings() {
    let guid = VhdxGuid::parse_display("{7584f8fb-36d3-4091-afb5-b1afe587bfa8}").unwrap();

    assert_eq!(guid.to_string(), "7584f8fb-36d3-4091-afb5-b1afe587bfa8");
  }
}
