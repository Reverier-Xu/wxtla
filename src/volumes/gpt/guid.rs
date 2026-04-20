//! GPT GUID parsing.

use std::fmt;

use crate::{Error, Result};

/// GUID value stored in GPT headers and entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GptGuid {
  part1: u32,
  part2: u16,
  part3: u16,
  part4: [u8; 8],
}

impl GptGuid {
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

  /// Parse a GPT GUID from 16 little-endian on-disk bytes.
  pub fn from_le_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != 16 {
      return Err(Error::invalid_format(format!(
        "gpt guid must be 16 bytes, got {}",
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
    self.part1 == 0 && self.part2 == 0 && self.part3 == 0 && self.part4 == [0; 8]
  }
}

impl fmt::Display for GptGuid {
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_guid_from_little_endian_bytes() {
    let guid = GptGuid::from_le_bytes(&[
      0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
      0xE4,
    ])
    .unwrap();

    assert_eq!(guid.to_string(), "0fc63daf-8483-4772-8e79-3d69d8477de4");
    assert!(!guid.is_nil());
  }
}
