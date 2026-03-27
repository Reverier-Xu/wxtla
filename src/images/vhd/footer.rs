//! VHD footer parsing.

use super::constants::{
  DEFAULT_SECTOR_SIZE, DISK_TYPE_DIFFERENTIAL, DISK_TYPE_DYNAMIC, DISK_TYPE_FIXED,
  FIXED_DATA_OFFSET, FOOTER_COOKIE, FOOTER_SIZE, VHD_FORMAT_VERSION,
};
use crate::{ByteSource, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdDiskType {
  Fixed,
  Dynamic,
  Differential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdDiskGeometry {
  pub cylinders: u16,
  pub heads: u8,
  pub sectors_per_track: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdFooter {
  pub features: u32,
  pub data_offset: u64,
  pub current_size: u64,
  pub disk_type: VhdDiskType,
  pub geometry: VhdDiskGeometry,
  pub identifier: [u8; 16],
}

impl VhdFooter {
  pub fn read(source: &dyn ByteSource) -> Result<Self> {
    let size = source.size()?;
    if size < FOOTER_SIZE as u64 {
      return Err(Error::InvalidFormat(
        "vhd source is smaller than a footer".to_string(),
      ));
    }
    let data = source.read_bytes_at(size - FOOTER_SIZE as u64, FOOTER_SIZE)?;
    Self::parse(&data)
  }

  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != FOOTER_SIZE {
      return Err(Error::InvalidFormat(format!(
        "vhd footer must be {FOOTER_SIZE} bytes, got {}",
        data.len()
      )));
    }
    if &data[0..8] != FOOTER_COOKIE {
      return Err(Error::InvalidFormat(
        "vhd footer signature is missing".to_string(),
      ));
    }
    if read_u32_be(data, 12)? != VHD_FORMAT_VERSION {
      return Err(Error::InvalidFormat(
        "unsupported vhd format version".to_string(),
      ));
    }

    let stored_checksum = read_u32_be(data, 64)?;
    let mut checksum_input = data.to_vec();
    checksum_input[64..68].fill(0);
    let calculated_checksum = ones_complement_checksum(&checksum_input);
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "vhd footer checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    Ok(Self {
      features: read_u32_be(data, 8)?,
      data_offset: read_u64_be(data, 16)?,
      current_size: read_u64_be(data, 48)?,
      disk_type: match read_u32_be(data, 60)? {
        DISK_TYPE_FIXED => VhdDiskType::Fixed,
        DISK_TYPE_DYNAMIC => VhdDiskType::Dynamic,
        DISK_TYPE_DIFFERENTIAL => VhdDiskType::Differential,
        other => {
          return Err(Error::InvalidFormat(format!(
            "unsupported vhd disk type: {other}"
          )));
        }
      },
      geometry: VhdDiskGeometry {
        cylinders: read_u16_be(data, 56)?,
        heads: *data
          .get(58)
          .ok_or_else(|| Error::InvalidFormat("vhd geometry is truncated".to_string()))?,
        sectors_per_track: *data
          .get(59)
          .ok_or_else(|| Error::InvalidFormat("vhd geometry is truncated".to_string()))?,
      },
      identifier: copy_array::<16>(&data[68..84])?,
    })
  }

  pub fn bytes_per_sector(&self) -> u32 {
    DEFAULT_SECTOR_SIZE
  }

  pub fn has_dynamic_header(&self) -> bool {
    self.data_offset != FIXED_DATA_OFFSET
  }
}

fn ones_complement_checksum(data: &[u8]) -> u32 {
  let sum = data
    .iter()
    .fold(0u32, |sum, value| sum.wrapping_add(u32::from(*value)));
  !sum
}

fn read_u16_be(data: &[u8], offset: usize) -> Result<u16> {
  let bytes = data
    .get(offset..offset + 2)
    .ok_or_else(|| Error::InvalidFormat(format!("vhd field at offset {offset} is truncated")))?;
  Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
  let bytes = data
    .get(offset..offset + 4)
    .ok_or_else(|| Error::InvalidFormat(format!("vhd field at offset {offset} is truncated")))?;
  Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_be(data: &[u8], offset: usize) -> Result<u64> {
  let bytes = data
    .get(offset..offset + 8)
    .ok_or_else(|| Error::InvalidFormat(format!("vhd field at offset {offset} is truncated")))?;
  Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
    Error::InvalidFormat(format!("vhd field at offset {offset} is truncated"))
  })?))
}

fn copy_array<const N: usize>(data: &[u8]) -> Result<[u8; N]> {
  data.try_into().map_err(|_| {
    Error::InvalidFormat(format!(
      "vhd fixed-size array conversion failed: expected {N} bytes, got {}",
      data.len()
    ))
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_footer_fields() {
    let mut data = vec![0u8; FOOTER_SIZE];
    data[0..8].copy_from_slice(b"conectix");
    data[8..12].copy_from_slice(&2u32.to_be_bytes());
    data[12..16].copy_from_slice(&VHD_FORMAT_VERSION.to_be_bytes());
    data[16..24].copy_from_slice(&FIXED_DATA_OFFSET.to_be_bytes());
    data[48..56].copy_from_slice(&4_194_304u64.to_be_bytes());
    data[56..58].copy_from_slice(&1024u16.to_be_bytes());
    data[58] = 16;
    data[59] = 63;
    data[60..64].copy_from_slice(&DISK_TYPE_FIXED.to_be_bytes());
    let checksum = ones_complement_checksum(&data);
    data[64..68].copy_from_slice(&checksum.to_be_bytes());

    let footer = VhdFooter::parse(&data).unwrap();

    assert_eq!(footer.disk_type, VhdDiskType::Fixed);
    assert_eq!(footer.current_size, 4_194_304);
    assert!(!footer.has_dynamic_header());
  }
}
