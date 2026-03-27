//! VHD dynamic and differential header parsing.

use super::constants::{
  DEFAULT_SECTOR_SIZE, DYNAMIC_HEADER_COOKIE, DYNAMIC_HEADER_SIZE, VHD_FORMAT_VERSION,
};
use crate::{ByteSource, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdParentLocator {
  pub platform_code: [u8; 4],
  pub platform_data_space: u32,
  pub data_size: u32,
  pub data_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdDynamicHeader {
  pub block_allocation_table_offset: u64,
  pub block_count: u32,
  pub block_size: u32,
  pub parent_identifier: [u8; 16],
  pub parent_name: String,
  pub parent_locators: Vec<VhdParentLocator>,
}

impl VhdDynamicHeader {
  pub fn read(source: &dyn ByteSource, offset: u64) -> Result<Self> {
    let data = source.read_bytes_at(offset, DYNAMIC_HEADER_SIZE)?;
    Self::parse(&data)
  }

  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != DYNAMIC_HEADER_SIZE {
      return Err(Error::InvalidFormat(format!(
        "vhd dynamic header must be {DYNAMIC_HEADER_SIZE} bytes, got {}",
        data.len()
      )));
    }
    if &data[0..8] != DYNAMIC_HEADER_COOKIE {
      return Err(Error::InvalidFormat(
        "vhd dynamic header signature is missing".to_string(),
      ));
    }
    if read_u32_be(data, 24)? != VHD_FORMAT_VERSION {
      return Err(Error::InvalidFormat(
        "unsupported vhd dynamic header version".to_string(),
      ));
    }

    let stored_checksum = read_u32_be(data, 36)?;
    let mut checksum_input = data.to_vec();
    checksum_input[36..40].fill(0);
    let calculated_checksum = ones_complement_checksum(&checksum_input);
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "vhd dynamic header checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    let mut parent_name_code_units = Vec::new();
    for chunk in data[64..576].chunks_exact(2) {
      let code_unit = u16::from_be_bytes([chunk[0], chunk[1]]);
      if code_unit == 0 {
        break;
      }
      parent_name_code_units.push(code_unit);
    }
    let parent_name = String::from_utf16(&parent_name_code_units)
      .map_err(|_| Error::InvalidFormat("vhd parent name is not valid UTF-16".to_string()))?;

    let mut parent_locators = Vec::new();
    for index in 0..8 {
      let offset = 576 + index * 24;
      let platform_code = copy_array::<4>(&data[offset..offset + 4])?;
      if platform_code == [0; 4] {
        continue;
      }
      parent_locators.push(VhdParentLocator {
        platform_code,
        platform_data_space: read_u32_be(data, offset + 4)?,
        data_size: read_u32_be(data, offset + 8)?,
        data_offset: read_u64_be(data, offset + 16)?,
      });
    }

    let block_size = read_u32_be(data, 32)?;
    if block_size == 0 || !block_size.is_multiple_of(DEFAULT_SECTOR_SIZE) {
      return Err(Error::InvalidFormat(format!(
        "invalid vhd block size: {block_size}"
      )));
    }

    Ok(Self {
      block_allocation_table_offset: read_u64_be(data, 16)?,
      block_count: read_u32_be(data, 28)?,
      block_size,
      parent_identifier: copy_array::<16>(&data[40..56])?,
      parent_name,
      parent_locators,
    })
  }

  pub fn sector_bitmap_size(&self) -> Result<u64> {
    let sectors_per_block = self
      .block_size
      .checked_div(512)
      .ok_or_else(|| Error::InvalidFormat("vhd block size is smaller than a sector".to_string()))?;
    let bitmap_bytes = u64::from(sectors_per_block).div_ceil(8);
    Ok(bitmap_bytes.div_ceil(512) * 512)
  }
}

fn ones_complement_checksum(data: &[u8]) -> u32 {
  let sum = data
    .iter()
    .fold(0u32, |sum, value| sum.wrapping_add(u32::from(*value)));
  !sum
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
  let bytes = data.get(offset..offset + 4).ok_or_else(|| {
    Error::InvalidFormat(format!("vhd dynamic field at offset {offset} is truncated"))
  })?;
  Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_be(data: &[u8], offset: usize) -> Result<u64> {
  let bytes = data.get(offset..offset + 8).ok_or_else(|| {
    Error::InvalidFormat(format!("vhd dynamic field at offset {offset} is truncated"))
  })?;
  Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
    Error::InvalidFormat(format!("vhd dynamic field at offset {offset} is truncated"))
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
  fn parses_dynamic_header_fields() {
    let mut data = vec![0u8; DYNAMIC_HEADER_SIZE];
    data[0..8].copy_from_slice(b"cxsparse");
    data[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    data[16..24].copy_from_slice(&0x600u64.to_be_bytes());
    data[24..28].copy_from_slice(&VHD_FORMAT_VERSION.to_be_bytes());
    data[28..32].copy_from_slice(&3u32.to_be_bytes());
    data[32..36].copy_from_slice(&2_097_152u32.to_be_bytes());
    data[64..66].copy_from_slice(&0x0044u16.to_be_bytes());
    let checksum = ones_complement_checksum(&data);
    data[36..40].copy_from_slice(&checksum.to_be_bytes());

    let header = VhdDynamicHeader::parse(&data).unwrap();

    assert_eq!(header.block_allocation_table_offset, 0x600);
    assert_eq!(header.block_count, 3);
    assert_eq!(header.block_size, 2_097_152);
  }

  #[test]
  fn rejects_zero_block_sizes() {
    let mut data = vec![0u8; DYNAMIC_HEADER_SIZE];
    data[0..8].copy_from_slice(b"cxsparse");
    data[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    data[16..24].copy_from_slice(&0x600u64.to_be_bytes());
    data[24..28].copy_from_slice(&VHD_FORMAT_VERSION.to_be_bytes());
    data[28..32].copy_from_slice(&3u32.to_be_bytes());
    let checksum = ones_complement_checksum(&data);
    data[36..40].copy_from_slice(&checksum.to_be_bytes());

    let error = VhdDynamicHeader::parse(&data).unwrap_err();

    assert!(matches!(error, Error::InvalidFormat(_)));
  }
}
