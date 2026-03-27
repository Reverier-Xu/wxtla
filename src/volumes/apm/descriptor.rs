//! Apple Partition Map driver descriptor parsing.

use super::constants::{BLOCK0_SIZE, DRIVER_DESCRIPTOR_SIGNATURE};
use crate::{ByteSource, Error, Result};

/// Device driver descriptor embedded in the APM driver descriptor block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApmDriverDescriptorEntry {
  /// Start block of the device driver.
  pub start_block: u32,
  /// Number of blocks occupied by the driver.
  pub block_count: u16,
  /// Operating system type.
  pub system_type: u16,
}

/// Parsed APM driver descriptor block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApmDriverDescriptor {
  /// Device block size in bytes.
  pub block_size: u16,
  /// Number of blocks on the device.
  pub block_count: u32,
  /// Device type field.
  pub device_type: u16,
  /// Device identifier field.
  pub device_identifier: u16,
  /// Device data field.
  pub device_data: u32,
  /// Driver descriptors listed in the block.
  pub driver_descriptors: Vec<ApmDriverDescriptorEntry>,
}

impl ApmDriverDescriptor {
  /// Read the driver descriptor from the start of a data source.
  pub fn read(source: &dyn ByteSource) -> Result<Self> {
    let data = source.read_bytes_at(0, BLOCK0_SIZE)?;
    Self::parse(&data)
  }

  /// Parse a driver descriptor block from 512 bytes.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != BLOCK0_SIZE {
      return Err(Error::InvalidFormat(format!(
        "apm driver descriptor must be {BLOCK0_SIZE} bytes, got {}",
        data.len()
      )));
    }
    if &data[0..2] != DRIVER_DESCRIPTOR_SIGNATURE {
      return Err(Error::InvalidFormat(
        "apm driver descriptor signature is missing".to_string(),
      ));
    }

    let block_size = read_u16_be(data, 2);
    let driver_count = usize::from(read_u16_be(data, 16));
    let available_driver_slots = (BLOCK0_SIZE - 18) / 8;
    if driver_count > available_driver_slots {
      return Err(Error::InvalidFormat(format!(
        "apm driver descriptor count is too large: {driver_count}"
      )));
    }

    let mut driver_descriptors = Vec::with_capacity(driver_count);
    for index in 0..driver_count {
      let offset = 18 + index * 8;
      driver_descriptors.push(ApmDriverDescriptorEntry {
        start_block: read_u32_be(data, offset),
        block_count: read_u16_be(data, offset + 4),
        system_type: read_u16_be(data, offset + 6),
      });
    }

    Ok(Self {
      block_size,
      block_count: read_u32_be(data, 4),
      device_type: read_u16_be(data, 8),
      device_identifier: read_u16_be(data, 10),
      device_data: read_u32_be(data, 12),
      driver_descriptors,
    })
  }
}

fn read_u16_be(data: &[u8], offset: usize) -> u16 {
  u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn read_u32_be(data: &[u8], offset: usize) -> u32 {
  u32::from_be_bytes([
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3],
  ])
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_driver_descriptor_fields() {
    let mut block = [0u8; BLOCK0_SIZE];
    block[0..2].copy_from_slice(b"ER");
    block[2..4].copy_from_slice(&512u16.to_be_bytes());
    block[4..8].copy_from_slice(&8192u32.to_be_bytes());
    block[16..18].copy_from_slice(&1u16.to_be_bytes());
    block[18..22].copy_from_slice(&12u32.to_be_bytes());
    block[22..24].copy_from_slice(&3u16.to_be_bytes());
    block[24..26].copy_from_slice(&1u16.to_be_bytes());

    let descriptor = ApmDriverDescriptor::parse(&block).unwrap();

    assert_eq!(descriptor.block_size, 512);
    assert_eq!(descriptor.block_count, 8192);
    assert_eq!(descriptor.driver_descriptors.len(), 1);
    assert_eq!(descriptor.driver_descriptors[0].start_block, 12);
  }
}
