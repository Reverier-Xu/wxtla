//! ext-family superblock and group-descriptor parsing.

use crate::{DataSource, Error, Result};

pub(crate) const SUPERBLOCK_OFFSET: u64 = 1024;
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;
const SUPERBLOCK_MAGIC: u16 = 0xEF53;
const FEATURE_INCOMPAT_EXTENTS: u32 = 0x0000_0040;

pub(crate) const INODE_FLAG_EXTENTS: u32 = 0x0008_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtVariant {
  Ext2,
  Ext3,
  Ext4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtSuperblock {
  pub variant: ExtVariant,
  pub blocks_count: u64,
  pub block_size: u32,
  pub blocks_per_group: u32,
  pub inodes_per_group: u32,
  pub inode_size: u16,
  pub first_data_block: u32,
  pub compatible_features: u32,
  pub incompatible_features: u32,
  pub readonly_compatible_features: u32,
  pub descriptor_size: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtGroupDescriptor {
  pub inode_table_block: u64,
}

impl ExtSuperblock {
  pub fn read(source: &dyn DataSource) -> Result<Self> {
    let bytes = source.read_bytes_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)?;
    Self::from_bytes(&bytes)
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    let superblock: &[u8; SUPERBLOCK_SIZE] = bytes
      .try_into()
      .map_err(|_| Error::InvalidFormat("ext superblock must be exactly 1024 bytes".to_string()))?;
    Self::from_superblock(superblock)
  }

  pub fn from_superblock(superblock: &[u8; SUPERBLOCK_SIZE]) -> Result<Self> {
    let magic = le_u16(&superblock[56..58]);
    if magic != SUPERBLOCK_MAGIC {
      return Err(Error::InvalidFormat(
        "ext superblock magic is missing".to_string(),
      ));
    }

    let log_block_size = le_u32(&superblock[24..28]);
    let block_size = 1024u32
      .checked_shl(log_block_size)
      .ok_or_else(|| Error::InvalidRange("ext block size overflow".to_string()))?;
    if block_size < 1024 {
      return Err(Error::InvalidFormat(
        "ext block size must be at least 1024 bytes".to_string(),
      ));
    }

    let blocks_count_lo = u64::from(le_u32(&superblock[4..8]));
    let incompatible_features = le_u32(&superblock[96..100]);
    let readonly_compatible_features = le_u32(&superblock[100..104]);
    let blocks_count_hi = if incompatible_features & 0x80 != 0 {
      u64::from(le_u32(&superblock[336..340]))
    } else {
      0
    };
    let blocks_count = blocks_count_lo | (blocks_count_hi << 32);
    if blocks_count == 0 {
      return Err(Error::InvalidFormat(
        "ext block count must be non-zero".to_string(),
      ));
    }

    let blocks_per_group = le_u32(&superblock[32..36]);
    let inodes_per_group = le_u32(&superblock[40..44]);
    if blocks_per_group == 0 || inodes_per_group == 0 {
      return Err(Error::InvalidFormat(
        "ext group sizes must be non-zero".to_string(),
      ));
    }

    let inode_size = le_u16(&superblock[88..90]);
    if inode_size < 128 {
      return Err(Error::InvalidFormat(
        "ext inode size must be at least 128 bytes".to_string(),
      ));
    }

    let compatible_features = le_u32(&superblock[92..96]);
    let variant = if incompatible_features & FEATURE_INCOMPAT_EXTENTS != 0 {
      ExtVariant::Ext4
    } else if compatible_features & 0x0000_0004 != 0 {
      ExtVariant::Ext3
    } else {
      ExtVariant::Ext2
    };
    let descriptor_size = if incompatible_features & 0x80 != 0 {
      let descriptor_size = le_u16(&superblock[254..256]);
      if descriptor_size < 32 {
        return Err(Error::InvalidFormat(
          "ext64 group descriptor size must be at least 32 bytes".to_string(),
        ));
      }
      descriptor_size
    } else {
      32
    };

    Ok(Self {
      variant,
      blocks_count,
      block_size,
      blocks_per_group,
      inodes_per_group,
      inode_size,
      first_data_block: le_u32(&superblock[20..24]),
      compatible_features,
      incompatible_features,
      readonly_compatible_features,
      descriptor_size,
    })
  }

  pub fn block_size_u64(&self) -> u64 {
    u64::from(self.block_size)
  }

  pub fn block_offset(&self, block: u64) -> Result<u64> {
    block
      .checked_mul(self.block_size_u64())
      .ok_or_else(|| Error::InvalidRange("ext block offset overflow".to_string()))
  }

  pub fn group_count(&self) -> u64 {
    self.blocks_count.div_ceil(u64::from(self.blocks_per_group))
  }

  pub fn group_descriptor_table_offset(&self) -> u64 {
    if self.block_size == 1024 {
      2 * self.block_size_u64()
    } else {
      self.block_size_u64()
    }
  }
}

pub(crate) fn read_group_descriptors(
  source: &dyn DataSource, superblock: &ExtSuperblock,
) -> Result<Vec<ExtGroupDescriptor>> {
  let descriptor_size = usize::from(superblock.descriptor_size);
  let group_count = usize::try_from(superblock.group_count())
    .map_err(|_| Error::InvalidRange("ext group count is too large".to_string()))?;
  let table_size = descriptor_size
    .checked_mul(group_count)
    .ok_or_else(|| Error::InvalidRange("ext descriptor table size overflow".to_string()))?;
  let table = source.read_bytes_at(superblock.group_descriptor_table_offset(), table_size)?;
  let mut descriptors = Vec::with_capacity(group_count);

  for descriptor in table.chunks_exact(descriptor_size) {
    let inode_table_lo = u64::from(le_u32(&descriptor[8..12]));
    let inode_table_hi = if descriptor_size >= 44 {
      u64::from(le_u32(&descriptor[40..44]))
    } else {
      0
    };
    descriptors.push(ExtGroupDescriptor {
      inode_table_block: inode_table_lo | (inode_table_hi << 32),
    });
  }

  Ok(descriptors)
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_ext4_when_extents_are_enabled() {
    let mut superblock = [0u8; SUPERBLOCK_SIZE];
    superblock[24..28].copy_from_slice(&0u32.to_le_bytes());
    superblock[4..8].copy_from_slice(&4096u32.to_le_bytes());
    superblock[32..36].copy_from_slice(&8192u32.to_le_bytes());
    superblock[40..44].copy_from_slice(&1024u32.to_le_bytes());
    superblock[56..58].copy_from_slice(&SUPERBLOCK_MAGIC.to_le_bytes());
    superblock[88..90].copy_from_slice(&256u16.to_le_bytes());
    superblock[96..100].copy_from_slice(&0x40u32.to_le_bytes());

    let parsed = ExtSuperblock::from_superblock(&superblock).unwrap();
    assert_eq!(parsed.variant, ExtVariant::Ext4);
  }
}
