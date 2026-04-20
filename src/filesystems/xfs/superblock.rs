use super::{
  constants::{SB_MAGIC, SECONDARY_FEATURE_FILETYPE, XFS_MAX_INODE_NUMBER},
  io::{be_u16, be_u32, be_u64, read_exact_at},
};
use crate::{ByteSource, Error, Result};

#[derive(Clone, Debug)]
pub(crate) struct XfsSuperblock {
  pub(crate) block_size: u32,
  pub(crate) sector_size: u16,
  pub(crate) inode_size: u16,
  pub(crate) inodes_per_block_log2: u8,
  pub(crate) ag_blocks: u32,
  pub(crate) ag_count: u32,
  pub(crate) root_ino: u64,
  pub(crate) format_version: u8,
  pub(crate) secondary_feature_flags: u32,
  pub(crate) dir_block_size: u32,
  pub(crate) relative_block_bits: u8,
  pub(crate) relative_inode_bits: u8,
}

impl XfsSuperblock {
  pub(crate) fn read(source: &dyn ByteSource) -> Result<Self> {
    let data = read_exact_at(source, 0, 512)?;
    if &data[0..4] != SB_MAGIC {
      return Err(Error::invalid_format(
        "invalid xfs superblock signature".to_string(),
      ));
    }

    let block_size = be_u32(&data[4..8]);
    let root_ino = be_u64(&data[56..64]) & XFS_MAX_INODE_NUMBER;
    let ag_blocks = be_u32(&data[84..88]);
    let ag_count = be_u32(&data[88..92]);
    let version_flags = be_u16(&data[100..102]);
    let format_version = (version_flags & 0x000F) as u8;
    let sector_size = be_u16(&data[102..104]);
    let inode_size = be_u16(&data[104..106]);
    let inodes_per_block = be_u16(&data[106..108]);
    let inodes_per_block_log2 = data[123];
    let relative_block_bits = data[124];
    let dir_blk_log2 = data[192];
    let secondary_feature_flags = be_u32(&data[200..204]);

    if !(4..=5).contains(&format_version) {
      return Err(Error::invalid_format("unsupported xfs version"));
    }
    if !(512..=32768).contains(&sector_size) {
      return Err(Error::invalid_format(
        "unsupported xfs sector size".to_string(),
      ));
    }
    if !(512..=65536).contains(&block_size) {
      return Err(Error::invalid_format(
        "unsupported xfs block size".to_string(),
      ));
    }
    if !(256..=2048).contains(&inode_size) {
      return Err(Error::invalid_format(
        "unsupported xfs inode size".to_string(),
      ));
    }
    if ag_blocks < 5 || ag_count == 0 {
      return Err(Error::invalid_format("invalid xfs geometry"));
    }
    if relative_block_bits == 0 || relative_block_bits > 31 {
      return Err(Error::invalid_format(
        "invalid allocation group size log2".to_string(),
      ));
    }
    if inodes_per_block_log2 == 0 || inodes_per_block_log2 > (32 - relative_block_bits) {
      return Err(Error::invalid_format(
        "invalid inodes per block log2".to_string(),
      ));
    }
    if (1u64 << inodes_per_block_log2) != u64::from(inodes_per_block) {
      return Err(Error::invalid_format(
        "mismatch between inodes per block and log2 values".to_string(),
      ));
    }

    let dir_block_size = if dir_blk_log2 == 0 {
      block_size
    } else {
      block_size
        .checked_mul(
          1u32
            .checked_shl(u32::from(dir_blk_log2))
            .ok_or_else(|| Error::invalid_range("invalid xfs directory block log2"))?,
        )
        .ok_or_else(|| Error::invalid_range("xfs directory block size overflow"))?
    };

    let relative_inode_bits = relative_block_bits
      .checked_add(inodes_per_block_log2)
      .ok_or_else(|| Error::invalid_range("xfs inode geometry overflow"))?;
    if relative_inode_bits == 0 || relative_inode_bits >= 32 {
      return Err(Error::invalid_format(
        "invalid xfs relative inode bits".to_string(),
      ));
    }

    Ok(Self {
      block_size,
      sector_size,
      inode_size,
      inodes_per_block_log2,
      ag_blocks,
      ag_count,
      root_ino,
      format_version,
      secondary_feature_flags,
      dir_block_size,
      relative_block_bits,
      relative_inode_bits,
    })
  }

  pub(crate) fn has_ftype(&self) -> bool {
    self.format_version == 5 || (self.secondary_feature_flags & SECONDARY_FEATURE_FILETYPE) != 0
  }
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;

  fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("xfs")
      .join("libfsxfs")
      .join(relative)
  }

  #[test]
  fn parses_libfsxfs_superblock_fixture() {
    let bytes = std::fs::read(fixture_path("superblock.1")).unwrap();
    let source = crate::BytesDataSource::new(Arc::<[u8]>::from(bytes));
    let superblock = XfsSuperblock::read(&source).unwrap();

    assert_eq!(superblock.block_size, 4096);
    assert_eq!(superblock.sector_size, 512);
    assert_eq!(superblock.inode_size, 512);
    assert_eq!(superblock.ag_blocks, 4096);
    assert_eq!(superblock.ag_count, 1);
    assert_eq!(superblock.root_ino, 11072);
    assert_eq!(superblock.format_version, 5);
    assert!(superblock.has_ftype());
  }
}
