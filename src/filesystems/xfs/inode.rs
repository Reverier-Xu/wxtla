use std::cmp::min;

use super::{
  constants::{FILETYPE_DIR, FILETYPE_MASK, FILETYPE_SYMLINK, FORK_INLINE, INODE_MAGIC},
  io::{be_u16, be_u32, be_u64},
};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub(crate) struct XfsInode {
  pub(crate) mode: u16,
  pub(crate) fork_type: u8,
  pub(crate) uid: u32,
  pub(crate) gid: u32,
  pub(crate) nlink: u32,
  pub(crate) size: u64,
  pub(crate) nextents: u32,
  pub(crate) data_fork: Vec<u8>,
  pub(crate) inline_data: Option<Vec<u8>>,
}

impl XfsInode {
  pub(crate) fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < 100 {
      return Err(Error::InvalidFormat("xfs inode too small".to_string()));
    }
    if &data[0..2] != INODE_MAGIC {
      return Err(Error::InvalidFormat(
        "invalid xfs inode signature".to_string(),
      ));
    }

    let mode = be_u16(&data[2..4]);
    let format_version = data[4];
    let fork_type = data[5];
    if !matches!(format_version, 1..=3) {
      return Err(Error::InvalidFormat(format!(
        "unsupported xfs inode format version: {format_version}"
      )));
    }

    let uid = be_u32(&data[8..12]);
    let gid = be_u32(&data[12..16]);
    let nlink = if format_version == 1 {
      u32::from(be_u16(&data[6..8]))
    } else {
      be_u32(&data[16..20])
    };

    let size = be_u64(&data[56..64]);
    let nextents = be_u32(&data[76..80]);
    let attr_fork_offset = usize::from(data[82]) * 8;

    let core_size = if format_version == 3 {
      176usize
    } else {
      100usize
    };
    if data.len() < core_size {
      return Err(Error::InvalidFormat(
        "xfs inode core is truncated".to_string(),
      ));
    }

    let mut data_fork_size = data.len() - core_size;
    if attr_fork_offset > 0 {
      if attr_fork_offset >= data_fork_size {
        return Err(Error::InvalidFormat(
          "invalid xfs inode attribute fork offset".to_string(),
        ));
      }
      data_fork_size = attr_fork_offset;
    }

    let data_fork = data[core_size..core_size + data_fork_size].to_vec();
    let inline_data = if fork_type == FORK_INLINE {
      if size as usize > data_fork.len() {
        return Err(Error::InvalidFormat(
          "xfs inline data size is out of bounds".to_string(),
        ));
      }
      Some(data_fork[..min(data_fork.len(), size as usize)].to_vec())
    } else {
      None
    };

    Ok(Self {
      mode,
      fork_type,
      uid,
      gid,
      nlink,
      size,
      nextents,
      data_fork,
      inline_data,
    })
  }

  pub(crate) fn is_dir(&self) -> bool {
    (self.mode & FILETYPE_MASK) == FILETYPE_DIR
  }

  pub(crate) fn is_symlink(&self) -> bool {
    (self.mode & FILETYPE_MASK) == FILETYPE_SYMLINK
  }
}
