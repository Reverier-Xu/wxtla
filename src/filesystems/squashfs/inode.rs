use super::superblock::{read_slice, read_u16_le, read_u32_le, read_u64_le};
use crate::{Error, Result};

pub(crate) const SQUASHFS_DIR_TYPE: u16 = 1;
pub(crate) const SQUASHFS_FILE_TYPE: u16 = 2;
pub(crate) const SQUASHFS_SYMLINK_TYPE: u16 = 3;
pub(crate) const SQUASHFS_BLKDEV_TYPE: u16 = 4;
pub(crate) const SQUASHFS_CHRDEV_TYPE: u16 = 5;
pub(crate) const SQUASHFS_FIFO_TYPE: u16 = 6;
pub(crate) const SQUASHFS_SOCKET_TYPE: u16 = 7;
pub(crate) const SQUASHFS_LDIR_TYPE: u16 = 8;
pub(crate) const SQUASHFS_LREG_TYPE: u16 = 9;
pub(crate) const SQUASHFS_LSYMLINK_TYPE: u16 = 10;
pub(crate) const SQUASHFS_LBLKDEV_TYPE: u16 = 11;
pub(crate) const SQUASHFS_LCHRDEV_TYPE: u16 = 12;
pub(crate) const SQUASHFS_LFIFO_TYPE: u16 = 13;
pub(crate) const SQUASHFS_LSOCKET_TYPE: u16 = 14;

pub(crate) const IPC_INODE_SIZE: usize = 20;
pub(crate) const LIPC_INODE_SIZE: usize = 24;
pub(crate) const DEV_INODE_SIZE: usize = 24;
pub(crate) const LDEV_INODE_SIZE: usize = 28;
pub(crate) const SYMLINK_INODE_SIZE: usize = 24;
pub(crate) const REG_INODE_SIZE: usize = 32;
pub(crate) const LREG_INODE_SIZE: usize = 56;
pub(crate) const DIR_INODE_SIZE: usize = 32;
pub(crate) const LDIR_INODE_SIZE: usize = 40;

pub(crate) const SQUASHFS_INVALID_FRAG: u32 = 0xFFFF_FFFF;
pub(crate) const SQUASHFS_INVALID_XATTR: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct SquashFsInode {
  pub inode_type: u16,
  pub mode: u16,
  pub uid_idx: u16,
  pub gid_idx: u16,
  pub mtime: u32,
  pub inode_number: u32,
  pub nlink: u32,
  pub xattr_idx: u32,
  pub file_size: u64,
  pub fragment_block_index: u32,
  pub fragment_offset: u32,
  pub start_block: u64,
  pub sparse: u64,
  pub block_sizes: Vec<u32>,
  pub symlink_target: String,
  pub parent_inode: u32,
  pub rdev: u32,
  pub dir_index_count: u16,
}

impl SquashFsInode {
  pub(crate) fn parse(bytes: &[u8], block_size: u64) -> Result<Self> {
    if bytes.len() < 2 {
      return Err(Error::invalid_format("squashfs inode is too short"));
    }

    let inode_type = read_u16_le(bytes, 0)?;

    match inode_type {
      SQUASHFS_DIR_TYPE => Self::parse_dir(bytes, false),
      SQUASHFS_LDIR_TYPE => Self::parse_dir(bytes, true),
      SQUASHFS_FILE_TYPE => Self::parse_reg(bytes, false, block_size),
      SQUASHFS_LREG_TYPE => Self::parse_reg(bytes, true, block_size),
      SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => Self::parse_symlink(bytes),
      SQUASHFS_BLKDEV_TYPE | SQUASHFS_CHRDEV_TYPE => Self::parse_dev(bytes, false),
      SQUASHFS_LBLKDEV_TYPE | SQUASHFS_LCHRDEV_TYPE => Self::parse_dev(bytes, true),
      SQUASHFS_FIFO_TYPE | SQUASHFS_SOCKET_TYPE => Self::parse_ipc(bytes, false),
      SQUASHFS_LFIFO_TYPE | SQUASHFS_LSOCKET_TYPE => Self::parse_ipc(bytes, true),
      _ => Err(Error::unsupported(format!(
        "unsupported squashfs inode type: {inode_type}"
      ))),
    }
  }

  fn parse_base_fields(bytes: &[u8], has_xattr: bool) -> Result<Self> {
    let inode_type = read_u16_le(bytes, 0)?;
    let mode = read_u16_le(bytes, 2)?;
    let uid_idx = read_u16_le(bytes, 4)?;
    let gid_idx = read_u16_le(bytes, 6)?;
    let mtime = read_u32_le(bytes, 8)?;
    let inode_number = read_u32_le(bytes, 12)?;

    Ok(Self {
      inode_type,
      mode,
      uid_idx,
      gid_idx,
      mtime,
      inode_number,
      nlink: 1,
      xattr_idx: if has_xattr {
        u32::MAX
      } else {
        SQUASHFS_INVALID_XATTR
      },
      file_size: 0,
      fragment_block_index: SQUASHFS_INVALID_FRAG,
      fragment_offset: 0,
      start_block: 0,
      sparse: 0,
      block_sizes: Vec::new(),
      symlink_target: String::new(),
      parent_inode: 0,
      rdev: 0,
      dir_index_count: 0,
    })
  }

  fn parse_ipc(bytes: &[u8], large: bool) -> Result<Self> {
    let min_size = if large {
      LIPC_INODE_SIZE
    } else {
      IPC_INODE_SIZE
    };
    if bytes.len() < min_size {
      return Err(Error::invalid_format("squashfs ipc inode is too short"));
    }

    let mut inode = Self::parse_base_fields(bytes, large)?;
    inode.nlink = read_u32_le(bytes, 16)?;
    if large {
      inode.xattr_idx = read_u32_le(bytes, 20)?;
    }
    Ok(inode)
  }

  fn parse_dev(bytes: &[u8], large: bool) -> Result<Self> {
    let min_size = if large {
      LDEV_INODE_SIZE
    } else {
      DEV_INODE_SIZE
    };
    if bytes.len() < min_size {
      return Err(Error::invalid_format("squashfs dev inode is too short"));
    }

    let mut inode = Self::parse_base_fields(bytes, large)?;
    inode.nlink = read_u32_le(bytes, 16)?;
    inode.rdev = read_u32_le(bytes, 20)?;
    if large {
      inode.xattr_idx = read_u32_le(bytes, 24)?;
    }
    Ok(inode)
  }

  fn parse_symlink(bytes: &[u8]) -> Result<Self> {
    let inode_type = read_u16_le(bytes, 0)?;
    let is_large = inode_type == SQUASHFS_LSYMLINK_TYPE;
    if bytes.len() < SYMLINK_INODE_SIZE {
      return Err(Error::invalid_format("squashfs symlink inode is too short"));
    }

    let mut inode = Self::parse_base_fields(bytes, is_large)?;
    inode.nlink = read_u32_le(bytes, 16)?;
    let target_size = read_u32_le(bytes, 20)? as usize;
    let target = read_slice(bytes, 24, target_size, "squashfs symlink target")?;
    inode.symlink_target = String::from_utf8_lossy(target).to_string();
    Ok(inode)
  }

  fn parse_reg(bytes: &[u8], large: bool, block_size: u64) -> Result<Self> {
    if large {
      if bytes.len() < LREG_INODE_SIZE {
        return Err(Error::invalid_format(
          "squashfs large reg inode is too short",
        ));
      }

      let mut inode = Self::parse_base_fields(bytes, true)?;
      inode.start_block = read_u32_le(bytes, 16)? as u64;
      inode.file_size = read_u64_le(bytes, 24)?;
      inode.sparse = read_u64_le(bytes, 32)?;
      inode.nlink = read_u32_le(bytes, 40)?;
      inode.fragment_block_index = read_u32_le(bytes, 44)?;
      inode.fragment_offset = read_u32_le(bytes, 48)?;
      inode.xattr_idx = read_u32_le(bytes, 52)?;

      let block_count =
        compute_block_count(inode.file_size, block_size, inode.fragment_block_index);
      let list_offset = 56;
      let list_size = block_count
        .checked_mul(4)
        .ok_or_else(|| Error::invalid_range("squashfs block list size overflow"))?;
      if list_size > 0 {
        let list_bytes = read_slice(bytes, list_offset, list_size, "squashfs block list")?;
        for chunk in list_bytes.chunks_exact(4) {
          inode
            .block_sizes
            .push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }
      }

      Ok(inode)
    } else {
      if bytes.len() < REG_INODE_SIZE {
        return Err(Error::invalid_format("squashfs regular inode is too short"));
      }

      let mut inode = Self::parse_base_fields(bytes, false)?;
      inode.start_block = read_u32_le(bytes, 16)? as u64;
      inode.fragment_block_index = read_u32_le(bytes, 20)?;
      inode.fragment_offset = read_u32_le(bytes, 24)?;
      inode.file_size = read_u32_le(bytes, 28)? as u64;

      let block_count =
        compute_block_count(inode.file_size, block_size, inode.fragment_block_index);
      let list_offset = 32;
      let list_size = block_count
        .checked_mul(4)
        .ok_or_else(|| Error::invalid_range("squashfs block list size overflow"))?;
      if list_size > 0 {
        let list_bytes = read_slice(bytes, list_offset, list_size, "squashfs block list")?;
        for chunk in list_bytes.chunks_exact(4) {
          inode
            .block_sizes
            .push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }
      }

      Ok(inode)
    }
  }

  fn parse_dir(bytes: &[u8], large: bool) -> Result<Self> {
    if large {
      if bytes.len() < LDIR_INODE_SIZE {
        return Err(Error::invalid_format(
          "squashfs large dir inode is too short",
        ));
      }

      let mut inode = Self::parse_base_fields(bytes, true)?;
      inode.nlink = read_u32_le(bytes, 16)?;
      inode.file_size = read_u32_le(bytes, 20)? as u64;
      inode.start_block = read_u32_le(bytes, 24)? as u64;
      inode.parent_inode = read_u32_le(bytes, 28)?;
      inode.dir_index_count = read_u16_le(bytes, 32)?;
      inode.fragment_offset = read_u16_le(bytes, 34)? as u32;
      inode.xattr_idx = read_u32_le(bytes, 36)?;

      let index_count = inode.dir_index_count as usize;
      let index_offset = 40;
      let index_size = index_count
        .checked_mul(12)
        .ok_or_else(|| Error::invalid_range("squashfs dir index size overflow"))?;
      if index_size > 0 {
        let index_bytes = read_slice(bytes, index_offset, index_size, "squashfs dir index")?;
        for chunk in index_bytes.chunks_exact(12) {
          let entry_start = read_u32_le(chunk, 4)?;
          inode.block_sizes.push(entry_start);
        }
      }

      Ok(inode)
    } else {
      if bytes.len() < DIR_INODE_SIZE {
        return Err(Error::invalid_format("squashfs dir inode is too short"));
      }

      let mut inode = Self::parse_base_fields(bytes, false)?;
      inode.start_block = read_u32_le(bytes, 16)? as u64;
      inode.nlink = read_u32_le(bytes, 20)?;
      let file_size = read_u16_le(bytes, 24)?;
      inode.fragment_offset = read_u16_le(bytes, 26)? as u32;
      inode.file_size = file_size as u64;
      inode.parent_inode = read_u32_le(bytes, 28)?;

      Ok(inode)
    }
  }

  pub(crate) fn block_count(&self, block_size: u64) -> usize {
    compute_block_count(self.file_size, block_size, self.fragment_block_index)
  }
}

fn compute_block_count(file_size: u64, block_size: u64, fragment_idx: u32) -> usize {
  if file_size == 0 || block_size == 0 {
    return 0;
  }
  if fragment_idx == SQUASHFS_INVALID_FRAG {
    file_size.div_ceil(block_size) as usize
  } else {
    (file_size / block_size) as usize
  }
}
