use crate::{ByteSource, Error, Result};

pub(crate) const SQUASHFS_MAGIC: &[u8; 4] = b"hsqs";

pub(crate) const ZLIB_COMPRESSION: u16 = 1;
#[allow(dead_code)]
pub(crate) const LZMA_COMPRESSION: u16 = 2;
#[allow(dead_code)]
pub(crate) const LZO_COMPRESSION: u16 = 3;
pub(crate) const XZ_COMPRESSION: u16 = 4;
#[allow(dead_code)]
pub(crate) const LZ4_COMPRESSION: u16 = 5;
pub(crate) const ZSTD_COMPRESSION: u16 = 6;

#[allow(dead_code)]
pub(crate) const SQUASHFS_NOI: u16 = 1 << 0;
#[allow(dead_code)]
pub(crate) const SQUASHFS_NOD: u16 = 1 << 1;
#[allow(dead_code)]
pub(crate) const SQUASHFS_NOF: u16 = 1 << 3;
pub(crate) const SQUASHFS_NO_FRAG: u16 = 1 << 4;
#[allow(dead_code)]
pub(crate) const SQUASHFS_ALWAYS_FRAG: u16 = 1 << 5;
#[allow(dead_code)]
pub(crate) const SQUASHFS_DUPLICATE: u16 = 1 << 6;
#[allow(dead_code)]
pub(crate) const SQUASHFS_EXPORT: u16 = 1 << 7;
#[allow(dead_code)]
pub(crate) const SQUASHFS_NOX: u16 = 1 << 8;
#[allow(dead_code)]
pub(crate) const SQUASHFS_NO_XATTR: u16 = 1 << 9;
#[allow(dead_code)]
pub(crate) const SQUASHFS_COMP_OPT: u16 = 1 << 10;

pub(crate) const SQUASHFS_COMPRESSED_BIT: u32 = 1 << 24;

pub(crate) const METADATA_SIZE: u64 = 8192;

pub(crate) const SUPERBLOCK_SIZE_V4: u64 = 96;

#[allow(dead_code)]
pub(crate) const SQUASHFS_INVALID_FRAG: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct SquashFsSuperblock {
  pub block_size: u32,
  pub block_log2: u16,
  pub compression: u16,
  pub flags: u16,
  pub major_version: u16,
  pub minor_version: u16,
  pub root_inode_offset: u64,
  pub bytes_used: u64,
  pub id_table_start: u64,
  pub xattr_id_table_start: u64,
  pub inode_table_start: u64,
  pub directory_table_start: u64,
  pub fragment_table_start: u64,
  pub lookup_table_start: u64,
  pub inode_count: u32,
  pub fragment_count: u32,
  pub id_count: u16,
  pub mkfs_time: u32,
}

impl SquashFsSuperblock {
  pub(crate) fn read(source: &dyn ByteSource) -> Result<Self> {
    let source_size = source.size()?;
    if source_size < SUPERBLOCK_SIZE_V4 {
      return Err(Error::invalid_format(
        "squashfs source is too small to contain a superblock",
      ));
    }

    let mut offset = source_size - SUPERBLOCK_SIZE_V4;
    loop {
      let data = source.read_bytes_at(offset, SUPERBLOCK_SIZE_V4 as usize)?;
      if &data[0..4] == SQUASHFS_MAGIC {
        return Self::parse_superblock(&data);
      }
      if offset == 0 {
        break;
      }
      offset = offset.saturating_sub(SUPERBLOCK_SIZE_V4);
      if offset < source_size.saturating_sub(1024 * 1024) {
        break;
      }
    }

    Err(Error::invalid_format(
      "invalid squashfs superblock signature",
    ))
  }

  fn parse_superblock(data: &[u8]) -> Result<Self> {
    let major_version = read_u16_le(data, 28)?;
    let minor_version = read_u16_le(data, 30)?;

    if major_version != 4 {
      return Err(Error::unsupported(format!(
        "unsupported squashfs version {major_version}.{minor_version}"
      )));
    }

    let block_size = read_u32_le(data, 12)?;
    let block_log2 = read_u16_le(data, 22)?;

    if !block_size.is_power_of_two() || !(4096..=1_048_576).contains(&block_size) {
      return Err(Error::invalid_format(format!(
        "invalid squashfs block size: {block_size}"
      )));
    }
    if (1u32 << u32::from(block_log2)) != block_size {
      return Err(Error::invalid_format(
        "squashfs block size does not match block_log2",
      ));
    }

    let flags = read_u16_le(data, 24)?;
    let compression = read_u16_le(data, 20)?;

    Ok(Self {
      block_size,
      block_log2,
      compression,
      flags,
      major_version,
      minor_version,
      root_inode_offset: read_u64_le(data, 32)?,
      bytes_used: read_u64_le(data, 40)?,
      id_table_start: read_u64_le(data, 48)?,
      xattr_id_table_start: read_u64_le(data, 56)?,
      inode_table_start: read_u64_le(data, 64)?,
      directory_table_start: read_u64_le(data, 72)?,
      fragment_table_start: read_u64_le(data, 80)?,
      lookup_table_start: read_u64_le(data, 88)?,
      inode_count: read_u32_le(data, 4)?,
      mkfs_time: read_u32_le(data, 8)?,
      fragment_count: read_u32_le(data, 16)?,
      id_count: read_u16_le(data, 26)?,
    })
  }

  pub(crate) fn has_fragments(&self) -> bool {
    (self.flags & SQUASHFS_NO_FRAG) == 0
  }

  #[allow(dead_code)]
  pub(crate) fn has_export_table(&self) -> bool {
    (self.flags & SQUASHFS_EXPORT) != 0
  }

  #[allow(dead_code)]
  pub(crate) fn has_xattrs(&self) -> bool {
    (self.flags & SQUASHFS_NO_XATTR) == 0
      && (self.flags & SQUASHFS_NOX) == 0
      && self.xattr_id_table_start != u64::MAX
  }

  #[allow(dead_code)]
  pub(crate) fn compression_name(&self) -> &'static str {
    match self.compression {
      ZLIB_COMPRESSION => "zlib",
      LZMA_COMPRESSION => "lzma",
      LZO_COMPRESSION => "lzo",
      XZ_COMPRESSION => "xz",
      LZ4_COMPRESSION => "lz4",
      ZSTD_COMPRESSION => "zstd",
      _ => "unknown",
    }
  }
}

pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
  Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
  Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
  Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

#[allow(dead_code)]
pub(crate) fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32> {
  Ok(i32::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  bytes
    .get(offset..offset + N)
    .ok_or_else(|| Error::invalid_format("squashfs field extends beyond available data"))?
    .try_into()
    .map_err(|_| Error::invalid_format("squashfs field is truncated"))
}

pub(crate) fn read_slice<'a>(
  bytes: &'a [u8], offset: usize, length: usize, what: &str,
) -> Result<&'a [u8]> {
  let end = offset
    .checked_add(length)
    .ok_or_else(|| Error::invalid_range(format!("{what} offset overflow")))?;
  bytes.get(offset..end).ok_or_else(|| {
    Error::invalid_format(format!("{what} extends beyond the available squashfs data"))
  })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SquashFsFragmentEntry {
  pub start_block: u64,
  pub size: u32,
}

impl SquashFsFragmentEntry {
  pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
    if bytes.len() < 16 {
      return Err(Error::invalid_format(
        "squashfs fragment entry is too short",
      ));
    }
    Ok(Self {
      start_block: read_u64_le(bytes, 0)?,
      size: read_u32_le(bytes, 8)?,
    })
  }
}
