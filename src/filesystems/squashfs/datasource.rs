use std::{io::Read, sync::Arc};

use flate2::read::ZlibDecoder;

use super::{
  inode::SQUASHFS_INVALID_FRAG,
  superblock::{
    SQUASHFS_COMPRESSED_BIT, SquashFsSuperblock, XZ_COMPRESSION, ZLIB_COMPRESSION, ZSTD_COMPRESSION,
  },
};
use crate::{ByteSource, ByteSourceCapabilities, ByteSourceHandle, Error, Result};

pub(crate) struct SquashFsDataReader {
  source: ByteSourceHandle,
  superblock: SquashFsSuperblock,
}

impl SquashFsDataReader {
  pub(crate) fn new(source: ByteSourceHandle, superblock: SquashFsSuperblock) -> Self {
    Self { source, superblock }
  }

  pub(crate) fn read_metadata_block(&self, offset: u64) -> Result<Vec<u8>> {
    let data = self.source.read_bytes_at(offset, 2)?;
    if data.len() < 2 {
      return Ok(Vec::new());
    }

    let size = u16::from_le_bytes([data[0], data[1]]);
    let (compressed_size, is_compressed) = if (size & 0x8000) != 0 {
      (u64::from(size & !0x8000), false)
    } else {
      (u64::from(size), true)
    };

    if compressed_size == 0 {
      return Ok(Vec::new());
    }

    let raw = self
      .source
      .read_bytes_at(offset + 2, compressed_size as usize)?;

    if !is_compressed {
      return Ok(raw);
    }

    self.decompress_block(&raw, u64::MAX)
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) fn read_file_block(
    &self, block_index: u64, start_block: u64, block_size: u32, block_sizes: &[u32],
    file_size: u64, fragment_idx: u32, fragment_offset: u32,
    fragment_blocks: &[super::superblock::SquashFsFragmentEntry],
  ) -> Result<Vec<u8>> {
    let block_count = block_sizes.len() as u64;

    if block_index >= block_count && fragment_idx == SQUASHFS_INVALID_FRAG {
      return Err(Error::invalid_format(format!(
        "squashfs block index {block_index} is out of bounds"
      )));
    }

    if block_index < block_count {
      let compressed_size = block_sizes[block_index as usize];
      if compressed_size == 0 {
        let actual_size: u64 =
          if block_index == block_count - 1 && fragment_idx != SQUASHFS_INVALID_FRAG {
            u64::from(block_size)
          } else {
            let remaining = file_size.saturating_sub(block_index * u64::from(block_size));
            remaining.min(u64::from(block_size))
          };
        return Ok(vec![0; actual_size as usize]);
      }

      let is_uncompressed = (compressed_size & SQUASHFS_COMPRESSED_BIT) != 0;
      let actual_size = compressed_size & !SQUASHFS_COMPRESSED_BIT;

      let physical_offset = start_block
        .checked_add(block_index)
        .and_then(|v| v.checked_mul(u64::from(block_size)))
        .ok_or_else(|| Error::invalid_range("squashfs data offset overflow"))?;

      let raw = self
        .source
        .read_bytes_at(physical_offset, actual_size as usize)?;

      if is_uncompressed {
        return Ok(raw);
      }

      return self.decompress_block(&raw, u64::from(block_size));
    }

    if fragment_idx != SQUASHFS_INVALID_FRAG {
      let fragment = fragment_blocks.get(fragment_idx as usize).ok_or_else(|| {
        Error::not_found(format!(
          "squashfs fragment index {fragment_idx} is out of bounds"
        ))
      })?;

      if fragment.size == 0 {
        return Ok(Vec::new());
      }

      let fragment_data = self
        .source
        .read_bytes_at(fragment.start_block, fragment.size as usize)?;

      let (data, _is_compressed) = self.decompress_block_if_needed(&fragment_data, u64::MAX);

      let start = fragment_offset as usize;
      let remaining = file_size.saturating_sub(block_index * u64::from(block_size)) as usize;
      let end = (start + remaining).min(data.len());

      return Ok(data[start..end].to_vec());
    }

    Err(Error::invalid_format(format!(
      "squashfs block index {block_index} is out of bounds"
    )))
  }

  pub(crate) fn block_size(&self) -> u32 {
    self.superblock.block_size
  }

  #[allow(dead_code)]
  pub(crate) fn compression(&self) -> u16 {
    self.superblock.compression
  }

  fn decompress_block_if_needed(&self, data: &[u8], max_output: u64) -> (Vec<u8>, bool) {
    if data.is_empty() {
      return (Vec::new(), false);
    }
    match self.superblock.compression {
      ZLIB_COMPRESSION => (
        Self::decompress_zlib(data).unwrap_or_else(|_| data.to_vec()),
        true,
      ),
      XZ_COMPRESSION => (
        Self::decompress_xz(data).unwrap_or_else(|_| data.to_vec()),
        true,
      ),
      ZSTD_COMPRESSION => (
        Self::decompress_zstd(data).unwrap_or_else(|_| data.to_vec()),
        true,
      ),
      _ => {
        let _ = max_output;
        (data.to_vec(), false)
      }
    }
  }

  fn decompress_block(&self, data: &[u8], _max_output: u64) -> Result<Vec<u8>> {
    if data.is_empty() {
      return Ok(Vec::new());
    }
    match self.superblock.compression {
      ZLIB_COMPRESSION => Self::decompress_zlib(data),
      XZ_COMPRESSION => Self::decompress_xz(data),
      ZSTD_COMPRESSION => Self::decompress_zstd(data),
      compression => Err(Error::unsupported(format!(
        "unsupported squashfs compression: {compression}"
      ))),
    }
  }

  fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
  }

  fn decompress_xz(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut decoder = xz2::read::XzDecoder::new(data);
    decoder.read_to_end(&mut output)?;
    Ok(output)
  }

  fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut decoder = zstd::Decoder::new(data)?;
    decoder.read_to_end(&mut output)?;
    Ok(output)
  }
}

pub(crate) struct SquashFsFileDataSource {
  reader: Arc<SquashFsDataReader>,
  block_sizes: Arc<[u32]>,
  fragment_blocks: Arc<[super::superblock::SquashFsFragmentEntry]>,
  file_size: u64,
  start_block: u64,
  fragment_idx: u32,
  fragment_offset: u32,
}

impl SquashFsFileDataSource {
  pub(crate) fn new(
    reader: Arc<SquashFsDataReader>, block_sizes: Arc<[u32]>,
    fragment_blocks: Arc<[super::superblock::SquashFsFragmentEntry]>, file_size: u64,
    start_block: u64, fragment_idx: u32, fragment_offset: u32,
  ) -> Self {
    Self {
      reader,
      block_sizes,
      fragment_blocks,
      file_size,
      start_block,
      fragment_idx,
      fragment_offset,
    }
  }
}

impl ByteSource for SquashFsFileDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let block_size = u64::from(self.reader.block_size());
    let remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;

    while written < remaining {
      let block_index = (file_offset / block_size) as usize;
      let block_offset = (file_offset % block_size) as usize;

      let data = self.reader.read_file_block(
        block_index as u64,
        self.start_block,
        self.reader.block_size(),
        &self.block_sizes,
        self.file_size,
        self.fragment_idx,
        self.fragment_offset,
        &self.fragment_blocks,
      )?;

      let step = remaining
        .saturating_sub(written)
        .min(data.len().saturating_sub(block_offset));
      if step == 0 {
        break;
      }

      buf[written..written + step].copy_from_slice(&data[block_offset..block_offset + step]);
      written += step;
      file_offset += step as u64;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.file_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.reader.source.capabilities()
  }
}
