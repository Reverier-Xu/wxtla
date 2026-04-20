use std::{
  collections::HashMap,
  io::Read,
  sync::{Arc, Mutex},
};

use flate2::read::ZlibDecoder;
use lzfse::decode_buffer;

use super::crypto::ApfsXtsCipher;
use crate::{ByteSource, ByteSourceCapabilities, ByteSourceHandle, Error, Result};

pub(super) const XATTR_DECMPFS_NAME: &str = "com.apple.decmpfs";
pub(super) const DECMPFS_MAGIC: &[u8; 4] = b"fpmc";
pub(super) const DECMPFS_BLOCK_SIZE: u64 = 65_536;

pub(super) const DECMPFS_ZLIB_ATTR: u32 = 3;
pub(super) const DECMPFS_ZLIB_RSRC: u32 = 4;
pub(super) const DECMPFS_SPARSE_ATTR: u32 = 5;
pub(super) const DECMPFS_LZVN_ATTR: u32 = 7;
pub(super) const DECMPFS_LZVN_RSRC: u32 = 8;
pub(super) const DECMPFS_PLAIN_ATTR: u32 = 9;
pub(super) const DECMPFS_PLAIN_RSRC: u32 = 10;
pub(super) const DECMPFS_LZFSE_ATTR: u32 = 11;
pub(super) const DECMPFS_LZFSE_RSRC: u32 = 12;

#[derive(Clone, Copy)]
pub(super) struct ApfsExtent {
  pub(super) logical_address: u64,
  pub(super) length: u64,
  pub(super) physical_block_number: u64,
  pub(super) crypto_id: u64,
}

pub(super) struct ApfsExtentDataSource {
  pub(super) source: ByteSourceHandle,
  pub(super) block_size: u64,
  pub(super) sectors_per_block: u64,
  pub(super) file_size: u64,
  pub(super) extents: Arc<[ApfsExtent]>,
  pub(super) decryptor: Option<Arc<ApfsXtsCipher>>,
}

pub(super) struct ApfsDecmpfsDataSource {
  pub(super) source: ByteSourceHandle,
  pub(super) algorithm: u32,
  pub(super) file_size: u64,
  pub(super) entries: Arc<[ApfsCompressedEntry]>,
  pub(super) cache: Mutex<HashMap<usize, Arc<[u8]>>>,
}

#[derive(Clone, Copy)]
pub(super) struct ApfsCompressedEntry {
  pub(super) offset: u64,
  pub(super) length: u64,
  pub(super) uncompressed_size: u64,
}

pub(super) struct ApfsDecmpfsHeader {
  pub(super) algorithm: u32,
  pub(super) uncompressed_size: u64,
}

pub(super) fn parse_decmpfs_header(bytes: &[u8]) -> Result<ApfsDecmpfsHeader> {
  if bytes.len() < 16 {
    return Err(Error::invalid_format(
      "apfs decmpfs header is too short".to_string(),
    ));
  }
  let magic = bytes
    .get(0..4)
    .ok_or_else(|| Error::invalid_format("apfs decmpfs header is truncated"))?;
  if magic != DECMPFS_MAGIC {
    return Err(Error::invalid_format(format!(
      "invalid apfs decmpfs magic: {magic:?}"
    )));
  }

  Ok(ApfsDecmpfsHeader {
    algorithm: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
    uncompressed_size: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
  })
}

pub(super) fn parse_compressed_resource_entries(
  source: &dyn ByteSource, algorithm: u32, uncompressed_size: u64,
) -> Result<Vec<ApfsCompressedEntry>> {
  match algorithm {
    DECMPFS_ZLIB_RSRC | DECMPFS_PLAIN_RSRC => {
      let header = source.read_bytes_at(0, 16)?;
      let data_offset = u64::from(u32::from_be_bytes(header[0..4].try_into().unwrap()));
      let metadata = source.read_bytes_at(data_offset, 8)?;
      let block_count = usize::try_from(u32::from_le_bytes(metadata[4..8].try_into().unwrap()))
        .map_err(|_| Error::invalid_range("apfs compressed block count exceeds usize"))?;
      let descriptors = source.read_bytes_at(
        data_offset + 8,
        block_count
          .checked_mul(8)
          .ok_or_else(|| Error::invalid_range("apfs compressed descriptor size overflow"))?,
      )?;
      let mut entries = Vec::with_capacity(block_count);
      for index in 0..block_count {
        let descriptor = &descriptors[index * 8..index * 8 + 8];
        let offset = u64::from(u32::from_le_bytes(descriptor[0..4].try_into().unwrap()));
        let length = u64::from(u32::from_le_bytes(descriptor[4..8].try_into().unwrap()));
        entries.push(ApfsCompressedEntry {
          offset: data_offset + 4 + offset,
          length,
          uncompressed_size: chunk_uncompressed_size(uncompressed_size, index),
        });
      }
      Ok(entries)
    }
    DECMPFS_LZFSE_RSRC => {
      let block_count = usize::try_from(uncompressed_size.div_ceil(DECMPFS_BLOCK_SIZE))
        .map_err(|_| Error::invalid_range("apfs compressed block count exceeds usize"))?;
      let offsets = source.read_bytes_at(
        0,
        (block_count + 1)
          .checked_mul(4)
          .ok_or_else(|| Error::invalid_range("apfs compressed offsets table size overflow"))?,
      )?;
      let mut entries = Vec::with_capacity(block_count);
      for index in 0..block_count {
        let start = u64::from(u32::from_le_bytes(
          offsets[index * 4..index * 4 + 4].try_into().unwrap(),
        ));
        let end = u64::from(u32::from_le_bytes(
          offsets[(index + 1) * 4..(index + 2) * 4]
            .try_into()
            .unwrap(),
        ));
        entries.push(ApfsCompressedEntry {
          offset: start,
          length: end.checked_sub(start).ok_or_else(|| {
            Error::invalid_format("apfs compressed resource offsets are not monotonic")
          })?,
          uncompressed_size: chunk_uncompressed_size(uncompressed_size, index),
        });
      }
      Ok(entries)
    }
    _ => Err(Error::unsupported(format!(
      "unsupported apfs resource compression algorithm: {algorithm}"
    ))),
  }
}

pub(super) fn decode_compressed_chunk(
  algorithm: u32, chunk: &[u8], expected_size: u64,
) -> Result<Vec<u8>> {
  let expected_size = usize::try_from(expected_size)
    .map_err(|_| Error::invalid_range("apfs decompressed chunk is too large"))?;
  let decoded = match algorithm {
    DECMPFS_ZLIB_ATTR | DECMPFS_ZLIB_RSRC => decode_zlib_chunk(chunk)?,
    DECMPFS_SPARSE_ATTR => vec![0; expected_size],
    DECMPFS_PLAIN_ATTR | DECMPFS_PLAIN_RSRC => decode_plain_chunk(chunk)?,
    DECMPFS_LZFSE_ATTR | DECMPFS_LZFSE_RSRC => decode_lzfse_chunk(chunk, expected_size)?,
    _ => {
      return Err(Error::unsupported(format!(
        "unsupported apfs decmpfs algorithm: {algorithm}"
      )));
    }
  };

  if decoded.len() != expected_size {
    return Err(Error::invalid_format(format!(
      "apfs compressed chunk decoded to {} bytes, expected {expected_size}",
      decoded.len()
    )));
  }
  Ok(decoded)
}

fn decode_zlib_chunk(chunk: &[u8]) -> Result<Vec<u8>> {
  let Some(first) = chunk.first().copied() else {
    return Ok(Vec::new());
  };
  if (first & 0x0F) == 0x0F {
    return Ok(chunk[1..].to_vec());
  }

  let mut decoder = ZlibDecoder::new(chunk);
  let mut decoded = Vec::new();
  decoder.read_to_end(&mut decoded)?;
  Ok(decoded)
}

fn decode_plain_chunk(chunk: &[u8]) -> Result<Vec<u8>> {
  let Some(_) = chunk.first() else {
    return Ok(Vec::new());
  };
  Ok(chunk[1..].to_vec())
}

fn decode_lzfse_chunk(chunk: &[u8], expected_size: usize) -> Result<Vec<u8>> {
  let Some(first) = chunk.first().copied() else {
    return Ok(Vec::new());
  };
  if first == 0xFF {
    return Ok(chunk[1..].to_vec());
  }

  let mut decoded = vec![0; expected_size.saturating_add(1)];
  let length = decode_buffer(chunk, &mut decoded)
    .map_err(|error| Error::invalid_format(format!("apfs lzfse decode failed: {error:?}")))?;
  Ok(decoded[..length].to_vec())
}

fn chunk_uncompressed_size(total_size: u64, index: usize) -> u64 {
  let logical_offset = DECMPFS_BLOCK_SIZE.saturating_mul(index as u64);
  (total_size - logical_offset).min(DECMPFS_BLOCK_SIZE)
}

impl ByteSource for ApfsExtentDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let mut remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;

    while remaining > 0 {
      let extent = self
        .extent_for_offset(file_offset)
        .ok_or_else(|| Error::invalid_format("apfs extent is missing for a data stream offset"))?;
      let extent_offset = file_offset - extent.logical_address;
      let step = remaining.min((extent.length - extent_offset) as usize);

      if extent.physical_block_number == 0 {
        buf[written..written + step].fill(0);
      } else {
        if let Some(decryptor) = &self.decryptor {
          let sector_offset = extent_offset / 512;
          let sector_padding = usize::try_from(extent_offset % 512)
            .map_err(|_| Error::invalid_range("apfs encrypted extent offset exceeds usize"))?;
          let cipher_length = super::helpers::align_up_512(
            u64::try_from(sector_padding + step)
              .map_err(|_| Error::invalid_range("apfs encrypted extent length exceeds u64"))?,
          );
          let physical_offset = extent
            .physical_block_number
            .checked_mul(self.block_size)
            .and_then(|base| base.checked_add(sector_offset * 512))
            .ok_or_else(|| Error::invalid_range("apfs physical offset overflow"))?;
          let mut ciphertext = self.source.read_bytes_at(
            physical_offset,
            usize::try_from(cipher_length)
              .map_err(|_| Error::invalid_range("apfs encrypted read length exceeds usize"))?,
          )?;
          decryptor.decrypt(
            extent
              .crypto_id
              .checked_mul(self.sectors_per_block)
              .and_then(|base| base.checked_add(sector_offset))
              .ok_or_else(|| Error::invalid_range("apfs encrypted sector index overflow"))?,
            &mut ciphertext,
          )?;
          buf[written..written + step]
            .copy_from_slice(&ciphertext[sector_padding..sector_padding + step]);
        } else {
          let physical_offset = extent
            .physical_block_number
            .checked_mul(self.block_size)
            .and_then(|base| base.checked_add(extent_offset))
            .ok_or_else(|| Error::invalid_range("apfs physical offset overflow"))?;
          self
            .source
            .read_exact_at(physical_offset, &mut buf[written..written + step])?;
        }
      }

      remaining -= step;
      written += step;
      file_offset += step as u64;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.file_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities()
  }
}

impl ApfsExtentDataSource {
  fn extent_for_offset(&self, offset: u64) -> Option<&ApfsExtent> {
    let index = self
      .extents
      .partition_point(|extent| extent.logical_address <= offset)
      .checked_sub(1)?;
    let extent = self.extents.get(index)?;
    let end = extent.logical_address.checked_add(extent.length)?;
    (offset < end).then_some(extent)
  }
}

impl ByteSource for ApfsDecmpfsDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let mut remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;

    while remaining > 0 {
      let block_index = usize::try_from(file_offset / DECMPFS_BLOCK_SIZE)
        .map_err(|_| Error::invalid_range("apfs compressed block index exceeds usize"))?;
      let block_offset = (file_offset % DECMPFS_BLOCK_SIZE) as usize;
      let chunk = self.decoded_block(block_index)?;
      let step = remaining.min(chunk.len().saturating_sub(block_offset));
      if step == 0 {
        return Err(Error::invalid_format(
          "apfs compressed block mapping is inconsistent".to_string(),
        ));
      }
      buf[written..written + step].copy_from_slice(&chunk[block_offset..block_offset + step]);
      written += step;
      remaining -= step;
      file_offset += step as u64;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.file_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities()
  }
}

impl ApfsDecmpfsDataSource {
  fn decoded_block(&self, index: usize) -> Result<Arc<[u8]>> {
    if let Some(chunk) = self
      .cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&index)
      .cloned()
    {
      return Ok(chunk);
    }

    let entry = self.entries.get(index).copied().ok_or_else(|| {
      Error::not_found(format!(
        "apfs compressed block index {index} is out of bounds"
      ))
    })?;
    let compressed = self.source.read_bytes_at(
      entry.offset,
      usize::try_from(entry.length)
        .map_err(|_| Error::invalid_range("apfs compressed chunk is too large"))?,
    )?;
    let decoded: Arc<[u8]> = Arc::from(
      decode_compressed_chunk(self.algorithm, &compressed, entry.uncompressed_size)?
        .into_boxed_slice(),
    );

    let mut cache = self
      .cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cache.get(&index).cloned() {
      return Ok(existing);
    }
    cache.insert(index, decoded.clone());
    Ok(decoded)
  }
}
