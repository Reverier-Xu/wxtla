//! PDI sparse extent parsing.

use std::sync::Arc;

use crate::{ByteSourceHandle, Error, Result};

const SIGNATURE1: &[u8; 16] = b"WithoutFreeSpace";
const SIGNATURE2: &[u8; 16] = b"WithouFreSpacExt";
const HEADER_SIZE: usize = 64;
const BAT_ENTRY_SIZE: usize = 4;
const SECTOR_SIZE: u64 = 512;

#[derive(Clone)]
pub struct PdiSparseExtent {
  source: ByteSourceHandle,
  pub block_size: u64,
  pub extent_size: u64,
  bat: Arc<[u32]>,
}

impl PdiSparseExtent {
  pub fn open(
    source: ByteSourceHandle, extent_sector_count: u64, expected_block_size_sectors: u32,
  ) -> Result<Self> {
    let header = source.read_bytes_at(0, HEADER_SIZE)?;
    if &header[0..16] != SIGNATURE1 && &header[0..16] != SIGNATURE2 {
      return Err(Error::invalid_format(
        "pdi sparse extent header signature is missing".to_string(),
      ));
    }

    let format_version = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    if format_version != 2 {
      return Err(Error::invalid_format(format!(
        "unsupported pdi sparse extent format version: {format_version}"
      )));
    }

    let sectors_per_block = u32::from_le_bytes([header[28], header[29], header[30], header[31]]);
    if sectors_per_block == 0 {
      return Err(Error::invalid_format(
        "pdi sparse extent sectors-per-block must be non-zero".to_string(),
      ));
    }
    if expected_block_size_sectors != 0 && sectors_per_block != expected_block_size_sectors {
      return Err(Error::invalid_format(
        "pdi sparse extent block size does not match the descriptor".to_string(),
      ));
    }

    let number_of_blocks = u32::from_le_bytes([header[32], header[33], header[34], header[35]]);
    let number_of_sectors = u64::from_le_bytes([
      header[36], header[37], header[38], header[39], header[40], header[41], header[42],
      header[43],
    ]);
    if number_of_sectors != extent_sector_count {
      return Err(Error::invalid_format(
        "pdi sparse extent sector count does not match the descriptor extent".to_string(),
      ));
    }

    let data_start_sector = u32::from_le_bytes([header[48], header[49], header[50], header[51]]);
    let block_size = u64::from(sectors_per_block)
      .checked_mul(SECTOR_SIZE)
      .ok_or_else(|| Error::invalid_range("pdi sparse block size overflow"))?;
    let extent_size = extent_sector_count
      .checked_mul(SECTOR_SIZE)
      .ok_or_else(|| Error::invalid_range("pdi sparse extent size overflow"))?;

    let number_of_blocks_usize = usize::try_from(number_of_blocks)
      .map_err(|_| Error::invalid_range("pdi sparse BAT entry count is too large"))?;
    let bat_size = number_of_blocks_usize
      .checked_mul(BAT_ENTRY_SIZE)
      .ok_or_else(|| Error::invalid_range("pdi sparse BAT size overflow"))?;
    let bat_data = source.read_bytes_at(HEADER_SIZE as u64, bat_size)?;
    let bat = bat_data
      .chunks_exact(4)
      .map(|chunk| Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
      .collect::<Result<Vec<_>>>()?;

    let source_size = source.size()?;
    let bat_end = (HEADER_SIZE as u64)
      .checked_add(u64::try_from(bat_size).unwrap_or(u64::MAX))
      .ok_or_else(|| Error::invalid_range("pdi sparse BAT end overflow"))?;
    let data_start_offset = u64::from(data_start_sector)
      .checked_mul(SECTOR_SIZE)
      .ok_or_else(|| Error::invalid_range("pdi sparse data start overflow"))?;
    if data_start_offset < bat_end {
      return Err(Error::invalid_format(
        "pdi sparse extent data area overlaps the BAT".to_string(),
      ));
    }
    if source_size < data_start_offset {
      return Err(Error::invalid_format(
        "pdi sparse extent data area starts beyond the file size".to_string(),
      ));
    }

    let required_blocks = extent_sector_count.div_ceil(u64::from(sectors_per_block));
    if u64::from(number_of_blocks) < required_blocks {
      return Err(Error::invalid_format(
        "pdi sparse BAT does not contain enough block entries".to_string(),
      ));
    }

    for sector_number in &bat {
      if *sector_number == 0 {
        continue;
      }
      if *sector_number < data_start_sector {
        return Err(Error::invalid_format(
          "pdi sparse block points before the data area".to_string(),
        ));
      }
      let data_offset = u64::from(*sector_number)
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| Error::invalid_range("pdi sparse block offset overflow"))?;
      let data_end = data_offset
        .checked_add(block_size)
        .ok_or_else(|| Error::invalid_range("pdi sparse block end overflow"))?;
      if data_end > source_size {
        return Err(Error::invalid_format(
          "pdi sparse block exceeds the extent file size".to_string(),
        ));
      }
    }

    Ok(Self {
      source,
      block_size,
      extent_size,
      bat: Arc::from(bat),
    })
  }

  pub fn read_present_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.extent_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::invalid_range("pdi sparse read offset overflow"))?;
      if absolute_offset >= self.extent_size {
        break;
      }

      let block_index = usize::try_from(absolute_offset / self.block_size)
        .map_err(|_| Error::invalid_range("pdi sparse block index is too large"))?;
      let within_block = absolute_offset % self.block_size;
      let available = usize::try_from(
        (self.block_size - within_block)
          .min(self.extent_size - absolute_offset)
          .min((buf.len() - copied) as u64),
      )
      .map_err(|_| Error::invalid_range("pdi sparse read size is too large"))?;

      let sector_number = *self
        .bat
        .get(block_index)
        .ok_or_else(|| Error::invalid_format("pdi sparse BAT is missing a block entry"))?;
      if sector_number == 0 {
        break;
      }

      let data_offset = u64::from(sector_number)
        .checked_mul(SECTOR_SIZE)
        .and_then(|value| value.checked_add(within_block))
        .ok_or_else(|| Error::invalid_range("pdi sparse block data offset overflow"))?;
      self
        .source
        .read_exact_at(data_offset, &mut buf[copied..copied + available])?;
      copied += available;
    }

    Ok(copied)
  }

  #[cfg(test)]
  pub fn is_allocated(&self, offset: u64) -> Result<bool> {
    if offset >= self.extent_size {
      return Ok(false);
    }

    let block_index = usize::try_from(offset / self.block_size)
      .map_err(|_| Error::invalid_range("pdi sparse block index is too large"))?;
    Ok(self.bat.get(block_index).copied().unwrap_or(0) != 0)
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::ByteSource;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl ByteSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = usize::try_from(offset)
        .map_err(|_| Error::invalid_range("test read offset is too large"))?;
      if offset >= self.data.len() {
        return Ok(0);
      }
      let read = buf.len().min(self.data.len() - offset);
      buf[..read].copy_from_slice(&self.data[offset..offset + read]);
      Ok(read)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.data.len() as u64)
    }
  }

  fn synthetic_sparse_extent() -> Vec<u8> {
    let mut data = vec![0u8; 1536];
    data[0..16].copy_from_slice(SIGNATURE1);
    data[16..20].copy_from_slice(&2u32.to_le_bytes());
    data[28..32].copy_from_slice(&1u32.to_le_bytes());
    data[32..36].copy_from_slice(&2u32.to_le_bytes());
    data[36..44].copy_from_slice(&2u64.to_le_bytes());
    data[48..52].copy_from_slice(&1u32.to_le_bytes());
    data[64..68].copy_from_slice(&1u32.to_le_bytes());
    data[68..72].copy_from_slice(&0u32.to_le_bytes());
    data[512..1024].fill(0xA5);
    data
  }

  #[test]
  fn parses_sparse_extent_and_reads_allocated_blocks() {
    let extent = PdiSparseExtent::open(
      Arc::new(MemDataSource {
        data: synthetic_sparse_extent(),
      }) as ByteSourceHandle,
      2,
      1,
    )
    .unwrap();
    let mut buf = vec![0u8; 512];

    assert!(extent.is_allocated(0).unwrap());
    assert!(!extent.is_allocated(512).unwrap());
    assert_eq!(extent.read_present_bytes(0, &mut buf).unwrap(), 512);
    assert_eq!(buf, vec![0xA5; 512]);
  }
}
