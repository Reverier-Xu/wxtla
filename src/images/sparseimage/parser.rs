//! Sparseimage metadata parsing.

use std::sync::Arc;

use super::header::{HEADER_BLOCK_SIZE, SparseImageHeader};
use crate::{DataSourceHandle, Error, Result};

pub(super) struct ParsedSparseImage {
  pub header: SparseImageHeader,
  pub media_size: u64,
  pub band_size: u64,
  pub guest_to_file_offsets: Arc<[Option<u64>]>,
  pub has_sparse_bands: bool,
}

pub(super) fn parse(source: DataSourceHandle) -> Result<ParsedSparseImage> {
  let source_size = source.size()?;
  let (header, header_block) = SparseImageHeader::read(source.as_ref())?;
  let media_size = header.media_size()?;
  let band_size = header.band_size()?;
  let band_count = usize::try_from(header.band_count())
    .map_err(|_| Error::InvalidRange("sparseimage band count is too large".to_string()))?;
  let array_bytes = band_count
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("sparseimage band array size overflow".to_string()))?;
  let array_end = 64usize
    .checked_add(array_bytes)
    .ok_or_else(|| Error::InvalidRange("sparseimage band array end overflow".to_string()))?;
  if array_end > HEADER_BLOCK_SIZE {
    return Err(Error::InvalidFormat(
      "sparseimage band array does not fit in the header block".to_string(),
    ));
  }
  if header_block[array_end..].iter().any(|&byte| byte != 0) {
    return Err(Error::InvalidFormat(
      "sparseimage header padding must be zero".to_string(),
    ));
  }

  let mut guest_to_file_offsets = vec![None; band_count];
  let mut has_sparse_bands = false;
  for array_index in 0..band_count {
    let start = 64 + array_index * 4;
    let band_number = u32::from_be_bytes([
      header_block[start],
      header_block[start + 1],
      header_block[start + 2],
      header_block[start + 3],
    ]);
    if band_number == 0 {
      has_sparse_bands = true;
      continue;
    }

    let guest_index = usize::try_from(band_number - 1)
      .map_err(|_| Error::InvalidRange("sparseimage band index is too large".to_string()))?;
    if guest_index >= band_count {
      return Err(Error::InvalidFormat(
        "sparseimage band number is out of bounds".to_string(),
      ));
    }
    if guest_to_file_offsets[guest_index].is_some() {
      return Err(Error::InvalidFormat(
        "sparseimage band numbers must be unique".to_string(),
      ));
    }

    let file_offset = (HEADER_BLOCK_SIZE as u64)
      .checked_add(
        u64::try_from(array_index)
          .map_err(|_| Error::InvalidRange("sparseimage file band index is too large".to_string()))?
          .checked_mul(band_size)
          .ok_or_else(|| {
            Error::InvalidRange("sparseimage band file offset overflow".to_string())
          })?,
      )
      .ok_or_else(|| Error::InvalidRange("sparseimage band file offset overflow".to_string()))?;
    let band_end = file_offset
      .checked_add(band_size)
      .ok_or_else(|| Error::InvalidRange("sparseimage band end overflow".to_string()))?;
    if band_end > source_size {
      return Err(Error::InvalidFormat(
        "sparseimage band data exceeds the source size".to_string(),
      ));
    }

    guest_to_file_offsets[guest_index] = Some(file_offset);
  }

  Ok(ParsedSparseImage {
    header,
    media_size,
    band_size,
    guest_to_file_offsets: Arc::from(guest_to_file_offsets),
    has_sparse_bands,
  })
}
