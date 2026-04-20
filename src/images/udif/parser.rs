//! UDIF metadata parsing.

use std::sync::Arc;

use crc32fast::Hasher;

use super::{
  block_map::{ParsedBlockMaps, UdifCompressionMethod, UdifRange, parse_block_maps},
  trailer::{TRAILER_SIZE, UdifTrailer},
};
use crate::{ByteSource, ByteSourceHandle, Error, Result};

pub(super) struct ParsedUdif {
  pub trailer: UdifTrailer,
  pub media_size: u64,
  pub ranges: Arc<[UdifRange]>,
  pub compression_method: UdifCompressionMethod,
  pub has_sparse_ranges: bool,
}

pub(super) fn parse(source: ByteSourceHandle) -> Result<ParsedUdif> {
  let source_size = source.size()?;
  let trailer = UdifTrailer::read(source.as_ref())?;
  validate_trailer_bounds(source_size, &trailer)?;
  verify_data_fork_checksum(source.as_ref(), &trailer)?;

  let media_size = if trailer.sector_count != 0 {
    trailer
      .sector_count
      .checked_mul(super::block_map::SECTOR_SIZE)
      .ok_or_else(|| Error::invalid_range("udif media size overflow"))?
  } else {
    trailer.data_fork_size
  };

  let (ranges, compression_method, has_sparse_ranges) = if trailer.plist_size == 0 {
    let range = UdifRange {
      media_offset: 0,
      size: trailer.data_fork_size,
      data_offset: trailer.data_fork_offset,
      data_size: trailer.data_fork_size,
      kind: super::block_map::UdifRangeKind::Raw,
    };
    (vec![range], UdifCompressionMethod::None, false)
  } else {
    let plist_size = usize::try_from(trailer.plist_size)
      .map_err(|_| Error::invalid_range("udif plist size is too large"))?;
    let plist_data = source.read_bytes_at(trailer.plist_offset, plist_size)?;
    let parsed = parse_block_maps(&plist_data, &trailer, media_size, source_size)?;
    verify_master_checksum(&trailer, &parsed)?;

    (
      parsed.ranges,
      parsed.compression_method,
      parsed.has_sparse_ranges,
    )
  };

  Ok(ParsedUdif {
    trailer,
    media_size,
    ranges: Arc::from(ranges),
    compression_method,
    has_sparse_ranges,
  })
}

fn validate_trailer_bounds(source_size: u64, trailer: &UdifTrailer) -> Result<()> {
  let trailer_offset = source_size
    .checked_sub(TRAILER_SIZE as u64)
    .ok_or_else(|| Error::invalid_range("udif trailer offset underflow"))?;
  let data_fork_end = trailer
    .data_fork_offset
    .checked_add(trailer.data_fork_size)
    .ok_or_else(|| Error::invalid_range("udif data fork end overflow"))?;
  if data_fork_end > source_size {
    return Err(Error::invalid_format(
      "udif data fork exceeds the source size".to_string(),
    ));
  }

  if trailer.plist_size != 0 {
    let plist_end = trailer
      .plist_offset
      .checked_add(trailer.plist_size)
      .ok_or_else(|| Error::invalid_range("udif plist end overflow"))?;
    if plist_end > trailer_offset {
      return Err(Error::invalid_format(
        "udif plist exceeds the trailer boundary".to_string(),
      ));
    }
  }

  Ok(())
}

fn verify_data_fork_checksum(source: &dyn ByteSource, trailer: &UdifTrailer) -> Result<()> {
  let Some(expected_crc32) = trailer.stored_data_crc32() else {
    return Ok(());
  };

  let mut hasher = Hasher::new();
  let mut offset = trailer.data_fork_offset;
  let end = trailer
    .data_fork_offset
    .checked_add(trailer.data_fork_size)
    .ok_or_else(|| Error::invalid_range("udif data fork end overflow"))?;
  while offset < end {
    let remaining = end - offset;
    let chunk = usize::try_from(remaining.min(1024 * 1024))
      .map_err(|_| Error::invalid_range("udif checksum chunk is too large"))?;
    let data = source.read_bytes_at(offset, chunk)?;
    hasher.update(&data);
    offset = offset
      .checked_add(chunk as u64)
      .ok_or_else(|| Error::invalid_range("udif checksum offset overflow"))?;
  }

  let actual = hasher.finalize();
  if actual != expected_crc32 {
    return Err(Error::invalid_format(format!(
      "udif data fork checksum mismatch: 0x{actual:08x} != 0x{expected_crc32:08x}"
    )));
  }

  Ok(())
}

fn verify_master_checksum(trailer: &UdifTrailer, parsed: &ParsedBlockMaps) -> Result<()> {
  let Some(expected_crc32) = trailer.stored_master_crc32() else {
    return Ok(());
  };

  let mut data = Vec::with_capacity(parsed.table_checksums.len() * 4);
  for checksum in &parsed.table_checksums {
    data.extend_from_slice(&checksum.to_be_bytes());
  }
  let actual = crc32fast::hash(&data);
  if actual != expected_crc32 {
    return Err(Error::invalid_format(format!(
      "udif master checksum mismatch: 0x{actual:08x} != 0x{expected_crc32:08x}"
    )));
  }

  Ok(())
}
