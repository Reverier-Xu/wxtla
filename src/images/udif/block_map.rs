//! UDIF block table parsing.

use std::io::Cursor;

use plist::Value;

use super::trailer::UdifTrailer;
use crate::{Error, Result};

pub(super) const SECTOR_SIZE: u64 = 512;
const BLOCK_TABLE_MAGIC: &[u8; 4] = b"mish";
const BLOCK_TABLE_HEADER_SIZE: usize = 204;
const BLOCK_RUN_SIZE: usize = 40;
const MAX_PLIST_SIZE: usize = 16 * 1024 * 1024;

const BLOCK_TYPE_ZERO_FILL: u32 = 0x0000_0000;
const BLOCK_TYPE_RAW: u32 = 0x0000_0001;
const BLOCK_TYPE_IGNORE: u32 = 0x0000_0002;
const BLOCK_TYPE_COMMENT: u32 = 0x7FFF_FFFE;
const BLOCK_TYPE_ADC: u32 = 0x8000_0004;
const BLOCK_TYPE_ZLIB: u32 = 0x8000_0005;
const BLOCK_TYPE_BZIP2: u32 = 0x8000_0006;
const BLOCK_TYPE_LZFSE: u32 = 0x8000_0007;
const BLOCK_TYPE_LZMA: u32 = 0x8000_0008;
const BLOCK_TYPE_END: u32 = 0xFFFF_FFFF;

/// Primary compression method observed in a UDIF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdifCompressionMethod {
  None,
  Adc,
  Zlib,
  Bzip2,
  Lzfse,
  Lzma,
  Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UdifRangeKind {
  Raw,
  Sparse,
  Adc,
  Zlib,
  Bzip2,
  Lzfse,
  Lzma,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UdifRange {
  pub media_offset: u64,
  pub size: u64,
  pub data_offset: u64,
  pub data_size: u64,
  pub kind: UdifRangeKind,
}

#[derive(Debug)]
pub(super) struct ParsedBlockMaps {
  pub ranges: Vec<UdifRange>,
  pub compression_method: UdifCompressionMethod,
  pub has_sparse_ranges: bool,
  pub table_checksums: Vec<u32>,
}

#[derive(Debug)]
struct UdifBlockTableHeader {
  start_sector: u64,
  sector_count: u64,
  checksum: [u8; 128],
  entry_count: u32,
}

#[derive(Debug)]
struct UdifBlockRun {
  entry_type: u32,
  start_sector: u64,
  sector_count: u64,
  data_offset: u64,
  data_size: u64,
}

pub(super) fn parse_block_maps(
  plist_data: &[u8], trailer: &UdifTrailer, image_size: u64, source_size: u64,
) -> Result<ParsedBlockMaps> {
  if plist_data.is_empty() || plist_data.len() > MAX_PLIST_SIZE {
    return Err(Error::InvalidFormat(format!(
      "unsupported udif plist size: {}",
      plist_data.len()
    )));
  }

  let plist = Value::from_reader_xml(Cursor::new(plist_data))
    .map_err(|error| Error::InvalidFormat(format!("unable to parse udif plist: {error}")))?;
  let root = plist
    .as_dictionary()
    .ok_or_else(|| Error::InvalidFormat("udif plist root must be a dictionary".to_string()))?;
  let resource_fork = root
    .get("resource-fork")
    .and_then(Value::as_dictionary)
    .ok_or_else(|| Error::InvalidFormat("udif plist is missing resource-fork".to_string()))?;
  let blkx = resource_fork
    .get("blkx")
    .and_then(Value::as_array)
    .ok_or_else(|| Error::InvalidFormat("udif plist is missing the blkx array".to_string()))?;

  let mut ranges = Vec::new();
  let mut compression_kinds = Vec::new();
  let mut has_sparse_ranges = false;
  let mut table_checksums = Vec::with_capacity(blkx.len());

  for entry in blkx {
    let entry_dict = entry
      .as_dictionary()
      .ok_or_else(|| Error::InvalidFormat("udif blkx entry must be a dictionary".to_string()))?;
    let data = entry_dict
      .get("Data")
      .and_then(Value::as_data)
      .ok_or_else(|| Error::InvalidFormat("udif blkx entry is missing Data".to_string()))?;
    let header = UdifBlockTableHeader::from_bytes(data)?;
    table_checksums.push(u32::from_be_bytes([
      header.checksum[0],
      header.checksum[1],
      header.checksum[2],
      header.checksum[3],
    ]));

    let mut offset = BLOCK_TABLE_HEADER_SIZE;
    for _ in 0..header.entry_count {
      let run_end = offset
        .checked_add(BLOCK_RUN_SIZE)
        .ok_or_else(|| Error::InvalidRange("udif block run end overflow".to_string()))?;
      let run = UdifBlockRun::from_bytes(
        data
          .get(offset..run_end)
          .ok_or_else(|| Error::InvalidFormat("udif block table is truncated".to_string()))?,
      )?;
      offset = run_end;

      if run.entry_type == BLOCK_TYPE_END {
        break;
      }
      if run.entry_type == BLOCK_TYPE_COMMENT {
        continue;
      }

      if run.sector_count == 0 {
        return Err(Error::InvalidFormat(
          "udif block runs must contain at least one sector".to_string(),
        ));
      }

      let start_sector = header
        .start_sector
        .checked_add(run.start_sector)
        .ok_or_else(|| Error::InvalidRange("udif media sector overflow".to_string()))?;
      let media_offset = start_sector
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| Error::InvalidRange("udif media offset overflow".to_string()))?;
      let size = run
        .sector_count
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| Error::InvalidRange("udif range size overflow".to_string()))?;
      let media_end = media_offset
        .checked_add(size)
        .ok_or_else(|| Error::InvalidRange("udif media end overflow".to_string()))?;
      if media_end > image_size {
        return Err(Error::InvalidFormat(
          "udif block run exceeds the declared media size".to_string(),
        ));
      }

      let kind = match run.entry_type {
        BLOCK_TYPE_ZERO_FILL | BLOCK_TYPE_IGNORE => {
          has_sparse_ranges = true;
          UdifRangeKind::Sparse
        }
        BLOCK_TYPE_RAW => UdifRangeKind::Raw,
        BLOCK_TYPE_ADC => {
          compression_kinds.push(UdifCompressionMethod::Adc);
          UdifRangeKind::Adc
        }
        BLOCK_TYPE_ZLIB => {
          compression_kinds.push(UdifCompressionMethod::Zlib);
          UdifRangeKind::Zlib
        }
        BLOCK_TYPE_BZIP2 => {
          compression_kinds.push(UdifCompressionMethod::Bzip2);
          UdifRangeKind::Bzip2
        }
        BLOCK_TYPE_LZFSE => {
          compression_kinds.push(UdifCompressionMethod::Lzfse);
          UdifRangeKind::Lzfse
        }
        BLOCK_TYPE_LZMA => {
          compression_kinds.push(UdifCompressionMethod::Lzma);
          UdifRangeKind::Lzma
        }
        other => {
          return Err(Error::InvalidFormat(format!(
            "unsupported udif block type: 0x{other:08x}"
          )));
        }
      };

      if !matches!(kind, UdifRangeKind::Sparse) {
        let data_fork_end = trailer
          .data_fork_offset
          .checked_add(trailer.data_fork_size)
          .ok_or_else(|| Error::InvalidRange("udif data fork end overflow".to_string()))?;
        if run.data_offset < trailer.data_fork_offset || run.data_offset > source_size {
          return Err(Error::InvalidFormat(
            "udif block run data offset is out of bounds".to_string(),
          ));
        }
        let data_end = run
          .data_offset
          .checked_add(run.data_size)
          .ok_or_else(|| Error::InvalidRange("udif range data end overflow".to_string()))?;
        if data_end > data_fork_end || data_end > source_size {
          return Err(Error::InvalidFormat(
            "udif block run data payload exceeds the data fork".to_string(),
          ));
        }
      }

      ranges.push(UdifRange {
        media_offset,
        size,
        data_offset: run.data_offset,
        data_size: run.data_size,
        kind,
      });
    }

    let covered_sectors = ranges
      .iter()
      .filter(|range| {
        range.media_offset / SECTOR_SIZE >= header.start_sector
          && range.media_offset / SECTOR_SIZE < header.start_sector + header.sector_count
      })
      .map(|range| range.size / SECTOR_SIZE)
      .sum::<u64>();
    if covered_sectors > header.sector_count {
      return Err(Error::InvalidFormat(
        "udif block table covers more sectors than its header declares".to_string(),
      ));
    }
  }

  ranges.sort_by_key(|range| range.media_offset);
  let mut previous_end = 0u64;
  for range in &ranges {
    if range.media_offset < previous_end {
      return Err(Error::InvalidFormat(
        "udif block runs overlap in guest media space".to_string(),
      ));
    }
    previous_end = range
      .media_offset
      .checked_add(range.size)
      .ok_or_else(|| Error::InvalidRange("udif range end overflow".to_string()))?;
  }

  let compression_method = if compression_kinds.is_empty() {
    UdifCompressionMethod::None
  } else if compression_kinds
    .iter()
    .all(|kind| *kind == compression_kinds[0])
  {
    compression_kinds[0]
  } else {
    UdifCompressionMethod::Mixed
  };

  Ok(ParsedBlockMaps {
    ranges,
    compression_method,
    has_sparse_ranges,
    table_checksums,
  })
}

impl UdifBlockTableHeader {
  fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < BLOCK_TABLE_HEADER_SIZE {
      return Err(Error::InvalidFormat(
        "udif block table header is truncated".to_string(),
      ));
    }
    if &data[0..4] != BLOCK_TABLE_MAGIC {
      return Err(Error::InvalidFormat(
        "udif block table signature is missing".to_string(),
      ));
    }

    let _version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    Ok(Self {
      start_sector: u64::from_be_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
      ]),
      sector_count: u64::from_be_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
      ]),
      checksum: data[72..200].try_into().map_err(|_| {
        Error::InvalidFormat("udif block table checksum length mismatch".to_string())
      })?,
      entry_count: u32::from_be_bytes([data[200], data[201], data[202], data[203]]),
    })
  }
}

impl UdifBlockRun {
  fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != BLOCK_RUN_SIZE {
      return Err(Error::InvalidFormat(
        "udif block run has an unexpected size".to_string(),
      ));
    }

    Ok(Self {
      entry_type: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
      start_sector: u64::from_be_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
      ]),
      sector_count: u64::from_be_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
      ]),
      data_offset: u64::from_be_bytes([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
      ]),
      data_size: u64::from_be_bytes([
        data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
      ]),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn accepts_newer_block_table_versions() {
    let mut data = vec![0u8; BLOCK_TABLE_HEADER_SIZE];
    data[0..4].copy_from_slice(BLOCK_TABLE_MAGIC);
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[16..24].copy_from_slice(&8u64.to_be_bytes());
    data[200..204].copy_from_slice(&1u32.to_be_bytes());

    let header = UdifBlockTableHeader::from_bytes(&data).unwrap();

    assert_eq!(header.sector_count, 8);
    assert_eq!(header.entry_count, 1);
  }
}
