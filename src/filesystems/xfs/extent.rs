use super::io::{be_u64, read_slice};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub(crate) struct XfsExtent {
  pub(crate) logical_block: u64,
  pub(crate) physical_block: u64,
  pub(crate) number_of_blocks: u64,
  pub(crate) is_sparse: bool,
}

pub(crate) fn parse_extent_records(data: &[u8], nrecs: usize) -> Result<Vec<XfsExtent>> {
  let mut extents = Vec::with_capacity(nrecs);
  for index in 0..nrecs {
    extents.push(parse_extent_record(read_slice(data, index * 16, 16)?));
  }
  Ok(extents)
}

pub(crate) fn parse_extent_record(data: &[u8]) -> XfsExtent {
  let mut upper = be_u64(&data[0..8]);
  let mut lower = be_u64(&data[8..16]);

  let number_of_blocks = lower & 0x001F_FFFF;
  lower >>= 21;
  let physical_block = lower | (upper & 0x1FF);
  upper >>= 9;
  let logical_block = upper & 0x003F_FFFF_FFFF_FFFF;
  upper >>= 54;

  XfsExtent {
    logical_block,
    physical_block,
    number_of_blocks,
    is_sparse: upper != 0,
  }
}

pub(crate) fn normalize_sparse_extents(
  mut extents: Vec<XfsExtent>, block_size: u64, file_size: u64,
) -> Result<Vec<XfsExtent>> {
  extents.sort_by_key(|extent| extent.logical_block);

  let mut normalized = Vec::new();
  let mut cursor = 0u64;
  let mut total_blocks = file_size / block_size;
  if !file_size.is_multiple_of(block_size) {
    total_blocks += 1;
  }

  for extent in extents {
    if extent.number_of_blocks == 0 {
      continue;
    }
    if extent.logical_block < cursor {
      return Err(Error::InvalidFormat(
        "overlapping xfs extents are not supported".to_string(),
      ));
    }
    if extent.logical_block > cursor {
      normalized.push(XfsExtent {
        logical_block: cursor,
        physical_block: 0,
        number_of_blocks: extent.logical_block - cursor,
        is_sparse: true,
      });
    }
    cursor = extent
      .logical_block
      .checked_add(extent.number_of_blocks)
      .ok_or_else(|| Error::InvalidRange("xfs extent logical range overflow".to_string()))?;
    normalized.push(extent);
  }

  if cursor < total_blocks {
    normalized.push(XfsExtent {
      logical_block: cursor,
      physical_block: 0,
      number_of_blocks: total_blocks - cursor,
      is_sparse: true,
    });
  }

  Ok(normalized)
}
