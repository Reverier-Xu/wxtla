//! Parsing of VHD fixed and dynamic metadata.

use std::sync::Arc;

use super::{
  dynamic_header::VhdDynamicHeader,
  footer::{VhdDiskType, VhdFooter},
};
use crate::{DataSource, DataSourceHandle, Error, Result};

pub struct ParsedVhd {
  pub footer: VhdFooter,
  pub dynamic_header: Option<VhdDynamicHeader>,
  pub block_allocation_table: Arc<[u32]>,
}

pub fn parse(source: DataSourceHandle) -> Result<ParsedVhd> {
  let footer = VhdFooter::read(source.as_ref())?;
  match footer.disk_type {
    VhdDiskType::Fixed => Ok(ParsedVhd {
      footer,
      dynamic_header: None,
      block_allocation_table: Arc::from(Vec::<u32>::new()),
    }),
    VhdDiskType::Dynamic | VhdDiskType::Differential => {
      let dynamic_header = VhdDynamicHeader::read(source.as_ref(), footer.data_offset)?;
      let bat = read_bat(source.as_ref(), &dynamic_header)?;
      Ok(ParsedVhd {
        footer,
        dynamic_header: Some(dynamic_header),
        block_allocation_table: bat,
      })
    }
  }
}

fn read_bat(source: &dyn DataSource, header: &VhdDynamicHeader) -> Result<Arc<[u32]>> {
  let entry_count = usize::try_from(header.block_count)
    .map_err(|_| Error::InvalidRange("vhd BAT entry count is too large".to_string()))?;
  let table_bytes = entry_count
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("vhd BAT size overflow".to_string()))?;
  let raw = source.read_bytes_at(header.block_allocation_table_offset, table_bytes)?;
  let entries = raw
    .chunks_exact(4)
    .map(|chunk| Ok(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
    .collect::<Result<Vec<_>>>()?;

  Ok(Arc::from(entries))
}
