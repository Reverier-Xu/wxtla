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
  pub parent_locator_paths: Vec<String>,
}

pub fn parse(source: DataSourceHandle) -> Result<ParsedVhd> {
  let footer = VhdFooter::read(source.as_ref())?;
  match footer.disk_type {
    VhdDiskType::Fixed => Ok(ParsedVhd {
      footer,
      dynamic_header: None,
      block_allocation_table: Arc::from(Vec::<u32>::new()),
      parent_locator_paths: Vec::new(),
    }),
    VhdDiskType::Dynamic | VhdDiskType::Differential => {
      let dynamic_header = VhdDynamicHeader::read(source.as_ref(), footer.data_offset)?;
      let parent_locator_paths = read_parent_locator_paths(source.as_ref(), &dynamic_header)?;
      let bat = read_bat(source.as_ref(), &dynamic_header)?;
      Ok(ParsedVhd {
        footer,
        dynamic_header: Some(dynamic_header),
        block_allocation_table: bat,
        parent_locator_paths,
      })
    }
  }
}

fn read_parent_locator_paths(
  source: &dyn DataSource, header: &VhdDynamicHeader,
) -> Result<Vec<String>> {
  let mut paths = Vec::new();
  for locator in &header.parent_locators {
    if locator.data_size == 0 {
      continue;
    }
    let data = source.read_bytes_at(
      locator.data_offset,
      usize::try_from(locator.data_size)
        .map_err(|_| Error::InvalidRange("vhd parent locator size is too large".to_string()))?,
    )?;
    if locator.platform_code == *b"W2ku" || locator.platform_code == *b"W2ru" {
      paths.push(decode_utf16_le_string(&data)?);
    }
  }

  Ok(paths)
}

fn decode_utf16_le_string(data: &[u8]) -> Result<String> {
  if !data.len().is_multiple_of(2) {
    return Err(Error::InvalidFormat(
      "vhd parent locator string has an odd byte count".to_string(),
    ));
  }
  let mut code_units = Vec::with_capacity(data.len() / 2);
  for chunk in data.chunks_exact(2) {
    let code_unit = u16::from_le_bytes([chunk[0], chunk[1]]);
    if code_unit == 0 {
      break;
    }
    code_units.push(code_unit);
  }

  String::from_utf16(&code_units)
    .map_err(|_| Error::InvalidFormat("vhd parent locator string is not valid UTF-16".to_string()))
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
