//! Parsing of VHD fixed and dynamic metadata.

use super::{
  dynamic_header::VhdDynamicHeader,
  footer::{VhdDiskType, VhdFooter},
};
use crate::{ByteSource, ByteSourceHandle, Error, Result};

pub struct ParsedVhd {
  pub footer: VhdFooter,
  pub dynamic_header: Option<VhdDynamicHeader>,
  pub block_allocation_table: VhdBatLayout,
  pub parent_locator_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VhdBatLayout {
  pub file_offset: u64,
  pub entry_count: u32,
}

pub fn parse(source: ByteSourceHandle) -> Result<ParsedVhd> {
  let footer = VhdFooter::read(source.as_ref())?;
  match footer.disk_type {
    VhdDiskType::Fixed => Ok(ParsedVhd {
      footer,
      dynamic_header: None,
      block_allocation_table: VhdBatLayout::default(),
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
  source: &dyn ByteSource, header: &VhdDynamicHeader,
) -> Result<Vec<String>> {
  let mut paths = Vec::new();
  for locator in &header.parent_locators {
    if locator.data_size == 0 {
      continue;
    }
    let data = source.read_bytes_at(
      locator.data_offset,
      usize::try_from(locator.data_size)
        .map_err(|_| Error::invalid_range("vhd parent locator size is too large"))?,
    )?;
    if locator.platform_code == *b"W2ku" || locator.platform_code == *b"W2ru" {
      paths.push(decode_utf16_le_string(&data)?);
    }
  }

  Ok(paths)
}

fn decode_utf16_le_string(data: &[u8]) -> Result<String> {
  if !data.len().is_multiple_of(2) {
    return Err(Error::invalid_format(
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
    .map_err(|_| Error::invalid_format("vhd parent locator string is not valid UTF-16"))
}

fn read_bat(source: &dyn ByteSource, header: &VhdDynamicHeader) -> Result<VhdBatLayout> {
  let entry_count = usize::try_from(header.block_count)
    .map_err(|_| Error::invalid_range("vhd BAT entry count is too large"))?;
  let table_bytes = entry_count
    .checked_mul(4)
    .ok_or_else(|| Error::invalid_range("vhd BAT size overflow"))?;
  let table_end = header
    .block_allocation_table_offset
    .checked_add(
      u64::try_from(table_bytes)
        .map_err(|_| Error::invalid_range("vhd BAT size does not fit in a file offset"))?,
    )
    .ok_or_else(|| Error::invalid_range("vhd BAT end overflow"))?;
  if table_end > source.size()? {
    return Err(Error::invalid_format(
      "vhd BAT exceeds the source size".to_string(),
    ));
  }

  Ok(VhdBatLayout {
    file_offset: header.block_allocation_table_offset,
    entry_count: header.block_count,
  })
}
