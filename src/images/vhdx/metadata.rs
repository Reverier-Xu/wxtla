//! VHDX metadata table parsing.

use std::collections::HashMap;

use super::{constants, guid::VhdxGuid, parent_locator::VhdxParentLocator};
use crate::{Error, Result};

/// Coarse VHDX image allocation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdxDiskType {
  Fixed,
  Dynamic,
  Differential,
}

/// Parsed VHDX metadata values required for read-only access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxMetadata {
  /// On-disk allocation mode.
  pub disk_type: VhdxDiskType,
  /// Payload block size in bytes.
  pub block_size: u32,
  /// Virtual disk size in bytes.
  pub virtual_disk_size: u64,
  /// Logical sector size in bytes.
  pub logical_sector_size: u32,
  /// Physical sector size in bytes.
  pub physical_sector_size: u32,
  /// Stable virtual disk identifier.
  pub virtual_disk_identifier: VhdxGuid,
  /// Differential parent locator, when present.
  pub parent_locator: Option<VhdxParentLocator>,
}

#[derive(Debug, Clone, Copy)]
struct MetadataEntry {
  item_offset: u32,
  item_length: u32,
  flags: u32,
}

impl VhdxMetadata {
  pub fn from_region(region_data: &[u8]) -> Result<Self> {
    if region_data.len() < constants::METADATA_TABLE_SIZE {
      return Err(Error::invalid_format(
        "vhdx metadata region is smaller than the metadata table".to_string(),
      ));
    }
    if &region_data[0..8] != constants::METADATA_TABLE_SIGNATURE {
      return Err(Error::invalid_format(
        "invalid vhdx metadata table signature".to_string(),
      ));
    }
    if region_data[8..10] != [0, 0] {
      return Err(Error::invalid_format(
        "vhdx metadata table reserved field is not zero".to_string(),
      ));
    }
    if region_data[12..32].iter().any(|&byte| byte != 0) {
      return Err(Error::invalid_format(
        "vhdx metadata table reserved bytes are not zero".to_string(),
      ));
    }

    let entry_count = usize::from(u16::from_le_bytes([region_data[10], region_data[11]]));
    if entry_count > constants::VHDX_MAX_TABLE_ENTRIES {
      return Err(Error::invalid_format(format!(
        "vhdx metadata table contains too many entries: {entry_count}"
      )));
    }

    let mut entries = HashMap::with_capacity(entry_count);
    for index in 0..entry_count {
      let entry_offset = 32usize
        .checked_add(
          index
            .checked_mul(32)
            .ok_or_else(|| Error::invalid_range("vhdx metadata entry offset overflow"))?,
        )
        .ok_or_else(|| Error::invalid_range("vhdx metadata entry offset overflow"))?;
      let entry_end = entry_offset
        .checked_add(32)
        .ok_or_else(|| Error::invalid_range("vhdx metadata entry end overflow"))?;
      let entry_data = region_data
        .get(entry_offset..entry_end)
        .ok_or_else(|| Error::invalid_format("vhdx metadata table ends inside an entry"))?;

      let item_id = VhdxGuid::from_le_bytes(&entry_data[0..16])?;
      let item_offset = u32::from_le_bytes([
        entry_data[16],
        entry_data[17],
        entry_data[18],
        entry_data[19],
      ]);
      let item_length = u32::from_le_bytes([
        entry_data[20],
        entry_data[21],
        entry_data[22],
        entry_data[23],
      ]);
      let flags = u32::from_le_bytes([
        entry_data[24],
        entry_data[25],
        entry_data[26],
        entry_data[27],
      ]);
      let reserved = u32::from_le_bytes([
        entry_data[28],
        entry_data[29],
        entry_data[30],
        entry_data[31],
      ]);
      if flags & !0x7 != 0 {
        return Err(Error::invalid_format(format!(
          "vhdx metadata entry {item_id} contains unsupported flags: 0x{flags:08x}"
        )));
      }
      if reserved != 0 {
        return Err(Error::invalid_format(format!(
          "vhdx metadata entry {item_id} reserved field is not zero"
        )));
      }
      if usize::try_from(item_offset)
        .map_err(|_| Error::invalid_range("vhdx metadata item offset is too large"))?
        < constants::METADATA_TABLE_SIZE
      {
        return Err(Error::invalid_format(format!(
          "vhdx metadata entry {item_id} overlaps the metadata table"
        )));
      }
      read_metadata_item(region_data, item_offset, item_length, item_id)?;
      if entries
        .insert(
          item_id,
          MetadataEntry {
            item_offset,
            item_length,
            flags,
          },
        )
        .is_some()
      {
        return Err(Error::invalid_format(format!(
          "duplicate vhdx metadata entry: {item_id}"
        )));
      }
    }

    let file_parameters = read_metadata_item(
      region_data,
      required_entry(&entries, constants::FILE_PARAMETERS_GUID)?.item_offset,
      required_entry(&entries, constants::FILE_PARAMETERS_GUID)?.item_length,
      constants::FILE_PARAMETERS_GUID,
    )?;
    if file_parameters.len() != 8 {
      return Err(Error::invalid_format(
        "vhdx file parameters item must be 8 bytes".to_string(),
      ));
    }
    let block_size = u32::from_le_bytes([
      file_parameters[0],
      file_parameters[1],
      file_parameters[2],
      file_parameters[3],
    ]);
    let file_parameters_flags = u32::from_le_bytes([
      file_parameters[4],
      file_parameters[5],
      file_parameters[6],
      file_parameters[7],
    ]);
    if file_parameters_flags & !0x3 != 0 {
      return Err(Error::invalid_format(format!(
        "vhdx file parameters contain unsupported flags: 0x{file_parameters_flags:08x}"
      )));
    }
    if !block_size.is_power_of_two()
      || !(constants::VHDX_MIN_BLOCK_SIZE..=constants::VHDX_MAX_BLOCK_SIZE).contains(&block_size)
    {
      return Err(Error::invalid_format(format!(
        "invalid vhdx block size: {block_size}"
      )));
    }
    let disk_type = match file_parameters_flags & 0x3 {
      0 => VhdxDiskType::Dynamic,
      1 => VhdxDiskType::Fixed,
      2 => VhdxDiskType::Differential,
      _ => {
        return Err(Error::invalid_format(format!(
          "unsupported vhdx disk type flags: 0x{file_parameters_flags:08x}"
        )));
      }
    };

    let virtual_disk_size_entry = required_entry(&entries, constants::VIRTUAL_DISK_SIZE_GUID)?;
    if virtual_disk_size_entry.flags & 0x4 == 0 {
      return Err(Error::invalid_format(
        "vhdx virtual disk size metadata item is not marked required".to_string(),
      ));
    }
    let virtual_disk_size = {
      let bytes = read_metadata_item(
        region_data,
        virtual_disk_size_entry.item_offset,
        virtual_disk_size_entry.item_length,
        constants::VIRTUAL_DISK_SIZE_GUID,
      )?;
      if bytes.len() != 8 {
        return Err(Error::invalid_format(
          "vhdx virtual disk size item must be 8 bytes".to_string(),
        ));
      }
      u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
      ])
    };
    if virtual_disk_size == 0 {
      return Err(Error::invalid_format(
        "vhdx virtual disk size must be non-zero".to_string(),
      ));
    }

    let logical_sector_size = read_sector_size(
      region_data,
      required_entry(&entries, constants::LOGICAL_SECTOR_SIZE_GUID)?,
      constants::LOGICAL_SECTOR_SIZE_GUID,
      "logical",
    )?;
    let physical_sector_size = read_sector_size(
      region_data,
      required_entry(&entries, constants::PHYSICAL_SECTOR_SIZE_GUID)?,
      constants::PHYSICAL_SECTOR_SIZE_GUID,
      "physical",
    )?;
    if !block_size.is_multiple_of(logical_sector_size) {
      return Err(Error::invalid_format(
        "vhdx block size is not aligned to the logical sector size".to_string(),
      ));
    }

    let virtual_disk_identifier = {
      let entry = required_entry(&entries, constants::VIRTUAL_DISK_IDENTIFIER_GUID)?;
      let bytes = read_metadata_item(
        region_data,
        entry.item_offset,
        entry.item_length,
        constants::VIRTUAL_DISK_IDENTIFIER_GUID,
      )?;
      VhdxGuid::from_le_bytes(bytes)?
    };

    let parent_locator = match entries.get(&constants::PARENT_LOCATOR_GUID) {
      Some(entry) => Some(VhdxParentLocator::from_bytes(read_metadata_item(
        region_data,
        entry.item_offset,
        entry.item_length,
        constants::PARENT_LOCATOR_GUID,
      )?)?),
      None => None,
    };
    if matches!(disk_type, VhdxDiskType::Differential) && parent_locator.is_none() {
      return Err(Error::invalid_format(
        "differential vhdx images must provide a parent locator".to_string(),
      ));
    }

    Ok(Self {
      disk_type,
      block_size,
      virtual_disk_size,
      logical_sector_size,
      physical_sector_size,
      virtual_disk_identifier,
      parent_locator,
    })
  }
}

fn required_entry(
  entries: &HashMap<VhdxGuid, MetadataEntry>, guid: VhdxGuid,
) -> Result<&MetadataEntry> {
  entries
    .get(&guid)
    .ok_or_else(|| Error::invalid_format(format!("missing required vhdx metadata item: {guid}")))
}

fn read_sector_size(
  region_data: &[u8], entry: &MetadataEntry, item_id: VhdxGuid, label: &str,
) -> Result<u32> {
  let bytes = read_metadata_item(region_data, entry.item_offset, entry.item_length, item_id)?;
  if bytes.len() != 4 {
    return Err(Error::invalid_format(format!(
      "vhdx {label} sector size item must be 4 bytes"
    )));
  }
  let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
  if value != 512 && value != 4096 {
    return Err(Error::invalid_format(format!(
      "invalid vhdx {label} sector size: {value}"
    )));
  }
  Ok(value)
}

fn read_metadata_item(
  region_data: &[u8], item_offset: u32, item_length: u32, item_id: VhdxGuid,
) -> Result<&[u8]> {
  let start = usize::try_from(item_offset).map_err(|_| {
    Error::invalid_range(format!("vhdx metadata item offset is too large: {item_id}"))
  })?;
  let length = usize::try_from(item_length).map_err(|_| {
    Error::invalid_range(format!("vhdx metadata item length is too large: {item_id}"))
  })?;
  let end = start
    .checked_add(length)
    .ok_or_else(|| Error::invalid_range(format!("vhdx metadata item range overflow: {item_id}")))?;

  region_data.get(start..end).ok_or_else(|| {
    Error::invalid_format(format!(
      "vhdx metadata item range exceeds the metadata region: {item_id}"
    ))
  })
}
