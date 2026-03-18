//! PDI descriptor parsing.

use quick_xml::de::from_str;
use serde::Deserialize;

use crate::{Error, Result};

const FIXED_SECTOR_SIZE: u64 = 512;
const NIL_GUID: &str = "00000000-0000-0000-0000-000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdiDescriptorImageType {
  Plain,
  Compressed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdiDescriptorImage {
  pub snapshot_identifier: String,
  pub image_type: PdiDescriptorImageType,
  pub file_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdiStorageExtent {
  pub start_sector: u64,
  pub end_sector: u64,
  pub block_size_sectors: u32,
  pub images: Vec<PdiDescriptorImage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdiSnapshot {
  pub identifier: String,
  pub parent_identifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdiDescriptor {
  pub disk_size_sectors: u64,
  pub logical_sector_size: u32,
  pub physical_sector_size: u32,
  pub extents: Vec<PdiStorageExtent>,
  pub snapshots: Vec<PdiSnapshot>,
}

impl PdiDescriptor {
  pub fn from_xml(text: &str) -> Result<Self> {
    let raw: RawPdiDescriptor = from_str(text).map_err(|error| {
      Error::InvalidFormat(format!("unable to parse pdi descriptor XML: {error}"))
    })?;
    if raw.version.trim() != "1.0" {
      return Err(Error::InvalidFormat(format!(
        "unsupported pdi descriptor version: {}",
        raw.version.trim()
      )));
    }

    let logical_sector_size = raw.disk_parameters.logical_sector_size.unwrap_or(512);
    if logical_sector_size == 0 {
      return Err(Error::InvalidFormat(
        "pdi logical sector size must be non-zero".to_string(),
      ));
    }
    let physical_sector_size = raw.disk_parameters.physical_sector_size.unwrap_or(4096);
    if physical_sector_size == 0 {
      return Err(Error::InvalidFormat(
        "pdi physical sector size must be non-zero".to_string(),
      ));
    }

    let disk_size_sectors = raw.disk_parameters.disk_size;
    if disk_size_sectors == 0 {
      return Err(Error::InvalidFormat(
        "pdi disk size must be non-zero".to_string(),
      ));
    }

    let mut extents = Vec::with_capacity(raw.storage_data.storages.len());
    for storage in raw.storage_data.storages {
      if storage.start >= storage.end {
        return Err(Error::InvalidFormat(format!(
          "pdi storage start sector {} must be smaller than end sector {}",
          storage.start, storage.end
        )));
      }
      if storage.block_size == 0 {
        return Err(Error::InvalidFormat(
          "pdi storage block size must be non-zero".to_string(),
        ));
      }

      let mut images = Vec::with_capacity(storage.images.len());
      for image in storage.images {
        let file_name = image.file.trim();
        if file_name.is_empty() {
          return Err(Error::InvalidFormat(
            "pdi storage image file name must not be empty".to_string(),
          ));
        }
        let snapshot_identifier = normalize_guid(&image.guid)?;
        let image_type = match image.image_type.trim() {
          "Compressed" => PdiDescriptorImageType::Compressed,
          "Plain" => PdiDescriptorImageType::Plain,
          other => {
            return Err(Error::InvalidFormat(format!(
              "unsupported pdi storage image type: {other}"
            )));
          }
        };

        images.push(PdiDescriptorImage {
          snapshot_identifier,
          image_type,
          file_name: file_name.to_string(),
        });
      }
      if images.is_empty() {
        return Err(Error::InvalidFormat(
          "pdi storage extents must contain at least one image".to_string(),
        ));
      }

      extents.push(PdiStorageExtent {
        start_sector: storage.start,
        end_sector: storage.end,
        block_size_sectors: storage.block_size,
        images,
      });
    }
    if extents.is_empty() {
      return Err(Error::InvalidFormat(
        "pdi descriptor must contain storage extents".to_string(),
      ));
    }

    let mut snapshots = Vec::with_capacity(raw.snapshots.shots.len());
    for shot in raw.snapshots.shots {
      let identifier = normalize_guid(&shot.guid)?;
      let parent_identifier = match normalize_guid(&shot.parent_guid)? {
        guid if guid == NIL_GUID => None,
        guid => Some(guid),
      };
      snapshots.push(PdiSnapshot {
        identifier,
        parent_identifier,
      });
    }

    Ok(Self {
      disk_size_sectors,
      logical_sector_size,
      physical_sector_size,
      extents,
      snapshots,
    })
  }

  pub fn media_size(&self) -> Result<u64> {
    self
      .disk_size_sectors
      .checked_mul(FIXED_SECTOR_SIZE)
      .ok_or_else(|| Error::InvalidRange("pdi media size overflow".to_string()))
  }
}

fn normalize_guid(value: &str) -> Result<String> {
  let value = value.trim();
  let value = value
    .strip_prefix('{')
    .and_then(|inner| inner.strip_suffix('}'))
    .unwrap_or(value)
    .to_ascii_lowercase();
  let mut parts = value.split('-');
  let Some(a) = parts.next() else {
    return Err(Error::InvalidFormat(
      "pdi guid must not be empty".to_string(),
    ));
  };
  let Some(b) = parts.next() else {
    return Err(Error::InvalidFormat(format!("invalid pdi guid: {value}")));
  };
  let Some(c) = parts.next() else {
    return Err(Error::InvalidFormat(format!("invalid pdi guid: {value}")));
  };
  let Some(d) = parts.next() else {
    return Err(Error::InvalidFormat(format!("invalid pdi guid: {value}")));
  };
  let Some(e) = parts.next() else {
    return Err(Error::InvalidFormat(format!("invalid pdi guid: {value}")));
  };
  if parts.next().is_some()
    || a.len() != 8
    || b.len() != 4
    || c.len() != 4
    || d.len() != 4
    || e.len() != 12
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
  {
    return Err(Error::InvalidFormat(format!("invalid pdi guid: {value}")));
  }
  Ok(value)
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Parallels_disk_image")]
struct RawPdiDescriptor {
  #[serde(rename = "@Version")]
  version: String,
  #[serde(rename = "Disk_Parameters")]
  disk_parameters: RawDiskParameters,
  #[serde(rename = "StorageData")]
  storage_data: RawStorageData,
  #[serde(rename = "Snapshots")]
  snapshots: RawSnapshots,
}

#[derive(Debug, Deserialize)]
struct RawDiskParameters {
  #[serde(rename = "Disk_size")]
  disk_size: u64,
  #[serde(rename = "LogicSectorSize")]
  logical_sector_size: Option<u32>,
  #[serde(rename = "PhysicalSectorSize")]
  physical_sector_size: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawStorageData {
  #[serde(rename = "Storage")]
  storages: Vec<RawStorage>,
}

#[derive(Debug, Deserialize)]
struct RawStorage {
  #[serde(rename = "Start")]
  start: u64,
  #[serde(rename = "End")]
  end: u64,
  #[serde(rename = "Blocksize")]
  block_size: u32,
  #[serde(rename = "Image")]
  images: Vec<RawImage>,
}

#[derive(Debug, Deserialize)]
struct RawImage {
  #[serde(rename = "GUID")]
  guid: String,
  #[serde(rename = "Type")]
  image_type: String,
  #[serde(rename = "File")]
  file: String,
}

#[derive(Debug, Deserialize)]
struct RawSnapshots {
  #[serde(rename = "Shot")]
  shots: Vec<RawSnapshot>,
}

#[derive(Debug, Deserialize)]
struct RawSnapshot {
  #[serde(rename = "GUID")]
  guid: String,
  #[serde(rename = "ParentGUID")]
  parent_guid: String,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_descriptor_fields() {
    let descriptor = PdiDescriptor::from_xml(
      "<?xml version='1.0' encoding='UTF-8'?><Parallels_disk_image Version=\"1.0\"><Disk_Parameters><Disk_size>8</Disk_size><PhysicalSectorSize>4096</PhysicalSectorSize><LogicSectorSize>512</LogicSectorSize></Disk_Parameters><StorageData><Storage><Start>0</Start><End>8</End><Blocksize>2</Blocksize><Image><GUID>{11111111-1111-1111-1111-111111111111}</GUID><Type>Compressed</Type><File>disk.hds</File></Image></Storage></StorageData><Snapshots><Shot><GUID>{11111111-1111-1111-1111-111111111111}</GUID><ParentGUID>{00000000-0000-0000-0000-000000000000}</ParentGUID></Shot></Snapshots></Parallels_disk_image>",
    )
    .unwrap();

    assert_eq!(descriptor.disk_size_sectors, 8);
    assert_eq!(descriptor.logical_sector_size, 512);
    assert_eq!(descriptor.physical_sector_size, 4096);
    assert_eq!(descriptor.extents.len(), 1);
    assert_eq!(descriptor.snapshots.len(), 1);
    assert_eq!(descriptor.extents[0].images[0].file_name, "disk.hds");
    assert_eq!(
      descriptor.extents[0].images[0].image_type,
      PdiDescriptorImageType::Compressed
    );
  }

  #[test]
  fn rejects_invalid_snapshot_guids() {
    let result = PdiDescriptor::from_xml(
      "<?xml version='1.0' encoding='UTF-8'?><Parallels_disk_image Version=\"1.0\"><Disk_Parameters><Disk_size>8</Disk_size></Disk_Parameters><StorageData><Storage><Start>0</Start><End>8</End><Blocksize>2</Blocksize><Image><GUID>{11111111-1111-1111-1111-111111111111}</GUID><Type>Plain</Type><File>disk.hds</File></Image></Storage></StorageData><Snapshots><Shot><GUID>bad</GUID><ParentGUID>{00000000-0000-0000-0000-000000000000}</ParentGUID></Shot></Snapshots></Parallels_disk_image>",
    );

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
