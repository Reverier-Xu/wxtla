//! PDI descriptor parsing.

use roxmltree::{Document, Node};

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
    let document = Document::parse(text).map_err(|error| {
      Error::InvalidFormat(format!("unable to parse pdi descriptor XML: {error}"))
    })?;
    let root = document.root_element();
    if root.tag_name().name() != "Parallels_disk_image" {
      return Err(Error::InvalidFormat(
        "pdi descriptor root element must be Parallels_disk_image".to_string(),
      ));
    }

    let version = root.attribute("Version").map(str::trim).ok_or_else(|| {
      Error::InvalidFormat("pdi descriptor is missing the Version attribute".to_string())
    })?;
    if version != "1.0" {
      return Err(Error::InvalidFormat(format!(
        "unsupported pdi descriptor version: {}",
        version
      )));
    }

    let disk_parameters = child_element(root, "Disk_Parameters")?;
    let logical_sector_size =
      optional_child_number(disk_parameters, "LogicSectorSize")?.unwrap_or(512);
    if logical_sector_size == 0 {
      return Err(Error::InvalidFormat(
        "pdi logical sector size must be non-zero".to_string(),
      ));
    }
    let physical_sector_size =
      optional_child_number(disk_parameters, "PhysicalSectorSize")?.unwrap_or(4096);
    if physical_sector_size == 0 {
      return Err(Error::InvalidFormat(
        "pdi physical sector size must be non-zero".to_string(),
      ));
    }

    let disk_size_sectors = child_number(disk_parameters, "Disk_size")?;
    if disk_size_sectors == 0 {
      return Err(Error::InvalidFormat(
        "pdi disk size must be non-zero".to_string(),
      ));
    }

    let storage_data = child_element(root, "StorageData")?;
    let storages = child_elements(storage_data, "Storage");
    let mut extents = Vec::with_capacity(storages.len());
    for storage in storages {
      let start_sector = child_number(storage, "Start")?;
      let end_sector = child_number(storage, "End")?;
      let block_size_sectors = child_number(storage, "Blocksize")?;
      if start_sector >= end_sector {
        return Err(Error::InvalidFormat(format!(
          "pdi storage start sector {} must be smaller than end sector {}",
          start_sector, end_sector
        )));
      }
      if block_size_sectors == 0 {
        return Err(Error::InvalidFormat(
          "pdi storage block size must be non-zero".to_string(),
        ));
      }

      let image_nodes = child_elements(storage, "Image");
      let mut images = Vec::with_capacity(image_nodes.len());
      for image in image_nodes {
        let file_name = child_text(image, "File")?;
        if file_name.is_empty() {
          return Err(Error::InvalidFormat(
            "pdi storage image file name must not be empty".to_string(),
          ));
        }
        let snapshot_identifier = normalize_guid(child_text(image, "GUID")?)?;
        let image_type = match child_text(image, "Type")? {
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
        start_sector,
        end_sector,
        block_size_sectors,
        images,
      });
    }
    if extents.is_empty() {
      return Err(Error::InvalidFormat(
        "pdi descriptor must contain storage extents".to_string(),
      ));
    }

    let snapshots_node = child_element(root, "Snapshots")?;
    let shot_nodes = child_elements(snapshots_node, "Shot");
    let mut snapshots = Vec::with_capacity(shot_nodes.len());
    for shot in shot_nodes {
      let identifier = normalize_guid(child_text(shot, "GUID")?)?;
      let parent_identifier = match normalize_guid(child_text(shot, "ParentGUID")?)? {
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

fn child_element<'a, 'input>(parent: Node<'a, 'input>, name: &str) -> Result<Node<'a, 'input>> {
  parent
    .children()
    .find(|child| child.is_element() && child.tag_name().name() == name)
    .ok_or_else(|| Error::InvalidFormat(format!("pdi descriptor is missing {name}")))
}

fn child_elements<'a, 'input>(parent: Node<'a, 'input>, name: &str) -> Vec<Node<'a, 'input>> {
  parent
    .children()
    .filter(|child| child.is_element() && child.tag_name().name() == name)
    .collect()
}

fn child_text<'a, 'input>(parent: Node<'a, 'input>, name: &str) -> Result<&'a str> {
  let child = child_element(parent, name)?;
  child
    .text()
    .map(str::trim)
    .ok_or_else(|| Error::InvalidFormat(format!("pdi descriptor {name} is missing text")))
}

fn child_number<T>(parent: Node<'_, '_>, name: &str) -> Result<T>
where
  T: std::str::FromStr,
  T::Err: std::fmt::Display, {
  child_text(parent, name)?
    .parse::<T>()
    .map_err(|error| Error::InvalidFormat(format!("invalid pdi descriptor {name} value: {error}")))
}

fn optional_child_number<T>(parent: Node<'_, '_>, name: &str) -> Result<Option<T>>
where
  T: std::str::FromStr,
  T::Err: std::fmt::Display, {
  let Some(child) = parent
    .children()
    .find(|child| child.is_element() && child.tag_name().name() == name)
  else {
    return Ok(None);
  };
  let text = child
    .text()
    .map(str::trim)
    .ok_or_else(|| Error::InvalidFormat(format!("pdi descriptor {name} is missing text")))?;
  text
    .parse::<T>()
    .map(Some)
    .map_err(|error| Error::InvalidFormat(format!("invalid pdi descriptor {name} value: {error}")))
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
