//! Text descriptor parsing for VMDK sparse images.

use crate::{Error, Result};

/// Top-level VMDK file form declared by the descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkFileType {
  MonolithicSparse,
  MonolithicFlat,
  StreamOptimized,
  Flat2GbExtent,
  Sparse2GbExtent,
  Vmfs,
  VmfsSparse,
  VmfsThin,
  Unknown,
}

/// Descriptor extent access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkExtentAccessMode {
  NoAccess,
  ReadOnly,
  ReadWrite,
  Unknown,
}

/// Descriptor extent backing type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkExtentType {
  Flat,
  Sparse,
  Vmfs,
  VmfsSparse,
  Zero,
  Unknown,
}

/// One parsed extent description line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmdkDescriptorExtent {
  /// Access mode declared by the descriptor.
  pub access_mode: VmdkExtentAccessMode,
  /// Extent length in sectors.
  pub sector_count: u64,
  /// Extent storage type.
  pub extent_type: VmdkExtentType,
  /// Relative extent file name when one is present.
  pub file_name: Option<String>,
  /// Optional start sector inside a flat extent.
  pub start_sector: u64,
}

/// Parsed VMDK text descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmdkDescriptor {
  /// Descriptor format version.
  pub version: u32,
  /// Content identifier of the current layer.
  pub content_id: u32,
  /// Parent content identifier when the layer has a parent.
  pub parent_content_id: Option<u32>,
  /// Declared disk layout.
  pub file_type: VmdkFileType,
  /// Declared extents.
  pub extents: Vec<VmdkDescriptorExtent>,
  /// Optional parent file name hint.
  pub parent_file_name_hint: Option<String>,
}

impl VmdkDescriptor {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    let data = data.split(|byte| *byte == 0).next().unwrap_or(data);
    let text = std::str::from_utf8(strip_utf8_bom(data)).map_err(|_| {
      Error::InvalidFormat("vmdk descriptor must be valid UTF-8 in the current step".to_string())
    })?;

    let mut version = None;
    let mut content_id = None;
    let mut parent_content_id = None;
    let mut file_type = None;
    let mut extents = Vec::new();
    let mut parent_file_name_hint = None;

    for raw_line in text.lines() {
      let line = raw_line.trim();
      if line.is_empty() || line.starts_with('#') {
        continue;
      }

      if let Some((key, value)) = line.split_once('=') {
        let normalized_key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match normalized_key.as_str() {
          "version" => {
            version = Some(parse_decimal_u32(value)?);
          }
          "cid" => {
            content_id = Some(parse_hex_u32(value)?);
          }
          "parentcid" => {
            let parsed = parse_hex_u32(value)?;
            parent_content_id = if parsed == u32::MAX {
              None
            } else {
              Some(parsed)
            };
          }
          "createtype" => {
            file_type = Some(parse_file_type(parse_quoted(value)?));
          }
          "parentfilenamehint" => {
            parent_file_name_hint = Some(parse_quoted(value)?.to_string());
          }
          "encoding" => {
            let encoding = parse_quoted(value)?;
            if !encoding.eq_ignore_ascii_case("utf-8") {
              return Err(Error::InvalidFormat(format!(
                "unsupported vmdk descriptor encoding in the current step: {encoding}"
              )));
            }
          }
          _ => {}
        }
      } else {
        extents.push(parse_extent(line)?);
      }
    }

    let descriptor = Self {
      version: version.ok_or_else(|| {
        Error::InvalidFormat("vmdk descriptor is missing the version field".to_string())
      })?,
      content_id: content_id.ok_or_else(|| {
        Error::InvalidFormat("vmdk descriptor is missing the cid field".to_string())
      })?,
      parent_content_id,
      file_type: file_type.ok_or_else(|| {
        Error::InvalidFormat("vmdk descriptor is missing the createtype field".to_string())
      })?,
      extents,
      parent_file_name_hint,
    };
    if descriptor.extents.is_empty() {
      return Err(Error::InvalidFormat(
        "vmdk descriptor must declare at least one extent".to_string(),
      ));
    }

    Ok(descriptor)
  }
}

fn strip_utf8_bom(data: &[u8]) -> &[u8] {
  data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data)
}

fn parse_extent(line: &str) -> Result<VmdkDescriptorExtent> {
  let (access_mode, rest) = next_token(line).ok_or_else(|| {
    Error::InvalidFormat("vmdk extent line is missing the access mode".to_string())
  })?;
  let (sector_count, rest) = next_token(rest).ok_or_else(|| {
    Error::InvalidFormat("vmdk extent line is missing the sector count".to_string())
  })?;
  let (extent_type, rest) = next_token(rest).ok_or_else(|| {
    Error::InvalidFormat("vmdk extent line is missing the extent type".to_string())
  })?;
  let rest = rest.trim_start();

  let access_mode = match access_mode.to_ascii_lowercase().as_str() {
    "noaccess" => VmdkExtentAccessMode::NoAccess,
    "rdonly" => VmdkExtentAccessMode::ReadOnly,
    "rw" => VmdkExtentAccessMode::ReadWrite,
    _ => VmdkExtentAccessMode::Unknown,
  };
  let extent_type = match extent_type.to_ascii_lowercase().as_str() {
    "flat" => VmdkExtentType::Flat,
    "sparse" => VmdkExtentType::Sparse,
    "vmfs" => VmdkExtentType::Vmfs,
    "vmfssparse" => VmdkExtentType::VmfsSparse,
    "zero" => VmdkExtentType::Zero,
    _ => VmdkExtentType::Unknown,
  };
  let sector_count = parse_decimal_u64(sector_count)?;
  if sector_count == 0 {
    return Err(Error::InvalidFormat(
      "vmdk extent sector count must be non-zero".to_string(),
    ));
  }

  if extent_type == VmdkExtentType::Zero {
    if !rest.is_empty() {
      return Err(Error::InvalidFormat(
        "vmdk ZERO extents must not carry a file name".to_string(),
      ));
    }
    return Ok(VmdkDescriptorExtent {
      access_mode,
      sector_count,
      extent_type,
      file_name: None,
      start_sector: 0,
    });
  }

  if !rest.starts_with('"') {
    return Err(Error::InvalidFormat(
      "vmdk extent file names must be quoted".to_string(),
    ));
  }
  let Some(quote_end) = rest[1..].find('"') else {
    return Err(Error::InvalidFormat(
      "unterminated vmdk extent file name".to_string(),
    ));
  };
  let file_name = &rest[1..quote_end + 1];
  let tail = rest[quote_end + 2..].trim();
  let start_sector = if tail.is_empty() {
    0
  } else {
    let (offset_token, remainder) = next_token(tail)
      .ok_or_else(|| Error::InvalidFormat("vmdk extent start sector is missing".to_string()))?;
    if !remainder.trim().is_empty() {
      return Err(Error::InvalidFormat(
        "vmdk extent contains unsupported trailing tokens".to_string(),
      ));
    }
    parse_decimal_u64(offset_token)?
  };

  Ok(VmdkDescriptorExtent {
    access_mode,
    sector_count,
    extent_type,
    file_name: Some(file_name.to_string()),
    start_sector,
  })
}

fn parse_file_type(value: &str) -> VmdkFileType {
  match value.to_ascii_lowercase().as_str() {
    "monolithicsparse" => VmdkFileType::MonolithicSparse,
    "monolithicflat" => VmdkFileType::MonolithicFlat,
    "streamoptimized" => VmdkFileType::StreamOptimized,
    "2gbmaxextentflat" | "twogbmaxextentflat" => VmdkFileType::Flat2GbExtent,
    "2gbmaxextentsparse" | "twogbmaxextentsparse" => VmdkFileType::Sparse2GbExtent,
    "vmfs" => VmdkFileType::Vmfs,
    "vmfssparse" => VmdkFileType::VmfsSparse,
    "vmfsthin" => VmdkFileType::VmfsThin,
    _ => VmdkFileType::Unknown,
  }
}

fn parse_quoted(value: &str) -> Result<&str> {
  if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
    return Err(Error::InvalidFormat(format!(
      "expected a quoted vmdk descriptor value: {value}"
    )));
  }
  Ok(&value[1..value.len() - 1])
}

fn parse_decimal_u32(value: &str) -> Result<u32> {
  value
    .parse()
    .map_err(|_| Error::InvalidFormat(format!("invalid decimal vmdk descriptor value: {value}")))
}

fn parse_decimal_u64(value: &str) -> Result<u64> {
  value
    .parse()
    .map_err(|_| Error::InvalidFormat(format!("invalid decimal vmdk descriptor value: {value}")))
}

fn parse_hex_u32(value: &str) -> Result<u32> {
  u32::from_str_radix(value, 16).map_err(|_| {
    Error::InvalidFormat(format!(
      "invalid hexadecimal vmdk descriptor value: {value}"
    ))
  })
}

fn next_token(input: &str) -> Option<(&str, &str)> {
  let trimmed = input.trim_start();
  if trimmed.is_empty() {
    return None;
  }
  let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
  Some((&trimmed[..end], &trimmed[end..]))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_monolithic_sparse_descriptor() {
    let descriptor = VmdkDescriptor::from_bytes(
      br#"# Disk DescriptorFile
version=1
CID=4c069322
parentCID=ffffffff
createType="monolithicSparse"

# Extent description
RW 8192 SPARSE "ext2.vmdk"
"#,
    )
    .unwrap();

    assert_eq!(descriptor.version, 1);
    assert_eq!(descriptor.content_id, 0x4C06_9322);
    assert_eq!(descriptor.parent_content_id, None);
    assert_eq!(descriptor.file_type, VmdkFileType::MonolithicSparse);
    assert_eq!(descriptor.extents.len(), 1);
    assert_eq!(descriptor.extents[0].extent_type, VmdkExtentType::Sparse);
  }

  #[test]
  fn rejects_non_utf8_descriptor_data() {
    let result = VmdkDescriptor::from_bytes(&[0xFF, 0xFF, 0x00]);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_unquoted_extent_file_names() {
    let result = parse_extent("RW 8192 SPARSE ext2.vmdk");

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
