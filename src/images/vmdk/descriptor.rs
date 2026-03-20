//! Text descriptor parsing for VMDK images.

use encoding_rs::{Encoding, UTF_8};

use crate::{Error, Result};

/// Top-level VMDK file form declared by the descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkFileType {
  Custom,
  FullDevice,
  MonolithicSparse,
  MonolithicFlat,
  PartitionedDevice,
  StreamOptimized,
  Flat2GbExtent,
  Sparse2GbExtent,
  Vmfs,
  VmfsSparse,
  VmfsThin,
  VmfsRaw,
  VmfsRdm,
  VmfsRdmp,
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
  VmfsRaw,
  VmfsRdm,
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
    let data = strip_utf8_bom(data.split(|byte| *byte == 0).next().unwrap_or(data));

    let mut version = None;
    let mut content_id = None;
    let mut parent_content_id = None;
    let mut file_type = None;
    let mut extents = Vec::new();
    let mut parent_file_name_hint = None;
    let mut descriptor_encoding = UTF_8;

    for raw_line in data.split(|byte| *byte == b'\n') {
      let line = trim_ascii(raw_line);
      if line.is_empty() || line[0] == b'#' {
        continue;
      }

      if let Some((key, value)) = split_key_value(line) {
        match ascii_lowercase(key).as_slice() {
          b"version" => {
            version = Some(parse_decimal_u32_bytes(value)?);
          }
          b"cid" => {
            content_id = Some(parse_hex_u32_bytes(value)?);
          }
          b"parentcid" => {
            let parsed = parse_hex_u32_bytes(value)?;
            parent_content_id = if parsed == u32::MAX {
              None
            } else {
              Some(parsed)
            };
          }
          b"createtype" => {
            file_type = Some(parse_file_type(parse_quoted_ascii(value)?));
          }
          b"parentfilenamehint" => {
            parent_file_name_hint = Some(decode_bytes(
              parse_quoted_bytes(value)?,
              descriptor_encoding,
              "vmdk parent file name hint",
            )?);
          }
          b"encoding" => {
            let label = parse_quoted_ascii(value)?;
            descriptor_encoding = resolve_encoding(label)?;
          }
          _ => {}
        }
      } else {
        extents.push(parse_extent_bytes(line, descriptor_encoding)?);
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

fn parse_extent_bytes(line: &[u8], encoding: &'static Encoding) -> Result<VmdkDescriptorExtent> {
  let (access_mode, rest) = next_token(line).ok_or_else(|| {
    Error::InvalidFormat("vmdk extent line is missing the access mode".to_string())
  })?;
  let (sector_count, rest) = next_token(rest).ok_or_else(|| {
    Error::InvalidFormat("vmdk extent line is missing the sector count".to_string())
  })?;
  let (extent_type, rest) = next_token(rest).ok_or_else(|| {
    Error::InvalidFormat("vmdk extent line is missing the extent type".to_string())
  })?;
  let rest = trim_ascii_start(rest);

  let access_mode = match ascii_lowercase(access_mode).as_slice() {
    b"noaccess" => VmdkExtentAccessMode::NoAccess,
    b"rdonly" => VmdkExtentAccessMode::ReadOnly,
    b"rw" => VmdkExtentAccessMode::ReadWrite,
    _ => VmdkExtentAccessMode::Unknown,
  };
  let extent_type = match ascii_lowercase(extent_type).as_slice() {
    b"flat" => VmdkExtentType::Flat,
    b"sparse" => VmdkExtentType::Sparse,
    b"vmfs" => VmdkExtentType::Vmfs,
    b"vmfssparse" => VmdkExtentType::VmfsSparse,
    b"vmfsraw" => VmdkExtentType::VmfsRaw,
    b"vmfsrdm" | b"vmfsrawdevicemap" | b"vmfspassthroughrawdevicemap" | b"vmfsrdmp" => {
      VmdkExtentType::VmfsRdm
    }
    b"zero" => VmdkExtentType::Zero,
    _ => VmdkExtentType::Unknown,
  };
  let sector_count = parse_decimal_u64_bytes(sector_count)?;
  if sector_count == 0 {
    return Err(Error::InvalidFormat(
      "vmdk extent sector count must be non-zero".to_string(),
    ));
  }

  if extent_type == VmdkExtentType::Zero {
    if !trim_ascii(rest).is_empty() {
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

  if !rest.starts_with(b"\"") {
    return Err(Error::InvalidFormat(
      "vmdk extent file names must be quoted".to_string(),
    ));
  }
  let Some(quote_end) = rest[1..].iter().position(|byte| *byte == b'"') else {
    return Err(Error::InvalidFormat(
      "unterminated vmdk extent file name".to_string(),
    ));
  };
  let file_name = decode_bytes(&rest[1..quote_end + 1], encoding, "vmdk extent file name")?;
  let tail = trim_ascii(&rest[quote_end + 2..]);
  let start_sector = if tail.is_empty() {
    0
  } else {
    let (offset_token, _) = next_token(tail)
      .ok_or_else(|| Error::InvalidFormat("vmdk extent start sector is missing".to_string()))?;
    parse_decimal_u64_bytes(offset_token)?
  };

  Ok(VmdkDescriptorExtent {
    access_mode,
    sector_count,
    extent_type,
    file_name: Some(file_name),
    start_sector,
  })
}

fn parse_file_type(value: &[u8]) -> VmdkFileType {
  match ascii_lowercase(value).as_slice() {
    b"custom" => VmdkFileType::Custom,
    b"fulldevice" => VmdkFileType::FullDevice,
    b"monolithicsparse" => VmdkFileType::MonolithicSparse,
    b"monolithicflat" => VmdkFileType::MonolithicFlat,
    b"partitioneddevice" => VmdkFileType::PartitionedDevice,
    b"streamoptimized" => VmdkFileType::StreamOptimized,
    b"2gbmaxextentflat" | b"twogbmaxextentflat" => VmdkFileType::Flat2GbExtent,
    b"2gbmaxextentsparse" | b"twogbmaxextentsparse" => VmdkFileType::Sparse2GbExtent,
    b"vmfs" | b"vmfspreallocated" | b"vmfseagerzeroedthick" => VmdkFileType::Vmfs,
    b"vmfssparse" => VmdkFileType::VmfsSparse,
    b"vmfsthin" => VmdkFileType::VmfsThin,
    b"vmfsraw" => VmdkFileType::VmfsRaw,
    b"vmfsrawdevicemap" | b"vmfsrdm" => VmdkFileType::VmfsRdm,
    b"vmfspassthroughrawdevicemap" | b"vmfsrdmp" => VmdkFileType::VmfsRdmp,
    _ => VmdkFileType::Unknown,
  }
}

fn resolve_encoding(label: &[u8]) -> Result<&'static Encoding> {
  let mut normalized = ascii_lowercase(label)
    .into_iter()
    .map(|byte| if byte == b'_' { b'-' } else { byte })
    .collect::<Vec<_>>();
  if normalized.starts_with(b"cp") || normalized.starts_with(b"ms") {
    normalized.splice(0..2, b"windows-".iter().copied());
  }

  Encoding::for_label(&normalized).ok_or_else(|| {
    Error::InvalidFormat(format!(
      "unsupported vmdk descriptor encoding: {}",
      String::from_utf8_lossy(label)
    ))
  })
}

fn strip_utf8_bom(data: &[u8]) -> &[u8] {
  data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data)
}

fn decode_bytes(data: &[u8], encoding: &'static Encoding, label: &str) -> Result<String> {
  let (decoded, _, had_errors) = encoding.decode(data);
  if had_errors {
    return Err(Error::InvalidFormat(format!(
      "{label} contains bytes that are invalid for {}",
      encoding.name()
    )));
  }
  Ok(decoded.into_owned())
}

fn split_key_value(line: &[u8]) -> Option<(&[u8], &[u8])> {
  let index = line.iter().position(|byte| *byte == b'=')?;
  Some((trim_ascii(&line[..index]), trim_ascii(&line[index + 1..])))
}

fn parse_quoted_ascii(value: &[u8]) -> Result<&[u8]> {
  let quoted = parse_quoted_bytes(value)?;
  if quoted.iter().all(u8::is_ascii) {
    Ok(quoted)
  } else {
    Err(Error::InvalidFormat(
      "vmdk descriptor control values must be ASCII".to_string(),
    ))
  }
}

fn parse_quoted_bytes(value: &[u8]) -> Result<&[u8]> {
  if value.len() < 2 || value[0] != b'"' || value[value.len() - 1] != b'"' {
    return Err(Error::InvalidFormat(format!(
      "expected a quoted vmdk descriptor value: {}",
      String::from_utf8_lossy(value)
    )));
  }
  Ok(&value[1..value.len() - 1])
}

fn parse_decimal_u32_bytes(value: &[u8]) -> Result<u32> {
  parse_decimal_u64_bytes(value)?.try_into().map_err(|_| {
    Error::InvalidFormat(format!(
      "invalid decimal vmdk descriptor value: {}",
      String::from_utf8_lossy(value)
    ))
  })
}

fn parse_decimal_u64_bytes(value: &[u8]) -> Result<u64> {
  let mut result = 0u64;
  if value.is_empty() {
    return Err(Error::InvalidFormat(
      "invalid decimal vmdk descriptor value: <empty>".to_string(),
    ));
  }
  for byte in value {
    if !byte.is_ascii_digit() {
      return Err(Error::InvalidFormat(format!(
        "invalid decimal vmdk descriptor value: {}",
        String::from_utf8_lossy(value)
      )));
    }
    result = result
      .checked_mul(10)
      .and_then(|current| current.checked_add(u64::from(byte - b'0')))
      .ok_or_else(|| {
        Error::InvalidFormat(format!(
          "invalid decimal vmdk descriptor value: {}",
          String::from_utf8_lossy(value)
        ))
      })?;
  }
  Ok(result)
}

fn parse_hex_u32_bytes(value: &[u8]) -> Result<u32> {
  let mut result = 0u32;
  if value.is_empty() {
    return Err(Error::InvalidFormat(
      "invalid hexadecimal vmdk descriptor value: <empty>".to_string(),
    ));
  }
  for byte in value {
    let digit = match byte {
      b'0'..=b'9' => u32::from(byte - b'0'),
      b'a'..=b'f' => u32::from(byte - b'a' + 10),
      b'A'..=b'F' => u32::from(byte - b'A' + 10),
      _ => {
        return Err(Error::InvalidFormat(format!(
          "invalid hexadecimal vmdk descriptor value: {}",
          String::from_utf8_lossy(value)
        )));
      }
    };
    result = result
      .checked_mul(16)
      .and_then(|current| current.checked_add(digit))
      .ok_or_else(|| {
        Error::InvalidFormat(format!(
          "invalid hexadecimal vmdk descriptor value: {}",
          String::from_utf8_lossy(value)
        ))
      })?;
  }
  Ok(result)
}

fn next_token(input: &[u8]) -> Option<(&[u8], &[u8])> {
  let trimmed = trim_ascii_start(input);
  if trimmed.is_empty() {
    return None;
  }
  let end = trimmed
    .iter()
    .position(u8::is_ascii_whitespace)
    .unwrap_or(trimmed.len());
  Some((&trimmed[..end], &trimmed[end..]))
}

fn trim_ascii_start(data: &[u8]) -> &[u8] {
  let start = data
    .iter()
    .position(|byte| !byte.is_ascii_whitespace())
    .unwrap_or(data.len());
  &data[start..]
}

fn trim_ascii(data: &[u8]) -> &[u8] {
  let start = data
    .iter()
    .position(|byte| !byte.is_ascii_whitespace())
    .unwrap_or(data.len());
  let end = data
    .iter()
    .rposition(|byte| !byte.is_ascii_whitespace())
    .map(|index| index + 1)
    .unwrap_or(start);
  &data[start..end]
}

fn ascii_lowercase(data: &[u8]) -> Vec<u8> {
  data.iter().map(u8::to_ascii_lowercase).collect()
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
  fn parses_windows_1252_descriptor_paths() {
    let descriptor = VmdkDescriptor::from_bytes(
      b"# Disk DescriptorFile\nversion=1\nencoding=\"windows-1252\"\nCID=4c069322\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\n\n# Extent description\nRW 8192 FLAT \"caf\xe9-flat.vmdk\" 0\n",
    )
    .unwrap();

    assert_eq!(
      descriptor.extents[0].file_name.as_deref(),
      Some("café-flat.vmdk")
    );
  }

  #[test]
  fn parses_device_extent_trailing_tokens() {
    let descriptor = VmdkDescriptor::from_bytes(
      br#"# Disk DescriptorFile
version=1
CID=4c069322
parentCID=ffffffff
createType="partitionedDevice"

# Extent description
RW 8192 FLAT "disk.raw" 63 partitionUUID deadbeef
"#,
    )
    .unwrap();

    assert_eq!(descriptor.file_type, VmdkFileType::PartitionedDevice);
    assert_eq!(descriptor.extents[0].start_sector, 63);
  }

  #[test]
  fn parses_raw_device_map_extent_aliases() {
    let descriptor = VmdkDescriptor::from_bytes(
      br#"# Disk DescriptorFile
version=1
CID=4c069322
parentCID=ffffffff
createType="vmfsrdmp"

RW 8192 VMFSPASSTHROUGHRAWDEVICEMAP "disk.raw" 0
"#,
    )
    .unwrap();

    assert_eq!(descriptor.file_type, VmdkFileType::VmfsRdmp);
    assert_eq!(descriptor.extents[0].extent_type, VmdkExtentType::VmfsRdm);
  }

  #[test]
  fn rejects_unquoted_extent_file_names() {
    let result = parse_extent_bytes(b"RW 8192 SPARSE ext2.vmdk", UTF_8);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
