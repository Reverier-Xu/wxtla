//! NTFS reparse-point parsing.

use crate::{Error, Result};

const REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const REPARSE_TAG_COMPRESSED: u32 = 0x8000_0017;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsReparsePointKind {
  MountPoint,
  SymbolicLink,
  WofCompressed,
  Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsReparsePointInfo {
  pub kind: NtfsReparsePointKind,
  pub tag: u32,
  pub substitute_name: Option<String>,
  pub print_name: Option<String>,
  pub flags: Option<u32>,
  pub compression_method: Option<u32>,
}

impl NtfsReparsePointInfo {
  pub fn preferred_target(&self) -> Option<String> {
    matches!(
      self.kind,
      NtfsReparsePointKind::MountPoint | NtfsReparsePointKind::SymbolicLink
    )
    .then(|| {
      self
        .print_name
        .clone()
        .filter(|name| !name.is_empty())
        .or_else(|| {
          self
            .substitute_name
            .as_deref()
            .map(normalize_substitute_name)
        })
    })
    .flatten()
  }

  pub fn is_link_like(&self) -> bool {
    matches!(
      self.kind,
      NtfsReparsePointKind::MountPoint | NtfsReparsePointKind::SymbolicLink
    )
  }
}

pub(crate) fn parse_reparse_point(bytes: &[u8]) -> Result<NtfsReparsePointInfo> {
  if bytes.len() < 8 {
    return Err(Error::InvalidFormat(
      "ntfs reparse point is too small".to_string(),
    ));
  }

  let tag = le_u32(&bytes[0..4]);
  let reparse_data_size = usize::from(le_u16(&bytes[4..6]));
  if reparse_data_size > bytes.len() - 8 {
    return Err(Error::InvalidFormat(
      "ntfs reparse-point payload exceeds the attribute bounds".to_string(),
    ));
  }
  let reparse_data = &bytes[8..8 + reparse_data_size];

  let mut info = NtfsReparsePointInfo {
    kind: match tag {
      REPARSE_TAG_MOUNT_POINT => NtfsReparsePointKind::MountPoint,
      REPARSE_TAG_SYMLINK => NtfsReparsePointKind::SymbolicLink,
      REPARSE_TAG_COMPRESSED => NtfsReparsePointKind::WofCompressed,
      _ => NtfsReparsePointKind::Other,
    },
    tag,
    substitute_name: None,
    print_name: None,
    flags: None,
    compression_method: None,
  };

  match tag {
    REPARSE_TAG_COMPRESSED => {
      if reparse_data.len() < 16 {
        return Err(Error::InvalidFormat(
          "compressed ntfs reparse-point payload is truncated".to_string(),
        ));
      }
      info.compression_method = Some(le_u32(&reparse_data[12..16]));
    }
    REPARSE_TAG_MOUNT_POINT | REPARSE_TAG_SYMLINK => {
      let header_size = if tag == REPARSE_TAG_SYMLINK {
        12usize
      } else {
        8usize
      };
      if reparse_data.len() < header_size {
        return Err(Error::InvalidFormat(
          "ntfs mount-point/symlink reparse payload is truncated".to_string(),
        ));
      }
      let substitute_name_offset = usize::from(le_u16(&reparse_data[0..2])) + header_size;
      let substitute_name_size = usize::from(le_u16(&reparse_data[2..4]));
      let print_name_offset = usize::from(le_u16(&reparse_data[4..6])) + header_size;
      let print_name_size = usize::from(le_u16(&reparse_data[6..8]));
      if tag == REPARSE_TAG_SYMLINK {
        info.flags = Some(le_u32(&reparse_data[8..12]));
      }

      info.substitute_name = read_utf16le_component(
        reparse_data,
        substitute_name_offset,
        substitute_name_size,
        "ntfs reparse substitute name",
      )?;
      info.print_name = read_utf16le_component(
        reparse_data,
        print_name_offset,
        print_name_size,
        "ntfs reparse print name",
      )?;
    }
    _ => {}
  }

  Ok(info)
}

fn read_utf16le_component(
  bytes: &[u8], offset: usize, size: usize, label: &str,
) -> Result<Option<String>> {
  if size == 0 {
    return Ok(None);
  }
  if !size.is_multiple_of(2) {
    return Err(Error::InvalidFormat(format!(
      "{label} has an odd byte length"
    )));
  }
  let end = offset
    .checked_add(size)
    .ok_or_else(|| Error::InvalidRange(format!("{label} end overflow")))?;
  let slice = bytes
    .get(offset..end)
    .ok_or_else(|| Error::InvalidFormat(format!("{label} exceeds the payload bounds")))?;
  let units = slice
    .chunks_exact(2)
    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  Ok(Some(String::from_utf16_lossy(&units)))
}

fn normalize_substitute_name(name: &str) -> String {
  name.strip_prefix(r"\??\").unwrap_or(name).to_string()
}

fn le_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_le_bytes(raw)
}

fn le_u32(bytes: &[u8]) -> u32 {
  let mut raw = [0u8; 4];
  raw.copy_from_slice(bytes);
  u32::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use super::*;

  fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("ntfs")
      .join("libfsntfs")
      .join(relative)
  }

  #[test]
  fn parses_libfsntfs_reparse_fixture() {
    let bytes = std::fs::read(fixture_path("reparse_point_values.1")).unwrap();
    let info = parse_reparse_point(&bytes[24..]).unwrap();

    assert_eq!(info.kind, NtfsReparsePointKind::MountPoint);
    assert_eq!(info.tag, REPARSE_TAG_MOUNT_POINT);
    assert_eq!(info.substitute_name.as_deref(), Some(r"\??\C:\Users"));
    assert_eq!(info.print_name.as_deref(), Some(r"C:\Users"));
    assert_eq!(info.preferred_target().as_deref(), Some(r"C:\Users"));
    assert_eq!(info.flags, None);
  }

  #[test]
  fn parses_wof_reparse_points_without_a_target() {
    let info = parse_reparse_point(&[
      0x17, 0x00, 0x00, 0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    ])
    .unwrap();

    assert_eq!(info.kind, NtfsReparsePointKind::WofCompressed);
    assert_eq!(info.compression_method, Some(3));
    assert_eq!(info.preferred_target(), None);
  }

  #[test]
  fn leaves_unknown_reparse_points_as_non_link_targets() {
    let info = parse_reparse_point(&[0x34, 0x12, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00]).unwrap();

    assert_eq!(info.kind, NtfsReparsePointKind::Other);
    assert!(!info.is_link_like());
    assert_eq!(info.preferred_target(), None);
  }
}
