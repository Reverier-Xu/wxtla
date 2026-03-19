//! ext-family extended-attribute parsing.

use std::sync::Arc;

use crate::{Error, Result};

const ATTRIBUTE_MAGIC: u32 = 0xEA02_0000;
const ENTRY_HEADER_SIZE: usize = 16;
const BLOCK_HEADER_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtExtendedAttribute {
  pub name: String,
  pub value: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtExtendedAttributeDescriptor {
  pub name: String,
  pub value_offset: u16,
  pub value_inode: u32,
  pub value_size: u32,
  pub attribute_hash: u32,
  pub entry_size: usize,
}

pub(crate) fn parse_inode_extended_attributes_with<F>(
  inode: &[u8], extended_inode_size: u16, mut resolve_external_inode: F,
) -> Result<Vec<ExtExtendedAttribute>>
where
  F: FnMut(u32, u32) -> Result<Arc<[u8]>>, {
  let offset = 128usize
    .checked_add(usize::from(extended_inode_size))
    .ok_or_else(|| Error::InvalidRange("ext inode xattr offset overflow".to_string()))?;
  if offset + 4 > inode.len() || le_u32(&inode[offset..offset + 4]) != ATTRIBUTE_MAGIC {
    return Ok(Vec::new());
  }

  parse_attribute_entries(
    &inode[offset + 4..],
    0,
    BLOCK_HEADER_SIZE,
    &mut resolve_external_inode,
  )
}

pub(crate) fn parse_external_attribute_block_with<F>(
  bytes: &[u8], mut resolve_external_inode: F,
) -> Result<Vec<ExtExtendedAttribute>>
where
  F: FnMut(u32, u32) -> Result<Arc<[u8]>>, {
  if bytes.len() < BLOCK_HEADER_SIZE {
    return Err(Error::InvalidFormat(
      "ext extended-attribute block is truncated".to_string(),
    ));
  }
  if le_u32(&bytes[0..4]) != ATTRIBUTE_MAGIC {
    return Err(Error::InvalidFormat(
      "ext extended-attribute block magic is invalid".to_string(),
    ));
  }
  if le_u32(&bytes[8..12]) != 1 {
    return Err(Error::InvalidFormat(
      "ext extended-attribute block count is unsupported".to_string(),
    ));
  }

  parse_attribute_entries(
    bytes,
    BLOCK_HEADER_SIZE,
    BLOCK_HEADER_SIZE,
    &mut resolve_external_inode,
  )
}

pub(crate) fn parse_attribute_descriptor(bytes: &[u8]) -> Result<ExtExtendedAttributeDescriptor> {
  if bytes.len() < ENTRY_HEADER_SIZE {
    return Err(Error::InvalidFormat(
      "ext extended-attribute entry is truncated".to_string(),
    ));
  }

  let name_size = usize::from(bytes[0]);
  let entry_size = align_to_four(
    ENTRY_HEADER_SIZE
      .checked_add(name_size)
      .ok_or_else(|| Error::InvalidRange("ext xattr entry size overflow".to_string()))?,
  );
  if entry_size > bytes.len() {
    return Err(Error::InvalidFormat(
      "ext extended-attribute entry exceeds the available bytes".to_string(),
    ));
  }

  Ok(ExtExtendedAttributeDescriptor {
    name: build_attribute_name(
      bytes[1],
      &bytes[ENTRY_HEADER_SIZE..ENTRY_HEADER_SIZE + name_size],
    )?,
    value_offset: le_u16(&bytes[2..4]),
    value_inode: le_u32(&bytes[4..8]),
    value_size: le_u32(&bytes[8..12]),
    attribute_hash: le_u32(&bytes[12..16]),
    entry_size,
  })
}

fn parse_attribute_entries(
  bytes: &[u8], start_offset: usize, minimum_value_offset: usize,
  resolve_external_inode: &mut impl FnMut(u32, u32) -> Result<Arc<[u8]>>,
) -> Result<Vec<ExtExtendedAttribute>> {
  let mut attributes = Vec::new();
  let mut offset = start_offset;

  while offset + ENTRY_HEADER_SIZE <= bytes.len() {
    if bytes[offset..offset + 4] == [0, 0, 0, 0] {
      break;
    }

    let descriptor = parse_attribute_descriptor(&bytes[offset..])?;
    let value = if descriptor.value_size == 0 {
      Arc::<[u8]>::from(Vec::<u8>::new())
    } else if descriptor.value_inode != 0 {
      resolve_external_inode(descriptor.value_inode, descriptor.value_size)?
    } else {
      let value_offset = usize::from(descriptor.value_offset);
      if value_offset < minimum_value_offset {
        return Err(Error::InvalidFormat(
          "ext xattr value offset is smaller than the header size".to_string(),
        ));
      }
      let value_end = value_offset
        .checked_add(
          usize::try_from(descriptor.value_size)
            .map_err(|_| Error::InvalidRange("ext xattr value size is too large".to_string()))?,
        )
        .ok_or_else(|| Error::InvalidRange("ext xattr value end overflow".to_string()))?;
      let value = bytes.get(value_offset..value_end).ok_or_else(|| {
        Error::InvalidFormat("ext xattr value exceeds the available bytes".to_string())
      })?;
      Arc::from(value)
    };

    attributes.push(ExtExtendedAttribute {
      name: descriptor.name,
      value,
    });
    offset = offset
      .checked_add(descriptor.entry_size)
      .ok_or_else(|| Error::InvalidRange("ext xattr offset overflow".to_string()))?;
  }

  Ok(attributes)
}

fn build_attribute_name(name_index: u8, suffix: &[u8]) -> Result<String> {
  let prefix = match name_index {
    0 => "",
    1 => "user.",
    2 => "system.posix_acl_access",
    3 => "system.posix_acl_default",
    4 => "trusted.",
    6 => "security.",
    7 => "system.",
    8 => "system.richacl",
    other => {
      return Err(Error::InvalidFormat(format!(
        "unsupported ext xattr name index: {other}"
      )));
    }
  };
  let suffix = String::from_utf8(suffix.to_vec())
    .map_err(|_| Error::InvalidFormat("ext xattr name is not valid UTF-8".to_string()))?;
  Ok(format!("{prefix}{suffix}"))
}

fn align_to_four(value: usize) -> usize {
  (value + 3) & !3
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
      .join("ext")
      .join("libfsext")
      .join(relative)
  }

  #[test]
  fn parses_libfsext_attribute_values_fixture() {
    let bytes = std::fs::read(fixture_path("attribute_values.1")).unwrap();
    let descriptor = parse_attribute_descriptor(&bytes).unwrap();

    assert_eq!(descriptor.name, "user.myxattr1");
    assert_eq!(descriptor.value_offset, 956);
    assert_eq!(descriptor.value_inode, 0);
    assert_eq!(descriptor.value_size, 25);
    assert_eq!(descriptor.entry_size, 24);
  }

  #[test]
  fn parses_external_inode_xattr_values() {
    let name = b"myxattr";
    let entry_size = align_to_four(ENTRY_HEADER_SIZE + name.len());
    let mut bytes = vec![0u8; BLOCK_HEADER_SIZE + entry_size + 4];
    bytes[0..4].copy_from_slice(&ATTRIBUTE_MAGIC.to_le_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[BLOCK_HEADER_SIZE] = name.len() as u8;
    bytes[BLOCK_HEADER_SIZE + 1] = 1;
    bytes[BLOCK_HEADER_SIZE + 4..BLOCK_HEADER_SIZE + 8].copy_from_slice(&42u32.to_le_bytes());
    bytes[BLOCK_HEADER_SIZE + 8..BLOCK_HEADER_SIZE + 12].copy_from_slice(&5u32.to_le_bytes());
    bytes
      [BLOCK_HEADER_SIZE + ENTRY_HEADER_SIZE..BLOCK_HEADER_SIZE + ENTRY_HEADER_SIZE + name.len()]
      .copy_from_slice(name);

    let attributes = parse_external_attribute_block_with(&bytes, |value_inode, value_size| {
      assert_eq!(value_inode, 42);
      assert_eq!(value_size, 5);
      Ok(Arc::from(&b"hello"[..]))
    })
    .unwrap();

    assert_eq!(attributes.len(), 1);
    assert_eq!(attributes[0].name, "user.myxattr");
    assert_eq!(attributes[0].value.as_ref(), b"hello");
  }
}
