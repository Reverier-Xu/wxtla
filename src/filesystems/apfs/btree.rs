//! APFS B-tree parsing and traversal.

use std::{cmp::Ordering, sync::Arc};

use super::ondisk::{
  ApfsBtreeInfo, ApfsBtreeNodeHeader, ApfsObjectHeader, BTNODE_FIXED_KV_SIZE, BTNODE_HASHED,
  BTNODE_LEAF, BTNODE_NOHEADER, BTREE_HASHED, BTREE_INFO_SIZE, BTREE_NODE_HEADER_SIZE,
  BTREE_NOHEADER, BTREE_PHYSICAL, OBJECT_HEADER_SIZE, OBJECT_TYPE_BTREE, OBJECT_TYPE_BTREE_NODE,
  OBJECT_TYPE_MASK, read_slice, read_u16_le, read_u64_le,
};
use crate::{ByteSourceHandle, Error, Result};

#[derive(Clone)]
pub(crate) struct ApfsBTree {
  source: ByteSourceHandle,
  block_size: u32,
  root_address: u64,
  root: ApfsBTreeNode,
  info: ApfsBtreeInfo,
  child_resolver: ApfsBTreeChildResolver,
  decryptor: Option<Arc<super::crypto::ApfsXtsCipher>>,
}

#[derive(Clone)]
enum ApfsBTreeChildResolver {
  Physical,
  Virtual {
    omap_tree: Box<ApfsBTree>,
    xid: u64,
    base_oid: u64,
  },
}

impl ApfsBTree {
  pub(crate) fn open(source: ByteSourceHandle, block_size: u32, root_address: u64) -> Result<Self> {
    let root_block = read_object_block(source.as_ref(), block_size, root_address, None)?;
    let root = ApfsBTreeNode::parse_root(&root_block)?;
    if (root.info.flags & BTREE_HASHED) != 0 || (root.header.flags & BTNODE_HASHED) != 0 {
      return Err(Error::Unsupported(
        "hashed APFS B-trees are not yet supported".to_string(),
      ));
    }
    if (root.info.flags & BTREE_NOHEADER) != 0 || (root.header.flags & BTNODE_NOHEADER) != 0 {
      return Err(Error::Unsupported(
        "headerless APFS B-trees are not yet supported".to_string(),
      ));
    }
    if (root.info.flags & BTREE_PHYSICAL) == 0 {
      return Err(Error::Unsupported(
        "non-physical APFS B-trees are not yet supported".to_string(),
      ));
    }

    Ok(Self {
      source,
      block_size,
      root_address,
      root: root.clone(),
      info: root.info,
      child_resolver: ApfsBTreeChildResolver::Physical,
      decryptor: None,
    })
  }

  pub(crate) fn open_virtual(
    source: ByteSourceHandle, block_size: u32, root_address: u64, omap_tree: ApfsBTree, xid: u64,
    base_oid: u64, decryptor: Option<Arc<super::crypto::ApfsXtsCipher>>,
  ) -> Result<Self> {
    let root_block = read_object_block(
      source.as_ref(),
      block_size,
      root_address,
      decryptor.as_ref(),
    )?;
    let root = ApfsBTreeNode::parse_root(&root_block)?;
    if (root.info.flags & BTREE_HASHED) != 0 || (root.header.flags & BTNODE_HASHED) != 0 {
      return Err(Error::Unsupported(
        "hashed APFS B-trees are not yet supported".to_string(),
      ));
    }
    if (root.info.flags & BTREE_NOHEADER) != 0 || (root.header.flags & BTNODE_NOHEADER) != 0 {
      return Err(Error::Unsupported(
        "headerless APFS B-trees are not yet supported".to_string(),
      ));
    }

    Ok(Self {
      source,
      block_size,
      root_address,
      root: root.clone(),
      info: root.info,
      child_resolver: ApfsBTreeChildResolver::Virtual {
        omap_tree: Box::new(omap_tree),
        xid,
        base_oid,
      },
      decryptor,
    })
  }

  pub(crate) fn search_floor<F>(&self, compare: F) -> Result<(Vec<u8>, Vec<u8>)>
  where
    F: Fn(&[u8]) -> Ordering, {
    let record = self.search_floor_at(self.root_address, &compare)?;
    record.ok_or_else(|| Error::NotFound("apfs btree record was not found".to_string()))
  }

  pub(crate) fn walk_records(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut records = Vec::new();
    self.walk_at(self.root_address, &mut records)?;
    Ok(records)
  }

  fn search_floor_at<F>(&self, address: u64, compare: &F) -> Result<Option<(Vec<u8>, Vec<u8>)>>
  where
    F: Fn(&[u8]) -> Ordering, {
    let node = self.node(address)?;
    let Some(index) = node.floor_index(compare)? else {
      return Ok(None);
    };

    if node.is_leaf() {
      return Ok(Some((
        node.key(index)?.to_vec(),
        node.value(index)?.to_vec(),
      )));
    }

    let child_address = self.resolve_child_identifier(node.child_identifier(index)?)?;
    self.search_floor_at(child_address, compare)
  }

  fn walk_at(&self, address: u64, records: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
    let node = self.node(address)?;
    if node.is_leaf() {
      for index in 0..node.key_count() {
        records.push((node.key(index)?.to_vec(), node.value(index)?.to_vec()));
      }
      return Ok(());
    }

    for index in 0..node.key_count() {
      self.walk_at(
        self.resolve_child_identifier(node.child_identifier(index)?)?,
        records,
      )?;
    }
    Ok(())
  }

  fn load_node(&self, address: u64) -> Result<ApfsBTreeNode> {
    let block = read_object_block(
      self.source.as_ref(),
      self.block_size,
      address,
      self.decryptor.as_ref(),
    )?;
    ApfsBTreeNode::parse_child(&block, self.info)
  }

  fn node(&self, address: u64) -> Result<ApfsBTreeNode> {
    if address == self.root_address {
      return Ok(self.root.clone());
    }
    self.load_node(address)
  }

  fn resolve_child_identifier(&self, child_identifier: u64) -> Result<u64> {
    match &self.child_resolver {
      ApfsBTreeChildResolver::Physical => Ok(child_identifier),
      ApfsBTreeChildResolver::Virtual {
        omap_tree,
        xid,
        base_oid,
      } => lookup_omap_address(
        omap_tree,
        base_oid.checked_add(child_identifier).ok_or_else(|| {
          Error::InvalidRange("apfs virtual btree child oid overflow".to_string())
        })?,
        *xid,
      ),
    }
  }
}

#[derive(Debug, Clone)]
struct ApfsBTreeNode {
  block: Vec<u8>,
  info: ApfsBtreeInfo,
  header: ApfsBtreeNodeHeader,
  table_start: usize,
  key_start: usize,
  value_end: usize,
  fixed_key_size: Option<usize>,
  fixed_value_size: Option<usize>,
}

impl ApfsBTreeNode {
  fn parse_root(block: &[u8]) -> Result<Self> {
    let footer_start = block
      .len()
      .checked_sub(BTREE_INFO_SIZE)
      .ok_or_else(|| Error::InvalidFormat("invalid apfs btree root block size".to_string()))?;
    let info = ApfsBtreeInfo::parse(&block[footer_start..])?;
    Self::parse(block, info, true)
  }

  fn parse_child(block: &[u8], info: ApfsBtreeInfo) -> Result<Self> {
    Self::parse(block, info, false)
  }

  fn parse(block: &[u8], info: ApfsBtreeInfo, root: bool) -> Result<Self> {
    let node_size = usize::try_from(info.node_size)
      .map_err(|_| Error::InvalidRange("apfs btree node size exceeds usize".to_string()))?;
    if block.len() < node_size {
      return Err(Error::InvalidFormat(
        "apfs btree block is shorter than the declared node size".to_string(),
      ));
    }

    let object_header = ApfsObjectHeader::parse(block)?;
    let type_code = object_header.object_type & OBJECT_TYPE_MASK;
    if root {
      if type_code != OBJECT_TYPE_BTREE && type_code != OBJECT_TYPE_BTREE_NODE && type_code != 0 {
        return Err(Error::InvalidFormat(format!(
          "invalid apfs btree root object type: 0x{:08x}",
          object_header.object_type
        )));
      }
    } else if type_code != OBJECT_TYPE_BTREE_NODE {
      return Err(Error::InvalidFormat(format!(
        "invalid apfs btree node object type: 0x{:08x}",
        object_header.object_type
      )));
    }

    let header_offset = OBJECT_HEADER_SIZE;
    let header = ApfsBtreeNodeHeader::parse(read_slice(
      block,
      header_offset,
      BTREE_NODE_HEADER_SIZE,
      "apfs btree node header",
    )?)?;
    let key_count = usize::try_from(header.key_count)
      .map_err(|_| Error::InvalidRange("apfs btree key count exceeds usize".to_string()))?;
    let entry_size = if (header.flags & BTNODE_FIXED_KV_SIZE) != 0 {
      4usize
    } else {
      8usize
    };
    let table_length = usize::from(header.table_space_length);
    if table_length < key_count.saturating_mul(entry_size) {
      return Err(Error::InvalidFormat(
        "apfs btree table space is too small for the number of entries".to_string(),
      ));
    }

    let table_start = header_offset
      .checked_add(BTREE_NODE_HEADER_SIZE)
      .and_then(|value| value.checked_add(usize::from(header.table_space_offset)))
      .ok_or_else(|| Error::InvalidRange("apfs btree table offset overflow".to_string()))?;
    let key_start = table_start
      .checked_add(table_length)
      .ok_or_else(|| Error::InvalidRange("apfs btree key offset overflow".to_string()))?;
    let footer_size = if root { BTREE_INFO_SIZE } else { 0 };
    let value_end = node_size
      .checked_sub(footer_size)
      .ok_or_else(|| Error::InvalidRange("apfs btree footer offset overflow".to_string()))?;
    if key_start > value_end {
      return Err(Error::InvalidFormat(
        "apfs btree key area overlaps the value area".to_string(),
      ));
    }

    Ok(Self {
      block: block[..node_size].to_vec(),
      info,
      header,
      table_start,
      key_start,
      value_end,
      fixed_key_size: if info.key_size == 0 {
        None
      } else {
        Some(usize::try_from(info.key_size).map_err(|_| {
          Error::InvalidRange("apfs btree fixed key size exceeds usize".to_string())
        })?)
      },
      fixed_value_size: if info.value_size == 0 {
        None
      } else {
        Some(usize::try_from(info.value_size).map_err(|_| {
          Error::InvalidRange("apfs btree fixed value size exceeds usize".to_string())
        })?)
      },
    })
  }

  fn is_leaf(&self) -> bool {
    (self.header.flags & BTNODE_LEAF) != 0
  }

  fn key_count(&self) -> usize {
    self.header.key_count as usize
  }

  fn key(&self, index: usize) -> Result<&[u8]> {
    let entry = self.entry(index)?;
    read_slice_bytes(
      self.block(),
      self.key_start,
      usize::from(entry.key_offset),
      entry.key_length,
      "apfs btree key",
    )
  }

  fn value(&self, index: usize) -> Result<&[u8]> {
    let entry = self.entry(index)?;
    let start = self
      .value_end
      .checked_sub(usize::from(entry.value_offset))
      .ok_or_else(|| Error::InvalidRange("apfs btree value offset underflow".to_string()))?;
    read_slice(self.block(), start, entry.value_length, "apfs btree value")
  }

  fn child_identifier(&self, index: usize) -> Result<u64> {
    let value = self.value(index)?;
    if value.len() < 8 {
      return Err(Error::Unsupported(
        "apfs btree branch values are too short to contain a child identifier".to_string(),
      ));
    }
    read_u64_le(value, 0)
  }

  fn floor_index<F>(&self, compare: &F) -> Result<Option<usize>>
  where
    F: Fn(&[u8]) -> Ordering, {
    let key_count = self.key_count();
    if key_count == 0 {
      return Ok(None);
    }

    let mut lo = 0usize;
    let mut hi = key_count;
    let mut candidate = None;
    while lo < hi {
      let mid = lo + (hi - lo) / 2;
      match compare(self.key(mid)?) {
        Ordering::Greater => {
          hi = mid;
        }
        Ordering::Equal | Ordering::Less => {
          candidate = Some(mid);
          lo = mid + 1;
        }
      }
    }
    Ok(candidate)
  }

  fn entry(&self, index: usize) -> Result<ApfsBTreeEntry> {
    if index >= self.key_count() {
      return Err(Error::NotFound(format!(
        "apfs btree key index {index} is out of bounds"
      )));
    }

    let entry_size = if (self.header.flags & BTNODE_FIXED_KV_SIZE) != 0 {
      4usize
    } else {
      8usize
    };
    let offset = self
      .table_start
      .checked_add(index.saturating_mul(entry_size))
      .ok_or_else(|| Error::InvalidRange("apfs btree toc offset overflow".to_string()))?;
    if (self.header.flags & BTNODE_FIXED_KV_SIZE) != 0 {
      let key_offset = read_u16_le(self.block(), offset)?;
      let value_offset = read_u16_le(self.block(), offset + 2)?;
      let key_length = self.fixed_key_size.ok_or_else(|| {
        Error::InvalidFormat(
          "apfs btree fixed-size node is missing a declared key size".to_string(),
        )
      })?;
      let value_length = self.fixed_value_size.ok_or_else(|| {
        Error::InvalidFormat(
          "apfs btree fixed-size node is missing a declared value size".to_string(),
        )
      })?;
      return Ok(ApfsBTreeEntry {
        key_offset,
        key_length,
        value_offset,
        value_length,
      });
    }

    Ok(ApfsBTreeEntry {
      key_offset: read_u16_le(self.block(), offset)?,
      key_length: usize::from(read_u16_le(self.block(), offset + 2)?),
      value_offset: read_u16_le(self.block(), offset + 4)?,
      value_length: usize::from(read_u16_le(self.block(), offset + 6)?),
    })
  }

  fn block(&self) -> &[u8] {
    &self.block
  }
}

#[derive(Debug, Clone, Copy)]
struct ApfsBTreeEntry {
  key_offset: u16,
  key_length: usize,
  value_offset: u16,
  value_length: usize,
}

fn read_blocks(
  source: &dyn crate::ByteSource, block_size: u32, address: u64, count: u64,
) -> Result<Vec<u8>> {
  let byte_offset = address
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("apfs block offset overflow".to_string()))?;
  let byte_count = count
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("apfs block count overflow".to_string()))?;
  let byte_count = usize::try_from(byte_count)
    .map_err(|_| Error::InvalidRange("apfs byte count exceeds usize".to_string()))?;
  source.read_bytes_at(byte_offset, byte_count)
}

fn read_object_block(
  source: &dyn crate::ByteSource, block_size: u32, address: u64,
  decryptor: Option<&Arc<super::crypto::ApfsXtsCipher>>,
) -> Result<Vec<u8>> {
  let block = read_blocks(source, block_size, address, 1)?;
  if object_block_matches(&block) || decryptor.is_none() {
    return Ok(block);
  }

  let mut decrypted = block.clone();
  let sectors_per_block = u64::from(block_size / 512);
  decryptor.unwrap().decrypt(
    address
      .checked_mul(sectors_per_block)
      .ok_or_else(|| Error::InvalidRange("apfs metadata sector index overflow".to_string()))?,
    &mut decrypted,
  )?;
  Ok(decrypted)
}

fn object_block_matches(block: &[u8]) -> bool {
  let Ok(header) = ApfsObjectHeader::parse(block) else {
    return false;
  };
  matches!(
    header.type_code(),
    OBJECT_TYPE_BTREE | OBJECT_TYPE_BTREE_NODE
  ) && header.validate_checksum(block)
}

fn read_slice_bytes<'a>(
  bytes: &'a [u8], base: usize, offset: usize, length: usize, what: &str,
) -> Result<&'a [u8]> {
  let start = base
    .checked_add(offset)
    .ok_or_else(|| Error::InvalidRange(format!("{what} offset overflow")))?;
  read_slice(bytes, start, length, what)
}

fn lookup_omap_address(tree: &ApfsBTree, oid: u64, xid: u64) -> Result<u64> {
  let (key, value) = tree.search_floor(|other| compare_omap_key(other, oid, xid))?;
  let key_oid = read_u64_le(&key, 0)?;
  if key_oid != oid {
    return Err(Error::NotFound(format!(
      "apfs omap entry was not found for oid {oid}"
    )));
  }
  let flags = u32::from_le_bytes(
    value
      .get(0..4)
      .ok_or_else(|| Error::InvalidFormat("apfs omap value is truncated".to_string()))?
      .try_into()
      .map_err(|_| Error::InvalidFormat("apfs omap value is truncated".to_string()))?,
  );
  if (flags & super::ondisk::OMAP_VAL_DELETED) != 0 {
    return Err(Error::NotFound(format!(
      "apfs omap entry for oid {oid} is marked deleted"
    )));
  }
  read_u64_le(&value, 8)
}

fn compare_omap_key(other: &[u8], oid: u64, xid: u64) -> Ordering {
  let other_oid = read_u64_le(other, 0).unwrap_or(0);
  let other_xid = read_u64_le(other, 8).unwrap_or(0);
  match other_oid.cmp(&oid) {
    Ordering::Equal => other_xid.cmp(&xid),
    ordering => ordering,
  }
}

#[cfg(test)]
mod tests {
  use std::fs;

  use super::*;
  use crate::filesystems::apfs::ondisk::{
    BTNODE_FIXED_KV_SIZE, BTNODE_LEAF, BTNODE_ROOT, BTREE_PHYSICAL,
  };

  #[test]
  fn parses_fixed_size_btree_fixtures() {
    let root = fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("apfs")
        .join("libfsapfs")
        .join("container_object_map_btree.1"),
    )
    .unwrap();

    let node = ApfsBTreeNode::parse_root(&root).unwrap();

    assert_eq!(
      node.header.flags,
      BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE
    );
    assert_eq!(node.header.key_count, 0);
    assert_eq!(node.info.flags & BTREE_PHYSICAL, BTREE_PHYSICAL);
    assert_eq!(node.key_count(), 0);
  }
}
