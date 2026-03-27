//! Shared HFS/HFS+ catalog B-tree helpers.

use crate::{ByteSource, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BTreeHeader {
  pub node_size: u16,
  pub first_leaf_node: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BTreeNodeDescriptor {
  pub next_node: u32,
  pub previous_node: u32,
  pub node_type: i8,
  pub node_level: u8,
  pub record_count: u16,
}

pub(crate) fn parse_btree_header(source: &dyn ByteSource) -> Result<BTreeHeader> {
  let header_bytes = source.read_bytes_at(0, 120)?;
  let descriptor = parse_node_descriptor(&header_bytes)?;
  if descriptor.node_type != 1 {
    return Err(Error::InvalidFormat(
      "hfs catalog b-tree header node is missing".to_string(),
    ));
  }
  let node_size = be_u16(&header_bytes[32..34]);
  if node_size < 512 || !node_size.is_power_of_two() {
    return Err(Error::InvalidFormat(format!(
      "unsupported hfs b-tree node size: {node_size}"
    )));
  }

  Ok(BTreeHeader {
    node_size,
    first_leaf_node: be_u32(&header_bytes[24..28]),
  })
}

pub(crate) fn read_leaf_records(
  source: &dyn ByteSource, header: &BTreeHeader,
) -> Result<Vec<Vec<u8>>> {
  let node_size = usize::from(header.node_size);
  let mut records = Vec::new();
  let mut next_leaf = header.first_leaf_node;

  while next_leaf != 0 {
    let node = source.read_bytes_at(
      u64::from(next_leaf) * u64::from(header.node_size),
      node_size,
    )?;
    let descriptor = parse_node_descriptor(&node)?;
    if descriptor.node_type != -1 {
      return Err(Error::InvalidFormat(format!(
        "expected an hfs leaf node, found node type {}",
        descriptor.node_type
      )));
    }
    for (start, end) in record_ranges(&node, descriptor.record_count)? {
      records.push(node[start..end].to_vec());
    }
    next_leaf = descriptor.next_node;
  }

  Ok(records)
}

fn parse_node_descriptor(node: &[u8]) -> Result<BTreeNodeDescriptor> {
  if node.len() < 14 {
    return Err(Error::InvalidFormat(
      "hfs b-tree node descriptor is truncated".to_string(),
    ));
  }

  Ok(BTreeNodeDescriptor {
    next_node: be_u32(&node[0..4]),
    previous_node: be_u32(&node[4..8]),
    node_type: node[8] as i8,
    node_level: node[9],
    record_count: be_u16(&node[10..12]),
  })
}

fn record_ranges(node: &[u8], record_count: u16) -> Result<Vec<(usize, usize)>> {
  let count = usize::from(record_count)
    .checked_add(1)
    .ok_or_else(|| Error::InvalidRange("hfs record count overflow".to_string()))?;
  let tail_size = count
    .checked_mul(2)
    .ok_or_else(|| Error::InvalidRange("hfs record table size overflow".to_string()))?;
  if tail_size > node.len() {
    return Err(Error::InvalidFormat(
      "hfs record offset table exceeds the node size".to_string(),
    ));
  }

  let table = &node[node.len() - tail_size..];
  let offsets = (0..count)
    .map(|index| be_u16(&table[index * 2..index * 2 + 2]))
    .collect::<Vec<_>>();
  let offsets = offsets
    .into_iter()
    .rev()
    .map(usize::from)
    .collect::<Vec<_>>();
  if offsets.windows(2).any(|pair| pair[0] > pair[1]) {
    return Err(Error::InvalidFormat(
      "hfs record offsets are not in ascending order".to_string(),
    ));
  }

  Ok(offsets.windows(2).map(|pair| (pair[0], pair[1])).collect())
}

fn be_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_be_bytes(raw)
}

fn be_u32(bytes: &[u8]) -> u32 {
  let mut raw = [0u8; 4];
  raw.copy_from_slice(bytes);
  u32::from_be_bytes(raw)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn extracts_record_ranges_from_a_node() {
    let mut node = vec![0u8; 512];
    node[8] = 0xFF;
    node[10..12].copy_from_slice(&2u16.to_be_bytes());
    node[512 - 6..512 - 4].copy_from_slice(&100u16.to_be_bytes());
    node[512 - 4..512 - 2].copy_from_slice(&40u16.to_be_bytes());
    node[512 - 2..512].copy_from_slice(&14u16.to_be_bytes());

    assert_eq!(record_ranges(&node, 2).unwrap(), vec![(14, 40), (40, 100)]);
  }
}
