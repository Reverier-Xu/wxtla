//! NTFS directory index parsing for `$I30`.

use std::collections::HashSet;

use crate::{
  ByteSource, ByteSourceHandle, Error, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind,
  Result,
};

const ATTRIBUTE_TYPE_FILE_NAME: u32 = 0x0000_0030;
const INDEX_ROOT_HEADER_SIZE: usize = 16;
const INDEX_NODE_HEADER_SIZE: usize = 16;
const INDEX_ENTRY_HEADER_SIZE: usize = 16;
const INDEX_RECORD_NODE_OFFSET: usize = 24;
const INDEX_RECORD_SIGNATURE: &[u8; 4] = b"INDX";

const INDEX_ENTRY_FLAG_BRANCH: u32 = 0x0000_0001;
const INDEX_ENTRY_FLAG_LAST: u32 = 0x0000_0002;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NtfsIndexRootHeader {
  attribute_type: u32,
  index_record_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NtfsIndexNodeHeader {
  values_offset: u32,
  size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NtfsIndexEntryHeader {
  file_reference: u64,
  entry_size: u16,
  key_size: u16,
  flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NtfsIndexFileNameKey {
  name: String,
  namespace: u8,
}

#[derive(Clone, Copy)]
struct NtfsIndexAllocation<'a> {
  source: Option<&'a dyn ByteSource>,
  cluster_size: u64,
  index_record_size: u32,
}

pub(crate) fn read_directory_index_entries(
  root_data: &[u8], allocation_source: Option<ByteSourceHandle>, cluster_size: u64,
  lookup_kind: &mut impl FnMut(u64) -> Result<NamespaceNodeKind>,
) -> Result<Vec<NamespaceDirectoryEntry>> {
  let root_header = parse_index_root_header(root_data)?;
  if root_header.attribute_type != ATTRIBUTE_TYPE_FILE_NAME {
    return Err(Error::invalid_format(format!(
      "unsupported ntfs $I30 index root attribute type: 0x{:08x}",
      root_header.attribute_type
    )));
  }

  let mut entries = Vec::new();
  let mut visited_subnodes = HashSet::new();
  let allocation = NtfsIndexAllocation {
    source: allocation_source.as_deref(),
    cluster_size,
    index_record_size: root_header.index_record_size,
  };
  collect_directory_entries_from_node(
    root_data,
    INDEX_ROOT_HEADER_SIZE,
    allocation,
    &mut visited_subnodes,
    &mut entries,
    lookup_kind,
  )?;
  Ok(entries)
}

fn collect_directory_entries_from_node(
  data: &[u8], node_offset: usize, allocation: NtfsIndexAllocation<'_>,
  visited_subnodes: &mut HashSet<u64>, entries: &mut Vec<NamespaceDirectoryEntry>,
  lookup_kind: &mut impl FnMut(u64) -> Result<NamespaceNodeKind>,
) -> Result<()> {
  let node_header = parse_index_node_header(data, node_offset)?;
  let mut entry_offset = node_offset
    .checked_add(
      usize::try_from(node_header.values_offset)
        .map_err(|_| Error::invalid_range("ntfs index values offset is too large"))?,
    )
    .ok_or_else(|| Error::invalid_range("ntfs index entry offset overflow"))?;
  let entry_end = node_offset
    .checked_add(
      usize::try_from(node_header.size)
        .map_err(|_| Error::invalid_range("ntfs index node size is too large"))?,
    )
    .ok_or_else(|| Error::invalid_range("ntfs index node size overflow"))?;
  if entry_end > data.len() {
    return Err(Error::invalid_format(
      "ntfs index node extends past the available bytes".to_string(),
    ));
  }

  while entry_offset < entry_end {
    let entry = parse_index_entry_header(data, entry_offset, entry_end)?;
    let key_offset = entry_offset
      .checked_add(INDEX_ENTRY_HEADER_SIZE)
      .ok_or_else(|| Error::invalid_range("ntfs index key offset overflow"))?;
    let key_end = key_offset
      .checked_add(usize::from(entry.key_size))
      .ok_or_else(|| Error::invalid_range("ntfs index key range overflow"))?;
    let entry_end_offset = entry_offset
      .checked_add(usize::from(entry.entry_size))
      .ok_or_else(|| Error::invalid_range("ntfs index entry range overflow"))?;
    if key_end > entry_end_offset || entry_end_offset > entry_end {
      return Err(Error::invalid_format(
        "ntfs index entry exceeds the available node bytes".to_string(),
      ));
    }
    let value_size = usize::from(entry.entry_size)
      .checked_sub(INDEX_ENTRY_HEADER_SIZE + usize::from(entry.key_size))
      .ok_or_else(|| Error::invalid_format("ntfs index entry key size is invalid"))?;

    if entry.flags & INDEX_ENTRY_FLAG_BRANCH != 0 {
      let child_vcn = read_branch_vcn(data, entry_end_offset, value_size)?;
      if visited_subnodes.insert(child_vcn) {
        let subnode = read_index_record(
          allocation.source.ok_or_else(|| {
            Error::invalid_format(
              "ntfs $I30 index refers to index-allocation buffers, but $INDEX_ALLOCATION is missing"
                .to_string(),
            )
          })?,
          child_vcn,
          allocation.cluster_size,
          allocation.index_record_size,
        )?;
        collect_directory_entries_from_node(
          &subnode,
          INDEX_RECORD_NODE_OFFSET,
          allocation,
          visited_subnodes,
          entries,
          lookup_kind,
        )?;
      }
    }

    if entry.flags & INDEX_ENTRY_FLAG_LAST != 0 {
      break;
    }
    if entry.key_size == 0 {
      return Err(Error::invalid_format(
        "ntfs index entry is missing its file-name key".to_string(),
      ));
    }

    let file_name = parse_index_file_name_key(&data[key_offset..key_end])?;
    if file_name.namespace != 2 && file_name.name != "." && file_name.name != ".." {
      let record_number = decode_file_reference(&entry.file_reference.to_le_bytes());
      let kind = lookup_kind(record_number)?;
      entries.push(NamespaceDirectoryEntry::new(
        file_name.name,
        NamespaceNodeId::from_u64(record_number),
        kind,
      ));
    }

    entry_offset = align_up(entry_end_offset, 8)?;
  }

  Ok(())
}

fn read_index_record(
  source: &dyn ByteSource, child_vcn: u64, cluster_size: u64, index_record_size: u32,
) -> Result<Vec<u8>> {
  let offset = child_vcn
    .checked_mul(cluster_size)
    .ok_or_else(|| Error::invalid_range("ntfs index record offset overflow"))?;
  let raw = source.read_bytes_at(
    offset,
    usize::try_from(index_record_size)
      .map_err(|_| Error::invalid_range("ntfs index record size is too large"))?,
  )?;
  let fixed = apply_update_sequence(&raw)?;
  if fixed.len() < INDEX_RECORD_NODE_OFFSET || &fixed[0..4] != INDEX_RECORD_SIGNATURE {
    return Err(Error::invalid_format(
      "ntfs index-allocation buffer has an invalid signature".to_string(),
    ));
  }
  Ok(fixed)
}

fn parse_index_root_header(data: &[u8]) -> Result<NtfsIndexRootHeader> {
  if data.len() < INDEX_ROOT_HEADER_SIZE + INDEX_NODE_HEADER_SIZE {
    return Err(Error::invalid_format(
      "ntfs $INDEX_ROOT attribute is truncated".to_string(),
    ));
  }

  Ok(NtfsIndexRootHeader {
    attribute_type: le_u32(&data[0..4]),
    index_record_size: le_u32(&data[8..12]),
  })
}

fn parse_index_node_header(data: &[u8], node_offset: usize) -> Result<NtfsIndexNodeHeader> {
  let header_end = node_offset
    .checked_add(INDEX_NODE_HEADER_SIZE)
    .ok_or_else(|| Error::invalid_range("ntfs index node header overflow"))?;
  let header = data
    .get(node_offset..header_end)
    .ok_or_else(|| Error::invalid_format("ntfs index node header exceeds the available bytes"))?;
  let values_offset = le_u32(&header[0..4]);
  let size = le_u32(&header[4..8]);
  if values_offset < INDEX_NODE_HEADER_SIZE as u32 || values_offset >= size {
    return Err(Error::invalid_format(
      "ntfs index node values offset is invalid".to_string(),
    ));
  }

  Ok(NtfsIndexNodeHeader {
    values_offset,
    size,
  })
}

fn parse_index_entry_header(
  data: &[u8], entry_offset: usize, entry_end: usize,
) -> Result<NtfsIndexEntryHeader> {
  let header_end = entry_offset
    .checked_add(INDEX_ENTRY_HEADER_SIZE)
    .ok_or_else(|| Error::invalid_range("ntfs index entry header overflow"))?;
  let header = data
    .get(entry_offset..header_end)
    .ok_or_else(|| Error::invalid_format("ntfs index entry header exceeds the available bytes"))?;
  let entry_size = le_u16(&header[8..10]);
  if usize::from(entry_size) < INDEX_ENTRY_HEADER_SIZE
    || entry_offset + usize::from(entry_size) > entry_end
  {
    return Err(Error::invalid_format(
      "ntfs index entry size is invalid".to_string(),
    ));
  }

  Ok(NtfsIndexEntryHeader {
    file_reference: le_u64(&header[0..8]),
    entry_size,
    key_size: le_u16(&header[10..12]),
    flags: le_u32(&header[12..16]),
  })
}

fn parse_index_file_name_key(data: &[u8]) -> Result<NtfsIndexFileNameKey> {
  if data.len() < 66 {
    return Err(Error::invalid_format(
      "ntfs directory index file-name key is truncated".to_string(),
    ));
  }

  Ok(NtfsIndexFileNameKey {
    name: read_utf16le(
      data,
      66,
      usize::from(data[64]),
      "ntfs directory index file-name",
    )?,
    namespace: data[65],
  })
}

fn read_branch_vcn(data: &[u8], entry_end: usize, value_size: usize) -> Result<u64> {
  if value_size < 8 {
    return Err(Error::invalid_format(
      "ntfs branch index entry is missing its child VCN".to_string(),
    ));
  }
  let value_offset = entry_end
    .checked_sub(8)
    .ok_or_else(|| Error::invalid_range("ntfs branch VCN offset overflow"))?;
  Ok(le_u64(data.get(value_offset..entry_end).ok_or_else(
    || Error::invalid_format("ntfs branch VCN exceeds the available bytes"),
  )?))
}

fn apply_update_sequence(raw: &[u8]) -> Result<Vec<u8>> {
  if raw.len() < 48 {
    return Err(Error::invalid_format(
      "ntfs index record is too small".to_string(),
    ));
  }

  let mut fixed = raw.to_vec();
  let update_sequence_offset = usize::from(le_u16(&fixed[4..6]));
  let update_sequence_count = usize::from(le_u16(&fixed[6..8]));
  if update_sequence_count == 0 {
    return Err(Error::invalid_format(
      "ntfs index update-sequence array must contain at least one element".to_string(),
    ));
  }
  let array_size = update_sequence_count
    .checked_mul(2)
    .ok_or_else(|| Error::invalid_range("ntfs index update-sequence overflow"))?;
  let update_sequence_end = update_sequence_offset
    .checked_add(array_size)
    .ok_or_else(|| Error::invalid_range("ntfs index update-sequence overflow"))?;
  if update_sequence_end > fixed.len() {
    return Err(Error::invalid_format(
      "ntfs index update-sequence array exceeds the index record".to_string(),
    ));
  }

  let sequence = [
    fixed[update_sequence_offset],
    fixed[update_sequence_offset + 1],
  ];
  for index in 1..update_sequence_count {
    let sector_end = index
      .checked_mul(512)
      .ok_or_else(|| Error::invalid_range("ntfs index sector end overflow"))?;
    if sector_end > fixed.len() {
      return Err(Error::invalid_format(
        "ntfs index update-sequence array references data beyond the index record".to_string(),
      ));
    }
    if fixed[sector_end - 2..sector_end] != sequence {
      return Err(Error::invalid_format(
        "ntfs index update-sequence array does not match the protected sector suffix".to_string(),
      ));
    }

    let replacement_offset = update_sequence_offset
      .checked_add(index * 2)
      .ok_or_else(|| Error::invalid_range("ntfs index replacement offset overflow"))?;
    fixed[sector_end - 2] = fixed[replacement_offset];
    fixed[sector_end - 1] = fixed[replacement_offset + 1];
  }

  Ok(fixed)
}

fn read_utf16le(bytes: &[u8], offset: usize, chars: usize, label: &str) -> Result<String> {
  let byte_len = chars
    .checked_mul(2)
    .ok_or_else(|| Error::invalid_range(format!("{label} length overflow")))?;
  let end = offset
    .checked_add(byte_len)
    .ok_or_else(|| Error::invalid_range(format!("{label} offset overflow")))?;
  let slice = bytes
    .get(offset..end)
    .ok_or_else(|| Error::invalid_format(format!("{label} exceeds the available bytes")))?;
  let units = slice
    .chunks_exact(2)
    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  String::from_utf16(&units)
    .map_err(|_| Error::invalid_format(format!("{label} is not valid UTF-16")))
}

fn decode_file_reference(bytes: &[u8]) -> u64 {
  let mut raw = [0u8; 8];
  raw[..6].copy_from_slice(&bytes[..6]);
  u64::from_le_bytes(raw)
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

fn le_u64(bytes: &[u8]) -> u64 {
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  u64::from_le_bytes(raw)
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
  let remainder = value % alignment;
  if remainder == 0 {
    Ok(value)
  } else {
    value
      .checked_add(alignment - remainder)
      .ok_or_else(|| Error::invalid_range("ntfs index alignment overflow"))
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::BytesDataSource;

  #[test]
  fn reads_root_directory_entries() {
    let root = build_index_root(
      vec![
        build_index_entry(42, Some(("child.txt", 1)), 0, None),
        build_index_entry(0, None, INDEX_ENTRY_FLAG_LAST, None),
      ],
      4096,
      false,
    );

    let entries =
      read_directory_index_entries(&root, None, 4096, &mut |_| Ok(NamespaceNodeKind::File))
        .unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "child.txt");
    assert_eq!(entries[0].kind, NamespaceNodeKind::File);
  }

  #[test]
  fn reads_index_allocation_subnodes() {
    let root = build_index_root(
      vec![build_index_entry(
        0,
        None,
        INDEX_ENTRY_FLAG_BRANCH | INDEX_ENTRY_FLAG_LAST,
        Some(0),
      )],
      4096,
      true,
    );
    let allocation = Arc::new(BytesDataSource::new(build_index_record(
      0,
      vec![
        build_index_entry(55, Some(("nested.txt", 1)), 0, None),
        build_index_entry(0, None, INDEX_ENTRY_FLAG_LAST, None),
      ],
      false,
      4096,
    ))) as ByteSourceHandle;

    let entries = read_directory_index_entries(&root, Some(allocation), 4096, &mut |_| {
      Ok(NamespaceNodeKind::File)
    })
    .unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "nested.txt");
  }

  fn build_index_root(
    entries: Vec<Vec<u8>>, index_record_size: u32, has_children: bool,
  ) -> Vec<u8> {
    let entry_data = encode_entries(entries);
    let node_size = u32::try_from(INDEX_NODE_HEADER_SIZE + entry_data.len()).unwrap();
    let mut bytes = vec![0u8; INDEX_ROOT_HEADER_SIZE + INDEX_NODE_HEADER_SIZE + entry_data.len()];
    bytes[0..4].copy_from_slice(&ATTRIBUTE_TYPE_FILE_NAME.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&index_record_size.to_le_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&(INDEX_NODE_HEADER_SIZE as u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&node_size.to_le_bytes());
    bytes[24..28].copy_from_slice(&node_size.to_le_bytes());
    bytes[28..32].copy_from_slice(&u32::from(has_children).to_le_bytes());
    bytes[32..].copy_from_slice(&entry_data);
    bytes
  }

  fn build_index_record(
    vcn: u64, entries: Vec<Vec<u8>>, has_children: bool, index_record_size: usize,
  ) -> Vec<u8> {
    let entry_data = encode_entries(entries);
    let values_offset = 40usize;
    let node_size = u32::try_from(values_offset + entry_data.len()).unwrap();
    let mut bytes = vec![0u8; index_record_size];
    bytes[0..4].copy_from_slice(INDEX_RECORD_SIGNATURE);
    bytes[4..6].copy_from_slice(&40u16.to_le_bytes());
    bytes[6..8]
      .copy_from_slice(&(u16::try_from(index_record_size / 512 + 1).unwrap()).to_le_bytes());
    bytes[16..24].copy_from_slice(&vcn.to_le_bytes());
    bytes[24..28].copy_from_slice(&(values_offset as u32).to_le_bytes());
    bytes[28..32].copy_from_slice(&node_size.to_le_bytes());
    bytes[32..36]
      .copy_from_slice(&(index_record_size as u32 - INDEX_RECORD_NODE_OFFSET as u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&u32::from(has_children).to_le_bytes());
    bytes[64..64 + entry_data.len()].copy_from_slice(&entry_data);

    bytes[40..42].copy_from_slice(&0xAA55u16.to_le_bytes());
    for sector in 0..(index_record_size / 512) {
      let usa_offset = 42 + sector * 2;
      bytes[usa_offset..usa_offset + 2].copy_from_slice(&0u16.to_le_bytes());
      let sector_end = (sector + 1) * 512;
      bytes[sector_end - 2..sector_end].copy_from_slice(&0xAA55u16.to_le_bytes());
    }

    bytes
  }

  fn encode_entries(entries: Vec<Vec<u8>>) -> Vec<u8> {
    let mut data = Vec::new();
    let entry_count = entries.len();
    for (index, entry) in entries.into_iter().enumerate() {
      data.extend_from_slice(&entry);
      if index + 1 != entry_count {
        let padding = (8 - data.len() % 8) % 8;
        data.resize(data.len() + padding, 0);
      }
    }
    data
  }

  fn build_index_entry(
    record_number: u64, name: Option<(&str, u8)>, flags: u32, child_vcn: Option<u64>,
  ) -> Vec<u8> {
    let key = name.map_or_else(Vec::new, |(name, namespace)| {
      build_file_name_key(name, namespace)
    });
    let value = child_vcn.map_or_else(Vec::new, |vcn| vcn.to_le_bytes().to_vec());
    let size = u16::try_from(INDEX_ENTRY_HEADER_SIZE + key.len() + value.len()).unwrap();
    let mut bytes = vec![0u8; usize::from(size)];
    bytes[0..8].copy_from_slice(&record_number.to_le_bytes());
    bytes[8..10].copy_from_slice(&size.to_le_bytes());
    bytes[10..12].copy_from_slice(&(key.len() as u16).to_le_bytes());
    bytes[12..16].copy_from_slice(&flags.to_le_bytes());
    bytes[16..16 + key.len()].copy_from_slice(&key);
    bytes[16 + key.len()..].copy_from_slice(&value);
    bytes
  }

  fn build_file_name_key(name: &str, namespace: u8) -> Vec<u8> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let mut bytes = vec![0u8; 66 + units.len() * 2];
    bytes[56..60].copy_from_slice(&0u32.to_le_bytes());
    bytes[64] = u8::try_from(units.len()).unwrap();
    bytes[65] = namespace;
    for (index, unit) in units.into_iter().enumerate() {
      let offset = 66 + index * 2;
      bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes
  }
}
