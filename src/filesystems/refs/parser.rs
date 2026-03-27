//! Minimal ReFS v1 metadata parsers.

use std::sync::Arc;

use crate::{ByteSource, Error, Result};

pub(crate) const VOLUME_HEADER_SIZE: usize = 512;
pub(crate) const METADATA_BLOCK_HEADER_V1_SIZE: usize = 48;
pub(crate) const METADATA_BLOCK_HEADER_V3_SIZE: usize = 80;
pub(crate) const SUPERBLOCK_SIZE: usize = 48;
pub(crate) const CHECKPOINT_HEADER_SIZE: usize = 16;
pub(crate) const CHECKPOINT_TRAILER_V1_SIZE: usize = 28;
pub(crate) const CHECKPOINT_TRAILER_V3_SIZE: usize = 52;
pub(crate) const BLOCK_REFERENCE_V1_SIZE: usize = 16;
pub(crate) const BLOCK_REFERENCE_V3_MIN_SIZE: usize = 40;
pub(crate) const TREE_HEADER_SIZE: usize = 36;
pub(crate) const NODE_HEADER_SIZE: usize = 32;
pub(crate) const NODE_RECORD_HEADER_SIZE: usize = 14;
pub(crate) const DIRECTORY_VALUES_SIZE: usize = 72;
pub(crate) const FILE_VALUES_SIZE: usize = 128;
pub(crate) const ATTRIBUTE_RESIDENT_HEADER_SIZE: usize = 60;
pub(crate) const ATTRIBUTE_NON_RESIDENT_HEADER_SIZE: usize = 96;
pub(crate) const DATA_RUN_SIZE: usize = 32;

pub(crate) const OBJECTS_TREE_INDEX: usize = 0;
pub(crate) const ROOT_DIRECTORY_OBJECT_ID: u64 = 0x0000_0600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefsVolumeHeader {
  pub bytes_per_sector: u32,
  pub cluster_block_size: u32,
  pub metadata_block_size: u32,
  pub volume_size: u64,
  pub major_version: u8,
  pub minor_version: u8,
  pub volume_serial_number: u64,
  pub container_size: u64,
}

impl RefsVolumeHeader {
  pub fn read(source: &dyn ByteSource) -> Result<Self> {
    let bytes = source.read_bytes_at(0, VOLUME_HEADER_SIZE)?;
    Self::from_bytes(&bytes)
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    let header: &[u8; VOLUME_HEADER_SIZE] = bytes.try_into().map_err(|_| {
      Error::InvalidFormat("refs volume header must be exactly 512 bytes".to_string())
    })?;
    Self::from_header(header)
  }

  pub fn from_header(header: &[u8; VOLUME_HEADER_SIZE]) -> Result<Self> {
    if &header[3..7] != b"ReFS" {
      return Err(Error::InvalidFormat(
        "refs volume header signature is missing".to_string(),
      ));
    }
    if &header[16..20] != b"FSRS" {
      return Err(Error::InvalidFormat(
        "refs secondary volume signature is missing".to_string(),
      ));
    }

    let bytes_per_sector = le_u32(&header[32..36]);
    if !matches!(bytes_per_sector, 256 | 512 | 1024 | 2048 | 4096) {
      return Err(Error::InvalidFormat(format!(
        "unsupported refs bytes-per-sector value: {bytes_per_sector}"
      )));
    }

    let sectors_per_cluster_block = le_u32(&header[36..40]);
    let cluster_block_size = sectors_per_cluster_block
      .checked_mul(bytes_per_sector)
      .ok_or_else(|| Error::InvalidRange("refs cluster block size overflow".to_string()))?;
    if !matches!(cluster_block_size, 4096 | 65536) {
      return Err(Error::InvalidFormat(format!(
        "unsupported refs cluster block size: {cluster_block_size}"
      )));
    }

    let major_version = header[40];
    let minor_version = header[41];
    if !matches!(major_version, 1 | 3) {
      return Err(Error::InvalidFormat(format!(
        "unsupported refs major version: {major_version}.{minor_version}"
      )));
    }

    let number_of_sectors = le_u64(&header[24..32]);
    let volume_size = number_of_sectors
      .checked_mul(u64::from(bytes_per_sector))
      .and_then(|size| size.checked_add(u64::from(bytes_per_sector)))
      .ok_or_else(|| Error::InvalidRange("refs volume size overflow".to_string()))?;

    Ok(Self {
      bytes_per_sector,
      cluster_block_size,
      metadata_block_size: if major_version == 1 {
        16 * 1024
      } else {
        cluster_block_size
      },
      volume_size,
      major_version,
      minor_version,
      volume_serial_number: le_u64(&header[56..64]),
      container_size: if major_version == 3 {
        let container_size = le_u64(&header[64..72]);
        if container_size == 0 {
          0x4000
        } else {
          container_size / u64::from(cluster_block_size)
        }
      } else {
        le_u64(&header[64..72])
      },
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsMetadataBlockHeaderV1 {
  pub block_number: u64,
  pub sequence_number: u64,
  pub object_identifier: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsSuperblock {
  pub volume_identifier: [u8; 16],
  pub primary_checkpoint_block_number: u64,
  pub secondary_checkpoint_block_number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsBlockReference {
  pub block_numbers: [u64; 4],
  pub checksum_type: u8,
  pub checksum_data_offset: u8,
  pub checksum_data_size: u16,
}

impl RefsBlockReference {
  pub(crate) fn present_block_numbers(&self) -> impl Iterator<Item = u64> + '_ {
    self
      .block_numbers
      .iter()
      .copied()
      .filter(|block_number| *block_number != 0)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsCheckpoint {
  pub sequence_number: u64,
  pub block_references: Vec<RefsBlockReference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsTreeHeader {
  pub table_data_offset: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsNodeHeader {
  pub data_area_start_offset: u32,
  pub data_area_end_offset: u32,
  pub node_level: u8,
  pub node_type_flags: u8,
  pub record_offsets_start_offset: u32,
  pub number_of_record_offsets: u32,
  pub record_offsets_end_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsNodeRecord {
  pub size: u32,
  pub flags: u16,
  pub key_data: Arc<[u8]>,
  pub value_data: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsMinistoreNode {
  pub header_data: Arc<[u8]>,
  pub node_type_flags: u8,
  pub records: Vec<RefsNodeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsDirectoryValues {
  pub object_identifier: u64,
  pub creation_time: u64,
  pub modification_time: u64,
  pub entry_modification_time: u64,
  pub access_time: u64,
  pub file_attribute_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsFileValues {
  pub creation_time: u64,
  pub modification_time: u64,
  pub entry_modification_time: u64,
  pub access_time: u64,
  pub file_attribute_flags: u32,
  pub identifier_lower: u64,
  pub identifier_upper: u64,
  pub data_size: u64,
  pub allocated_data_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsDataRun {
  pub logical_offset: u64,
  pub block_count: u64,
  pub physical_block_number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefsAttributeValue {
  Resident(Arc<[u8]>),
  NonResident {
    allocated_data_size: u64,
    data_size: u64,
    valid_data_size: u64,
    data_runs: Vec<RefsDataRun>,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefsAttribute {
  pub attribute_type: u32,
  pub name: Option<String>,
  pub value: RefsAttributeValue,
}

pub(crate) fn parse_metadata_block_header_v1(bytes: &[u8]) -> Result<RefsMetadataBlockHeaderV1> {
  let header = bytes
    .get(..METADATA_BLOCK_HEADER_V1_SIZE)
    .ok_or_else(|| Error::InvalidFormat("refs metadata block header is truncated".to_string()))?;
  let mut object_identifier = [0u8; 16];
  object_identifier.copy_from_slice(&header[16..32]);

  Ok(RefsMetadataBlockHeaderV1 {
    block_number: le_u64(&header[0..8]),
    sequence_number: le_u64(&header[8..16]),
    object_identifier,
  })
}

pub(crate) fn parse_superblock_metadata(bytes: &[u8], major_version: u8) -> Result<RefsSuperblock> {
  let header_size = metadata_header_size(major_version)?;
  if bytes.len() < header_size + SUPERBLOCK_SIZE {
    return Err(Error::InvalidFormat(
      "refs superblock metadata is truncated".to_string(),
    ));
  }
  let body = &bytes[header_size..];
  let checkpoints_data_offset = le_u32(&body[32..36]);
  let number_of_checkpoints = le_u32(&body[36..40]);
  let self_reference_data_offset = le_u32(&body[40..44]);
  let self_reference_data_size = le_u32(&body[44..48]);
  if number_of_checkpoints != 2 {
    return Err(Error::InvalidFormat(
      "unsupported refs checkpoint count".to_string(),
    ));
  }
  let checkpoints_data_offset = relative_metadata_offset(
    checkpoints_data_offset,
    header_size,
    body.len(),
    SUPERBLOCK_SIZE + header_size,
    "refs checkpoints data",
  )?;
  let self_reference_data_offset = relative_metadata_offset(
    self_reference_data_offset,
    header_size,
    body.len(),
    checkpoints_data_offset + 16 + header_size,
    "refs superblock self reference",
  )?;
  if self_reference_data_offset + self_reference_data_size as usize > body.len() {
    return Err(Error::InvalidFormat(
      "refs superblock self-reference data exceeds the metadata block".to_string(),
    ));
  }

  let checkpoint_data = body
    .get(checkpoints_data_offset..checkpoints_data_offset + 16)
    .ok_or_else(|| Error::InvalidFormat("refs checkpoints data is truncated".to_string()))?;
  let mut volume_identifier = [0u8; 16];
  volume_identifier.copy_from_slice(&body[0..16]);

  Ok(RefsSuperblock {
    volume_identifier,
    primary_checkpoint_block_number: le_u64(&checkpoint_data[0..8]),
    secondary_checkpoint_block_number: le_u64(&checkpoint_data[8..16]),
  })
}

pub(crate) fn parse_checkpoint_metadata(bytes: &[u8], major_version: u8) -> Result<RefsCheckpoint> {
  let header_size = metadata_header_size(major_version)?;
  let checkpoint_trailer_size = checkpoint_trailer_size(major_version)?;
  if bytes.len() < header_size + CHECKPOINT_HEADER_SIZE + checkpoint_trailer_size {
    return Err(Error::InvalidFormat(
      "refs checkpoint metadata is truncated".to_string(),
    ));
  }
  let body = &bytes[header_size..];
  let self_reference_data_offset = le_u32(&body[8..12]);
  let self_reference_data_size = le_u32(&body[12..16]);
  let trailer_offset = CHECKPOINT_HEADER_SIZE;
  let sequence_number = le_u64(&body[trailer_offset..trailer_offset + 8]);
  let number_of_offsets_offset = trailer_offset + if major_version == 1 { 24 } else { 48 };
  let number_of_offsets =
    le_u32(&body[number_of_offsets_offset..number_of_offsets_offset + 4]) as usize;
  let offsets_data_offset = trailer_offset + checkpoint_trailer_size;
  let offsets_end = offsets_data_offset
    .checked_add(number_of_offsets * 4)
    .ok_or_else(|| Error::InvalidRange("refs checkpoint offsets overflow".to_string()))?;
  if offsets_end > body.len() {
    return Err(Error::InvalidFormat(
      "refs checkpoint offset table exceeds the metadata block".to_string(),
    ));
  }

  let self_reference_data_offset = relative_metadata_offset(
    self_reference_data_offset,
    header_size,
    body.len(),
    CHECKPOINT_HEADER_SIZE + header_size,
    "refs checkpoint self reference",
  )?;
  if self_reference_data_offset + self_reference_data_size as usize > body.len() {
    return Err(Error::InvalidFormat(
      "refs checkpoint self-reference data exceeds the metadata block".to_string(),
    ));
  }

  let mut block_references = Vec::with_capacity(number_of_offsets);
  for index in 0..number_of_offsets {
    let raw_offset =
      le_u32(&body[offsets_data_offset + index * 4..offsets_data_offset + index * 4 + 4]);
    let block_reference_offset = relative_metadata_offset(
      raw_offset,
      header_size,
      body.len(),
      self_reference_data_offset + header_size,
      "refs checkpoint block reference",
    )?;
    block_references.push(parse_block_reference(
      &body[block_reference_offset..],
      major_version,
    )?);
  }

  Ok(RefsCheckpoint {
    sequence_number,
    block_references,
  })
}

pub(crate) fn parse_block_reference(bytes: &[u8], major_version: u8) -> Result<RefsBlockReference> {
  match major_version {
    1 => {
      let bytes = bytes
        .get(..BLOCK_REFERENCE_V1_SIZE)
        .ok_or_else(|| Error::InvalidFormat("refs block reference is truncated".to_string()))?;

      Ok(RefsBlockReference {
        block_numbers: [le_u64(&bytes[0..8]), 0, 0, 0],
        checksum_type: bytes[10],
        checksum_data_offset: bytes[11],
        checksum_data_size: le_u16(&bytes[12..14]),
      })
    }
    3 => {
      let prefix = bytes
        .get(..BLOCK_REFERENCE_V3_MIN_SIZE)
        .ok_or_else(|| Error::InvalidFormat("refs block reference is truncated".to_string()))?;
      let checksum_data_size = le_u16(&prefix[36..38]);
      let total_size = BLOCK_REFERENCE_V3_MIN_SIZE
        .checked_add(usize::from(checksum_data_size))
        .ok_or_else(|| Error::InvalidRange("refs block reference size overflow".to_string()))?;
      let bytes = bytes
        .get(..total_size)
        .ok_or_else(|| Error::InvalidFormat("refs block reference is truncated".to_string()))?;

      Ok(RefsBlockReference {
        block_numbers: [
          le_u64(&bytes[0..8]),
          le_u64(&bytes[8..16]),
          le_u64(&bytes[16..24]),
          le_u64(&bytes[24..32]),
        ],
        checksum_type: bytes[34],
        checksum_data_offset: bytes[35],
        checksum_data_size,
      })
    }
    other => Err(Error::InvalidFormat(format!(
      "unsupported refs metadata version: {other}"
    ))),
  }
}

pub(crate) fn parse_tree_header(bytes: &[u8]) -> Result<RefsTreeHeader> {
  let bytes = bytes
    .get(..TREE_HEADER_SIZE)
    .ok_or_else(|| Error::InvalidFormat("refs tree header is truncated".to_string()))?;
  Ok(RefsTreeHeader {
    table_data_offset: le_u16(&bytes[0..2]),
  })
}

pub(crate) fn parse_node_header(bytes: &[u8]) -> Result<RefsNodeHeader> {
  let bytes = bytes
    .get(..NODE_HEADER_SIZE)
    .ok_or_else(|| Error::InvalidFormat("refs node header is truncated".to_string()))?;
  Ok(RefsNodeHeader {
    data_area_start_offset: le_u32(&bytes[0..4]),
    data_area_end_offset: le_u32(&bytes[4..8]),
    node_level: bytes[12],
    node_type_flags: bytes[13],
    record_offsets_start_offset: le_u32(&bytes[16..20]),
    number_of_record_offsets: le_u32(&bytes[20..24]),
    record_offsets_end_offset: le_u32(&bytes[24..28]),
  })
}

pub(crate) fn parse_node_record(bytes: &[u8]) -> Result<RefsNodeRecord> {
  let bytes = bytes
    .get(..)
    .ok_or_else(|| Error::InvalidFormat("refs node record is missing".to_string()))?;
  if bytes.len() < NODE_RECORD_HEADER_SIZE {
    return Err(Error::InvalidFormat(
      "refs node record is truncated".to_string(),
    ));
  }

  let size = usize::try_from(le_u32(&bytes[0..4]))
    .map_err(|_| Error::InvalidRange("refs node record size is too large".to_string()))?;
  if size < NODE_RECORD_HEADER_SIZE || size > bytes.len() {
    return Err(Error::InvalidFormat(
      "refs node record size is invalid".to_string(),
    ));
  }

  let key_data_offset = usize::from(le_u16(&bytes[4..6]));
  let key_data_size = usize::from(le_u16(&bytes[6..8]));
  let value_data_offset = usize::from(le_u16(&bytes[10..12]));
  let value_data_size = usize::from(le_u16(&bytes[12..14]));
  let key_data_end = key_data_offset
    .checked_add(key_data_size)
    .ok_or_else(|| Error::InvalidRange("refs node key end overflow".to_string()))?;
  let value_data_end = value_data_offset
    .checked_add(value_data_size)
    .ok_or_else(|| Error::InvalidRange("refs node value end overflow".to_string()))?;
  if key_data_offset < NODE_RECORD_HEADER_SIZE
    || key_data_end > size
    || value_data_offset < NODE_RECORD_HEADER_SIZE
    || value_data_end > size
  {
    return Err(Error::InvalidFormat(
      "refs node record key/value bounds are invalid".to_string(),
    ));
  }

  Ok(RefsNodeRecord {
    size: size as u32,
    flags: le_u16(&bytes[8..10]),
    key_data: Arc::from(&bytes[key_data_offset..key_data_end]),
    value_data: Arc::from(&bytes[value_data_offset..value_data_end]),
  })
}

pub(crate) fn parse_ministore_node_data(
  bytes: &[u8], major_version: u8,
) -> Result<RefsMinistoreNode> {
  if bytes.len() < 4 {
    return Err(Error::InvalidFormat(
      "refs ministore node is too small".to_string(),
    ));
  }
  let node_header_offset = usize::try_from(le_u32(&bytes[0..4]))
    .map_err(|_| Error::InvalidRange("refs node header offset is too large".to_string()))?;
  if node_header_offset < 4 || node_header_offset >= bytes.len().saturating_sub(4) {
    return Err(Error::InvalidFormat(
      "refs node header offset is out of bounds".to_string(),
    ));
  }

  let mut data_offset = 4usize;
  let header_data = if node_header_offset >= data_offset + TREE_HEADER_SIZE {
    let _tree_header = parse_tree_header(&bytes[data_offset..])?;
    data_offset += TREE_HEADER_SIZE;
    Arc::from(&bytes[data_offset..node_header_offset])
  } else {
    Arc::<[u8]>::from(Vec::<u8>::new())
  };

  let node_header = parse_node_header(&bytes[node_header_offset..])?;
  if node_header.data_area_start_offset < NODE_HEADER_SIZE as u32
    || node_header.data_area_start_offset > (bytes.len() - node_header_offset) as u32
    || node_header.data_area_end_offset < NODE_HEADER_SIZE as u32
    || node_header.data_area_end_offset > (bytes.len() - node_header_offset) as u32
  {
    return Err(Error::InvalidFormat(
      "refs node header data-area bounds are invalid".to_string(),
    ));
  }

  let record_offsets_start = node_header_offset
    .checked_add(
      usize::try_from(node_header.record_offsets_start_offset).map_err(|_| {
        Error::InvalidRange("refs record-offset table start is too large".to_string())
      })?,
    )
    .ok_or_else(|| Error::InvalidRange("refs record-offset table start overflow".to_string()))?;
  let record_offsets_size = usize::try_from(node_header.number_of_record_offsets)
    .map_err(|_| Error::InvalidRange("refs record count is too large".to_string()))?
    .checked_mul(4)
    .ok_or_else(|| Error::InvalidRange("refs record-offset table size overflow".to_string()))?;
  let record_offsets_end = record_offsets_start
    .checked_add(record_offsets_size)
    .ok_or_else(|| Error::InvalidRange("refs record-offset table end overflow".to_string()))?;
  if record_offsets_start > bytes.len() || record_offsets_end > bytes.len() {
    return Err(Error::InvalidFormat(
      "refs record-offset table exceeds the node bounds".to_string(),
    ));
  }

  let mut records =
    Vec::with_capacity(usize::try_from(node_header.number_of_record_offsets).unwrap_or(0));
  let mut offset_cursor = record_offsets_start;
  for _ in 0..node_header.number_of_record_offsets {
    let mut record_data_offset = usize::try_from(le_u32(&bytes[offset_cursor..offset_cursor + 4]))
      .map_err(|_| Error::InvalidRange("refs record data offset is too large".to_string()))?;
    offset_cursor += 4;
    if major_version == 3 {
      record_data_offset &= 0xFFFF;
    }
    let min_offset = usize::try_from(node_header.data_area_start_offset)
      .map_err(|_| Error::InvalidRange("refs data area offset is too large".to_string()))?;
    let max_offset = usize::try_from(node_header.data_area_end_offset)
      .map_err(|_| Error::InvalidRange("refs data area offset is too large".to_string()))?;
    if record_data_offset < min_offset || record_data_offset >= max_offset {
      return Err(Error::InvalidFormat(
        "refs record data offset is outside the node data area".to_string(),
      ));
    }

    let absolute_record_offset = node_header_offset
      .checked_add(record_data_offset)
      .ok_or_else(|| Error::InvalidRange("refs absolute record offset overflow".to_string()))?;
    let record_size = usize::try_from(le_u32(
      &bytes[absolute_record_offset..absolute_record_offset + 4],
    ))
    .map_err(|_| Error::InvalidRange("refs record size is too large".to_string()))?;
    let record_end = absolute_record_offset
      .checked_add(record_size)
      .ok_or_else(|| Error::InvalidRange("refs record end overflow".to_string()))?;
    if record_end > bytes.len() {
      return Err(Error::InvalidFormat(
        "refs record extends past the node bounds".to_string(),
      ));
    }
    records.push(parse_node_record(
      &bytes[absolute_record_offset..record_end],
    )?);
  }

  Ok(RefsMinistoreNode {
    header_data,
    node_type_flags: node_header.node_type_flags,
    records,
  })
}

pub(crate) fn parse_directory_values(bytes: &[u8]) -> Result<RefsDirectoryValues> {
  let bytes = bytes
    .get(..DIRECTORY_VALUES_SIZE)
    .ok_or_else(|| Error::InvalidFormat("refs directory values are truncated".to_string()))?;

  Ok(RefsDirectoryValues {
    object_identifier: le_u64(&bytes[0..8]),
    creation_time: le_u64(&bytes[16..24]),
    modification_time: le_u64(&bytes[24..32]),
    entry_modification_time: le_u64(&bytes[32..40]),
    access_time: le_u64(&bytes[40..48]),
    file_attribute_flags: le_u32(&bytes[64..68]),
  })
}

pub(crate) fn parse_file_values(bytes: &[u8]) -> Result<RefsFileValues> {
  let bytes = bytes
    .get(..FILE_VALUES_SIZE)
    .ok_or_else(|| Error::InvalidFormat("refs file values header is truncated".to_string()))?;

  Ok(RefsFileValues {
    creation_time: le_u64(&bytes[0..8]),
    modification_time: le_u64(&bytes[8..16]),
    entry_modification_time: le_u64(&bytes[16..24]),
    access_time: le_u64(&bytes[24..32]),
    file_attribute_flags: le_u32(&bytes[32..36]),
    identifier_lower: le_u64(&bytes[40..48]),
    identifier_upper: le_u64(&bytes[48..56]),
    data_size: le_u64(&bytes[64..72]),
    allocated_data_size: le_u64(&bytes[72..80]),
  })
}

pub(crate) fn parse_directory_entry_name(key_data: &[u8]) -> Result<String> {
  if key_data.len() < 4 {
    return Err(Error::InvalidFormat(
      "refs directory entry key is truncated".to_string(),
    ));
  }
  decode_utf16le_string(&key_data[4..])
}

pub(crate) fn parse_directory_entry_type(key_data: &[u8]) -> Result<u16> {
  if key_data.len() < 4 {
    return Err(Error::InvalidFormat(
      "refs directory entry key is truncated".to_string(),
    ));
  }
  Ok(le_u16(&key_data[2..4]))
}

pub(crate) fn parse_resident_attribute(bytes: &[u8]) -> Result<RefsAttributeValue> {
  if bytes.len() < ATTRIBUTE_RESIDENT_HEADER_SIZE {
    return Err(Error::InvalidFormat(
      "refs resident attribute is truncated".to_string(),
    ));
  }

  let inline_data_offset = usize::try_from(le_u32(&bytes[4..8]))
    .map_err(|_| Error::InvalidRange("refs inline data offset is too large".to_string()))?;
  let inline_data_size = usize::try_from(le_u32(&bytes[8..12]))
    .map_err(|_| Error::InvalidRange("refs inline data size is too large".to_string()))?;
  if inline_data_offset < ATTRIBUTE_RESIDENT_HEADER_SIZE {
    return Err(Error::InvalidFormat(
      "refs resident attribute inline-data offset is invalid".to_string(),
    ));
  }
  let inline_data_end = inline_data_offset
    .checked_add(inline_data_size)
    .ok_or_else(|| Error::InvalidRange("refs inline data end overflow".to_string()))?;
  if inline_data_end > bytes.len() {
    return Err(Error::InvalidFormat(
      "refs resident attribute inline data exceeds the record bounds".to_string(),
    ));
  }

  Ok(RefsAttributeValue::Resident(Arc::from(
    &bytes[inline_data_offset..inline_data_end],
  )))
}

pub(crate) fn parse_data_run(bytes: &[u8]) -> Result<RefsDataRun> {
  let bytes = bytes
    .get(..DATA_RUN_SIZE)
    .ok_or_else(|| Error::InvalidFormat("refs data run is truncated".to_string()))?;

  Ok(RefsDataRun {
    logical_offset: le_u64(&bytes[0..8]),
    block_count: le_u64(&bytes[8..16]),
    physical_block_number: le_u64(&bytes[16..24]),
  })
}

#[cfg(test)]
pub(crate) fn build_object_key(object_identifier: u64) -> [u8; 16] {
  let mut key = [0u8; 16];
  key[8..16].copy_from_slice(&object_identifier.to_le_bytes());
  key
}

pub(crate) fn decode_utf16le_string(bytes: &[u8]) -> Result<String> {
  if !bytes.len().is_multiple_of(2) {
    return Err(Error::InvalidFormat(
      "refs UTF-16LE string has an odd byte count".to_string(),
    ));
  }

  let units = bytes
    .chunks_exact(2)
    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    .take_while(|unit| *unit != 0)
    .collect::<Vec<_>>();
  Ok(String::from_utf16_lossy(&units))
}

fn relative_metadata_offset(
  raw_offset: u32, header_size: usize, body_size: usize, min_absolute_offset: usize, label: &str,
) -> Result<usize> {
  if raw_offset < min_absolute_offset as u32 || raw_offset >= (body_size + header_size) as u32 {
    return Err(Error::InvalidFormat(format!(
      "{label} offset is out of bounds"
    )));
  }
  Ok(raw_offset as usize - header_size)
}

pub(crate) fn metadata_header_size(major_version: u8) -> Result<usize> {
  match major_version {
    1 => Ok(METADATA_BLOCK_HEADER_V1_SIZE),
    3 => Ok(METADATA_BLOCK_HEADER_V3_SIZE),
    other => Err(Error::InvalidFormat(format!(
      "unsupported refs metadata version: {other}"
    ))),
  }
}

fn checkpoint_trailer_size(major_version: u8) -> Result<usize> {
  match major_version {
    1 => Ok(CHECKPOINT_TRAILER_V1_SIZE),
    3 => Ok(CHECKPOINT_TRAILER_V3_SIZE),
    other => Err(Error::InvalidFormat(format!(
      "unsupported refs metadata version: {other}"
    ))),
  }
}

pub(crate) fn le_u16(bytes: &[u8]) -> u16 {
  let mut raw = [0u8; 2];
  raw.copy_from_slice(bytes);
  u16::from_le_bytes(raw)
}

pub(crate) fn le_u32(bytes: &[u8]) -> u32 {
  let mut raw = [0u8; 4];
  raw.copy_from_slice(bytes);
  u32::from_le_bytes(raw)
}

pub(crate) fn le_u64(bytes: &[u8]) -> u64 {
  let mut raw = [0u8; 8];
  raw.copy_from_slice(bytes);
  u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;
  use crate::BytesDataSource;

  fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("refs")
      .join("libfsrefs")
      .join(relative)
  }

  fn synthetic_volume_header(
    major_version: u8, minor_version: u8, cluster_block_size: u32,
  ) -> [u8; VOLUME_HEADER_SIZE] {
    let mut header = [0u8; VOLUME_HEADER_SIZE];
    header[3..11].copy_from_slice(b"ReFS\0\0\0\0");
    header[16..20].copy_from_slice(b"FSRS");
    header[20..22].copy_from_slice(&0x0200u16.to_le_bytes());
    header[24..32].copy_from_slice(&2048u64.to_le_bytes());
    header[32..36].copy_from_slice(&512u32.to_le_bytes());
    header[36..40].copy_from_slice(&(cluster_block_size / 512).to_le_bytes());
    header[40] = major_version;
    header[41] = minor_version;
    header[56..64].copy_from_slice(&1u64.to_le_bytes());
    header
  }

  #[test]
  fn parses_volume_header_fixture() {
    let bytes = std::fs::read(fixture_path("volume_header.1")).unwrap();
    let header = RefsVolumeHeader::from_bytes(&bytes).unwrap();

    assert_eq!(header.bytes_per_sector, 512);
    assert_eq!(header.cluster_block_size, 65_536);
    assert_eq!(header.metadata_block_size, 16 * 1024);
    assert_eq!(header.major_version, 1);
    assert_eq!(header.minor_version, 2);
    assert_eq!(header.volume_size, 1_006_633_472);
    assert_eq!(header.container_size, 0);
  }

  #[test]
  fn parses_v3_volume_headers() {
    let header = RefsVolumeHeader::from_bytes(&synthetic_volume_header(3, 1, 4096)).unwrap();

    assert_eq!(header.cluster_block_size, 4096);
    assert_eq!(header.metadata_block_size, 4096);
    assert_eq!(header.major_version, 3);
    assert_eq!(header.minor_version, 1);
    assert_eq!(header.container_size, 0x4000);
  }

  #[test]
  fn parses_superblock_fixture() {
    let bytes = std::fs::read(fixture_path("superblock.1")).unwrap();
    let superblock = parse_superblock_metadata(&bytes, 1).unwrap();

    assert_eq!(superblock.primary_checkpoint_block_number, 646);
    assert_eq!(superblock.secondary_checkpoint_block_number, 7404);
  }

  #[test]
  fn parses_v3_superblock_fixture() {
    let bytes = std::fs::read(fixture_path("superblock.2")).unwrap();
    let superblock = parse_superblock_metadata(&bytes, 3).unwrap();

    assert_eq!(superblock.primary_checkpoint_block_number, 5112);
    assert_eq!(superblock.secondary_checkpoint_block_number, 60_980);
  }

  #[test]
  fn parses_checkpoint_fixture() {
    let bytes = std::fs::read(fixture_path("checkpoint.1")).unwrap();
    let checkpoint = parse_checkpoint_metadata(&bytes, 1).unwrap();

    assert_eq!(checkpoint.sequence_number, 10);
    assert_eq!(checkpoint.block_references.len(), 6);
    assert_eq!(checkpoint.block_references[0].block_numbers, [119, 0, 0, 0]);
    assert_eq!(checkpoint.block_references[5].block_numbers, [122, 0, 0, 0]);
  }

  #[test]
  fn parses_v3_checkpoint_fixture() {
    let bytes = std::fs::read(fixture_path("checkpoint.2")).unwrap();
    let checkpoint = parse_checkpoint_metadata(&bytes, 3).unwrap();

    assert_eq!(checkpoint.sequence_number, 33);
    assert_eq!(checkpoint.block_references.len(), 13);
    assert_eq!(
      checkpoint.block_references[0].block_numbers,
      [78_770, 78_771, 78_772, 78_773]
    );
    assert_eq!(
      checkpoint.block_references[12].block_numbers,
      [88, 89, 90, 91]
    );
  }

  #[test]
  fn parses_v3_block_reference_fixture() {
    let bytes = std::fs::read(fixture_path("block_descriptor.2")).unwrap();
    let reference = parse_block_reference(&bytes, 3).unwrap();

    assert_eq!(reference.block_numbers, [30, 0, 0, 0]);
    assert_eq!(reference.checksum_type, 1);
    assert_eq!(reference.checksum_data_offset, 8);
    assert_eq!(reference.checksum_data_size, 4);
  }

  #[test]
  fn parses_node_header_fixture() {
    let bytes = std::fs::read(fixture_path("node_header.1")).unwrap();
    let header = parse_node_header(&bytes).unwrap();

    assert_eq!(header.data_area_start_offset, 32);
    assert_eq!(header.data_area_end_offset, 672);
    assert_eq!(header.node_level, 0);
    assert_eq!(header.node_type_flags, 2);
    assert_eq!(header.record_offsets_start_offset, 13_648);
    assert_eq!(header.number_of_record_offsets, 8);
    assert_eq!(header.record_offsets_end_offset, 13_680);
  }

  #[test]
  fn parses_node_record_fixture() {
    let bytes = std::fs::read(fixture_path("node_record.1")).unwrap();
    let record = parse_node_record(&bytes).unwrap();

    assert_eq!(record.size, 176);
    assert_eq!(record.flags, 0);
    assert_eq!(record.key_data.len(), 16);
    assert_eq!(record.value_data.len(), 160);
  }

  #[test]
  fn parses_data_run_fixture() {
    let bytes = std::fs::read(fixture_path("data_run.1")).unwrap();
    let run = parse_data_run(&bytes).unwrap();

    assert_eq!(run.logical_offset, 0);
    assert_eq!(run.block_count, 4);
    assert_eq!(run.physical_block_number, 224);
  }

  #[test]
  fn reads_volume_header_via_data_source() {
    let bytes = std::fs::read(fixture_path("volume_header.1")).unwrap();
    let source = BytesDataSource::new(Arc::<[u8]>::from(bytes));
    let header = RefsVolumeHeader::read(&source).unwrap();

    assert_eq!(header.cluster_block_size, 65_536);
  }
}
