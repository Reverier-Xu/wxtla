//! Read-only in-memory VHDX log replay.

use std::sync::Arc;

use super::{constants, guid::VhdxGuid, header::VhdxImageHeader};
use crate::{ByteSource, ByteSourceCapabilities, ByteSourceHandle, Error, Result};

const LOG_SECTOR_SIZE: u64 = 4 * 1024;
const LOG_ENTRY_HEADER_SIZE: usize = 64;
const LOG_DESCRIPTOR_SIZE: usize = 32;

const LOG_ENTRY_SIGNATURE: u32 = 0x6567_6F6C;
const LOG_DATA_SIGNATURE: u32 = 0x6174_6164;
const LOG_DESCRIPTOR_SIGNATURE: u32 = 0x6373_6564;
const LOG_ZERO_DESCRIPTOR_SIGNATURE: u32 = 0x6F72_657A;

pub(super) fn apply(
  source: ByteSourceHandle, active_header: &VhdxImageHeader, active_header_offset: u64,
) -> Result<ByteSourceHandle> {
  if active_header.log_version != 0 {
    return Err(Error::InvalidFormat(
      "vhdx active log uses an unsupported log format version".to_string(),
    ));
  }
  if active_header.log_identifier == VhdxGuid::NIL || active_header.log_length == 0 {
    return Ok(source);
  }

  let source_size = source.size()?;
  validate_log_bounds(source_size, active_header)?;
  let sequence = find_active_sequence(source.as_ref(), active_header, source_size)?;
  let mut patches = sequence.patches;
  patches.push(build_cleared_header_patch(
    source.as_ref(),
    source_size,
    &patches,
    active_header_offset,
  )?);
  let replayed_size =
    patches
      .iter()
      .try_fold(source_size.max(sequence.last_file_offset), |size, patch| {
        patch
          .end()
          .map(|end| size.max(end))
          .ok_or_else(|| Error::InvalidRange("vhdx replay patch range overflow".to_string()))
      })?;

  Ok(Arc::new(VhdxReplayLogDataSource {
    source,
    source_size,
    replayed_size,
    patches: Arc::from(patches.into_boxed_slice()),
  }) as ByteSourceHandle)
}

#[derive(Clone)]
struct ReplayPatch {
  offset: u64,
  data: ReplayPatchData,
}

#[derive(Clone)]
enum ReplayPatchData {
  Bytes(Arc<[u8]>),
  Zero(u64),
}

impl ReplayPatch {
  fn bytes(offset: u64, data: impl Into<Arc<[u8]>>) -> Self {
    Self {
      offset,
      data: ReplayPatchData::Bytes(data.into()),
    }
  }

  fn zero(offset: u64, length: u64) -> Self {
    Self {
      offset,
      data: ReplayPatchData::Zero(length),
    }
  }

  fn len(&self) -> u64 {
    match &self.data {
      ReplayPatchData::Bytes(data) => data.len() as u64,
      ReplayPatchData::Zero(length) => *length,
    }
  }

  fn end(&self) -> Option<u64> {
    self.offset.checked_add(self.len())
  }
}

struct VhdxReplayLogDataSource {
  source: ByteSourceHandle,
  source_size: u64,
  replayed_size: u64,
  patches: Arc<[ReplayPatch]>,
}

impl ByteSource for VhdxReplayLogDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.replayed_size || buf.is_empty() {
      return Ok(0);
    }

    let limit = usize::try_from(self.replayed_size - offset)
      .unwrap_or(usize::MAX)
      .min(buf.len());
    if offset < self.source_size {
      let base_len =
        usize::try_from((self.source_size - offset).min(limit as u64)).unwrap_or(limit);
      self.source.read_exact_at(offset, &mut buf[..base_len])?;
      if base_len < limit {
        buf[base_len..limit].fill(0);
      }
    } else {
      buf[..limit].fill(0);
    }

    for patch in self.patches.iter() {
      apply_patch_to_buffer(patch, offset, &mut buf[..limit])?;
    }

    Ok(limit)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.replayed_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    "image.vhdx.replayed_log"
  }
}

fn apply_patch_to_buffer(patch: &ReplayPatch, offset: u64, buf: &mut [u8]) -> Result<()> {
  let request_end = offset
    .checked_add(buf.len() as u64)
    .ok_or_else(|| Error::InvalidRange("vhdx replay read range overflow".to_string()))?;
  let Some(patch_end) = patch.end() else {
    return Err(Error::InvalidRange(
      "vhdx replay patch range overflow".to_string(),
    ));
  };
  if patch.offset >= request_end || patch_end <= offset {
    return Ok(());
  }

  let overlap_start = patch.offset.max(offset);
  let overlap_end = patch_end.min(request_end);
  let buffer_start = usize::try_from(overlap_start - offset)
    .map_err(|_| Error::InvalidRange("vhdx replay overlap offset is too large".to_string()))?;
  let buffer_end = usize::try_from(overlap_end - offset)
    .map_err(|_| Error::InvalidRange("vhdx replay overlap offset is too large".to_string()))?;

  match &patch.data {
    ReplayPatchData::Bytes(data) => {
      let source_start = usize::try_from(overlap_start - patch.offset)
        .map_err(|_| Error::InvalidRange("vhdx replay overlap offset is too large".to_string()))?;
      let source_end = source_start
        .checked_add(buffer_end - buffer_start)
        .ok_or_else(|| Error::InvalidRange("vhdx replay overlap range overflow".to_string()))?;
      buf[buffer_start..buffer_end].copy_from_slice(&data[source_start..source_end]);
    }
    ReplayPatchData::Zero(_) => {
      buf[buffer_start..buffer_end].fill(0);
    }
  }

  Ok(())
}

struct ParsedLogSequence {
  head_sequence_number: u64,
  flushed_file_offset: u64,
  last_file_offset: u64,
  patches: Vec<ReplayPatch>,
}

struct ParsedLogEntry {
  tail: u32,
  sequence_number: u64,
  entry_length: u32,
  flushed_file_offset: u64,
  last_file_offset: u64,
  patches: Vec<ReplayPatch>,
}

fn validate_log_bounds(source_size: u64, header: &VhdxImageHeader) -> Result<()> {
  if header.log_offset < constants::VHDX_ALIGNMENT
    || !header.log_offset.is_multiple_of(constants::VHDX_ALIGNMENT)
  {
    return Err(Error::InvalidFormat(format!(
      "invalid vhdx log offset: {}",
      header.log_offset
    )));
  }
  if header.log_length == 0
    || !u64::from(header.log_length).is_multiple_of(constants::VHDX_ALIGNMENT)
  {
    return Err(Error::InvalidFormat(format!(
      "invalid vhdx log length: {}",
      header.log_length
    )));
  }
  let log_end = header
    .log_offset
    .checked_add(u64::from(header.log_length))
    .ok_or_else(|| Error::InvalidRange("vhdx log range overflow".to_string()))?;
  if log_end > source_size {
    return Err(Error::InvalidFormat(
      "vhdx log region exceeds the source size".to_string(),
    ));
  }
  Ok(())
}

fn find_active_sequence(
  source: &dyn ByteSource, header: &VhdxImageHeader, source_size: u64,
) -> Result<ParsedLogSequence> {
  let mut candidate = None::<ParsedLogSequence>;

  for tail in (0..u64::from(header.log_length)).step_by(LOG_SECTOR_SIZE as usize) {
    let mut position = u32::try_from(tail)
      .map_err(|_| Error::InvalidRange("vhdx log tail offset is too large".to_string()))?;
    let mut expected_previous_sequence = None;
    let mut entries = Vec::new();
    let mut covered = 0u64;

    loop {
      if covered >= u64::from(header.log_length) {
        break;
      }

      let Some(entry) = parse_log_entry(source, header, position, expected_previous_sequence)?
      else {
        break;
      };
      covered = covered
        .checked_add(u64::from(entry.entry_length))
        .ok_or_else(|| Error::InvalidRange("vhdx log sequence length overflow".to_string()))?;
      expected_previous_sequence = Some(entry.sequence_number);
      position = advance_log_offset(position, entry.entry_length, header.log_length)?;
      entries.push(entry);
    }

    let Some(head) = entries.last() else {
      continue;
    };
    if u64::from(head.tail) != tail {
      continue;
    }

    let sequence = ParsedLogSequence {
      head_sequence_number: head.sequence_number,
      flushed_file_offset: head.flushed_file_offset,
      last_file_offset: head.last_file_offset,
      patches: entries
        .into_iter()
        .flat_map(|entry| entry.patches)
        .collect(),
    };
    if candidate
      .as_ref()
      .is_none_or(|current| sequence.head_sequence_number > current.head_sequence_number)
    {
      candidate = Some(sequence);
    }
  }

  let candidate = candidate.ok_or_else(|| {
    Error::InvalidFormat(
      "vhdx image header advertises an active log but no valid log sequence was found".to_string(),
    )
  })?;
  if candidate.flushed_file_offset > source_size {
    return Err(Error::InvalidFormat(
      "vhdx active log references file data beyond the source size".to_string(),
    ));
  }

  Ok(candidate)
}

fn parse_log_entry(
  source: &dyn ByteSource, header: &VhdxImageHeader, start: u32,
  expected_previous_sequence: Option<u64>,
) -> Result<Option<ParsedLogEntry>> {
  let header_bytes = read_wrapped_bytes(
    source,
    header.log_offset,
    header.log_length,
    start,
    LOG_ENTRY_HEADER_SIZE,
  )?;
  if le_u32(&header_bytes[0..4]) != LOG_ENTRY_SIGNATURE {
    return Ok(None);
  }

  let entry_length = le_u32(&header_bytes[8..12]);
  let tail = le_u32(&header_bytes[12..16]);
  let sequence_number = le_u64(&header_bytes[16..24]);
  let descriptor_count = le_u32(&header_bytes[24..28]);
  let reserved = le_u32(&header_bytes[28..32]);
  let log_guid = VhdxGuid::from_le_bytes(&header_bytes[32..48])?;
  let flushed_file_offset = le_u64(&header_bytes[48..56]);
  let last_file_offset = le_u64(&header_bytes[56..64]);
  let Some(expected_descriptor_sectors) = compute_descriptor_sectors(descriptor_count) else {
    return Ok(None);
  };
  if entry_length < LOG_SECTOR_SIZE as u32
    || u64::from(entry_length) > u64::from(header.log_length)
    || !u64::from(entry_length).is_multiple_of(LOG_SECTOR_SIZE)
    || sequence_number == 0
    || reserved != 0
    || tail >= header.log_length
    || !u64::from(tail).is_multiple_of(LOG_SECTOR_SIZE)
    || log_guid != header.log_identifier
    || last_file_offset < flushed_file_offset
    || u64::from(entry_length) < expected_descriptor_sectors * LOG_SECTOR_SIZE
  {
    return Ok(None);
  }
  if let Some(previous_sequence) = expected_previous_sequence
    && previous_sequence.checked_add(1) != Some(sequence_number)
  {
    return Ok(None);
  }

  let entry_bytes = read_wrapped_bytes(
    source,
    header.log_offset,
    header.log_length,
    start,
    usize::try_from(entry_length)
      .map_err(|_| Error::InvalidRange("vhdx log entry length is too large".to_string()))?,
  )?;
  let stored_checksum = le_u32(&entry_bytes[4..8]);
  if calculate_crc32c(&entry_bytes, 4)? != stored_checksum {
    return Ok(None);
  }

  let total_sectors = u64::from(entry_length) / LOG_SECTOR_SIZE;
  let data_section_offset = usize::try_from(expected_descriptor_sectors * LOG_SECTOR_SIZE)
    .map_err(|_| Error::InvalidRange("vhdx log data section offset is too large".to_string()))?;
  let mut data_descriptor_count = 0usize;
  let mut patches = Vec::new();

  for descriptor_index in 0..usize::try_from(descriptor_count)
    .map_err(|_| Error::InvalidRange("vhdx log descriptor count is too large".to_string()))?
  {
    let descriptor_offset = LOG_ENTRY_HEADER_SIZE
      .checked_add(
        descriptor_index
          .checked_mul(LOG_DESCRIPTOR_SIZE)
          .ok_or_else(|| Error::InvalidRange("vhdx log descriptor offset overflow".to_string()))?,
      )
      .ok_or_else(|| Error::InvalidRange("vhdx log descriptor offset overflow".to_string()))?;
    let descriptor_end = descriptor_offset
      .checked_add(LOG_DESCRIPTOR_SIZE)
      .ok_or_else(|| Error::InvalidRange("vhdx log descriptor range overflow".to_string()))?;
    let Some(descriptor_bytes) = entry_bytes.get(descriptor_offset..descriptor_end) else {
      return Ok(None);
    };
    let signature = le_u32(&descriptor_bytes[0..4]);
    let file_offset = le_u64(&descriptor_bytes[16..24]);
    let descriptor_sequence = le_u64(&descriptor_bytes[24..32]);
    if descriptor_sequence != sequence_number || !file_offset.is_multiple_of(LOG_SECTOR_SIZE) {
      return Ok(None);
    }

    match signature {
      LOG_ZERO_DESCRIPTOR_SIGNATURE => {
        let zero_length = le_u64(&descriptor_bytes[8..16]);
        if zero_length == 0 || !zero_length.is_multiple_of(LOG_SECTOR_SIZE) {
          return Ok(None);
        }
        patches.push(ReplayPatch::zero(file_offset, zero_length));
      }
      LOG_DESCRIPTOR_SIGNATURE => {
        let sector_offset = data_section_offset
          .checked_add(
            data_descriptor_count
              .checked_mul(LOG_SECTOR_SIZE as usize)
              .ok_or_else(|| {
                Error::InvalidRange("vhdx log data sector offset overflow".to_string())
              })?,
          )
          .ok_or_else(|| Error::InvalidRange("vhdx log data sector offset overflow".to_string()))?;
        let sector_end = sector_offset
          .checked_add(LOG_SECTOR_SIZE as usize)
          .ok_or_else(|| Error::InvalidRange("vhdx log data sector range overflow".to_string()))?;
        let Some(sector_bytes) = entry_bytes.get(sector_offset..sector_end) else {
          return Ok(None);
        };
        if le_u32(&sector_bytes[0..4]) != LOG_DATA_SIGNATURE {
          return Ok(None);
        }
        let data_sequence = u64::from(le_u32(&sector_bytes[4..8])) << 32
          | u64::from(le_u32(&sector_bytes[4092..4096]));
        if data_sequence != sequence_number {
          return Ok(None);
        }

        let mut sector = vec![0u8; LOG_SECTOR_SIZE as usize];
        sector[0..8].copy_from_slice(&descriptor_bytes[8..16]);
        sector[8..4092].copy_from_slice(&sector_bytes[8..4092]);
        sector[4092..4096].copy_from_slice(&descriptor_bytes[4..8]);
        patches.push(ReplayPatch::bytes(file_offset, sector));
        data_descriptor_count += 1;
      }
      _ => return Ok(None),
    }
  }

  if total_sectors != expected_descriptor_sectors + data_descriptor_count as u64 {
    return Ok(None);
  }

  Ok(Some(ParsedLogEntry {
    tail,
    sequence_number,
    entry_length,
    flushed_file_offset,
    last_file_offset,
    patches,
  }))
}

fn compute_descriptor_sectors(descriptor_count: u32) -> Option<u64> {
  let descriptors_with_header = u64::from(descriptor_count).checked_add(2)?;
  Some(descriptors_with_header.div_ceil(128))
}

fn advance_log_offset(start: u32, entry_length: u32, log_length: u32) -> Result<u32> {
  let advanced = u64::from(start)
    .checked_add(u64::from(entry_length))
    .ok_or_else(|| Error::InvalidRange("vhdx log offset overflow".to_string()))?;
  Ok((advanced % u64::from(log_length)) as u32)
}

fn read_wrapped_bytes(
  source: &dyn ByteSource, log_offset: u64, log_length: u32, start: u32, len: usize,
) -> Result<Vec<u8>> {
  let mut bytes = vec![0u8; len];
  let start = u64::from(start);
  let log_length = u64::from(log_length);
  let first_len = usize::try_from((log_length - start).min(len as u64)).unwrap_or(len);
  source.read_exact_at(
    log_offset
      .checked_add(start)
      .ok_or_else(|| Error::InvalidRange("vhdx log read offset overflow".to_string()))?,
    &mut bytes[..first_len],
  )?;
  if first_len < len {
    source.read_exact_at(log_offset, &mut bytes[first_len..])?;
  }
  Ok(bytes)
}

fn build_cleared_header_patch(
  source: &dyn ByteSource, source_size: u64, patches: &[ReplayPatch], active_header_offset: u64,
) -> Result<ReplayPatch> {
  let mut header_bytes = materialize_range(
    source,
    source_size,
    patches,
    active_header_offset,
    constants::IMAGE_HEADER_SIZE,
  )?;
  header_bytes[48..64].fill(0);
  header_bytes[4..8].fill(0);
  let checksum = calculate_crc32c(&header_bytes, 4)?;
  header_bytes[4..8].copy_from_slice(&checksum.to_le_bytes());
  Ok(ReplayPatch::bytes(active_header_offset, header_bytes))
}

fn materialize_range(
  source: &dyn ByteSource, source_size: u64, patches: &[ReplayPatch], offset: u64, len: usize,
) -> Result<Vec<u8>> {
  let mut bytes = vec![0u8; len];
  if offset < source_size {
    let base_len = usize::try_from((source_size - offset).min(len as u64)).unwrap_or(len);
    source.read_exact_at(offset, &mut bytes[..base_len])?;
  }
  for patch in patches {
    apply_patch_to_buffer(patch, offset, &mut bytes)?;
  }
  Ok(bytes)
}

fn calculate_crc32c(data: &[u8], checksum_offset: usize) -> Result<u32> {
  let checksum_end = checksum_offset
    .checked_add(4)
    .ok_or_else(|| Error::InvalidRange("vhdx checksum offset overflow".to_string()))?;
  let mut checksum = crc32c::crc32c_append(0, &data[..checksum_offset]);
  checksum = crc32c::crc32c_append(checksum, &[0; 4]);
  checksum = crc32c::crc32c_append(checksum, &data[checksum_end..]);
  Ok(checksum)
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::BytesDataSource;

  const ACTIVE_HEADER_OFFSET: u64 = constants::PRIMARY_IMAGE_HEADER_OFFSET;

  fn sample_log_guid() -> VhdxGuid {
    VhdxGuid::from_fields(
      0x1122_3344,
      0x5566,
      0x7788,
      [0x90, 0xAB, 0xCD, 0xEF, 1, 2, 3, 4],
    )
  }

  fn header_bytes(log_guid: VhdxGuid, log_offset: u64, log_length: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; constants::IMAGE_HEADER_SIZE];
    bytes[0..4].copy_from_slice(constants::IMAGE_HEADER_SIGNATURE);
    bytes[8..16].copy_from_slice(&2u64.to_le_bytes());
    bytes[48..64].copy_from_slice(&log_guid.to_le_bytes());
    bytes[66..68].copy_from_slice(&1u16.to_le_bytes());
    bytes[68..72].copy_from_slice(&log_length.to_le_bytes());
    bytes[72..80].copy_from_slice(&log_offset.to_le_bytes());
    let checksum = calculate_crc32c(&bytes, 4).unwrap();
    bytes[4..8].copy_from_slice(&checksum.to_le_bytes());
    bytes
  }

  fn single_data_descriptor_entry(
    log_guid: VhdxGuid, file_offset: u64, sector: &[u8; 4096],
  ) -> Vec<u8> {
    let mut bytes = vec![0u8; 2 * LOG_SECTOR_SIZE as usize];
    bytes[0..4].copy_from_slice(&LOG_ENTRY_SIGNATURE.to_le_bytes());
    bytes[8..12].copy_from_slice(&(2 * LOG_SECTOR_SIZE as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
    bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..48].copy_from_slice(&log_guid.to_le_bytes());
    bytes[48..56].copy_from_slice(&(2 * 1024 * 1024u64).to_le_bytes());
    bytes[56..64].copy_from_slice(&(2 * 1024 * 1024u64).to_le_bytes());
    bytes[64..68].copy_from_slice(&LOG_DESCRIPTOR_SIGNATURE.to_le_bytes());
    bytes[68..72].copy_from_slice(&sector[4092..4096]);
    bytes[72..80].copy_from_slice(&sector[0..8]);
    bytes[80..88].copy_from_slice(&file_offset.to_le_bytes());
    bytes[88..96].copy_from_slice(&1u64.to_le_bytes());
    bytes[4096..4100].copy_from_slice(&LOG_DATA_SIGNATURE.to_le_bytes());
    bytes[4100..4104].copy_from_slice(&0u32.to_le_bytes());
    bytes[4104..8188].copy_from_slice(&sector[8..4092]);
    bytes[8188..8192].copy_from_slice(&1u32.to_le_bytes());
    let checksum = calculate_crc32c(&bytes, 4).unwrap();
    bytes[4..8].copy_from_slice(&checksum.to_le_bytes());
    bytes
  }

  #[test]
  fn replays_active_log_entries_into_an_overlay_source() {
    let log_guid = sample_log_guid();
    let header = VhdxImageHeader {
      sequence_number: 2,
      file_write_identifier: VhdxGuid::NIL,
      data_write_identifier: VhdxGuid::NIL,
      log_identifier: log_guid,
      log_version: 0,
      format_version: 1,
      log_length: 1024 * 1024,
      log_offset: 1024 * 1024,
    };
    let mut source_bytes = vec![0u8; 2 * 1024 * 1024];
    source_bytes
      [ACTIVE_HEADER_OFFSET as usize..ACTIVE_HEADER_OFFSET as usize + constants::IMAGE_HEADER_SIZE]
      .copy_from_slice(&header_bytes(
        log_guid,
        header.log_offset,
        header.log_length,
      ));
    let mut sector = [0u8; 4096];
    sector.fill(0x5A);
    source_bytes[header.log_offset as usize..header.log_offset as usize + 8192]
      .copy_from_slice(&single_data_descriptor_entry(log_guid, 0x4000, &sector));
    let source = Arc::new(BytesDataSource::new(source_bytes)) as ByteSourceHandle;

    let replayed = apply(source, &header, ACTIVE_HEADER_OFFSET).unwrap();
    let mut patched = [0u8; 4096];
    replayed.read_exact_at(0x4000, &mut patched).unwrap();
    let header_after = replayed
      .read_bytes_at(ACTIVE_HEADER_OFFSET + 48, 16)
      .unwrap();

    assert_eq!(patched, sector);
    assert_eq!(header_after, vec![0u8; 16]);
  }
}
