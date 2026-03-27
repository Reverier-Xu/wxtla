//! Parsing of GPT headers and entries.

use super::{
  constants,
  entry::{GptPartitionEntry, GptPartitionInfo},
  header::GptHeader,
  integrity::{validate_entry_array_crc, validate_header_crc, validate_header_pair},
  system::{GptHeaderLocation, GptVolumeSystem},
  validation::validate_layout,
};
use crate::{ByteSource, ByteSourceHandle, Error, Result, volumes::mbr::MbrPartitionEntry};

#[derive(Debug)]
struct GptCandidate {
  header: GptHeader,
  partitions: Vec<GptPartitionInfo>,
}

#[derive(Debug)]
struct GptHeaderCandidate {
  header: GptHeader,
}

pub(super) fn candidate_block_sizes(source: &dyn ByteSource) -> Result<Vec<u32>> {
  let mut candidates = Vec::new();
  let source_size = source.size()?;
  for block_size in constants::SUPPORTED_BLOCK_SIZES {
    if source_size < u64::from(block_size) + constants::HEADER_SIGNATURE.len() as u64 {
      continue;
    }

    let signature =
      source.read_bytes_at(u64::from(block_size), constants::HEADER_SIGNATURE.len())?;
    if signature == constants::HEADER_SIGNATURE {
      push_candidate_block_size(&mut candidates, block_size);
    }
  }
  for block_size in constants::SUPPORTED_BLOCK_SIZES {
    push_candidate_block_size(&mut candidates, block_size);
  }

  Ok(candidates)
}

pub(super) fn open(source: ByteSourceHandle) -> Result<GptVolumeSystem> {
  let mut first_error = None;
  for block_size in candidate_block_sizes(source.as_ref())? {
    match open_with_block_size(source.clone(), block_size) {
      Ok(system) => return Ok(system),
      Err(error) => {
        if first_error.is_none() {
          first_error = Some(error);
        }
      }
    }
  }

  Err(first_error.unwrap_or_else(|| {
    Error::InvalidFormat("unable to infer a supported gpt block size".to_string())
  }))
}

pub(super) fn validate_primary_probe(source: &dyn ByteSource, block_size: u32) -> Result<()> {
  validate_protective_mbr(source)?;
  read_header_candidate(source, block_size, GptHeaderLocation::Primary).map(|_| ())
}

pub(super) fn open_with_block_size(
  source: ByteSourceHandle, block_size: u32,
) -> Result<GptVolumeSystem> {
  validate_protective_mbr(source.as_ref())?;

  let primary_header =
    read_header_candidate(source.as_ref(), block_size, GptHeaderLocation::Primary);
  let backup_header = read_header_candidate(source.as_ref(), block_size, GptHeaderLocation::Backup);

  match (primary_header, backup_header) {
    (Ok(primary), Ok(backup)) => {
      let headers_match = validate_header_pair(&primary.header, &backup.header).is_ok();
      if let Ok(primary_candidate) = read_partitions_candidate(
        source.as_ref(),
        block_size,
        GptHeaderLocation::Primary,
        primary.header.clone(),
      ) {
        GptVolumeSystem::new(
          source,
          block_size,
          GptHeaderLocation::Primary,
          Some(primary.header),
          headers_match.then_some(backup.header),
          primary_candidate.partitions,
        )
      } else if let Ok(backup_candidate) = read_partitions_candidate(
        source.as_ref(),
        block_size,
        GptHeaderLocation::Backup,
        backup.header.clone(),
      ) {
        GptVolumeSystem::new(
          source,
          block_size,
          GptHeaderLocation::Backup,
          None,
          Some(backup.header),
          backup_candidate.partitions,
        )
      } else {
        Err(Error::InvalidFormat(
          "unable to open a valid primary or backup gpt header".to_string(),
        ))
      }
    }
    (Ok(primary), Err(_)) => {
      let primary = read_partitions_candidate(
        source.as_ref(),
        block_size,
        GptHeaderLocation::Primary,
        primary.header.clone(),
      )?;
      GptVolumeSystem::new(
        source,
        block_size,
        GptHeaderLocation::Primary,
        Some(primary.header),
        None,
        primary.partitions,
      )
    }
    (Err(_), Ok(backup)) => {
      let backup = read_partitions_candidate(
        source.as_ref(),
        block_size,
        GptHeaderLocation::Backup,
        backup.header.clone(),
      )?;
      GptVolumeSystem::new(
        source,
        block_size,
        GptHeaderLocation::Backup,
        None,
        Some(backup.header),
        backup.partitions,
      )
    }
    (Err(_primary_error), Err(_backup_error)) => Err(Error::InvalidFormat(
      "unable to open a valid primary or backup gpt header".to_string(),
    )),
  }
}

fn read_header_candidate(
  source: &dyn ByteSource, block_size: u32, location: GptHeaderLocation,
) -> Result<GptHeaderCandidate> {
  let source_size = source.size()?;
  let expected_current_lba = match location {
    GptHeaderLocation::Primary => constants::PRIMARY_HEADER_LBA,
    GptHeaderLocation::Backup => last_lba(source_size, block_size)?,
  };
  let (header, header_block) = read_header_block(source, block_size, expected_current_lba)?;
  validate_header_crc(&header_block, &header)?;

  Ok(GptHeaderCandidate { header })
}

fn read_partitions_candidate(
  source: &dyn ByteSource, block_size: u32, location: GptHeaderLocation, header: GptHeader,
) -> Result<GptCandidate> {
  let source_size = source.size()?;
  let expected_current_lba = match location {
    GptHeaderLocation::Primary => constants::PRIMARY_HEADER_LBA,
    GptHeaderLocation::Backup => last_lba(source_size, block_size)?,
  };

  let entry_array = read_entry_array(source, block_size, &header)?;
  validate_entry_array_crc(&entry_array, header.entry_array_crc32)?;
  let partitions = parse_partitions(&entry_array, block_size, &header)?;

  validate_layout(
    source_size,
    block_size,
    expected_current_lba,
    &header,
    &partitions,
  )?;

  Ok(GptCandidate { header, partitions })
}

fn last_lba(source_size: u64, block_size: u32) -> Result<u64> {
  let block_size = u64::from(block_size);
  if source_size < block_size {
    return Err(Error::InvalidFormat(
      "source is too small to hold a gpt backup header".to_string(),
    ));
  }
  let total_blocks = source_size / block_size;
  total_blocks
    .checked_sub(1)
    .ok_or_else(|| Error::InvalidFormat("source does not contain a full gpt block".to_string()))
}

fn read_header_block(
  source: &dyn ByteSource, block_size: u32, lba: u64,
) -> Result<(GptHeader, Vec<u8>)> {
  let offset = lba
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("gpt header offset overflow".to_string()))?;
  let block = source.read_bytes_at(offset, block_size as usize)?;
  let header = GptHeader::parse(&block)?;
  Ok((header, block))
}

fn push_candidate_block_size(candidates: &mut Vec<u32>, block_size: u32) {
  if !candidates.contains(&block_size) {
    candidates.push(block_size);
  }
}

fn read_entry_array(
  source: &dyn ByteSource, block_size: u32, header: &GptHeader,
) -> Result<Vec<u8>> {
  let entry_array_offset = header
    .entry_array_start_lba
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("gpt entry array offset overflow".to_string()))?;
  let total_entry_bytes = u64::from(header.entry_count)
    .checked_mul(u64::from(header.entry_size))
    .ok_or_else(|| Error::InvalidRange("gpt entry array size overflow".to_string()))?;

  source.read_bytes_at(
    entry_array_offset,
    usize::try_from(total_entry_bytes)
      .map_err(|_| Error::InvalidRange("gpt entry array is too large".to_string()))?,
  )
}

fn parse_partitions(
  data: &[u8], block_size: u32, header: &GptHeader,
) -> Result<Vec<GptPartitionInfo>> {
  let entry_size = usize::try_from(header.entry_size)
    .map_err(|_| Error::InvalidRange("gpt entry size is too large".to_string()))?;
  let mut partitions = Vec::new();

  for index in 0..header.entry_count as usize {
    let start = index
      .checked_mul(entry_size)
      .ok_or_else(|| Error::InvalidRange("gpt entry offset overflow".to_string()))?;
    let end = start
      .checked_add(entry_size)
      .ok_or_else(|| Error::InvalidRange("gpt entry end overflow".to_string()))?;
    let entry = GptPartitionEntry::parse(index, &data[start..end])?;
    if entry.is_unused() {
      continue;
    }
    partitions.push(GptPartitionInfo::from_entry(entry, block_size)?);
  }

  Ok(partitions)
}

fn validate_protective_mbr(source: &dyn ByteSource) -> Result<()> {
  let sector = source.read_bytes_at(0, 512)?;
  if sector[510..512] != [0x55, 0xAA] {
    return Err(Error::InvalidFormat(
      "gpt protective mbr signature is missing".to_string(),
    ));
  }

  let mut has_protective_partition = false;
  for index in 0..4 {
    let start = 446 + index * 16;
    let end = start + 16;
    let entry = MbrPartitionEntry::parse(&sector[start..end])?;
    if entry.is_protective() {
      has_protective_partition = true;
      break;
    }
  }

  if !has_protective_partition {
    return Err(Error::InvalidFormat(
      "gpt protective mbr entry is missing".to_string(),
    ));
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn computes_last_lba_for_the_block_size() {
    assert_eq!(last_lba(4096 * 64, 4096).unwrap(), 63);
  }
}
