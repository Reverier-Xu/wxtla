//! Parsing and sector-size inference for MBR layouts.

use std::collections::HashSet;

use super::{
  boot_record::MbrBootRecord,
  constants::{MAX_LOGICAL_PARTITIONS, SUPPORTED_BYTES_PER_SECTOR},
  entry::{MbrPartitionInfo, MbrPartitionOrigin},
  system::MbrVolumeSystem,
  validation::validate_partitions,
};
use crate::{DataSource, DataSourceHandle, Error, Result, volumes::VolumeRole};

const EXT_SUPERBLOCK_MAGIC_OFFSET: u64 = 1024 + 56;
const PARTITION_BOOT_SIGNATURE_OFFSET: u64 = 510;
const GPT_HEADER_MAGIC_OFFSET: u64 = 512;
const FAT12_MAGIC: &[u8] = b"FAT12   ";
const FAT16_MAGIC: &[u8] = b"FAT16   ";
const FAT32_MAGIC: &[u8] = b"FAT32   ";
const NTFS_OEM_ID: &[u8] = b"NTFS    ";
const GPT_HEADER_MAGIC: &[u8] = b"EFI PART";
const HFS_MAGIC: &[u8] = b"BD";
const HFS_PLUS_MAGIC: &[u8] = b"H+";
const HFSX_MAGIC: &[u8] = b"HX";
const EXT_SUPERBLOCK_MAGIC: [u8; 2] = [0x53, 0xEF];

#[derive(Debug)]
struct MbrParsedLayout {
  bytes_per_sector: u32,
  disk_signature: u32,
  partitions: Vec<MbrPartitionInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CandidateScore {
  evidence_score: u16,
  logical_partition_count: usize,
  recognized_partition_count: usize,
  bytes_per_sector_preference: u8,
}

pub(super) fn open(source: DataSourceHandle) -> Result<MbrVolumeSystem> {
  let boot_record = MbrBootRecord::read(source.as_ref(), 0)?;
  let parsed = infer_layout(source.as_ref(), &boot_record)?;

  Ok(MbrVolumeSystem::new(
    source,
    parsed.bytes_per_sector,
    parsed.disk_signature,
    parsed.partitions,
  ))
}

pub(super) fn open_with_sector_size(
  source: DataSourceHandle, bytes_per_sector: u32,
) -> Result<MbrVolumeSystem> {
  let boot_record = MbrBootRecord::read(source.as_ref(), 0)?;
  let parsed = parse_layout(source.as_ref(), &boot_record, bytes_per_sector)?;

  Ok(MbrVolumeSystem::new(
    source,
    parsed.bytes_per_sector,
    parsed.disk_signature,
    parsed.partitions,
  ))
}

fn infer_layout(source: &dyn DataSource, boot_record: &MbrBootRecord) -> Result<MbrParsedLayout> {
  let mut best_match = None;

  for bytes_per_sector in SUPPORTED_BYTES_PER_SECTOR {
    let Ok(parsed) = parse_layout(source, boot_record, bytes_per_sector) else {
      continue;
    };
    let score = score_candidate(source, &parsed)?;

    match best_match {
      Some((best_score, _)) if best_score >= score => {}
      _ => {
        best_match = Some((score, parsed));
      }
    }
  }

  best_match
    .map(|(_, parsed)| parsed)
    .ok_or_else(|| Error::InvalidFormat("unable to infer a supported mbr sector size".to_string()))
}

fn parse_layout(
  source: &dyn DataSource, boot_record: &MbrBootRecord, bytes_per_sector: u32,
) -> Result<MbrParsedLayout> {
  if !SUPPORTED_BYTES_PER_SECTOR.contains(&bytes_per_sector) {
    return Err(Error::InvalidFormat(format!(
      "unsupported mbr bytes per sector: {bytes_per_sector}"
    )));
  }

  let mut partitions = Vec::new();
  let mut first_extended_container_lba = None;

  for entry in boot_record.entries().iter().copied() {
    if entry.is_unused() {
      continue;
    }

    let info = MbrPartitionInfo::from_primary(partitions.len(), entry, bytes_per_sector)?;
    if entry.is_extended() {
      if first_extended_container_lba.is_some() {
        return Err(Error::InvalidFormat(
          "multiple primary extended partition entries are not supported".to_string(),
        ));
      }
      first_extended_container_lba = Some(u64::from(entry.start_lba));
    }
    partitions.push(info);
  }

  if let Some(first_extended_container_lba) = first_extended_container_lba {
    parse_logical_partitions(
      source,
      bytes_per_sector,
      first_extended_container_lba,
      &mut partitions,
    )?;
  }

  validate_partitions(source.size()?, &partitions)?;

  Ok(MbrParsedLayout {
    bytes_per_sector,
    disk_signature: boot_record.disk_signature(),
    partitions,
  })
}

fn parse_logical_partitions(
  source: &dyn DataSource, bytes_per_sector: u32, first_ebr_lba: u64,
  partitions: &mut Vec<MbrPartitionInfo>,
) -> Result<()> {
  let mut current_ebr_lba = first_ebr_lba;
  let mut seen_ebrs = HashSet::new();

  loop {
    if !seen_ebrs.insert(current_ebr_lba) {
      return Err(Error::InvalidFormat(
        "mbr extended partition chain contains a loop".to_string(),
      ));
    }
    if partitions.len() >= MAX_LOGICAL_PARTITIONS {
      return Err(Error::InvalidFormat(format!(
        "mbr exceeds the maximum of {MAX_LOGICAL_PARTITIONS} logical partitions"
      )));
    }

    let ebr_offset = current_ebr_lba
      .checked_mul(u64::from(bytes_per_sector))
      .ok_or_else(|| Error::InvalidRange("ebr offset overflow".to_string()))?;
    let ebr = MbrBootRecord::read(source, ebr_offset)?;
    let mut logical_entry = None;
    let mut next_link = None;

    for entry in ebr.entries().iter().copied() {
      if entry.is_unused() {
        continue;
      }

      if entry.is_extended() {
        if next_link.is_some() {
          return Err(Error::InvalidFormat(
            "ebr contains more than one chained extended entry".to_string(),
          ));
        }
        next_link = Some(entry);
      } else {
        if logical_entry.is_some() {
          return Err(Error::InvalidFormat(
            "ebr contains more than one logical partition entry".to_string(),
          ));
        }
        logical_entry = Some(entry);
      }
    }

    let logical_entry = logical_entry.ok_or_else(|| {
      Error::InvalidFormat("ebr is missing the logical partition entry".to_string())
    })?;
    let absolute_start_lba = current_ebr_lba
      .checked_add(u64::from(logical_entry.start_lba))
      .ok_or_else(|| Error::InvalidRange("logical partition lba overflow".to_string()))?;
    partitions.push(MbrPartitionInfo::from_entry(
      partitions.len(),
      logical_entry,
      absolute_start_lba,
      VolumeRole::Logical,
      MbrPartitionOrigin::Logical,
      bytes_per_sector,
    )?);

    current_ebr_lba = match next_link {
      Some(next_link) => first_ebr_lba
        .checked_add(u64::from(next_link.start_lba))
        .ok_or_else(|| Error::InvalidRange("next ebr lba overflow".to_string()))?,
      None => break,
    };
  }

  Ok(())
}

fn score_candidate(source: &dyn DataSource, parsed: &MbrParsedLayout) -> Result<CandidateScore> {
  let mut evidence_score = 0u16;
  let mut recognized_partition_count = 0usize;
  let logical_partition_count = parsed
    .partitions
    .iter()
    .filter(|partition| partition.origin == MbrPartitionOrigin::Logical)
    .count();

  for partition in &parsed.partitions {
    if matches!(
      partition.record.role,
      VolumeRole::ExtendedContainer | VolumeRole::Protective
    ) {
      if partition.record.role == VolumeRole::ExtendedContainer && logical_partition_count > 0 {
        evidence_score += 20;
      }
      if partition.record.role == VolumeRole::Protective
        && read_magic(source, GPT_HEADER_MAGIC_OFFSET, GPT_HEADER_MAGIC.len())?.as_deref()
          == Some(GPT_HEADER_MAGIC)
      {
        evidence_score += 40;
        recognized_partition_count += 1;
      }
      continue;
    }

    let offset = partition.record.span.byte_offset;
    let has_strong_signature = (is_fat_type(partition.type_code)
      && partition_has_fat_signature(source, offset)?)
      || (is_ntfs_type(partition.type_code) && partition_has_ntfs_signature(source, offset)?)
      || (partition.type_code == 0x83 && partition_has_ext_signature(source, offset)?)
      || (partition.type_code == 0xAF && partition_has_hfs_signature(source, offset)?);
    let partition_score = if has_strong_signature {
      24
    } else if partition_has_boot_signature(source, offset)? {
      4
    } else {
      0
    };

    if partition_score > 0 {
      recognized_partition_count += 1;
      evidence_score += partition_score;
    }
  }

  evidence_score += (parsed.partitions.len() as u16) * 2;
  evidence_score += (logical_partition_count as u16) * 10;

  Ok(CandidateScore {
    evidence_score,
    logical_partition_count,
    recognized_partition_count,
    bytes_per_sector_preference: bytes_per_sector_preference(parsed.bytes_per_sector),
  })
}

fn bytes_per_sector_preference(bytes_per_sector: u32) -> u8 {
  match bytes_per_sector {
    512 => 4,
    1024 => 3,
    2048 => 2,
    4096 => 1,
    _ => 0,
  }
}

fn is_fat_type(type_code: u8) -> bool {
  matches!(type_code, 0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E)
}

fn is_ntfs_type(type_code: u8) -> bool {
  matches!(type_code, 0x07 | 0x17 | 0x27)
}

fn partition_has_boot_signature(source: &dyn DataSource, offset: u64) -> Result<bool> {
  Ok(
    read_magic(
      source,
      offset + PARTITION_BOOT_SIGNATURE_OFFSET,
      super::constants::BOOT_SIGNATURE.len(),
    )?
    .as_deref()
      == Some(&super::constants::BOOT_SIGNATURE),
  )
}

fn partition_has_fat_signature(source: &dyn DataSource, offset: u64) -> Result<bool> {
  if !partition_has_boot_signature(source, offset)? {
    return Ok(false);
  }

  let fat12_or_16 = read_magic(source, offset + 54, 8)?;
  let fat32 = read_magic(source, offset + 82, 8)?;

  Ok(
    fat12_or_16
      .as_deref()
      .is_some_and(|bytes| bytes == FAT12_MAGIC || bytes == FAT16_MAGIC)
      || fat32.as_deref().is_some_and(|bytes| bytes == FAT32_MAGIC),
  )
}

fn partition_has_ntfs_signature(source: &dyn DataSource, offset: u64) -> Result<bool> {
  if !partition_has_boot_signature(source, offset)? {
    return Ok(false);
  }

  Ok(read_magic(source, offset + 3, NTFS_OEM_ID.len())?.as_deref() == Some(NTFS_OEM_ID))
}

fn partition_has_ext_signature(source: &dyn DataSource, offset: u64) -> Result<bool> {
  Ok(
    read_magic(
      source,
      offset + EXT_SUPERBLOCK_MAGIC_OFFSET,
      EXT_SUPERBLOCK_MAGIC.len(),
    )?
    .as_deref()
      == Some(&EXT_SUPERBLOCK_MAGIC),
  )
}

fn partition_has_hfs_signature(source: &dyn DataSource, offset: u64) -> Result<bool> {
  Ok(
    read_magic(source, offset + 1024, 2)?
      .as_deref()
      .is_some_and(|bytes| bytes == HFS_MAGIC || bytes == HFS_PLUS_MAGIC || bytes == HFSX_MAGIC),
  )
}

fn read_magic(source: &dyn DataSource, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
  match source.read_bytes_at(offset, len) {
    Ok(bytes) => Ok(Some(bytes)),
    Err(Error::UnexpectedEof { .. }) => Ok(None),
    Err(error) => Err(error),
  }
}
