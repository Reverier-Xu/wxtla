//! CLFS (Common Log File System) driver and probe registration.

mod driver;
mod filesystem;

pub use driver::ClfsDriver;
pub use filesystem::ClfsFileSystem;

use crate::{
  Error, FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.clfs", FormatKind::FileSystem);

pub(crate) const SECTOR_SIZE: u64 = 512;
pub(crate) const CLFS_CONTROL_RECORD_MAGIC: u64 = 0xC1F5_C1F5_0000_5F1C;

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(ClfsProbe);
}

struct ClfsProbe;

impl FormatProbe for ClfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.source().size()?;
    if size < SECTOR_SIZE * 4 {
      return Ok(ProbeResult::rejected());
    }

    let Ok(data) = context.source().read_bytes_at(0, SECTOR_SIZE as usize) else {
      return Ok(ProbeResult::rejected());
    };

    let total_sectors = u16::from_le_bytes(
      data[4..6]
        .try_into()
        .map_err(|_| Error::invalid_format("clfs header is truncated"))?,
    ) as u64;

    if !(4..=64).contains(&total_sectors) {
      return Ok(ProbeResult::rejected());
    }

    let block_size = total_sectors * SECTOR_SIZE;
    if block_size > size {
      return Ok(ProbeResult::rejected());
    }

    let Ok(block_data) = context.source().read_bytes_at(0, block_size as usize) else {
      return Ok(ProbeResult::rejected());
    };

    if block_data.len() < 0x48 + 8 {
      return Ok(ProbeResult::rejected());
    }

    let magic = u64::from_le_bytes(
      block_data[0x48..0x50]
        .try_into()
        .map_err(|_| Error::invalid_format("clfs control record is truncated"))?,
    );

    if magic == CLFS_CONTROL_RECORD_MAGIC {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "clfs control record magic is valid",
      )));
    }

    Ok(ProbeResult::rejected())
  }
}

pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
  Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
  Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
  Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  bytes
    .get(offset..offset + N)
    .ok_or_else(|| Error::invalid_format("clfs field extends beyond available data"))?
    .try_into()
    .map_err(|_| Error::invalid_format("clfs field is truncated"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  #[test]
  fn probe_matches_clfs_magic() {
    let mut data = vec![0u8; 4096];
    data[4..6].copy_from_slice(&8u16.to_le_bytes());
    data[0x48..0x50].copy_from_slice(&CLFS_CONTROL_RECORD_MAGIC.to_le_bytes());

    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(data);

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }

  #[test]
  fn probe_rejects_non_clfs() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0u8; 4096]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }
}
