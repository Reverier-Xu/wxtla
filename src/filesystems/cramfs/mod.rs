//! CRAMFS filesystem driver and probe registration.

mod driver;
mod filesystem;

pub use driver::CramFsDriver;
pub use filesystem::CramFsFileSystem;

use crate::{
  Error, FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.cramfs", FormatKind::FileSystem);

pub(crate) const CRAMFS_MAGIC: u32 = 0x28CD_3D45;
pub(crate) const CRAMFS_SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
pub(crate) const CRAMFS_BLOCK_SIZE: u64 = 4096;
pub(crate) const CRAMFS_SUPERBLOCK_SIZE: usize = 64;

pub(crate) const CRAMFS_FLAG_UNCOMPRESSED_BLOCK: u32 = 0x8000_0000;
pub(crate) const CRAMFS_FLAG_DIRECT_POINTER: u32 = 0x4000_0000;

#[allow(dead_code)]
pub(crate) const CRAMFS_FLAG_FSID_VERSION_2: u32 = 0x0000_0001;
#[allow(dead_code)]
pub(crate) const CRAMFS_FLAG_SORTED_DIRS: u32 = 0x0000_0002;
#[allow(dead_code)]
pub(crate) const CRAMFS_FLAG_HOLES: u32 = 0x0000_0100;
#[allow(dead_code)]
pub(crate) const CRAMFS_FLAG_SHIFTED_ROOT_OFFSET: u32 = 0x0000_0400;

#[allow(dead_code)]
pub(crate) const CRAMFS_MODE_WIDTH: u32 = 16;
#[allow(dead_code)]
pub(crate) const CRAMFS_UID_WIDTH: u32 = 16;
#[allow(dead_code)]
pub(crate) const CRAMFS_GID_WIDTH: u32 = 8;
#[allow(dead_code)]
pub(crate) const CRAMFS_NAMELEN_WIDTH: u32 = 6;
#[allow(dead_code)]
pub(crate) const CRAMFS_OFFSET_WIDTH: u32 = 26;
#[allow(dead_code)]
pub(crate) const CRAMFS_SIZE_WIDTH: u32 = 24;

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(CramFsProbe);
}

struct CramFsProbe;

impl FormatProbe for CramFsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.source().size()?;
    if size < CRAMFS_SUPERBLOCK_SIZE as u64 {
      return Ok(ProbeResult::rejected());
    }
    let header = context.source().read_bytes_at(0, CRAMFS_SUPERBLOCK_SIZE)?;
    let magic = u32::from_le_bytes(
      header
        .get(0..4)
        .ok_or_else(|| Error::invalid_format("cramfs header is truncated"))?
        .try_into()
        .map_err(|_| Error::invalid_format("cramfs header is truncated"))?,
    );
    if magic != CRAMFS_MAGIC {
      return Ok(ProbeResult::rejected());
    }
    let sig = header
      .get(16..32)
      .ok_or_else(|| Error::invalid_format("cramfs header is truncated"))?;
    if sig != CRAMFS_SIGNATURE {
      return Ok(ProbeResult::rejected());
    }
    Ok(ProbeResult::matched(ProbeMatch::new(
      DESCRIPTOR,
      ProbeConfidence::Exact,
      "cramfs magic and signature are valid",
    )))
  }
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
  Ok(u32::from_le_bytes(read_array::<4>(bytes, offset)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  bytes
    .get(offset..offset + N)
    .ok_or_else(|| Error::invalid_format("cramfs field extends beyond available data"))?
    .try_into()
    .map_err(|_| Error::invalid_format("cramfs field is truncated"))
}

pub(crate) fn read_slice<'a>(
  bytes: &'a [u8], offset: usize, length: usize, what: &str,
) -> Result<&'a [u8]> {
  let end = offset
    .checked_add(length)
    .ok_or_else(|| Error::invalid_range(format!("{what} offset overflow")))?;
  bytes.get(offset..end).ok_or_else(|| {
    Error::invalid_format(format!("{what} extends beyond the available cramfs data"))
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  fn make_minimal_cramfs_image() -> Vec<u8> {
    let mut data = vec![0u8; 4096];

    data[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
    data[4..8].copy_from_slice(&4096u32.to_le_bytes());
    data[16..32].copy_from_slice(CRAMFS_SIGNATURE);

    data
  }

  #[test]
  fn probe_matches_minimal_cramfs_image() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(make_minimal_cramfs_image());

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }

  #[test]
  fn probe_rejects_non_cramfs_image() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0u8; 256]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }
}
