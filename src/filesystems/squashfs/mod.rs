//! SquashFS filesystem driver and probe registration.

mod datasource;
mod directory;
mod driver;
mod filesystem;
mod inode;
mod superblock;

pub use driver::SquashFsDriver;
pub use filesystem::SquashFsFileSystem;

use self::superblock::{SQUASHFS_MAGIC, SquashFsSuperblock};
use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.squashfs", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(SquashFsProbe);
}

struct SquashFsProbe;

impl FormatProbe for SquashFsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.source().size()?;
    if size < 96 {
      return Ok(ProbeResult::rejected());
    }
    let header = context.source().read_bytes_at(size - 96, 96)?;
    if &header[0..4] != SQUASHFS_MAGIC {
      return Ok(ProbeResult::rejected());
    }
    if SquashFsSuperblock::read(context.source()).is_ok() {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "squashfs superblock geometry is valid",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  fn make_minimal_squashfs_image() -> Vec<u8> {
    let image_size: usize = 4096;
    let mut data = vec![0u8; image_size];
    let sb_offset = image_size - 96;

    data[sb_offset..sb_offset + 4].copy_from_slice(SQUASHFS_MAGIC);
    data[sb_offset + 4..sb_offset + 8].copy_from_slice(&1u32.to_le_bytes());
    data[sb_offset + 12..sb_offset + 16].copy_from_slice(&4096u32.to_le_bytes());
    data[sb_offset + 22..sb_offset + 24].copy_from_slice(&12u16.to_le_bytes());
    data[sb_offset + 28..sb_offset + 30].copy_from_slice(&4u16.to_le_bytes());
    data[sb_offset + 32..sb_offset + 40].copy_from_slice(&4096u64.to_le_bytes());
    data[sb_offset + 40..sb_offset + 48].copy_from_slice(&4096u64.to_le_bytes());
    data[sb_offset + 48..sb_offset + 56].copy_from_slice(&u64::MAX.to_le_bytes());
    data[sb_offset + 56..sb_offset + 64].copy_from_slice(&u64::MAX.to_le_bytes());
    data[sb_offset + 64..sb_offset + 72].copy_from_slice(&0u64.to_le_bytes());
    data[sb_offset + 72..sb_offset + 80].copy_from_slice(&0u64.to_le_bytes());
    data[sb_offset + 80..sb_offset + 88].copy_from_slice(&u64::MAX.to_le_bytes());
    data[sb_offset + 88..sb_offset + 96].copy_from_slice(&u64::MAX.to_le_bytes());

    data
  }

  #[test]
  fn probe_matches_minimal_squashfs_image() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(make_minimal_squashfs_image());

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }

  #[test]
  fn probe_rejects_empty_image() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0u8; 64]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }

  #[test]
  fn probe_rejects_non_squashfs_image() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0u8; 128]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }
}
