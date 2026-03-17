//! ext-family filesystem descriptor and probe registration.

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

use super::inventory::FormatInventoryEntry;

/// ext-family filesystem descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.ext", FormatKind::FileSystem);

/// Inventory entry for the ext format module.
pub const INVENTORY: FormatInventoryEntry = FormatInventoryEntry::new(DESCRIPTOR, register_probes);

const SUPERBLOCK_MAGIC_LE: [u8; 2] = [0x53, 0xef];

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(ExtProbe);
}

struct ExtProbe;

impl FormatProbe for ExtProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(superblock_magic) = context.read_bytes_at(1024 + 56, SUPERBLOCK_MAGIC_LE.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if superblock_magic == SUPERBLOCK_MAGIC_LE {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "ext superblock magic found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
