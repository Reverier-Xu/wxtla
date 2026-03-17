//! NTFS filesystem descriptor and probe registration.

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

use super::inventory::FormatInventoryEntry;

/// NTFS filesystem descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.ntfs", FormatKind::FileSystem);

/// Inventory entry for the NTFS format module.
pub const INVENTORY: FormatInventoryEntry = FormatInventoryEntry::new(DESCRIPTOR, register_probes);

const OEM_ID: &[u8] = b"NTFS    ";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(NtfsProbe);
}

struct NtfsProbe;

impl FormatProbe for NtfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(510, 2) else {
      return Ok(ProbeResult::rejected());
    };
    if signature != [0x55, 0xaa] {
      return Ok(ProbeResult::rejected());
    }

    let Ok(oem_id) = context.read_bytes_at(3, OEM_ID.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if oem_id == OEM_ID {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "ntfs oem id found in boot sector",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
