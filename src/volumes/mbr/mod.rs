//! MBR volume-system descriptor and probe registration.

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// MBR volume-system descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.mbr", FormatKind::VolumeSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(MbrProbe);
}

struct MbrProbe;

impl FormatProbe for MbrProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(510, 2) else {
      return Ok(ProbeResult::rejected());
    };

    if signature == [0x55, 0xaa] {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Weak,
        "mbr boot signature found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
