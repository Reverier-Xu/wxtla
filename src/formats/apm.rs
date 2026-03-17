//! APM volume-system descriptor and probe registration.

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

use super::inventory::FormatInventoryEntry;

/// APM volume-system descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.apm", FormatKind::VolumeSystem);

/// Inventory entry for the APM format module.
pub const INVENTORY: FormatInventoryEntry = FormatInventoryEntry::new(DESCRIPTOR, register_probes);

const DRIVER_DESCRIPTOR_MAGIC: &[u8] = b"ER";
const PARTITION_MAP_MAGIC: &[u8] = b"PM";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(ApmProbe);
}

struct ApmProbe;

impl FormatProbe for ApmProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(driver_descriptor) = context.read_bytes_at(0, DRIVER_DESCRIPTOR_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };
    if driver_descriptor != DRIVER_DESCRIPTOR_MAGIC {
      return Ok(ProbeResult::rejected());
    }

    let Ok(partition_map) = context.read_bytes_at(512, PARTITION_MAP_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if partition_map == PARTITION_MAP_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "apm driver descriptor and partition map found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
