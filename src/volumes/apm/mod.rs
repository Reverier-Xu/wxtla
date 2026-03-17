//! APM volume-system driver and probe registration.

mod constants;
mod descriptor;
mod driver;
mod entry;
mod parser;
mod system;

pub use descriptor::{ApmDriverDescriptor, ApmDriverDescriptorEntry};
pub use driver::ApmDriver;
pub use entry::{ApmPartitionInfo, ApmPartitionMapEntry};
pub use system::ApmVolumeSystem;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// APM volume-system descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.apm", FormatKind::VolumeSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(ApmProbe);
}

struct ApmProbe;

impl FormatProbe for ApmProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(driver_descriptor) = context.read_bytes_at(0, constants::SIGNATURE_LEN) else {
      return Ok(ProbeResult::rejected());
    };
    if driver_descriptor != constants::DRIVER_DESCRIPTOR_SIGNATURE {
      return Ok(ProbeResult::rejected());
    }

    let Ok(partition_map) = context.read_bytes_at(
      u64::from(constants::PARTITION_MAP_OFFSET),
      constants::SIGNATURE_LEN,
    ) else {
      return Ok(ProbeResult::rejected());
    };

    if partition_map == constants::PARTITION_MAP_SIGNATURE {
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
