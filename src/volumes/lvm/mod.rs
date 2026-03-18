//! LVM2 volume-manager driver and probe registration.

mod checksum;
mod constants;
mod driver;
mod io_utils;
mod metadata_text;
mod model;
mod parser;
mod system;

pub use driver::LvmDriver;
pub use model::{LvmChunk, LvmLogicalVolumeInfo, LvmParsedImage};
pub use system::LvmVolumeSystem;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// LVM2 volume-manager descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.lvm", FormatKind::VolumeManager);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(LvmProbe);
}

struct LvmProbe;

impl FormatProbe for LvmProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    if parser::parse_lvm_image(context.source()).is_ok() {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "lvm2 label and metadata found",
      )));
    }

    Ok(ProbeResult::rejected())
  }
}
