//! RAR archive driver and probe registration.

mod archive;
mod driver;

pub use archive::RarArchive;
pub use driver::RarDriver;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// RAR archive descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("archive.rar", FormatKind::Archive);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(RarProbe);
}

struct RarProbe;

impl FormatProbe for RarProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(8) else {
      return Ok(ProbeResult::rejected());
    };
    if header.starts_with(b"Rar!\x1A\x07\x00")
      || header == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]
    {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "rar archive signature found",
      )));
    }
    Ok(ProbeResult::rejected())
  }
}
