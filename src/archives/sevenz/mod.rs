//! 7z archive driver and probe registration.

mod archive;
mod driver;

pub use archive::SevenZipArchive;
pub use driver::SevenZipDriver;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// 7z archive descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("archive.7z", FormatKind::Archive);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(SevenZipProbe);
}

struct SevenZipProbe;

impl FormatProbe for SevenZipProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(6) else {
      return Ok(ProbeResult::rejected());
    };
    if header == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "7z archive signature found",
      )));
    }
    Ok(ProbeResult::rejected())
  }
}
