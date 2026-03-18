//! ZIP archive driver and probe registration.

mod archive;
mod driver;

pub use archive::ZipArchive;
pub use driver::ZipDriver;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// ZIP archive descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("archive.zip", FormatKind::Archive);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(ZipProbe);
}

struct ZipProbe;

impl FormatProbe for ZipProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(4) else {
      return Ok(ProbeResult::rejected());
    };
    if header == b"PK\x03\x04" || header == b"PK\x05\x06" || header == b"PK\x07\x08" {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "zip local header or end-of-central-directory signature found",
      )));
    }

    Ok(ProbeResult::rejected())
  }
}
