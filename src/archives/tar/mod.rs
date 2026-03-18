//! TAR archive driver and probe registration.

mod archive;
mod driver;

pub use archive::TarArchive;
pub use driver::TarDriver;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// TAR archive descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("archive.tar", FormatKind::Archive);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(TarProbe);
}

struct TarProbe;

impl FormatProbe for TarProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(512) else {
      return Ok(ProbeResult::rejected());
    };
    match archive::TarHeader::from_bytes(&header) {
      Ok(parsed) => {
        let confidence = if parsed.has_ustar_magic {
          ProbeConfidence::Exact
        } else {
          ProbeConfidence::Likely
        };
        Ok(ProbeResult::matched(ProbeMatch::new(
          DESCRIPTOR,
          confidence,
          "tar archive header found",
        )))
      }
      Err(_) => Ok(ProbeResult::rejected()),
    }
  }
}
