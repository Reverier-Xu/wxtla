//! EWF image driver and probe registration.

mod cache;
mod constants;
mod driver;
mod file_header;
mod hash;
mod image;
mod naming;
mod parser;
mod section;
mod table;
mod types;
mod volume;

pub use driver::EwfDriver;
pub use image::EwfImage;
pub use types::{EwfChunkDescriptor, EwfChunkEncoding, EwfMediaType};

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// EWF image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.ewf", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(EwfProbe);
}

struct EwfProbe;

impl FormatProbe for EwfProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(0, constants::FILE_HEADER_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if signature == constants::FILE_HEADER_MAGIC || signature == constants::FILE_HEADER_MAGIC_LVF {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "ewf segment header found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
