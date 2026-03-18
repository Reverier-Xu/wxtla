//! UDIF image driver and probe registration.

mod block_map;
mod cache;
mod driver;
mod image;
mod parser;
mod trailer;

pub use block_map::UdifCompressionMethod;
pub use driver::UdifDriver;
pub use image::UdifImage;
pub use trailer::UdifTrailer;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// UDIF / DMG image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.udif", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const TRAILER_MAGIC: &[u8] = b"koly";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(UdifProbe);
}

struct UdifProbe;

impl FormatProbe for UdifProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.size()?;
    if size < 512 {
      return Ok(ProbeResult::rejected());
    }

    let trailer_offset = size - 512;
    let Ok(trailer_magic) = context.read_bytes_at(trailer_offset, TRAILER_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if trailer_magic == TRAILER_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "udif koly trailer found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
