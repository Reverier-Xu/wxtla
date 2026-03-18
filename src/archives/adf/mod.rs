//! AccessData AD1 archive driver and probe registration.

mod archive;
mod driver;

pub use archive::AdfArchive;
pub use driver::AdfDriver;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// AccessData AD1 archive descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("archive.ad1", FormatKind::Archive);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const SEGMENT_MARGIN_SIGNATURE: &[u8; 15] = b"ADSEGMENTEDFILE";
const IMAGE_HEADER_SIGNATURE: &[u8; 14] = b"ADLOGICALIMAGE";
const MARGIN_SIZE: usize = 512;

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(AdfProbe);
}

struct AdfProbe;

impl FormatProbe for AdfProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    if context.size()? < (MARGIN_SIZE + 16) as u64 {
      return Ok(ProbeResult::rejected());
    }

    let margin = context.header(MARGIN_SIZE)?;
    if &margin[0..15] != SEGMENT_MARGIN_SIGNATURE {
      return Ok(ProbeResult::rejected());
    }

    let header = context.read_bytes_at(MARGIN_SIZE as u64, 16)?;
    if &header[0..14] != IMAGE_HEADER_SIGNATURE {
      return Ok(ProbeResult::rejected());
    }

    Ok(ProbeResult::matched(ProbeMatch::new(
      DESCRIPTOR,
      ProbeConfidence::Exact,
      "accessdata ad1 segmented archive header found",
    )))
  }
}
