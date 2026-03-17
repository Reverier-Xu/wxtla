//! VHD image descriptor and probe registration.

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

use super::inventory::FormatInventoryEntry;

/// VHD image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.vhd", FormatKind::Image);

/// Inventory entry for the VHD format module.
pub const INVENTORY: FormatInventoryEntry = FormatInventoryEntry::new(DESCRIPTOR, register_probes);

const FOOTER_MAGIC: &[u8] = b"conectix";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(VhdProbe);
}

struct VhdProbe;

impl FormatProbe for VhdProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    if let Ok(header) = context.header(FOOTER_MAGIC.len())
      && header == FOOTER_MAGIC
    {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "vhd footer signature found at file start",
      )));
    }

    let size = context.size()?;
    if size < 512 {
      return Ok(ProbeResult::rejected());
    }

    let footer_offset = size - 512;
    let Ok(footer_magic) = context.read_bytes_at(footer_offset, FOOTER_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if footer_magic == FOOTER_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "vhd footer signature found at trailer",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
