//! VHD image driver and probe registration.

mod cache;
mod constants;
mod driver;
mod dynamic_header;
mod footer;
mod image;
mod parser;

pub use driver::VhdDriver;
pub use dynamic_header::{VhdDynamicHeader, VhdParentLocator};
pub use footer::{VhdDiskGeometry, VhdDiskType, VhdFooter};
pub use image::VhdImage;

use crate::{FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry};

/// VHD image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.vhd", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(VhdProbe);
}

struct VhdProbe;

impl crate::FormatProbe for VhdProbe {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &crate::ProbeContext<'_>) -> crate::Result<crate::ProbeResult> {
    let size = context.size()?;
    if size < 512 {
      return Ok(crate::ProbeResult::rejected());
    }
    let footer_offset = size - 512;
    let Ok(signature) = context.read_bytes_at(footer_offset, 8) else {
      return Ok(crate::ProbeResult::rejected());
    };

    if signature == constants::FOOTER_COOKIE {
      Ok(crate::ProbeResult::matched(crate::ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "vhd footer signature found at trailer",
      )))
    } else {
      Ok(crate::ProbeResult::rejected())
    }
  }
}
