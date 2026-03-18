//! Sparsebundle driver and probe registration.

mod driver;
mod image;
mod parser;

pub use driver::SparseBundleDriver;
pub use image::SparseBundleImage;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, RelatedSourcePurpose, Result,
};

/// Sparsebundle image descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("image.sparsebundle", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const TEXT_PROBE_LIMIT: usize = 32 * 1024;
const XML_DECLARATION: &str = "<?xml";
const BUNDLE_TYPE_MARKER: &str = "com.apple.diskimage.sparsebundle";
const FIRST_BAND_PATH: &str = "bands/0";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(SparseBundleProbe);
}

struct SparseBundleProbe;

impl FormatProbe for SparseBundleProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Some(text) = read_probe_text(context)? else {
      return Ok(ProbeResult::rejected());
    };

    if !text.starts_with(XML_DECLARATION) || !text.contains(BUNDLE_TYPE_MARKER) {
      return Ok(ProbeResult::rejected());
    }

    if context
      .resolve_related_path(RelatedSourcePurpose::Band, FIRST_BAND_PATH)?
      .is_some()
    {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "sparsebundle info plist and first band found",
      )))
    } else {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Strong,
        "sparsebundle info plist found",
      )))
    }
  }
}

fn read_probe_text(context: &ProbeContext<'_>) -> Result<Option<String>> {
  let size = context.size()?.min(TEXT_PROBE_LIMIT as u64) as usize;
  let bytes = context.read_bytes_at(0, size)?;
  Ok(std::str::from_utf8(&bytes).ok().map(str::to_owned))
}
