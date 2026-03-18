//! Parallels PDI driver and probe registration.

mod descriptor;
mod driver;
mod image;
mod sparse_extent;

pub use descriptor::{PdiDescriptor, PdiDescriptorImageType, PdiSnapshot};
pub use driver::PdiDriver;
pub use image::PdiImage;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, RelatedSourcePurpose, Result,
};

/// PDI image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.pdi", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const TEXT_PROBE_LIMIT: usize = 64 * 1024;
const XML_DECLARATION: &str = "<?xml";
const ROOT_TAG: &str = "<Parallels_disk_image";
const FILE_OPEN_TAG: &str = "<File>";
const FILE_CLOSE_TAG: &str = "</File>";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(PdiProbe);
}

struct PdiProbe;

impl FormatProbe for PdiProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Some(text) = read_probe_text(context)? else {
      return Ok(ProbeResult::rejected());
    };

    if !text.starts_with(XML_DECLARATION) || !text.contains(ROOT_TAG) {
      return Ok(ProbeResult::rejected());
    }

    let Some(backing_file) = extract_tag_value(&text, FILE_OPEN_TAG, FILE_CLOSE_TAG) else {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Likely,
        "parallels disk descriptor found",
      )));
    };

    if context
      .resolve_related_path(RelatedSourcePurpose::Extent, backing_file)?
      .is_some()
    {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "parallels disk descriptor and extent file found",
      )))
    } else {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Likely,
        "parallels disk descriptor found",
      )))
    }
  }
}

fn read_probe_text(context: &ProbeContext<'_>) -> Result<Option<String>> {
  let size = context.size()?.min(TEXT_PROBE_LIMIT as u64) as usize;
  let bytes = context.read_bytes_at(0, size)?;
  Ok(std::str::from_utf8(&bytes).ok().map(str::to_owned))
}

fn extract_tag_value<'a>(text: &'a str, open_tag: &str, close_tag: &str) -> Option<&'a str> {
  let start = text.find(open_tag)? + open_tag.len();
  let end = text[start..].find(close_tag)? + start;
  Some(text[start..end].trim())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn extracts_first_backing_file_from_descriptor_text() {
    let text = "<File>disk.hds</File><File>ignored.hds</File>";

    assert_eq!(
      extract_tag_value(text, FILE_OPEN_TAG, FILE_CLOSE_TAG),
      Some("disk.hds")
    );
  }
}
