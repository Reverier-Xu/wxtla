//! VMDK image driver and probe registration.

mod cache;
mod constants;
mod cowd_header;
mod descriptor;
mod driver;
mod header;
mod image;
mod parser;
mod resolve;

pub use cowd_header::VmdkCowdHeader;
pub use descriptor::{
  VmdkDescriptor, VmdkDescriptorExtent, VmdkExtentAccessMode, VmdkExtentType, VmdkFileType,
};
pub use driver::VmdkDriver;
pub use header::VmdkSparseHeader;
pub use image::VmdkImage;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result, formats::probe_support::OffsetMagicProbe,
};

/// VMDK image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.vmdk", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const MAGIC: &[u8] = b"KDMV";
const COWD_MAGIC: &[u8] = b"COWD";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    MAGIC,
    ProbeConfidence::Exact,
    "vmdk sparse header found",
  ));
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    COWD_MAGIC,
    ProbeConfidence::Exact,
    "vmdk cowd header found",
  ));
  registry.register(VmdkDescriptorProbe);
}

struct VmdkDescriptorProbe;

impl FormatProbe for VmdkDescriptorProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.size()?;
    if size == 0 || size > 128 * 1024 {
      return Ok(ProbeResult::rejected());
    }

    let bytes = context.read_bytes_at(
      0,
      usize::try_from(size)
        .map_err(|_| crate::Error::invalid_range("vmdk descriptor probe size is too large"))?,
    )?;
    let Ok(descriptor) = VmdkDescriptor::from_bytes(&bytes) else {
      return Ok(ProbeResult::rejected());
    };
    if descriptor.file_type == VmdkFileType::Unknown {
      return Ok(ProbeResult::rejected());
    }

    let confidence = if context
      .source_identity()
      .and_then(crate::SourceIdentity::extension)
      .is_some_and(|extension| extension.eq_ignore_ascii_case("vmdk"))
    {
      ProbeConfidence::Exact
    } else {
      ProbeConfidence::Likely
    };
    Ok(ProbeResult::matched(ProbeMatch::new(
      DESCRIPTOR,
      confidence,
      "vmdk descriptor file found",
    )))
  }
}
