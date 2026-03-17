//! EWF image driver and probe registration.

mod cache;
mod constants;
mod driver;
mod file_header;
mod hash;
mod image;
mod parser;
mod section;
mod table;
mod types;
mod volume;

pub use driver::EwfDriver;
pub use image::EwfImage;
pub use types::{EwfChunkDescriptor, EwfChunkEncoding, EwfMediaType};

use crate::{
  FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry,
  formats::probe_support::OffsetMagicProbe,
};

/// EWF image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.ewf", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    constants::FILE_HEADER_MAGIC,
    ProbeConfidence::Exact,
    "ewf segment header found",
  ));
}
