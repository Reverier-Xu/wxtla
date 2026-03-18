//! Sparseimage driver and probe registration.

mod driver;
mod header;
mod image;
mod parser;

pub use driver::SparseImageDriver;
pub use header::SparseImageHeader;
pub use image::SparseImage;

use crate::{
  FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry,
  formats::probe_support::OffsetMagicProbe,
};

/// Sparseimage descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("image.sparseimage", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const MAGIC: &[u8] = b"sprs";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    MAGIC,
    ProbeConfidence::Exact,
    "sparseimage header found",
  ));
}
