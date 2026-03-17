//! QCOW image driver and probe registration.

mod cache;
mod constants;
mod driver;
mod header;
mod image;
mod parser;
mod validation;

pub use driver::QcowDriver;
pub use header::QcowHeader;
pub use image::QcowImage;

use crate::{
  FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry,
  formats::probe_support::OffsetMagicProbe,
};

/// QCOW image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.qcow", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    constants::FILE_HEADER_MAGIC,
    ProbeConfidence::Exact,
    "qcow header found",
  ));
}
