//! VMDK image driver and probe registration.

mod cache;
mod constants;
mod descriptor;
mod driver;
mod header;
mod image;
mod parser;

pub use descriptor::{
  VmdkDescriptor, VmdkDescriptorExtent, VmdkExtentAccessMode, VmdkExtentType, VmdkFileType,
};
pub use driver::VmdkDriver;
pub use header::VmdkSparseHeader;
pub use image::VmdkImage;

use crate::{
  FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry,
  formats::probe_support::OffsetMagicProbe,
};

/// VMDK image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.vmdk", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const MAGIC: &[u8] = b"KDMV";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    MAGIC,
    ProbeConfidence::Exact,
    "vmdk sparse header found",
  ));
}
