//! VHDX image driver and probe registration.

mod cache;
mod constants;
mod driver;
mod guid;
mod header;
mod image;
mod log_replay;
mod metadata;
mod parent_locator;
mod parser;

pub use driver::VhdxDriver;
pub use guid::VhdxGuid;
pub use header::VhdxImageHeader;
pub use image::VhdxImage;
pub use metadata::{VhdxDiskType, VhdxMetadata};
pub use parent_locator::{VhdxParentLocator, VhdxParentLocatorEntry};

use crate::{
  FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry,
  formats::probe_support::OffsetMagicProbe,
};

/// VHDX image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.vhdx", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const MAGIC: &[u8] = b"vhdxfile";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    MAGIC,
    ProbeConfidence::Exact,
    "vhdx file identifier found",
  ));
}
