//! GPT volume-system driver and probe registration.

mod constants;
mod driver;
mod entry;
mod guid;
mod header;
mod parser;
mod system;
mod validation;

pub use driver::GptDriver;
pub use entry::{GptPartitionEntry, GptPartitionInfo};
pub use guid::GptGuid;
pub use header::GptHeader;
pub use system::GptVolumeSystem;

use crate::{
  FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry,
  formats::probe_support::OffsetMagicProbe,
};

/// GPT volume-system descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.gpt", FormatKind::VolumeSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    u64::from(constants::DEFAULT_BLOCK_SIZE),
    constants::HEADER_SIGNATURE,
    ProbeConfidence::Exact,
    "gpt header found at lba1",
  ));
}
