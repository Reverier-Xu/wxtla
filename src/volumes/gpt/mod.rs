//! GPT volume-system descriptor and probe registration.

use crate::{FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry};

use crate::formats::probe_support::OffsetMagicProbe;

/// GPT volume-system descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.gpt", FormatKind::VolumeSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const MAGIC: &[u8] = b"EFI PART";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    512,
    MAGIC,
    ProbeConfidence::Exact,
    "gpt header found at lba1",
  ));
}
