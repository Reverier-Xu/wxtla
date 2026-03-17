//! QCOW image descriptor and probe registration.

use crate::{FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry};

use crate::formats::probe_support::OffsetMagicProbe;

/// QCOW image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.qcow", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const MAGIC: &[u8] = b"QFI\xfb";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    MAGIC,
    ProbeConfidence::Exact,
    "qcow header found",
  ));
}
