//! Sparseimage descriptor and probe registration.

use crate::{FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry};

use super::{inventory::FormatInventoryEntry, probe_support::OffsetMagicProbe};

/// Sparseimage descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("image.sparseimage", FormatKind::Image);

/// Inventory entry for the sparseimage format module.
pub const INVENTORY: FormatInventoryEntry = FormatInventoryEntry::new(DESCRIPTOR, register_probes);

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
