//! VHDX image descriptor and probe registration.

use crate::{FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry};

use super::{inventory::FormatInventoryEntry, probe_support::OffsetMagicProbe};

/// VHDX image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.vhdx", FormatKind::Image);

/// Inventory entry for the VHDX format module.
pub const INVENTORY: FormatInventoryEntry = FormatInventoryEntry::new(DESCRIPTOR, register_probes);

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
