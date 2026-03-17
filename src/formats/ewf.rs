//! EWF image descriptor and probe registration.

use crate::{FormatDescriptor, FormatKind, ProbeConfidence, ProbeRegistry};

use super::{inventory::FormatInventoryEntry, probe_support::OffsetMagicProbe};

/// EWF image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.ewf", FormatKind::Image);

/// Inventory entry for the EWF format module.
pub const INVENTORY: FormatInventoryEntry = FormatInventoryEntry::new(DESCRIPTOR, register_probes);

const MAGIC: &[u8] = b"EVF\t\r\n\xff\0";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(OffsetMagicProbe::new(
    DESCRIPTOR,
    0,
    MAGIC,
    ProbeConfidence::Exact,
    "ewf segment header found",
  ));
}
