//! Helpers for building probe registries from format inventories.

use crate::ProbeRegistry;

use super::inventory::{FormatInventory, builtin_inventory};

/// Build a probe registry from a format inventory.
pub fn probe_registry_from_inventory(inventory: FormatInventory) -> ProbeRegistry {
  let mut registry = ProbeRegistry::new();
  for entry in inventory.entries() {
    entry.register_probes(&mut registry);
  }
  registry
}

/// Build a probe registry containing all built-in format probes.
pub fn builtin_probe_registry() -> ProbeRegistry {
  probe_registry_from_inventory(builtin_inventory())
}
