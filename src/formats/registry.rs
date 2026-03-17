//! Helpers for building probe registries from format inventories.

use super::inventory::{FormatInventory, builtin_inventory};
use crate::{FormatKind, ProbeRegistry};

/// Build a probe registry from a format inventory.
pub fn probe_registry_from_inventory(inventory: FormatInventory) -> ProbeRegistry {
  let mut registry = ProbeRegistry::new();
  for entry in inventory.entries() {
    entry.register_probes(&mut registry);
  }
  registry
}

/// Build a probe registry for a specific format kind from a format inventory.
pub fn probe_registry_from_inventory_for_kind(
  inventory: &FormatInventory, kind: FormatKind,
) -> ProbeRegistry {
  let mut registry = ProbeRegistry::new();
  for entry in inventory.entries_of_kind(kind) {
    entry.register_probes(&mut registry);
  }
  registry
}

/// Build a probe registry containing all built-in format probes.
pub fn builtin_probe_registry() -> ProbeRegistry {
  probe_registry_from_inventory(builtin_inventory())
}

/// Build a probe registry for a specific built-in format kind.
pub fn builtin_probe_registry_for_kind(kind: FormatKind) -> ProbeRegistry {
  let inventory = builtin_inventory();
  probe_registry_from_inventory_for_kind(&inventory, kind)
}
