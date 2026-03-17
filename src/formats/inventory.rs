//! Built-in format inventory.

use crate::{FormatDescriptor, ProbeRegistry};

/// A single inventory entry for a built-in format.
#[derive(Clone, Copy)]
pub struct FormatInventoryEntry {
  /// Format descriptor published by the format module.
  pub descriptor: FormatDescriptor,
  register_probes: fn(&mut ProbeRegistry),
}

impl FormatInventoryEntry {
  /// Create a new inventory entry.
  pub const fn new(descriptor: FormatDescriptor, register_probes: fn(&mut ProbeRegistry)) -> Self {
    Self {
      descriptor,
      register_probes,
    }
  }

  /// Register this format's probes into a registry.
  pub fn register_probes(&self, registry: &mut ProbeRegistry) {
    (self.register_probes)(registry);
  }
}

inventory::collect!(FormatInventoryEntry);

/// Inventory of built-in formats.
pub struct FormatInventory {
  entries: Vec<&'static FormatInventoryEntry>,
}

impl FormatInventory {
  /// Create an inventory from discovered entries.
  pub fn new(entries: Vec<&'static FormatInventoryEntry>) -> Self {
    Self { entries }
  }

  /// Return the inventory entries.
  pub fn entries(&self) -> &[&'static FormatInventoryEntry] {
    &self.entries
  }

  /// Return the number of known formats.
  pub fn len(&self) -> usize {
    self.entries.len()
  }

  /// Return `true` when the inventory is empty.
  pub fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }
}

/// Return the built-in inventory of currently known formats.
pub fn builtin_inventory() -> FormatInventory {
  let mut entries: Vec<_> = inventory::iter::<FormatInventoryEntry>
    .into_iter()
    .collect();
  entries.sort_by_key(|entry| (entry.descriptor.kind.probe_sort_rank(), entry.descriptor.id));
  FormatInventory::new(entries)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{images::ewf, volumes::gpt};

  #[test]
  fn builtin_inventory_contains_known_formats() {
    let inventory = builtin_inventory();

    assert!(!inventory.is_empty());
    assert!(
      inventory
        .entries()
        .iter()
        .any(|entry| entry.descriptor == gpt::DESCRIPTOR)
    );
    assert!(
      inventory
        .entries()
        .iter()
        .any(|entry| entry.descriptor == ewf::DESCRIPTOR)
    );
  }
}
