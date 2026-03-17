//! Built-in format inventory.

use crate::{FormatDescriptor, ProbeRegistry};

use super::{apm, ewf, ext, fat, gpt, hfs, mbr, ntfs, qcow, sparseimage, udif, vhd, vhdx, vmdk};

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

/// Inventory of built-in formats.
#[derive(Clone, Copy)]
pub struct FormatInventory {
  entries: &'static [FormatInventoryEntry],
}

impl FormatInventory {
  /// Create an inventory from a static entry slice.
  pub const fn new(entries: &'static [FormatInventoryEntry]) -> Self {
    Self { entries }
  }

  /// Return the inventory entries.
  pub fn entries(&self) -> &'static [FormatInventoryEntry] {
    self.entries
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

const BUILTIN_ENTRIES: &[FormatInventoryEntry] = &[
  ewf::INVENTORY,
  qcow::INVENTORY,
  vhd::INVENTORY,
  vhdx::INVENTORY,
  vmdk::INVENTORY,
  sparseimage::INVENTORY,
  udif::INVENTORY,
  gpt::INVENTORY,
  apm::INVENTORY,
  mbr::INVENTORY,
  fat::INVENTORY,
  ntfs::INVENTORY,
  ext::INVENTORY,
  hfs::INVENTORY,
];

/// Return the built-in inventory of currently known formats.
pub fn builtin_inventory() -> FormatInventory {
  FormatInventory::new(BUILTIN_ENTRIES)
}

#[cfg(test)]
mod tests {
  use super::*;

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
