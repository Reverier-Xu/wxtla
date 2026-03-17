//! Format inventory and probe registration helpers.

pub mod inventory;
pub mod registry;

pub(crate) mod probe_support;

pub use inventory::{FormatInventory, FormatInventoryEntry, builtin_inventory};
pub use registry::{
  builtin_probe_registry, builtin_probe_registry_for_kind, probe_registry_from_inventory,
  probe_registry_from_inventory_for_kind,
};
