//! Built-in format descriptors, inventory, and probe registration helpers.

pub mod apm;
pub mod ewf;
pub mod ext;
pub mod fat;
pub mod gpt;
pub mod hfs;
pub mod inventory;
pub mod mbr;
pub mod ntfs;
pub mod qcow;
pub mod registry;
pub mod sparseimage;
pub mod udif;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;

mod probe_support;

pub use inventory::{FormatInventory, FormatInventoryEntry, builtin_inventory};
pub use registry::{builtin_probe_registry, probe_registry_from_inventory};
