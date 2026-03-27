//! Volume and partition-map format modules.

mod driver;
mod record;

pub mod apm;
pub mod bitlocker;
pub mod gpt;
pub mod lvm;
pub mod mbr;

pub(crate) use driver::VolumeSystem;
pub use record::{VolumeRecord, VolumeRole, VolumeSpan};
