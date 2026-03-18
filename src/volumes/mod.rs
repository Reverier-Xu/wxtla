//! Volume and partition-map format modules.

mod driver;
mod record;

pub mod apm;
pub mod bitlocker;
pub mod gpt;
pub mod mbr;

pub use driver::{VolumeSystem, VolumeSystemDriver};
pub use record::{VolumeRecord, VolumeRole, VolumeSpan};
