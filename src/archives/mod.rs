//! Archive format modules.

mod driver;
mod entry;

pub mod adf;

pub use driver::{Archive, ArchiveDriver};
pub use entry::{ArchiveDirectoryEntry, ArchiveEntryId, ArchiveEntryKind, ArchiveEntryRecord};
