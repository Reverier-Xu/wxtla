//! Archive format modules.

mod driver;
mod entry;

pub mod adf;
pub mod tar;

pub use driver::{Archive, ArchiveDriver};
pub use entry::{ArchiveDirectoryEntry, ArchiveEntryId, ArchiveEntryKind, ArchiveEntryRecord};
