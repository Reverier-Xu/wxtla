//! Core archive-driver interfaces.

use super::{ArchiveDirectoryEntry, ArchiveEntryId, ArchiveEntryRecord};
use crate::{DataSourceHandle, FormatDescriptor, Result, SourceHints};

/// Read-only archive surface exposed by an archive driver.
pub trait Archive: Send + Sync {
  /// Return the format descriptor for this opened archive.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the identifier of the archive root entry.
  fn root_entry_id(&self) -> ArchiveEntryId;

  /// Resolve metadata for an archive entry.
  fn entry(&self, entry_id: &ArchiveEntryId) -> Result<ArchiveEntryRecord>;

  /// List the direct children of an archive directory entry.
  fn read_dir(&self, directory_id: &ArchiveEntryId) -> Result<Vec<ArchiveDirectoryEntry>>;

  /// Open file content for a readable archive entry.
  fn open_file(&self, entry_id: &ArchiveEntryId) -> Result<DataSourceHandle>;

  /// Return `true` when the archive is currently locked behind an optional
  /// secret.
  fn is_locked(&self) -> bool {
    false
  }

  /// Attempt to unlock the archive with a password.
  fn unlock_with_password(&mut self, _password: &str) -> Result<bool> {
    Ok(false)
  }
}

/// Opens a specific archive format into a read-only archive surface.
pub trait ArchiveDriver: Send + Sync {
  /// Return the format descriptor handled by this driver.
  fn descriptor(&self) -> FormatDescriptor;

  /// Open the archive from the provided byte source.
  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn Archive>>;
}
