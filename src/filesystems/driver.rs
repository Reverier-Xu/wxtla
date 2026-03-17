//! Core filesystem-driver interfaces.

use super::{DirectoryEntry, FileSystemNodeId, FileSystemNodeRecord};
use crate::{DataSourceHandle, FormatDescriptor, Result, SourceHints};

/// Read-only filesystem surface exposed by a filesystem driver.
pub trait FileSystem: Send + Sync {
  /// Return the format descriptor for this opened filesystem.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the identifier of the root node.
  fn root_node_id(&self) -> FileSystemNodeId;

  /// Resolve metadata for a filesystem node.
  fn node(&self, node_id: &FileSystemNodeId) -> Result<FileSystemNodeRecord>;

  /// List the direct children of a directory node.
  fn read_dir(&self, directory_id: &FileSystemNodeId) -> Result<Vec<DirectoryEntry>>;

  /// Open file content for a readable file node.
  fn open_file(&self, file_id: &FileSystemNodeId) -> Result<DataSourceHandle>;
}

/// Opens a specific filesystem format into a read-only filesystem surface.
pub trait FileSystemDriver: Send + Sync {
  /// Return the format descriptor handled by this driver.
  fn descriptor(&self) -> FormatDescriptor;

  /// Open the filesystem from the provided byte source.
  fn open(&self, source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Box<dyn FileSystem>>;
}
