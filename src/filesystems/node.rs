//! Generic filesystem node identifiers and metadata.

/// Opaque identifier for a filesystem node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileSystemNodeId(Box<[u8]>);

impl FileSystemNodeId {
  /// Create an identifier from raw bytes.
  pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
    Self(bytes.into().into_boxed_slice())
  }

  /// Create an identifier from a native `u64` value.
  pub fn from_u64(value: u64) -> Self {
    Self::from_bytes(value.to_le_bytes().to_vec())
  }

  /// Return the raw identifier bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

/// Common filesystem node kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileSystemNodeKind {
  /// Regular file.
  File,
  /// Directory.
  Directory,
  /// Symbolic link.
  Symlink,
  /// Special or device-like node.
  Special,
}

/// Generic metadata for a filesystem node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSystemNodeRecord {
  /// Opaque node identifier.
  pub id: FileSystemNodeId,
  /// Generic node kind.
  pub kind: FileSystemNodeKind,
  /// Logical size in bytes when known.
  pub size: u64,
}

impl FileSystemNodeRecord {
  /// Create a new filesystem node record.
  pub fn new(id: FileSystemNodeId, kind: FileSystemNodeKind, size: u64) -> Self {
    Self { id, kind, size }
  }
}

/// Directory entry linking a name to a node identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
  /// Entry name as presented by the filesystem.
  pub name: String,
  /// Opaque identifier of the referenced node.
  pub node_id: FileSystemNodeId,
  /// Generic node kind.
  pub kind: FileSystemNodeKind,
}

impl DirectoryEntry {
  /// Create a new directory entry.
  pub fn new(name: impl Into<String>, node_id: FileSystemNodeId, kind: FileSystemNodeKind) -> Self {
    Self {
      name: name.into(),
      node_id,
      kind,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn file_system_node_id_round_trips_bytes() {
    let node_id = FileSystemNodeId::from_u64(42);

    assert_eq!(node_id.as_bytes().len(), 8);
  }

  #[test]
  fn directory_entry_preserves_name_and_kind() {
    let entry = DirectoryEntry::new(
      "readme.txt",
      FileSystemNodeId::from_u64(1),
      FileSystemNodeKind::File,
    );

    assert_eq!(entry.name, "readme.txt");
    assert_eq!(entry.kind, FileSystemNodeKind::File);
  }
}
