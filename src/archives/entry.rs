//! Generic archive entry identifiers and metadata.

/// Opaque identifier for an archive entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArchiveEntryId(Box<[u8]>);

impl ArchiveEntryId {
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

/// Common archive entry kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveEntryKind {
  /// Regular file entry.
  File,
  /// Directory entry.
  Directory,
  /// Symbolic link entry.
  Symlink,
  /// Special or implementation-defined entry.
  Special,
}

/// Generic metadata for an archive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntryRecord {
  /// Opaque archive entry identifier.
  pub id: ArchiveEntryId,
  /// Generic entry kind.
  pub kind: ArchiveEntryKind,
  /// Full logical path inside the archive.
  pub path: String,
  /// Logical size in bytes when known.
  pub size: u64,
}

impl ArchiveEntryRecord {
  /// Create a new archive entry record.
  pub fn new(
    id: ArchiveEntryId, kind: ArchiveEntryKind, path: impl Into<String>, size: u64,
  ) -> Self {
    Self {
      id,
      kind,
      path: path.into(),
      size,
    }
  }
}

/// Directory entry linking a name to an archive entry identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveDirectoryEntry {
  /// Entry name relative to the containing archive directory.
  pub name: String,
  /// Opaque identifier of the referenced archive entry.
  pub entry_id: ArchiveEntryId,
  /// Generic entry kind.
  pub kind: ArchiveEntryKind,
}

impl ArchiveDirectoryEntry {
  /// Create a new archive directory entry.
  pub fn new(name: impl Into<String>, entry_id: ArchiveEntryId, kind: ArchiveEntryKind) -> Self {
    Self {
      name: name.into(),
      entry_id,
      kind,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn archive_entry_id_round_trips_bytes() {
    let entry_id = ArchiveEntryId::from_u64(7);

    assert_eq!(entry_id.as_bytes().len(), 8);
  }

  #[test]
  fn archive_directory_entry_preserves_name_and_kind() {
    let entry = ArchiveDirectoryEntry::new(
      "file.txt",
      ArchiveEntryId::from_u64(3),
      ArchiveEntryKind::File,
    );

    assert_eq!(entry.name, "file.txt");
    assert_eq!(entry.kind, ArchiveEntryKind::File);
  }
}
