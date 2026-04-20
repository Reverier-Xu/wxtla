//! Generic namespace-facing metadata and stream types.

use super::{ByteSourceHandle, Error, Result};

/// Opaque identifier for a namespace node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamespaceNodeId(Box<[u8]>);

impl NamespaceNodeId {
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

/// Common namespace node kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceNodeKind {
  /// Regular file-like node.
  File,
  /// Directory-like node.
  Directory,
  /// Symbolic link node.
  Symlink,
  /// Special or implementation-defined node.
  Special,
}

/// Generic metadata for a namespace node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceNodeRecord {
  /// Opaque node identifier.
  pub id: NamespaceNodeId,
  /// Generic node kind.
  pub kind: NamespaceNodeKind,
  /// Logical size in bytes when known.
  pub size: u64,
  /// Logical path when the backing format exposes one cheaply, or an empty
  /// string when the path is not materialized.
  pub path: String,
}

impl NamespaceNodeRecord {
  /// Create a new namespace node record.
  pub fn new(id: NamespaceNodeId, kind: NamespaceNodeKind, size: u64) -> Self {
    Self {
      id,
      kind,
      size,
      path: String::new(),
    }
  }

  /// Attach a logical path to the record.
  pub fn with_path(mut self, path: impl Into<String>) -> Self {
    self.path = path.into();
    self
  }
}

/// Directory entry linking a name to a namespace node identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDirectoryEntry {
  /// Entry name relative to the containing namespace directory.
  pub name: String,
  /// Opaque identifier of the referenced node.
  pub node_id: NamespaceNodeId,
  /// Generic node kind.
  pub kind: NamespaceNodeKind,
}

impl NamespaceDirectoryEntry {
  /// Create a new namespace directory entry.
  pub fn new(name: impl Into<String>, node_id: NamespaceNodeId, kind: NamespaceNodeKind) -> Self {
    Self {
      name: name.into(),
      node_id,
      kind,
    }
  }
}

/// Generic stream classifications exposed by namespace nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceStreamKind {
  /// The default unnamed file content stream.
  Data,
  /// A named alternate data stream.
  NamedData,
  /// A named or unnamed fork.
  Fork,
  /// An extended-attribute-backed stream.
  ExtendedAttribute,
  /// Another format-specific stream kind.
  Other,
}

/// Opaque identifier for a namespace stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamespaceStreamId {
  /// Generic stream kind.
  pub kind: NamespaceStreamKind,
  /// Optional stream or fork name.
  pub name: Option<String>,
}

impl NamespaceStreamId {
  /// Construct the default unnamed data stream identifier.
  pub fn data() -> Self {
    Self {
      kind: NamespaceStreamKind::Data,
      name: None,
    }
  }

  /// Construct a named data stream identifier.
  pub fn named_data(name: impl Into<String>) -> Self {
    Self {
      kind: NamespaceStreamKind::NamedData,
      name: Some(name.into()),
    }
  }

  /// Construct a fork identifier.
  pub fn fork(name: impl Into<String>) -> Self {
    Self {
      kind: NamespaceStreamKind::Fork,
      name: Some(name.into()),
    }
  }

  /// Construct an xattr-backed stream identifier.
  pub fn xattr(name: impl Into<String>) -> Self {
    Self {
      kind: NamespaceStreamKind::ExtendedAttribute,
      name: Some(name.into()),
    }
  }
}

/// Generic metadata for a namespace stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceStreamRecord {
  /// Stream identifier.
  pub id: NamespaceStreamId,
  /// Logical size in bytes when known.
  pub size: u64,
}

impl NamespaceStreamRecord {
  /// Create a new namespace stream record.
  pub fn new(id: NamespaceStreamId, size: u64) -> Self {
    Self { id, size }
  }
}

/// Namespace facet exposed by filesystem- and archive-like formats.
pub trait NamespaceSource: Send + Sync {
  /// Return the identifier of the root node.
  fn root_node_id(&self) -> NamespaceNodeId;

  /// Resolve metadata for a namespace node.
  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord>;

  /// List the direct children of a directory node.
  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>>;

  /// Resolve a direct child entry by name.
  fn lookup_name(
    &self, directory_id: &NamespaceNodeId, name: &str,
  ) -> Result<NamespaceDirectoryEntry> {
    self
      .read_dir(directory_id)?
      .into_iter()
      .find(|entry| entry.name == name)
      .ok_or_else(|| Error::not_found(format!("namespace entry not found: {name}")))
  }

  /// Resolve a lexical path from the root node.
  fn resolve_path(&self, path: &str) -> Result<NamespaceNodeRecord> {
    let mut current = self.root_node_id();
    for component in path.split('/') {
      if component.is_empty() || component == "." {
        continue;
      }
      if component == ".." {
        return Err(Error::unsupported(
          "generic namespace path resolution does not support parent traversal".to_string(),
        ));
      }
      current = self.lookup_name(&current, component)?.node_id;
    }
    self.node(&current)
  }

  /// Enumerate all readable streams exposed by a node.
  fn data_streams(&self, node_id: &NamespaceNodeId) -> Result<Vec<NamespaceStreamRecord>>;

  /// Open a specific node stream as a byte source.
  fn open_stream(
    &self, node_id: &NamespaceNodeId, stream_id: &NamespaceStreamId,
  ) -> Result<ByteSourceHandle>;

  /// Open the default unnamed content stream of a node.
  fn open_content(&self, node_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    self.open_stream(node_id, &NamespaceStreamId::data())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn namespace_node_id_round_trips_bytes() {
    let node_id = NamespaceNodeId::from_u64(42);

    assert_eq!(node_id.as_bytes().len(), 8);
  }

  #[test]
  fn directory_entry_preserves_name_and_kind() {
    let entry = NamespaceDirectoryEntry::new(
      "readme.txt",
      NamespaceNodeId::from_u64(1),
      NamespaceNodeKind::File,
    );

    assert_eq!(entry.name, "readme.txt");
    assert_eq!(entry.kind, NamespaceNodeKind::File);
  }

  #[test]
  fn default_stream_id_is_unnamed_data() {
    let stream_id = NamespaceStreamId::data();

    assert_eq!(stream_id.kind, NamespaceStreamKind::Data);
    assert_eq!(stream_id.name, None);
  }
}
