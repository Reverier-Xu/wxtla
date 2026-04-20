//! Internal filesystem helpers shared by concrete filesystem drivers.

use crate::{
  ByteSourceHandle, FormatDescriptor, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind,
  NamespaceNodeRecord, NamespaceStreamId, NamespaceStreamRecord, Result,
};

/// Internal read-only filesystem surface exposed by a concrete filesystem type.
pub(crate) trait FileSystem: Send + Sync {
  /// Return the format descriptor for this opened filesystem.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the identifier of the root node.
  fn root_node_id(&self) -> NamespaceNodeId;

  /// Resolve metadata for a filesystem node.
  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord>;

  /// List the direct children of a directory node.
  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>>;

  /// Open file content for a readable file node.
  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle>;

  /// Enumerate streams exposed by a node.
  fn data_streams(&self, node_id: &NamespaceNodeId) -> Result<Vec<NamespaceStreamRecord>> {
    let node = self.node(node_id)?;
    Ok(match node.kind {
      NamespaceNodeKind::File | NamespaceNodeKind::Symlink => {
        vec![NamespaceStreamRecord::new(
          NamespaceStreamId::data(),
          node.size,
        )]
      }
      NamespaceNodeKind::Directory | NamespaceNodeKind::Special => Vec::new(),
    })
  }

  /// Open a specific stream exposed by a node.
  fn open_stream(
    &self, node_id: &NamespaceNodeId, stream_id: &NamespaceStreamId,
  ) -> Result<ByteSourceHandle> {
    if *stream_id == NamespaceStreamId::data() {
      self.open_file(node_id)
    } else {
      Err(crate::Error::not_found(format!(
        "{} does not expose stream {:?}",
        self.descriptor().id,
        stream_id
      )))
    }
  }
}

macro_rules! impl_file_system_data_source {
  ($ty:ty) => {
    impl crate::NamespaceSource for $ty {
      fn root_node_id(&self) -> crate::NamespaceNodeId {
        crate::filesystems::driver::FileSystem::root_node_id(self)
      }

      fn node(
        &self, node_id: &crate::NamespaceNodeId,
      ) -> crate::Result<crate::NamespaceNodeRecord> {
        crate::filesystems::driver::FileSystem::node(self, node_id)
      }

      fn read_dir(
        &self, directory_id: &crate::NamespaceNodeId,
      ) -> crate::Result<Vec<crate::NamespaceDirectoryEntry>> {
        crate::filesystems::driver::FileSystem::read_dir(self, directory_id)
      }

      fn data_streams(
        &self, node_id: &crate::NamespaceNodeId,
      ) -> crate::Result<Vec<crate::NamespaceStreamRecord>> {
        crate::filesystems::driver::FileSystem::data_streams(self, node_id)
      }

      fn open_stream(
        &self, node_id: &crate::NamespaceNodeId, stream_id: &crate::NamespaceStreamId,
      ) -> crate::Result<crate::ByteSourceHandle> {
        crate::filesystems::driver::FileSystem::open_stream(self, node_id, stream_id)
      }
    }

    impl crate::DataSource for $ty {
      fn descriptor(&self) -> crate::FormatDescriptor {
        crate::filesystems::driver::FileSystem::descriptor(self)
      }

      fn facets(&self) -> crate::DataSourceFacets {
        crate::DataSourceFacets::namespace()
      }

      fn namespace(&self) -> Option<&dyn crate::NamespaceSource> {
        Some(self)
      }
    }
  };
}

pub(crate) use impl_file_system_data_source;
