//! Internal archive helpers shared by concrete archive drivers.

use crate::{
  ByteSourceHandle, FormatDescriptor, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind,
  NamespaceNodeRecord, NamespaceStreamId, NamespaceStreamRecord, Result,
};

/// Internal read-only archive surface exposed by a concrete archive type.
#[allow(dead_code)]
pub(crate) trait Archive: Send + Sync {
  /// Return the format descriptor for this opened archive.
  fn descriptor(&self) -> FormatDescriptor;

  /// Return the identifier of the archive root entry.
  fn root_entry_id(&self) -> NamespaceNodeId;

  /// Resolve metadata for an archive entry.
  fn entry(&self, entry_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord>;

  /// List the direct children of an archive directory entry.
  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>>;

  /// Open file content for a readable archive entry.
  fn open_file(&self, entry_id: &NamespaceNodeId) -> Result<ByteSourceHandle>;

  /// Return `true` when the archive is locked behind optional credentials.
  fn is_locked(&self) -> bool {
    false
  }

  /// Attempt to unlock the archive with a password.
  fn unlock_with_password(&mut self, _password: &str) -> Result<bool> {
    Ok(false)
  }

  /// Enumerate streams exposed by an archive node.
  fn data_streams(&self, entry_id: &NamespaceNodeId) -> Result<Vec<NamespaceStreamRecord>> {
    let entry = self.entry(entry_id)?;
    Ok(match entry.kind {
      NamespaceNodeKind::File | NamespaceNodeKind::Symlink => {
        vec![NamespaceStreamRecord::new(
          NamespaceStreamId::data(),
          entry.size,
        )]
      }
      NamespaceNodeKind::Directory | NamespaceNodeKind::Special => Vec::new(),
    })
  }

  /// Open a specific archive node stream.
  fn open_stream(
    &self, entry_id: &NamespaceNodeId, stream_id: &NamespaceStreamId,
  ) -> Result<ByteSourceHandle> {
    if *stream_id == NamespaceStreamId::data() {
      self.open_file(entry_id)
    } else {
      Err(crate::Error::NotFound(format!(
        "{} does not expose stream {:?}",
        self.descriptor().id,
        stream_id
      )))
    }
  }
}

macro_rules! impl_archive_data_source {
  ($ty:ty) => {
    impl crate::NamespaceSource for $ty {
      fn root_node_id(&self) -> crate::NamespaceNodeId {
        crate::archives::driver::Archive::root_entry_id(self)
      }

      fn node(
        &self, node_id: &crate::NamespaceNodeId,
      ) -> crate::Result<crate::NamespaceNodeRecord> {
        crate::archives::driver::Archive::entry(self, node_id)
      }

      fn read_dir(
        &self, directory_id: &crate::NamespaceNodeId,
      ) -> crate::Result<Vec<crate::NamespaceDirectoryEntry>> {
        crate::archives::driver::Archive::read_dir(self, directory_id)
      }

      fn data_streams(
        &self, node_id: &crate::NamespaceNodeId,
      ) -> crate::Result<Vec<crate::NamespaceStreamRecord>> {
        crate::archives::driver::Archive::data_streams(self, node_id)
      }

      fn open_stream(
        &self, node_id: &crate::NamespaceNodeId, stream_id: &crate::NamespaceStreamId,
      ) -> crate::Result<crate::ByteSourceHandle> {
        crate::archives::driver::Archive::open_stream(self, node_id, stream_id)
      }
    }

    impl crate::DataSource for $ty {
      fn descriptor(&self) -> crate::FormatDescriptor {
        crate::archives::driver::Archive::descriptor(self)
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

pub(crate) use impl_archive_data_source;
