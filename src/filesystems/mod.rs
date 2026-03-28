//! Read-only filesystem format modules.

mod driver;

pub mod apfs;
pub mod ext;
pub mod fat;
pub mod hfs;
pub mod ntfs;
pub mod refs;
pub mod xfs;

pub use apfs::{
  APFS_FILE_INFO_DATA_HASH, ApfsChangeInfo, ApfsContainer, ApfsDriver, ApfsExtendedAttribute,
  ApfsFileInfoRecord, ApfsFirmlink, ApfsIntegrityMetadata, ApfsNodeDetails, ApfsPrange,
  ApfsSnapshotInfo, ApfsSpecialFileKind, ApfsVolume, ApfsVolumeGroupInfo, ApfsVolumeGroupMember,
  ApfsVolumeGroupView, ApfsVolumeInfo,
};
pub(crate) use driver::FileSystem;
pub use ext::{ExtDriver, ExtExtendedAttribute, ExtFileSystem, ExtNodeDetails};
pub use fat::{FatDriver, FatFileSystem, FatNodeDetails};
pub use hfs::{HfsDriver, HfsExtendedAttribute, HfsFileSystem};
pub use ntfs::{NtfsDriver, NtfsFileSystem};
pub use refs::{RefsDataStreamInfo, RefsDriver, RefsFileSystem, RefsNodeDetails};
pub use xfs::{XfsDriver, XfsFileSystem, XfsNodeDetails};

pub use crate::{
  NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord,
  NamespaceSource, NamespaceStreamId, NamespaceStreamKind, NamespaceStreamRecord,
};
