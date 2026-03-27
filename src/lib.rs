//! Concurrent read-only parsing foundations for filesystem, partition table,
//! and image drivers.

pub mod archives;
pub mod core;
pub mod filesystems;
pub mod formats;
pub mod images;
pub mod volumes;

pub use core::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceReadConcurrency,
  ByteSourceReadStats, ByteSourceReadStatsSnapshot, ByteSourceSeekCost, ByteViewSource,
  BytesDataSource, Credential, DataSource, DataSourceFacets, DataViewId, DataViewKind,
  DataViewRecord, DataViewSelector, Driver, Error, FileDataSource, FormatDescriptor, FormatKind,
  FormatProbe, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord,
  NamespaceSource, NamespaceStreamId, NamespaceStreamKind, NamespaceStreamRecord,
  ObservedDataSource, OpenOptions, ProbeCachedDataSource, ProbeConfidence, ProbeContext,
  ProbeMatch, ProbeOptions, ProbeRegistry, ProbeReport, ProbeResult, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, RelatedSourceResolver, Result, SharedDataSource,
  SliceDataSource, SourceHints, SourceIdentity, TableSource, VerificationPolicy,
};
