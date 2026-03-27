//! Foundational concurrent read primitives shared by parser drivers.

mod data_source;
mod error;
mod namespace;
mod opened;
mod probe;
mod resolver;

pub use data_source::{
  ByteSource, ByteSourceCapabilities, ByteSourceReadConcurrency, ByteSourceReadStats,
  ByteSourceReadStatsSnapshot, ByteSourceSeekCost, BytesDataSource, FileDataSource,
  ObservedDataSource, ProbeCachedDataSource, SharedDataSource, SliceDataSource,
};
pub use error::{Error, Result};
pub use namespace::{
  NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord,
  NamespaceSource, NamespaceStreamId, NamespaceStreamKind, NamespaceStreamRecord,
};
pub use opened::{
  ByteViewSource, Credential, DataSource, DataSourceFacets, DataViewId, DataViewKind,
  DataViewRecord, DataViewSelector, Driver, OpenOptions, TableSource, VerificationPolicy,
};
pub use probe::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeOptions, ProbeRegistry, ProbeReport, ProbeResult, SourceHints,
};
pub use resolver::{
  ByteSourceHandle, RelatedPathBuf, RelatedSourcePurpose, RelatedSourceRequest,
  RelatedSourceResolver, SourceIdentity,
};
