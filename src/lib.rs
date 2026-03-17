//! Concurrent read-only parsing foundations for filesystem, partition table,
//! and image drivers.

pub mod archives;
pub mod core;
pub mod filesystems;
pub mod formats;
pub mod images;
pub mod volumes;

pub use core::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceReadConcurrency,
  DataSourceReadStats, DataSourceReadStatsSnapshot, DataSourceSeekCost, Error, FormatDescriptor,
  FormatKind, FormatProbe, ObservedDataSource, ProbeCachedDataSource, ProbeConfidence,
  ProbeContext, ProbeMatch, ProbeOptions, ProbeRegistry, ProbeReport, ProbeResult, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, RelatedSourceResolver, Result, SharedDataSource,
  SliceDataSource, SourceHints, SourceIdentity,
};
