//! Concurrent read-only parsing foundations for filesystem, partition table,
//! and image drivers.

pub mod core;
pub mod formats;

pub use core::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceReadConcurrency,
  DataSourceReadStats, DataSourceReadStatsSnapshot, DataSourceSeekCost, Error, FormatDescriptor,
  FormatKind, FormatProbe, ObservedDataSource, ProbeCachedDataSource, ProbeConfidence,
  ProbeContext, ProbeMatch, ProbeRegistry, ProbeReport, ProbeResult, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, RelatedSourceResolver, Result, SharedDataSource,
  SliceDataSource,
};
