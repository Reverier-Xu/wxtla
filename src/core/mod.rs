//! Foundational concurrent read primitives shared by parser drivers.

mod data_source;
mod error;
mod probe;
mod resolver;

pub use data_source::{
  DataSource, DataSourceCapabilities, DataSourceReadConcurrency, DataSourceReadStats,
  DataSourceReadStatsSnapshot, DataSourceSeekCost, ObservedDataSource, ProbeCachedDataSource,
  SharedDataSource, SliceDataSource,
};
pub use error::{Error, Result};
pub use probe::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeOptions, ProbeRegistry, ProbeReport, ProbeResult,
};
pub use resolver::{
  DataSourceHandle, RelatedPathBuf, RelatedSourcePurpose, RelatedSourceRequest,
  RelatedSourceResolver, SourceIdentity,
};
