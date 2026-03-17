//! Concurrent read-only parsing foundations for filesystem, partition table,
//! and image drivers.

pub mod core;

pub use core::{
  DataSource, DataSourceCapabilities, DataSourceReadConcurrency, DataSourceReadStats,
  DataSourceReadStatsSnapshot, DataSourceSeekCost, Error, ObservedDataSource,
  ProbeCachedDataSource, Result, SharedDataSource, SliceDataSource,
};
