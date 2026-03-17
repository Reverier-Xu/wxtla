//! Concurrent read-only parsing foundations for filesystem, partition table,
//! and image drivers.

pub mod core;

pub use core::{
  DataSource, DataSourceCapabilities, DataSourceReadConcurrency, DataSourceReadStats,
  DataSourceReadStatsSnapshot, DataSourceSeekCost, Error, LocalDataSource, ObservedDataSource,
  ProbeCachedDataSource, Result, SharedDataSource, SliceDataSource, open_local_file,
};
