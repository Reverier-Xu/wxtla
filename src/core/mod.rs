//! Foundational concurrent read primitives shared by parser drivers.

mod data_source;
mod error;

pub use data_source::{
  DataSource, DataSourceCapabilities, DataSourceReadConcurrency, DataSourceReadStats,
  DataSourceReadStatsSnapshot, DataSourceSeekCost, ObservedDataSource, ProbeCachedDataSource,
  SharedDataSource, SliceDataSource,
};
pub use error::{Error, Result};
