//! Error types for the crate's shared core infrastructure.

use thiserror::Error;

/// Errors returned by concurrent read primitives.
#[derive(Debug, Error)]
pub enum Error {
  /// An I/O error occurred while reading from a backing source.
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),

  /// A requested byte range could not be represented or satisfied.
  #[error("invalid data source range: {0}")]
  InvalidRange(String),
}

/// Result alias used by the crate's core infrastructure.
pub type Result<T> = std::result::Result<T, Error>;
