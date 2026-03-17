//! Error types for the crate's shared core infrastructure.

use thiserror::Error;

/// Errors returned by concurrent read primitives.
#[derive(Debug, Error)]
pub enum Error {
  /// An I/O error occurred while reading from a backing source.
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),

  /// A read operation reached the end of a source before enough bytes were
  /// available.
  #[error("unexpected end of data at offset {offset}: expected {expected} bytes, got {actual}")]
  UnexpectedEof {
    /// Byte offset where the short read began.
    offset: u64,
    /// Number of bytes that were requested.
    expected: usize,
    /// Number of bytes that were actually read.
    actual: usize,
  },

  /// A requested byte range could not be represented or satisfied.
  #[error("invalid data source range: {0}")]
  InvalidRange(String),

  /// Parsed bytes do not match the structural requirements of a format.
  #[error("invalid format: {0}")]
  InvalidFormat(String),

  /// A parser requested an invalid related-source reference.
  #[error("invalid source reference: {0}")]
  InvalidSourceReference(String),

  /// A requested item was not present in a parsed structure.
  #[error("not found: {0}")]
  NotFound(String),
}

/// Result alias used by the crate's core infrastructure.
pub type Result<T> = std::result::Result<T, Error>;
