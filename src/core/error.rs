//! Error types for the crate's shared core infrastructure.

use std::borrow::Cow;

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
  InvalidRange(Cow<'static, str>),

  /// Parsed bytes do not match the structural requirements of a format.
  #[error("invalid format: {0}")]
  InvalidFormat(Cow<'static, str>),

  /// A parser requested an invalid related-source reference.
  #[error("invalid source reference: {0}")]
  InvalidSourceReference(Cow<'static, str>),

  /// A requested item was not present in a parsed structure.
  #[error("not found: {0}")]
  NotFound(Cow<'static, str>),

  /// The requested operation is not supported by the current format or view.
  #[error("unsupported: {0}")]
  Unsupported(Cow<'static, str>),
}

impl Error {
  pub fn invalid_range(message: impl Into<Cow<'static, str>>) -> Self {
    Self::InvalidRange(message.into())
  }

  pub fn invalid_format(message: impl Into<Cow<'static, str>>) -> Self {
    Self::InvalidFormat(message.into())
  }

  pub fn invalid_source_reference(message: impl Into<Cow<'static, str>>) -> Self {
    Self::InvalidSourceReference(message.into())
  }

  pub fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
    Self::NotFound(message.into())
  }

  pub fn unsupported(message: impl Into<Cow<'static, str>>) -> Self {
    Self::Unsupported(message.into())
  }
}

/// Result alias used by the crate's core infrastructure.
pub type Result<T> = std::result::Result<T, Error>;
