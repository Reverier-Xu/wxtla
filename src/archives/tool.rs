//! External archive tool resolution and security validation.
//!
//! # Security
//!
//! RAR and 7z backends invoke external command-line tools for archive
//! extraction. This module resolves absolute paths to those tools from the
//! system `PATH` and validates that each candidate is a regular file before
//! execution, reducing the risk of executing a maliciously placed binary.

use std::path::PathBuf;

use crate::{Error, Result};

pub(crate) fn find_tool(names: &[&str]) -> Result<PathBuf> {
  let path_var = std::env::var_os("PATH").unwrap_or_default();
  for dir in std::env::split_paths(&path_var) {
    for name in names {
      let candidate = if cfg!(windows) {
        for ext in ["exe", "cmd"] {
          let with_ext = dir.join(format!("{name}.{ext}"));
          if with_ext.is_file() {
            return Ok(with_ext);
          }
        }
        dir.join(name)
      } else {
        dir.join(name)
      };
      if candidate.is_file() {
        return Ok(candidate);
      }
    }
  }
  Err(Error::unsupported(format!(
    "archive extraction requires one of: {}",
    names.join(", ")
  )))
}
