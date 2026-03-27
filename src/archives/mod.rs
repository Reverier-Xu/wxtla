//! Archive format modules.

mod cache;
mod driver;

pub mod adf;
pub mod rar;
pub mod sevenz;
pub mod tar;
pub mod zip;

pub(crate) use driver::Archive;

pub(crate) use crate::{
  NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord,
};
