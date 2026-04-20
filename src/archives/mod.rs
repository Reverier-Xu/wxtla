//! Archive format modules.

mod cache;
mod driver;
#[cfg(any(feature = "rar", feature = "sevenz"))]
pub(crate) mod tool;

pub mod adf;
#[cfg(feature = "rar")]
pub mod rar;
#[cfg(feature = "sevenz")]
pub mod sevenz;
pub mod tar;
pub mod zip;

pub(crate) use driver::Archive;
