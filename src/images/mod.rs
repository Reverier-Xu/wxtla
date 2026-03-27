//! Image and image-container format modules.

mod driver;

pub mod ewf;
pub mod pdi;
pub mod qcow;
pub mod sparsebundle;
pub mod sparseimage;
pub mod splitraw;
pub mod udif;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;

pub(crate) use driver::Image;
