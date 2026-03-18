//! Constants shared by the VHD parser.

pub(super) const FOOTER_SIZE: usize = 512;
pub(super) const DYNAMIC_HEADER_SIZE: usize = 1024;

pub(super) const FOOTER_COOKIE: &[u8] = b"conectix";
pub(super) const DYNAMIC_HEADER_COOKIE: &[u8] = b"cxsparse";

pub(super) const VHD_FORMAT_VERSION: u32 = 0x0001_0000;
pub(super) const FIXED_DATA_OFFSET: u64 = u64::MAX;

pub(super) const DISK_TYPE_FIXED: u32 = 2;
pub(super) const DISK_TYPE_DYNAMIC: u32 = 3;
pub(super) const DISK_TYPE_DIFFERENTIAL: u32 = 4;

pub(super) const DEFAULT_SECTOR_SIZE: u32 = 512;
