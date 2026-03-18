//! Constants shared by the VMDK parser.

pub(super) const BYTES_PER_SECTOR: u64 = 512;
pub(super) const SPARSE_HEADER_SIZE: usize = 512;

pub(super) const SPARSE_HEADER_MAGIC: &[u8; 4] = b"KDMV";

pub(super) const FLAG_VALID_NEWLINE_TEST: u32 = 0x0000_0001;
pub(super) const FLAG_USE_SECONDARY_GD: u32 = 0x0000_0002;
pub(super) const FLAG_USE_ZERO_GRAIN: u32 = 0x0000_0004;
pub(super) const FLAG_HAS_COMPRESSED_GRAINS: u32 = 0x0001_0000;
pub(super) const FLAG_HAS_MARKERS: u32 = 0x0002_0000;

pub(super) const SUPPORTED_HEADER_FLAGS: u32 = FLAG_VALID_NEWLINE_TEST
  | FLAG_USE_SECONDARY_GD
  | FLAG_USE_ZERO_GRAIN
  | FLAG_HAS_COMPRESSED_GRAINS
  | FLAG_HAS_MARKERS;

pub(super) const GD_AT_END: u64 = u64::MAX;
