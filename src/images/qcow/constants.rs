//! Constants shared by the QCOW parser.

pub(super) const FILE_HEADER_MAGIC: &[u8] = b"QFI\xfb";

pub(super) const QCOW_VERSION_1: u32 = 1;
pub(super) const QCOW_VERSION_2: u32 = 2;
pub(super) const QCOW_VERSION_3: u32 = 3;

pub(super) const QCOW_CRYPT_NONE: u32 = 0;
pub(super) const QCOW_COMPRESSION_ZLIB: u8 = 0;
pub(super) const QCOW_COMPRESSION_ZSTD: u8 = 1;

pub(super) const QCOW_OFLAG_COMPRESSED: u64 = 1u64 << 62;
pub(super) const QCOW_OFLAG_COPIED: u64 = 1u64 << 63;

pub(super) const QCOW_INCOMPAT_DIRTY: u64 = 0x0000_0001;
pub(super) const QCOW_INCOMPAT_CORRUPT: u64 = 0x0000_0002;
pub(super) const QCOW_INCOMPAT_DATA_FILE: u64 = 0x0000_0004;
pub(super) const QCOW_INCOMPAT_COMPRESSION: u64 = 0x0000_0008;
pub(super) const QCOW_INCOMPAT_EXTL2: u64 = 0x0000_0010;

pub(super) const QCOW_V2_HEADER_SIZE: usize = 72;
pub(super) const QCOW_V3_HEADER_MIN_SIZE: usize = 104;
pub(super) const QCOW_V3_HEADER_WITH_COMPRESSION: usize = 112;
pub(super) const QCOW_V1_HEADER_SIZE: usize = 48;

pub(super) const SUPPORTED_CLUSTER_BITS: core::ops::RangeInclusive<u32> = 9..=21;
pub(super) const SUPPORTED_REFCOUNT_ORDER: u32 = 4;

pub(super) const DEFAULT_CLUSTER_CACHE_CAPACITY: usize = 64;
pub(super) const DEFAULT_L2_CACHE_CAPACITY: usize = 64;
