//! Constants shared by the APM parser.

pub(super) const BLOCK0_SIZE: usize = 512;
pub(super) const PARTITION_ENTRY_SIZE: usize = 512;
pub(super) const PARTITION_MAP_OFFSET: u32 = 512;
pub(super) const SIGNATURE_LEN: usize = 2;

pub(super) const DRIVER_DESCRIPTOR_SIGNATURE: &[u8] = b"ER";
pub(super) const PARTITION_MAP_SIGNATURE: &[u8] = b"PM";
