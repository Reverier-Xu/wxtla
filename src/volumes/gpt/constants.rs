//! Constants shared by the GPT parser.

pub(super) const DEFAULT_BLOCK_SIZE: u32 = 512;
pub(super) const SUPPORTED_BLOCK_SIZES: [u32; 2] = [512, 4096];

pub(super) const HEADER_SIGNATURE: &[u8] = b"EFI PART";
pub(super) const HEADER_MIN_SIZE: usize = 92;
pub(super) const PARTITION_ENTRY_MIN_SIZE: usize = 128;

pub(super) const PRIMARY_HEADER_LBA: u64 = 1;
pub(super) const PARTITION_TYPE_GUID_OFFSET: usize = 0;
pub(super) const PARTITION_GUID_OFFSET: usize = 16;
pub(super) const FIRST_LBA_OFFSET: usize = 32;
pub(super) const LAST_LBA_OFFSET: usize = 40;
pub(super) const ATTRIBUTE_FLAGS_OFFSET: usize = 48;
pub(super) const NAME_OFFSET: usize = 56;
pub(super) const NAME_LEN: usize = 72;

pub(super) const GPT_FORMAT_REVISION: u32 = 0x0001_0000;
