//! Constants shared by the MBR parser.

pub(super) const BOOT_RECORD_SIZE: usize = 512;
pub(super) const PARTITION_ENTRY_COUNT: usize = 4;
pub(super) const PARTITION_ENTRY_OFFSET: usize = 446;
pub(super) const PARTITION_ENTRY_SIZE: usize = 16;
pub(super) const DISK_SIGNATURE_OFFSET: usize = 440;
pub(super) const BOOT_SIGNATURE_OFFSET: usize = 510;
pub(super) const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xAA];

pub(super) const PARTITION_TYPE_EMPTY: u8 = 0x00;
pub(super) const PARTITION_TYPE_EXTENDED_CHS: u8 = 0x05;
pub(super) const PARTITION_TYPE_EXTENDED_LBA: u8 = 0x0F;
pub(super) const PARTITION_TYPE_EXTENDED_LINUX: u8 = 0x85;
pub(super) const PARTITION_TYPE_GPT_PROTECTIVE: u8 = 0xEE;

pub(super) const DEFAULT_BYTES_PER_SECTOR: u32 = 512;
