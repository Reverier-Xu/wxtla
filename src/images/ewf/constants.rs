//! Constants shared by the EWF parser.

pub(super) const FILE_HEADER_SIZE: usize = 13;
pub(super) const FILE_HEADER_MAGIC: &[u8] = b"EVF\t\r\n\xff\0";
pub(super) const FILE_HEADER_MAGIC_LVF: &[u8] = b"LVF\t\r\n\xff\0";

pub(super) const SECTION_DESCRIPTOR_SIZE: usize = 76;

pub(super) const SECTION_TYPE_DATA: &[u8] = b"data";
pub(super) const SECTION_TYPE_DIGEST: &[u8] = b"digest";
pub(super) const SECTION_TYPE_DISK: &[u8] = b"disk";
pub(super) const SECTION_TYPE_DONE: &[u8] = b"done";
pub(super) const SECTION_TYPE_ERROR2: &[u8] = b"error2";
pub(super) const SECTION_TYPE_HASH: &[u8] = b"hash";
pub(super) const SECTION_TYPE_HEADER: &[u8] = b"header";
pub(super) const SECTION_TYPE_HEADER2: &[u8] = b"header2";
pub(super) const SECTION_TYPE_NEXT: &[u8] = b"next";
pub(super) const SECTION_TYPE_SECTORS: &[u8] = b"sectors";
pub(super) const SECTION_TYPE_TABLE: &[u8] = b"table";
pub(super) const SECTION_TYPE_TABLE2: &[u8] = b"table2";
pub(super) const SECTION_TYPE_VOLUME: &[u8] = b"volume";

pub(super) const E01_VOLUME_DATA_SIZE: usize = 1052;
pub(super) const S01_VOLUME_DATA_SIZE: usize = 94;
pub(super) const HASH_DATA_SIZE: usize = 36;
pub(super) const DIGEST_DATA_SIZE: usize = 80;
pub(super) const ERROR2_HEADER_SIZE: usize = 520;
pub(super) const ERROR2_ENTRY_SIZE: usize = 8;
pub(super) const ERROR2_FOOTER_SIZE: usize = 4;

pub(super) const TABLE_HEADER_SIZE: usize = 24;
pub(super) const TABLE_FOOTER_SIZE: usize = 4;

pub(super) const DEFAULT_CHUNK_CACHE_CAPACITY: usize = 64;
