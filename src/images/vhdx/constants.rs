//! Constants shared by the VHDX parser.

use super::guid::VhdxGuid;

pub(super) const FILE_IDENTIFIER_SIZE: usize = 64 * 1024;
pub(super) const IMAGE_HEADER_SIZE: usize = 4 * 1024;
pub(super) const REGION_TABLE_SIZE: usize = 64 * 1024;
pub(super) const METADATA_TABLE_SIZE: usize = 64 * 1024;

pub(super) const FILE_IDENTIFIER_OFFSET: u64 = 0;
pub(super) const PRIMARY_IMAGE_HEADER_OFFSET: u64 = 64 * 1024;
pub(super) const SECONDARY_IMAGE_HEADER_OFFSET: u64 = 2 * 64 * 1024;
pub(super) const PRIMARY_REGION_TABLE_OFFSET: u64 = 3 * 64 * 1024;
pub(super) const SECONDARY_REGION_TABLE_OFFSET: u64 = 4 * 64 * 1024;

pub(super) const FILE_IDENTIFIER_SIGNATURE: &[u8; 8] = b"vhdxfile";
pub(super) const IMAGE_HEADER_SIGNATURE: &[u8; 4] = b"head";
pub(super) const REGION_TABLE_SIGNATURE: &[u8; 4] = b"regi";
pub(super) const METADATA_TABLE_SIGNATURE: &[u8; 8] = b"metadata";

pub(super) const VHDX_ALIGNMENT: u64 = 1024 * 1024;
pub(super) const VHDX_MIN_BLOCK_SIZE: u32 = 1024 * 1024;
pub(super) const VHDX_MAX_BLOCK_SIZE: u32 = 256 * 1024 * 1024;
pub(super) const VHDX_MAX_TABLE_ENTRIES: usize = 2047;
pub(super) const SECTOR_BITMAP_BLOCK_SIZE: u64 = 1024 * 1024;
pub(super) const SECTORS_PER_BITMAP_BLOCK: u64 = 1 << 23;

pub(super) const BAT_REGION_GUID: VhdxGuid = VhdxGuid::from_fields(
  0x2DC2_7766,
  0xF623,
  0x4200,
  [0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08],
);

pub(super) const METADATA_REGION_GUID: VhdxGuid = VhdxGuid::from_fields(
  0x8B7C_A206,
  0x4790,
  0x4B9A,
  [0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E],
);

pub(super) const FILE_PARAMETERS_GUID: VhdxGuid = VhdxGuid::from_fields(
  0xCAA1_6737,
  0xFA36,
  0x4D43,
  [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B],
);

pub(super) const VIRTUAL_DISK_SIZE_GUID: VhdxGuid = VhdxGuid::from_fields(
  0x2FA5_4224,
  0xCD1B,
  0x4876,
  [0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8],
);

pub(super) const LOGICAL_SECTOR_SIZE_GUID: VhdxGuid = VhdxGuid::from_fields(
  0x8141_BF1D,
  0xA96F,
  0x4709,
  [0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F],
);

pub(super) const PHYSICAL_SECTOR_SIZE_GUID: VhdxGuid = VhdxGuid::from_fields(
  0xCDA3_48C7,
  0x445D,
  0x4471,
  [0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56],
);

pub(super) const VIRTUAL_DISK_IDENTIFIER_GUID: VhdxGuid = VhdxGuid::from_fields(
  0xBECA_12AB,
  0xB2E6,
  0x4523,
  [0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46],
);

pub(super) const PARENT_LOCATOR_GUID: VhdxGuid = VhdxGuid::from_fields(
  0xA8D3_5F2D,
  0xB30B,
  0x454D,
  [0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C],
);

pub(super) const PARENT_LOCATOR_TYPE_GUID: VhdxGuid = VhdxGuid::from_fields(
  0xB04A_EFB7,
  0xD19E,
  0x4A81,
  [0xB7, 0x89, 0x25, 0xB8, 0xE9, 0x44, 0x59, 0x13],
);
