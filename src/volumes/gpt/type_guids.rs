//! Well-known GPT partition type GUIDs and coarse role classification.

use super::guid::GptGuid;
use crate::volumes::VolumeRole;

/// Unused GPT entry type.
pub const UNUSED: GptGuid = GptGuid::from_fields(0x0000_0000, 0x0000, 0x0000, [0; 8]);
/// EFI System partition type GUID.
pub const EFI_SYSTEM: GptGuid = GptGuid::from_fields(
  0xC12A_7328,
  0xF81F,
  0x11D2,
  [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
);
/// BIOS boot partition type GUID.
pub const BIOS_BOOT: GptGuid = GptGuid::from_fields(
  0x2168_6148,
  0x6449,
  0x6E6F,
  [0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49],
);
/// Microsoft reserved partition type GUID.
pub const MICROSOFT_RESERVED: GptGuid = GptGuid::from_fields(
  0xE3C9_E316,
  0x0B5C,
  0x4DB8,
  [0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE],
);
/// Microsoft basic data partition type GUID.
pub const MICROSOFT_BASIC_DATA: GptGuid = GptGuid::from_fields(
  0xEBD0_A0A2,
  0xB9E5,
  0x4433,
  [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
);
/// Linux filesystem data partition type GUID.
pub const LINUX_FILESYSTEM: GptGuid = GptGuid::from_fields(
  0x0FC6_3DAF,
  0x8483,
  0x4772,
  [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
);

/// Classify a known GPT partition type into a coarse generic role.
pub fn volume_role_for_type_guid(type_guid: GptGuid) -> VolumeRole {
  if matches!(type_guid, EFI_SYSTEM | BIOS_BOOT | MICROSOFT_RESERVED) {
    VolumeRole::Metadata
  } else {
    VolumeRole::Primary
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_metadata_partition_types() {
    assert_eq!(volume_role_for_type_guid(EFI_SYSTEM), VolumeRole::Metadata);
    assert_eq!(
      volume_role_for_type_guid(MICROSOFT_RESERVED),
      VolumeRole::Metadata
    );
    assert_eq!(
      volume_role_for_type_guid(MICROSOFT_BASIC_DATA),
      VolumeRole::Primary
    );
  }
}
