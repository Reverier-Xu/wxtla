//! Known APM partition type identifiers.

use crate::volumes::VolumeRole;

/// Apple partition map metadata entry.
pub const PARTITION_MAP: &str = "Apple_partition_map";
/// Apple free-space marker entry.
pub const FREE: &str = "Apple_Free";
/// Apple HFS partition entry.
pub const HFS: &str = "Apple_HFS";

const DRIVER_PREFIXES: &[&str] = &[
  "Apple_Driver",
  "Apple_FWDriver",
  "Apple_Driver43",
  "Apple_Driver43_CD",
  "Apple_Driver_ATA",
  "Apple_Driver_ATAPI",
  "Apple_Driver_IOKit",
  "Apple_Driver_OpenFirmware",
];

const BOOT_PREFIXES: &[&str] = &[
  "Apple_Boot",
  "Apple_Boot_RAID",
  "Apple_Bootstrap",
  "Apple_Loader",
  "Apple_Patches",
];

/// Classify a known APM partition type into a coarse generic role.
pub fn volume_role_for_type_identifier(type_identifier: &str) -> VolumeRole {
  if type_identifier == PARTITION_MAP
    || DRIVER_PREFIXES.contains(&type_identifier)
    || BOOT_PREFIXES.contains(&type_identifier)
  {
    VolumeRole::Metadata
  } else if type_identifier == FREE {
    VolumeRole::Unknown
  } else {
    VolumeRole::Primary
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_known_partition_types() {
    assert_eq!(
      volume_role_for_type_identifier(PARTITION_MAP),
      VolumeRole::Metadata
    );
    assert_eq!(volume_role_for_type_identifier(FREE), VolumeRole::Unknown);
    assert_eq!(volume_role_for_type_identifier(HFS), VolumeRole::Primary);
  }
}
