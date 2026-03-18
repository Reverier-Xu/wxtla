//! FAT filesystem driver and probe registration.

mod boot_sector;
mod driver;
mod filesystem;

pub use boot_sector::{FatBootSector, FatType};
pub use driver::FatDriver;
pub use filesystem::FatFileSystem;

use self::boot_sector::BOOT_SECTOR_SIZE;
use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// FAT filesystem descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.fat", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(FatProbe);
}

struct FatProbe;

impl FormatProbe for FatProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(BOOT_SECTOR_SIZE) else {
      return Ok(ProbeResult::rejected());
    };
    if boot_sector::FatBootSector::from_bytes(&header).is_ok() {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Strong,
        "fat boot sector geometry is valid",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
