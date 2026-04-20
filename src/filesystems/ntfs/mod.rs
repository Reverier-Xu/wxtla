//! NTFS filesystem driver and probe registration.

mod attribute_list;
mod boot_sector;
mod driver;
mod filesystem;
mod index;
mod record;
mod reparse;
mod runlist;
mod stream;

pub use attribute_list::{NtfsAttributeListEntry, parse_attribute_list};
pub use boot_sector::NtfsBootSector;
pub use driver::NtfsDriver;
pub use filesystem::{NtfsDataStreamInfo, NtfsFileSystem};
pub use reparse::{NtfsReparsePointInfo, NtfsReparsePointKind};

use self::boot_sector::BOOT_SECTOR_SIZE;
use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// NTFS filesystem descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.ntfs", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(NtfsProbe);
}

struct NtfsProbe;

impl FormatProbe for NtfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(BOOT_SECTOR_SIZE) else {
      return Ok(ProbeResult::rejected());
    };
    if boot_sector::NtfsBootSector::from_bytes(&header).is_ok() {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "ntfs boot sector geometry is valid",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
