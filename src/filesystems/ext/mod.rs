//! ext-family filesystem driver and probe registration.

mod driver;
mod filesystem;
mod superblock;

pub use driver::ExtDriver;
pub use filesystem::ExtFileSystem;
pub use superblock::{ExtSuperblock, ExtVariant};

use self::superblock::SUPERBLOCK_SIZE;
use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// ext-family filesystem descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.ext", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(ExtProbe);
}

struct ExtProbe;

impl FormatProbe for ExtProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(superblock) = context.read_bytes_at(1024, SUPERBLOCK_SIZE) else {
      return Ok(ProbeResult::rejected());
    };

    if superblock::ExtSuperblock::from_bytes(&superblock).is_ok() {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "ext superblock layout is valid",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
