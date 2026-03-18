//! HFS-family filesystem driver and probe registration.

mod btree;
mod driver;
mod filesystem;

pub use driver::HfsDriver;
pub use filesystem::HfsFileSystem;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// Classic HFS filesystem descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.hfs", FormatKind::FileSystem);
/// HFS+ / HFSX filesystem descriptor.
pub const PLUS_DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.hfsplus", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const HFS_MAGIC: &[u8] = b"BD";
const HFS_PLUS_MAGIC: &[u8] = b"H+";
const HFSX_MAGIC: &[u8] = b"HX";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(HfsProbe);
}

struct HfsProbe;

impl FormatProbe for HfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(1024, 2) else {
      return Ok(ProbeResult::rejected());
    };

    if signature == HFS_MAGIC {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "hfs signature found in volume header",
      )));
    }

    if signature == HFS_PLUS_MAGIC || signature == HFSX_MAGIC {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        PLUS_DESCRIPTOR,
        ProbeConfidence::Exact,
        "hfs+ signature found in volume header",
      )));
    }

    Ok(ProbeResult::rejected())
  }
}
