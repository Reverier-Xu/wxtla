//! XFS filesystem driver and probe registration.

mod constants;
mod data_source;
mod directory;
mod driver;
mod extent;
mod filesystem;
mod inode;
mod io;
mod superblock;

pub use driver::XfsDriver;
pub use filesystem::{XfsFileSystem, XfsNodeDetails};

use self::{constants::SB_MAGIC, superblock::XfsSuperblock};
use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.xfs", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(XfsProbe);
}

struct XfsProbe;

impl FormatProbe for XfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(512) else {
      return Ok(ProbeResult::rejected());
    };
    if &header[0..4] != SB_MAGIC {
      return Ok(ProbeResult::rejected());
    }

    if XfsSuperblock::read(context.source()).is_ok() {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "xfs superblock geometry is valid",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
