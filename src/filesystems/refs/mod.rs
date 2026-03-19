//! ReFS filesystem driver and probe registration.

mod data_source;
mod driver;
mod filesystem;
mod parser;

pub use driver::RefsDriver;
pub use filesystem::{RefsDataStreamInfo, RefsFileSystem, RefsNodeDetails};
pub use parser::RefsVolumeHeader;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.refs", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(RefsProbe);
}

struct RefsProbe;

impl FormatProbe for RefsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.header(parser::VOLUME_HEADER_SIZE) else {
      return Ok(ProbeResult::rejected());
    };
    if parser::RefsVolumeHeader::from_bytes(&header).is_ok() {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Strong,
        "refs volume header geometry is valid",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
