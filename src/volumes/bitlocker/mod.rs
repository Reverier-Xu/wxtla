//! BitLocker volume driver and probe registration.

mod crypto;
mod driver;
mod header;
mod metadata;
mod system;

pub use driver::BitlockerDriver;
pub use header::{BitlockerHeaderFlavor, BitlockerVolumeHeader};
pub use metadata::{
  BitlockerEncryptionMethod, BitlockerKeyProtectorKind, BitlockerMetadata,
  BitlockerMetadataBlockHeader, BitlockerMetadataHeader, BitlockerVolumeMasterKey,
};
pub use system::BitlockerVolumeSystem;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// BitLocker stacked volume descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.bitlocker", FormatKind::VolumeManager);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(BitlockerProbe);
}

struct BitlockerProbe;

impl FormatProbe for BitlockerProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header_bytes) = context.header(512) else {
      return Ok(ProbeResult::rejected());
    };
    if BitlockerVolumeHeader::from_bytes(&header_bytes).is_ok() {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "bitlocker volume header found",
      )));
    }

    Ok(ProbeResult::rejected())
  }
}
