//! FAT filesystem descriptor and probe registration.

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

const FAT12_MAGIC: &[u8] = b"FAT12   ";
const FAT16_MAGIC: &[u8] = b"FAT16   ";
const FAT32_MAGIC: &[u8] = b"FAT32   ";

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(FatProbe);
}

struct FatProbe;

impl FormatProbe for FatProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(510, 2) else {
      return Ok(ProbeResult::rejected());
    };
    if signature != [0x55, 0xAA] {
      return Ok(ProbeResult::rejected());
    }

    let fat12_or_16 = context.read_bytes_at(54, 8).ok();
    let fat32 = context.read_bytes_at(82, 8).ok();
    let matched = fat12_or_16
      .as_deref()
      .is_some_and(|bytes| bytes == FAT12_MAGIC || bytes == FAT16_MAGIC)
      || fat32.as_deref().is_some_and(|bytes| bytes == FAT32_MAGIC);

    if matched {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Strong,
        "fat type string found in boot sector",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
