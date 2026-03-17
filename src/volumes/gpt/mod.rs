//! GPT volume-system driver and probe registration.

mod constants;
mod driver;
mod entry;
mod guid;
mod header;
mod integrity;
mod parser;
mod system;
mod type_guids;
mod validation;

pub use driver::GptDriver;
pub use entry::{GptPartitionEntry, GptPartitionInfo};
pub use guid::GptGuid;
pub use header::GptHeader;
pub use system::GptVolumeSystem;
pub use type_guids::{
  BIOS_BOOT, EFI_SYSTEM, LINUX_FILESYSTEM, MICROSOFT_BASIC_DATA, MICROSOFT_RESERVED,
};

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// GPT volume-system descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("volume.gpt", FormatKind::VolumeSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(GptProbe);
}

struct GptProbe;

impl FormatProbe for GptProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    for block_size in constants::SUPPORTED_BLOCK_SIZES {
      let Ok(signature) =
        context.read_bytes_at(u64::from(block_size), constants::HEADER_SIGNATURE.len())
      else {
        continue;
      };
      if signature == constants::HEADER_SIGNATURE {
        let detail = if block_size == constants::DEFAULT_BLOCK_SIZE {
          "gpt header found at lba1"
        } else {
          "gpt header found at lba1 with non-default block size"
        };
        return Ok(ProbeResult::matched(ProbeMatch::new(
          DESCRIPTOR,
          ProbeConfidence::Exact,
          detail,
        )));
      }
    }

    Ok(ProbeResult::rejected())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl crate::DataSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = offset as usize;
      if offset >= self.data.len() {
        return Ok(0);
      }
      let read = buf.len().min(self.data.len() - offset);
      buf[..read].copy_from_slice(&self.data[offset..offset + read]);
      Ok(read)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.data.len() as u64)
    }
  }

  #[test]
  fn probe_matches_non_default_block_size_header() {
    let mut data = vec![0u8; 8192];
    data[4096..4104].copy_from_slice(constants::HEADER_SIGNATURE);
    let source = MemDataSource { data };
    let probe = GptProbe;
    let context = ProbeContext::new(&source);

    assert!(matches!(
      probe.probe(&context).unwrap(),
      ProbeResult::Matched(_)
    ));
  }
}
