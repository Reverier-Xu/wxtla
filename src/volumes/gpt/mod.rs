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
pub use system::{GptHeaderLocation, GptVolumeSystem};
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
    for block_size in parser::candidate_block_sizes(context.source())? {
      if parser::validate_primary_probe(context.source(), block_size).is_ok() {
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
    data[446 + 4] = 0xEE;
    data[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    data[446 + 12..446 + 16].copy_from_slice(&15u32.to_le_bytes());
    data[510..512].copy_from_slice(&[0x55, 0xAA]);
    data[4096..4104].copy_from_slice(constants::HEADER_SIGNATURE);
    data[4104..4108].copy_from_slice(&constants::GPT_FORMAT_REVISION.to_le_bytes());
    data[4108..4112].copy_from_slice(&92u32.to_le_bytes());
    data[4116..4120].copy_from_slice(&1u32.to_le_bytes());
    data[4120..4128].copy_from_slice(&1u64.to_le_bytes());
    data[4128..4136].copy_from_slice(&15u64.to_le_bytes());
    data[4136..4144].copy_from_slice(&34u64.to_le_bytes());
    data[4144..4152].copy_from_slice(&14u64.to_le_bytes());
    data[4152..4168].copy_from_slice(&[1; 16]);
    data[4168..4176].copy_from_slice(&2u64.to_le_bytes());
    data[4176..4180].copy_from_slice(&1u32.to_le_bytes());
    data[4180..4184].copy_from_slice(&128u32.to_le_bytes());
    let mut checksum_input = data[4096..4188].to_vec();
    checksum_input[16..20].fill(0);
    let crc = crate::volumes::gpt::integrity::crc32(&checksum_input);
    data[4112..4116].copy_from_slice(&crc.to_le_bytes());
    let source = MemDataSource { data };
    let probe = GptProbe;
    let context = ProbeContext::new(&source);

    assert!(matches!(
      probe.probe(&context).unwrap(),
      ProbeResult::Matched(_)
    ));
  }

  #[test]
  fn probe_rejects_bare_signature_false_positives() {
    let mut data = vec![0u8; 8192];
    data[4096..4104].copy_from_slice(constants::HEADER_SIGNATURE);
    let source = MemDataSource { data };
    let probe = GptProbe;
    let context = ProbeContext::new(&source);

    assert!(matches!(
      probe.probe(&context).unwrap(),
      ProbeResult::Rejected
    ));
  }
}
