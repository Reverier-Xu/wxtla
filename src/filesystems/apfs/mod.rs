//! APFS container driver and probe registration.

mod btree;
mod container;
mod crypto;
mod driver;
mod filesystem;
mod group;
mod keybag;
mod ondisk;
mod records;

use container::probe_apfs_container;
pub use container::{ApfsContainer, ApfsVolume, ApfsVolumeInfo};
pub use driver::ApfsDriver;
pub use filesystem::{
  ApfsExtendedAttribute, ApfsNodeDetails, ApfsSnapshotInfo, ApfsSpecialFileKind,
};
pub use group::{ApfsFirmlink, ApfsVolumeGroupInfo, ApfsVolumeGroupMember, ApfsVolumeGroupView};
pub use ondisk::{ApfsChangeInfo, ApfsIntegrityMetadata};
pub use records::{APFS_FILE_INFO_DATA_HASH, ApfsFileInfoRecord};

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// APFS filesystem descriptor.
pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.apfs", FormatKind::FileSystem);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(ApfsProbe);
}

struct ApfsProbe;

impl FormatProbe for ApfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    if probe_apfs_container(context.source())? {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "apfs container superblock layout is valid",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

#[cfg(test)]
mod tests {
  use std::{fs::File, io::Read};

  use flate2::read::GzDecoder;

  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  fn fixture_gzip_bytes(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("apfs")
      .join("dissect.apfs")
      .join(name);
    let file = File::open(path).unwrap();
    let mut decoder = GzDecoder::new(file);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes).unwrap();
    bytes
  }

  #[test]
  fn probe_matches_decompressed_apfs_fixture() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(fixture_gzip_bytes("case_insensitive.bin.gz"));

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }
}
