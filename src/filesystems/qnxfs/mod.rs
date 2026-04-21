//! QNX4 filesystem driver and probe registration.

mod driver;
mod filesystem;

pub use driver::QnxFsDriver;
pub use filesystem::QnxFsFileSystem;

use crate::{
  Error, FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.qnxfs", FormatKind::FileSystem);

pub(crate) const QNX4_BLOCK_SIZE: u64 = 512;
pub(crate) const QNX4_DIR_ENTRY_SIZE: usize = 64;
pub(crate) const QNX4_INODES_PER_BLOCK: u32 = 8;
pub(crate) const QNX4_ROOT_INO: u32 = 1;
pub(crate) const QNX4_SHORT_NAME_MAX: usize = 16;
pub(crate) const QNX4_NAME_MAX: usize = 48;
pub(crate) const QNX4_MAX_XTNTS_PER_XBLK: usize = 60;

pub(crate) const QNX4_FILE_USED: u8 = 0x01;
pub(crate) const QNX4_FILE_LINK: u8 = 0x08;

pub(crate) const S_IFMT: u16 = 0xF000;
pub(crate) const S_IFDIR: u16 = 0x4000;
pub(crate) const S_IFREG: u16 = 0x8000;
pub(crate) const S_IFLNK: u16 = 0xA000;
#[allow(dead_code)]
pub(crate) const S_IFBLK: u16 = 0x6000;
#[allow(dead_code)]
pub(crate) const S_IFCHR: u16 = 0x2000;
#[allow(dead_code)]
pub(crate) const S_IFIFO: u16 = 0x1000;
#[allow(dead_code)]
pub(crate) const S_IFSOCK: u16 = 0xC000;

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(QnxFsProbe);
}

struct QnxFsProbe;

impl FormatProbe for QnxFsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.source().size()?;
    if size < QNX4_BLOCK_SIZE * 2 {
      return Ok(ProbeResult::rejected());
    }
    let Ok(data) = context.source().read_bytes_at(QNX4_BLOCK_SIZE, 16) else {
      return Ok(ProbeResult::rejected());
    };
    if data[0] == b'/' && data[1..16].iter().all(|&b| b == 0) {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "qnx4 superblock signature is valid",
      )));
    }
    Ok(ProbeResult::rejected())
  }
}

pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
  Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
  Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  bytes
    .get(offset..offset + N)
    .ok_or_else(|| Error::invalid_format("qnx4 field extends beyond available data"))?
    .try_into()
    .map_err(|_| Error::invalid_format("qnx4 field is truncated"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  #[test]
  fn probe_matches_qnx4_superblock() {
    let mut data = vec![0u8; 1024];
    data[512] = b'/';

    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(data);

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }

  #[test]
  fn probe_rejects_non_qnx4_image() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0u8; 1024]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }
}
