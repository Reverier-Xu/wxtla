//! JFFS2 filesystem driver and probe registration.

mod driver;
mod filesystem;

pub use driver::Jffs2Driver;
pub use filesystem::Jffs2FileSystem;

use crate::{
  Error, FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.jffs2", FormatKind::FileSystem);

pub(crate) const JFFS2_MAGIC_BITMASK: u16 = 0x1985;
pub(crate) const JFFS2_OLD_MAGIC_BITMASK: u16 = 0x1984;
pub(crate) const JFFS2_EMPTY_BITMASK: u16 = 0xFFFF;
#[allow(dead_code)]
pub(crate) const JFFS2_DIRTY_BITMASK: u16 = 0x0000;

pub(crate) const JFFS2_NODETYPE_DIRENT: u16 = 0xE001;
pub(crate) const JFFS2_NODETYPE_INODE: u16 = 0xE002;
#[allow(dead_code)]
pub(crate) const JFFS2_NODETYPE_CLEANMARKER: u16 = 0x2003;
#[allow(dead_code)]
pub(crate) const JFFS2_NODETYPE_PADDING: u16 = 0x2004;

pub(crate) const JFFS2_COMPR_ZLIB: u8 = 0x06;
#[allow(dead_code)]
pub(crate) const JFFS2_COMPR_NONE: u8 = 0x00;
#[allow(dead_code)]
pub(crate) const JFFS2_COMPR_ZERO: u8 = 0x01;

pub(crate) const DT_DIR: u8 = 4;
pub(crate) const DT_REG: u8 = 8;
pub(crate) const DT_LNK: u8 = 10;
#[allow(dead_code)]
pub(crate) const DT_BLK: u8 = 6;
#[allow(dead_code)]
pub(crate) const DT_CHR: u8 = 2;
#[allow(dead_code)]
pub(crate) const DT_FIFO: u8 = 1;
#[allow(dead_code)]
pub(crate) const DT_SOCK: u8 = 12;

pub(crate) const S_IFMT: u32 = 0xF000;
pub(crate) const S_IFDIR: u32 = 0x4000;
pub(crate) const S_IFREG: u32 = 0x8000;
pub(crate) const S_IFLNK: u32 = 0xA000;

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(Jffs2Probe);
}

struct Jffs2Probe;

impl FormatProbe for Jffs2Probe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.source().size()?;
    if size < 12 {
      return Ok(ProbeResult::rejected());
    }
    let Ok(header) = context.source().read_bytes_at(0, 12) else {
      return Ok(ProbeResult::rejected());
    };
    let magic = u16::from_be_bytes(
      header[0..2]
        .try_into()
        .map_err(|_| Error::invalid_format("jffs2 header is truncated"))?,
    );
    if magic == JFFS2_MAGIC_BITMASK || magic == JFFS2_OLD_MAGIC_BITMASK {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "jffs2 node magic is valid",
      )));
    }
    Ok(ProbeResult::rejected())
  }
}

pub(crate) fn read_u16_be(bytes: &[u8], offset: usize) -> Result<u16> {
  Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32> {
  Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  bytes
    .get(offset..offset + N)
    .ok_or_else(|| Error::invalid_format("jffs2 field extends beyond available data"))?
    .try_into()
    .map_err(|_| Error::invalid_format("jffs2 field is truncated"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  #[test]
  fn probe_matches_jffs2_node() {
    let mut data = vec![0xFFu8; 4096];
    data[0..2].copy_from_slice(&JFFS2_MAGIC_BITMASK.to_be_bytes());
    data[2..4].copy_from_slice(&JFFS2_NODETYPE_INODE.to_be_bytes());
    data[4..8].copy_from_slice(&68u32.to_be_bytes());

    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(data);

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }

  #[test]
  fn probe_rejects_empty_flash() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0xFFu8; 4096]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }
}
