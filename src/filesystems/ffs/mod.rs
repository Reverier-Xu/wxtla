//! FFS/UFS filesystem driver and probe registration.

mod driver;
mod filesystem;

pub use driver::FfsDriver;
pub use filesystem::FfsFileSystem;

use crate::{
  Error, FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.ffs", FormatKind::FileSystem);

pub(crate) const FS_UFS1_MAGIC: u32 = 0x011954;
pub(crate) const FS_UFS2_MAGIC: u32 = 0x19540119;
pub(crate) const SBLOCK_SEARCH: &[u64] = &[8192, 65536, 262144, 0];
pub(crate) const SBLOCKSIZE: usize = 8192;
pub(crate) const UFS_ROOTINO: u32 = 2;
pub(crate) const UFS_NDADDR: usize = 12;
pub(crate) const UFS_NIADDR: usize = 3;
pub(crate) const UFS_MAXNAMLEN: usize = 255;

#[allow(dead_code)]
pub(crate) const DT_UNKNOWN: u8 = 0;
pub(crate) const DT_FIFO: u8 = 1;
pub(crate) const DT_CHR: u8 = 2;
pub(crate) const DT_DIR: u8 = 4;
pub(crate) const DT_BLK: u8 = 6;
pub(crate) const DT_REG: u8 = 8;
pub(crate) const DT_LNK: u8 = 10;
pub(crate) const DT_SOCK: u8 = 12;
#[allow(dead_code)]
pub(crate) const DT_WHT: u8 = 14;

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
  registry.register(FfsProbe);
}

struct FfsProbe;

impl FormatProbe for FfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.source().size()?;
    for &offset in SBLOCK_SEARCH {
      if offset + SBLOCKSIZE as u64 > size {
        continue;
      }
      let Ok(data) = context.source().read_bytes_at(offset, SBLOCKSIZE) else {
        continue;
      };
      if data.len() < 0x220 {
        continue;
      }
      let magic = u32::from_le_bytes(
        data[0x21C..0x220]
          .try_into()
          .map_err(|_| Error::invalid_format("ffs header is truncated"))?,
      );
      if magic == FS_UFS1_MAGIC || magic == FS_UFS2_MAGIC {
        return Ok(ProbeResult::matched(ProbeMatch::new(
          DESCRIPTOR,
          ProbeConfidence::Exact,
          "ffs superblock magic is valid",
        )));
      }
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

pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
  Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32> {
  Ok(i32::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_i64_le(bytes: &[u8], offset: usize) -> Result<i64> {
  Ok(i64::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  bytes
    .get(offset..offset + N)
    .ok_or_else(|| Error::invalid_format("ffs field extends beyond available data"))?
    .try_into()
    .map_err(|_| Error::invalid_format("ffs field is truncated"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  fn make_minimal_ufs2_superblock() -> Vec<u8> {
    let mut data = vec![0u8; 65536 + SBLOCKSIZE];
    let sb_offset = 65536usize;

    data[sb_offset + 0x21C..sb_offset + 0x220].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());

    data
  }

  #[test]
  fn probe_matches_ufs2_superblock() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(make_minimal_ufs2_superblock());

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }

  #[test]
  fn probe_rejects_non_ffs_image() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0u8; 1024]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }
}
