//! VMFS filesystem driver and probe registration.

mod driver;
mod filesystem;

pub use driver::VmfsDriver;
pub use filesystem::VmfsFileSystem;

use crate::{
  Error, FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

pub const DESCRIPTOR: FormatDescriptor =
  FormatDescriptor::new("filesystem.vmfs", FormatKind::FileSystem);

pub(crate) const VMFS_MAGIC_NUMBER: u32 = 0x2FAB_F15E;
pub(crate) const VMFSL_MAGIC_NUMBER: u32 = 0x2FAB_F15F;
pub(crate) const VMFS6_MAGIC_NUMBER: u32 = 0x2FAB_F160;
pub(crate) const VMFS6L_MAGIC_NUMBER: u32 = 0x2FAB_F161;

pub(crate) const FS3_FS_HEADER_OFFSET: u64 = 0x200000;
pub(crate) const FS3_MAX_FILE_NAME_LENGTH: usize = 128;

pub(crate) const FS3_DESCRIPTOR_SIZE: usize = 0x170;

pub(crate) const ROOT_DIR_DESC_ADDR: u32 = 0x00000004;
#[allow(dead_code)]
pub(crate) const FBB_DESC_ADDR: u32 = 0x00400004;
#[allow(dead_code)]
pub(crate) const FDBC_DESC_ADDR: u32 = 0x00800004;
#[allow(dead_code)]
pub(crate) const PBC_DESC_ADDR: u32 = 0x00C00004;
#[allow(dead_code)]
pub(crate) const SB_DESC_ADDR: u32 = 0x01000004;
#[allow(dead_code)]
pub(crate) const VH_DESC_ADDR: u32 = 0x01400004;
#[allow(dead_code)]
pub(crate) const PB2_DESC_ADDR: u32 = 0x01800004;

#[allow(dead_code)]
pub(crate) const FS3_DESCRIPTOR_TYPE_INVALID: u32 = 0;
#[allow(dead_code)]
pub(crate) const FS3_DESCRIPTOR_TYPE_VOLUME: u32 = 1;
pub(crate) const FS3_DESCRIPTOR_TYPE_DIRECTORY: u32 = 2;
pub(crate) const FS3_DESCRIPTOR_TYPE_REGFILE: u32 = 3;
pub(crate) const FS3_DESCRIPTOR_TYPE_SYMLINK: u32 = 4;
#[allow(dead_code)]
pub(crate) const FS3_DESCRIPTOR_TYPE_SYSFILE: u32 = 5;
#[allow(dead_code)]
pub(crate) const FS3_DESCRIPTOR_TYPE_RDM: u32 = 6;

#[allow(dead_code)]
pub(crate) const S_IFMT: u32 = 0xF000;
#[allow(dead_code)]
pub(crate) const S_IFDIR: u32 = 0x4000;
#[allow(dead_code)]
pub(crate) const S_IFREG: u32 = 0x8000;
#[allow(dead_code)]
pub(crate) const S_IFLNK: u32 = 0xA000;

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(VmfsProbe);
}

struct VmfsProbe;

impl FormatProbe for VmfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.source().size()?;
    if size < FS3_FS_HEADER_OFFSET + 4 {
      return Ok(ProbeResult::rejected());
    }
    let Ok(data) = context
      .source()
      .read_bytes_at(FS3_FS_HEADER_OFFSET, 4)
    else {
      return Ok(ProbeResult::rejected());
    };
    let magic = u32::from_le_bytes(
      data
        .try_into()
        .map_err(|_| Error::invalid_format("vmfs header is truncated"))?,
    );
    if matches!(
      magic,
      VMFS_MAGIC_NUMBER | VMFSL_MAGIC_NUMBER | VMFS6_MAGIC_NUMBER | VMFS6L_MAGIC_NUMBER
    ) {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "vmfs descriptor magic is valid",
      )));
    }
    Ok(ProbeResult::rejected())
  }
}

#[allow(dead_code)]
pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
  Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
  Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
  Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
  bytes
    .get(offset..offset + N)
    .ok_or_else(|| Error::invalid_format("vmfs field extends beyond available data"))?
    .try_into()
    .map_err(|_| Error::invalid_format("vmfs field is truncated"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ByteSource, BytesDataSource, formats};

  #[test]
  fn probe_matches_vmfs_magic() {
    let mut data = vec![0u8; FS3_FS_HEADER_OFFSET as usize + 16];
    let offset = FS3_FS_HEADER_OFFSET as usize;
    data[offset..offset + 4].copy_from_slice(&VMFS_MAGIC_NUMBER.to_le_bytes());

    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(data);

    let probe_match = registry
      .probe_best(&source as &dyn ByteSource)
      .unwrap()
      .unwrap();
    assert_eq!(probe_match.format, DESCRIPTOR);
  }

  #[test]
  fn probe_rejects_non_vmfs() {
    let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
    let source = BytesDataSource::new(vec![0u8; FS3_FS_HEADER_OFFSET as usize + 16]);

    let result = registry.probe_best(&source as &dyn ByteSource).unwrap();
    assert!(result.is_none());
  }
}
