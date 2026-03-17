//! Built-in format descriptors and lightweight signature probes.

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, Result,
};

/// Built-in descriptor for EWF images.
pub const EWF_IMAGE: FormatDescriptor = FormatDescriptor::new("image.ewf", FormatKind::Image);
/// Built-in descriptor for QCOW images.
pub const QCOW_IMAGE: FormatDescriptor = FormatDescriptor::new("image.qcow", FormatKind::Image);
/// Built-in descriptor for VHD images.
pub const VHD_IMAGE: FormatDescriptor = FormatDescriptor::new("image.vhd", FormatKind::Image);
/// Built-in descriptor for VHDX images.
pub const VHDX_IMAGE: FormatDescriptor = FormatDescriptor::new("image.vhdx", FormatKind::Image);
/// Built-in descriptor for VMDK images.
pub const VMDK_IMAGE: FormatDescriptor = FormatDescriptor::new("image.vmdk", FormatKind::Image);
/// Built-in descriptor for sparseimage images.
pub const SPARSE_IMAGE: FormatDescriptor =
  FormatDescriptor::new("image.sparseimage", FormatKind::Image);
/// Built-in descriptor for UDIF / DMG images.
pub const UDIF_IMAGE: FormatDescriptor = FormatDescriptor::new("image.udif", FormatKind::Image);
/// Built-in descriptor for MBR volume systems.
pub const MBR_VOLUME_SYSTEM: FormatDescriptor =
  FormatDescriptor::new("volume.mbr", FormatKind::VolumeSystem);
/// Built-in descriptor for GPT volume systems.
pub const GPT_VOLUME_SYSTEM: FormatDescriptor =
  FormatDescriptor::new("volume.gpt", FormatKind::VolumeSystem);
/// Built-in descriptor for APM volume systems.
pub const APM_VOLUME_SYSTEM: FormatDescriptor =
  FormatDescriptor::new("volume.apm", FormatKind::VolumeSystem);
/// Built-in descriptor for FAT filesystems.
pub const FAT_FILESYSTEM: FormatDescriptor =
  FormatDescriptor::new("filesystem.fat", FormatKind::FileSystem);
/// Built-in descriptor for NTFS filesystems.
pub const NTFS_FILESYSTEM: FormatDescriptor =
  FormatDescriptor::new("filesystem.ntfs", FormatKind::FileSystem);
/// Built-in descriptor for ext-family filesystems.
pub const EXT_FILESYSTEM: FormatDescriptor =
  FormatDescriptor::new("filesystem.ext", FormatKind::FileSystem);
/// Built-in descriptor for classic HFS filesystems.
pub const HFS_FILESYSTEM: FormatDescriptor =
  FormatDescriptor::new("filesystem.hfs", FormatKind::FileSystem);
/// Built-in descriptor for HFS+ / HFSX filesystems.
pub const HFS_PLUS_FILESYSTEM: FormatDescriptor =
  FormatDescriptor::new("filesystem.hfsplus", FormatKind::FileSystem);

const EWF_MAGIC: &[u8] = b"EVF\t\r\n\xff\0";
const QCOW_MAGIC: &[u8] = b"QFI\xfb";
const VHDX_MAGIC: &[u8] = b"vhdxfile";
const VHD_MAGIC: &[u8] = b"conectix";
const VMDK_MAGIC: &[u8] = b"KDMV";
const SPARSE_IMAGE_MAGIC: &[u8] = b"sprs";
const UDIF_MAGIC: &[u8] = b"koly";
const GPT_MAGIC: &[u8] = b"EFI PART";
const APM_DRIVER_DESCRIPTOR_MAGIC: &[u8] = b"ER";
const APM_PARTITION_MAP_MAGIC: &[u8] = b"PM";
const FAT12_MAGIC: &[u8] = b"FAT12   ";
const FAT16_MAGIC: &[u8] = b"FAT16   ";
const FAT32_MAGIC: &[u8] = b"FAT32   ";
const NTFS_MAGIC: &[u8] = b"NTFS    ";
const EXT_MAGIC_LE: [u8; 2] = [0x53, 0xef];
const HFS_MAGIC: &[u8] = b"BD";
const HFS_PLUS_MAGIC: &[u8] = b"H+";
const HFSX_MAGIC: &[u8] = b"HX";

/// Construct the built-in signature probe registry.
pub fn builtin_probe_registry() -> ProbeRegistry {
  ProbeRegistry::new()
    .with_probe(OffsetMagicProbe::new(
      EWF_IMAGE,
      0,
      EWF_MAGIC,
      ProbeConfidence::Exact,
      "ewf segment header found",
    ))
    .with_probe(OffsetMagicProbe::new(
      QCOW_IMAGE,
      0,
      QCOW_MAGIC,
      ProbeConfidence::Exact,
      "qcow header found",
    ))
    .with_probe(VhdProbe)
    .with_probe(OffsetMagicProbe::new(
      VHDX_IMAGE,
      0,
      VHDX_MAGIC,
      ProbeConfidence::Exact,
      "vhdx file identifier found",
    ))
    .with_probe(OffsetMagicProbe::new(
      VMDK_IMAGE,
      0,
      VMDK_MAGIC,
      ProbeConfidence::Exact,
      "vmdk sparse header found",
    ))
    .with_probe(OffsetMagicProbe::new(
      SPARSE_IMAGE,
      0,
      SPARSE_IMAGE_MAGIC,
      ProbeConfidence::Exact,
      "sparseimage header found",
    ))
    .with_probe(UdifProbe)
    .with_probe(GptProbe)
    .with_probe(ApmProbe)
    .with_probe(MbrProbe)
    .with_probe(FatProbe)
    .with_probe(NtfsProbe)
    .with_probe(ExtProbe)
    .with_probe(HfsProbe)
}

struct OffsetMagicProbe {
  descriptor: FormatDescriptor,
  offset: u64,
  magic: &'static [u8],
  confidence: ProbeConfidence,
  detail: &'static str,
}

impl OffsetMagicProbe {
  const fn new(
    descriptor: FormatDescriptor, offset: u64, magic: &'static [u8], confidence: ProbeConfidence,
    detail: &'static str,
  ) -> Self {
    Self {
      descriptor,
      offset,
      magic,
      confidence,
      detail,
    }
  }
}

impl FormatProbe for OffsetMagicProbe {
  fn descriptor(&self) -> FormatDescriptor {
    self.descriptor
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(bytes) = context.read_bytes_at(self.offset, self.magic.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if bytes == self.magic {
      Ok(ProbeResult::matched(ProbeMatch::new(
        self.descriptor,
        self.confidence,
        self.detail,
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct VhdProbe;

impl FormatProbe for VhdProbe {
  fn descriptor(&self) -> FormatDescriptor {
    VHD_IMAGE
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    if let Ok(header) = context.header(VHD_MAGIC.len())
      && header == VHD_MAGIC
    {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        VHD_IMAGE,
        ProbeConfidence::Exact,
        "vhd footer signature found at file start",
      )));
    }

    let size = context.size()?;
    if size < 512 {
      return Ok(ProbeResult::rejected());
    }
    let footer_offset = size - 512;
    let Ok(footer_magic) = context.read_bytes_at(footer_offset, VHD_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if footer_magic == VHD_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        VHD_IMAGE,
        ProbeConfidence::Exact,
        "vhd footer signature found at trailer",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct UdifProbe;

impl FormatProbe for UdifProbe {
  fn descriptor(&self) -> FormatDescriptor {
    UDIF_IMAGE
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let size = context.size()?;
    if size < 512 {
      return Ok(ProbeResult::rejected());
    }
    let trailer_offset = size - 512;
    let Ok(trailer_magic) = context.read_bytes_at(trailer_offset, UDIF_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if trailer_magic == UDIF_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        UDIF_IMAGE,
        ProbeConfidence::Exact,
        "udif koly trailer found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct GptProbe;

impl FormatProbe for GptProbe {
  fn descriptor(&self) -> FormatDescriptor {
    GPT_VOLUME_SYSTEM
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(header) = context.read_bytes_at(512, GPT_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if header == GPT_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        GPT_VOLUME_SYSTEM,
        ProbeConfidence::Exact,
        "gpt header found at lba1",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct ApmProbe;

impl FormatProbe for ApmProbe {
  fn descriptor(&self) -> FormatDescriptor {
    APM_VOLUME_SYSTEM
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(driver_descriptor) = context.read_bytes_at(0, APM_DRIVER_DESCRIPTOR_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };
    if driver_descriptor != APM_DRIVER_DESCRIPTOR_MAGIC {
      return Ok(ProbeResult::rejected());
    }

    let Ok(partition_map) = context.read_bytes_at(512, APM_PARTITION_MAP_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if partition_map == APM_PARTITION_MAP_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        APM_VOLUME_SYSTEM,
        ProbeConfidence::Exact,
        "apm driver descriptor and partition map found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct MbrProbe;

impl FormatProbe for MbrProbe {
  fn descriptor(&self) -> FormatDescriptor {
    MBR_VOLUME_SYSTEM
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(510, 2) else {
      return Ok(ProbeResult::rejected());
    };

    if signature == [0x55, 0xaa] {
      Ok(ProbeResult::matched(ProbeMatch::new(
        MBR_VOLUME_SYSTEM,
        ProbeConfidence::Weak,
        "mbr boot signature found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct FatProbe;

impl FormatProbe for FatProbe {
  fn descriptor(&self) -> FormatDescriptor {
    FAT_FILESYSTEM
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(510, 2) else {
      return Ok(ProbeResult::rejected());
    };
    if signature != [0x55, 0xaa] {
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
        FAT_FILESYSTEM,
        ProbeConfidence::Strong,
        "fat type string found in boot sector",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct NtfsProbe;

impl FormatProbe for NtfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    NTFS_FILESYSTEM
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(510, 2) else {
      return Ok(ProbeResult::rejected());
    };
    if signature != [0x55, 0xaa] {
      return Ok(ProbeResult::rejected());
    }

    let Ok(oem_id) = context.read_bytes_at(3, NTFS_MAGIC.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if oem_id == NTFS_MAGIC {
      Ok(ProbeResult::matched(ProbeMatch::new(
        NTFS_FILESYSTEM,
        ProbeConfidence::Exact,
        "ntfs oem id found in boot sector",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct ExtProbe;

impl FormatProbe for ExtProbe {
  fn descriptor(&self) -> FormatDescriptor {
    EXT_FILESYSTEM
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(superblock_magic) = context.read_bytes_at(1024 + 56, EXT_MAGIC_LE.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if superblock_magic == EXT_MAGIC_LE {
      Ok(ProbeResult::matched(ProbeMatch::new(
        EXT_FILESYSTEM,
        ProbeConfidence::Exact,
        "ext superblock magic found",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

struct HfsProbe;

impl FormatProbe for HfsProbe {
  fn descriptor(&self) -> FormatDescriptor {
    HFS_FILESYSTEM
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(signature) = context.read_bytes_at(1024, 2) else {
      return Ok(ProbeResult::rejected());
    };

    if signature == HFS_MAGIC {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        HFS_FILESYSTEM,
        ProbeConfidence::Exact,
        "hfs signature found in volume header",
      )));
    }

    if signature == HFS_PLUS_MAGIC || signature == HFSX_MAGIC {
      return Ok(ProbeResult::matched(ProbeMatch::new(
        HFS_PLUS_FILESYSTEM,
        ProbeConfidence::Exact,
        "hfs+ signature found in volume header",
      )));
    }

    Ok(ProbeResult::rejected())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::DataSource;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
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
  fn builtin_registry_prefers_gpt_over_weak_mbr_match() {
    let mut data = vec![0u8; 4096];
    data[510] = 0x55;
    data[511] = 0xaa;
    data[512..520].copy_from_slice(GPT_MAGIC);
    let source = MemDataSource { data };

    let best_match = builtin_probe_registry()
      .probe_best(&source)
      .unwrap()
      .unwrap();

    assert_eq!(best_match.format, GPT_VOLUME_SYSTEM);
  }

  #[test]
  fn builtin_registry_detects_hfs_plus_signature() {
    let mut data = vec![0u8; 4096];
    data[1024..1026].copy_from_slice(HFS_PLUS_MAGIC);
    let source = MemDataSource { data };

    let best_match = builtin_probe_registry()
      .probe_best(&source)
      .unwrap()
      .unwrap();

    assert_eq!(best_match.format, HFS_PLUS_FILESYSTEM);
  }
}
