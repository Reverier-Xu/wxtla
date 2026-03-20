use super::{
  DESCRIPTOR, model::resolve_pv_pe_start, parser::parse_lvm_image, system::LvmVolumeSystem,
};
use crate::{
  DataSourceHandle, Result, SourceHints,
  volumes::{VolumeSystem, VolumeSystemDriver},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct LvmDriver;

impl LvmDriver {
  pub const fn new() -> Self {
    Self
  }

  pub fn open(source: DataSourceHandle) -> Result<LvmVolumeSystem> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(
    source: DataSourceHandle, _hints: SourceHints<'_>,
  ) -> Result<LvmVolumeSystem> {
    let parsed = parse_lvm_image(source.as_ref())?;
    let current_pv_pe_start =
      resolve_pv_pe_start(&parsed.metadata.physical_volumes, &parsed.current_pv_name);
    let super::model::LvmParsedImage {
      label,
      metadata,
      current_pv_name,
    } = parsed;
    let super::model::ParsedMetadata {
      vg_name,
      extent_size_bytes,
      logical_volumes,
      ..
    } = metadata;

    LvmVolumeSystem::new(
      source,
      label,
      current_pv_name,
      current_pv_pe_start,
      vg_name,
      extent_size_bytes,
      logical_volumes,
    )
  }
}

impl VolumeSystemDriver for LvmDriver {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn open(
    &self, source: DataSourceHandle, hints: SourceHints<'_>,
  ) -> Result<Box<dyn VolumeSystem>> {
    Ok(Box::new(Self::open_with_hints(source, hints)?))
  }
}

#[cfg(test)]
mod tests {
  use std::{cmp::min, sync::Arc};

  use super::*;
  use crate::{DataSource, volumes::lvm::checksum};

  struct MemoryDataSource {
    bytes: Vec<u8>,
  }

  impl DataSource for MemoryDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = offset as usize;
      if offset >= self.bytes.len() {
        return Ok(0);
      }
      let count = min(buf.len(), self.bytes.len() - offset);
      buf[..count].copy_from_slice(&self.bytes[offset..offset + count]);
      Ok(count)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.bytes.len() as u64)
    }
  }

  #[test]
  fn lvm_opens_and_reads_logical_volume() {
    let image = build_lvm_image(
      vec![("segment1", 0, 1, "pv0", 0), ("segment2", 1, 1, "pv0", 1)],
      &[(0x10000, b"ABCD"), (0x11000, b"WXYZ")],
    );
    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();

    assert_eq!(system.vg_name(), "vg0");
    assert_eq!(system.volumes().len(), 1);
    assert_eq!(system.volumes()[0].name.as_deref(), Some("lv0"));

    let source = system.open_volume(0).unwrap();
    let mut first = [0u8; 4];
    assert_eq!(source.read_at(0, &mut first).unwrap(), 4);
    assert_eq!(&first, b"ABCD");

    let mut second = [0u8; 4];
    assert_eq!(source.read_at(4096, &mut second).unwrap(), 4);
    assert_eq!(&second, b"WXYZ");
  }

  #[test]
  fn lvm_missing_physical_volume_reads_as_zeroes() {
    let image = build_lvm_image(
      vec![("segment1", 0, 1, "pv0", 0), ("segment2", 1, 1, "pv1", 1)],
      &[(0x10000, b"ABCD")],
    );

    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();
    let source = system.open_volume(0).unwrap();

    let mut second = [0u8; 4];
    assert_eq!(source.read_at(4096, &mut second).unwrap(), 4);
    assert_eq!(&second, &[0, 0, 0, 0]);
  }

  #[test]
  fn lvm_reads_multi_stripe_segments() {
    let mut image = build_lvm_image_with_raw_metadata(
      r#"
vg0 {
  id = "vgid"
  seqno = 1
  extent_size = 8
  physical_volumes {
    pv0 {
      id = "aaaaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaaaa"
    }
    pv1 {
      id = "bbbbbb-bbbb-bbbb-bbbb-bbbb-bbbb-bbbbbb"
    }
  }
  logical_volumes {
    lv0 {
      id = "lvid"
      segment_count = 1
      segment1 {
        start_extent = 0
        extent_count = 2
        stripe_size = 4
        stripe_count = 2
        stripes = [ "pv0", 0, "pv0", 1 ]
      }
    }
  }
}
"#,
    );
    image[0x10000..0x10800].fill(b'A');
    image[0x10800..0x11000].fill(b'B');
    image[0x11000..0x11800].fill(b'C');
    image[0x11800..0x12000].fill(b'D');

    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();
    let source = system.open_volume(0).unwrap();
    let data = source.read_all().unwrap();

    assert_eq!(data.len(), 8192);
    assert!(data[..2048].iter().all(|byte| *byte == b'A'));
    assert!(data[2048..4096].iter().all(|byte| *byte == b'C'));
    assert!(data[4096..6144].iter().all(|byte| *byte == b'B'));
    assert!(data[6144..].iter().all(|byte| *byte == b'D'));
  }

  #[test]
  fn lvm_metadata_with_global_assignments_is_supported() {
    let image = build_lvm_image_with_raw_metadata(
      r#"
contents = "Text Format Volume Group"
version = 1
description = ""
creation_host = host
creation_time = 1700000000

vg0 {
  id = "vgid"
  seqno = 1
  extent_size = 8
  max_lv = 0
  max_pv = 0
  metadata_copies = 0
  physical_volumes {
    pv0 {
      id = "aaaaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaaaa"
      pe_start = 2048
      pe_count = 1024
    }
  }
  logical_volumes {
    lv0 {
      id = "lvid"
      status = ["READ", "WRITE", visible]
      segment_count = 1
      segment1 {
        start_extent = 0
        extent_count = 1
        type = striped
        stripe_count = 1
        stripes = [ "pv0", 0 ]
      }
    }
  }
}
"#,
    );

    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();
    assert_eq!(system.volumes().len(), 1);
    assert_eq!(system.volumes()[0].name.as_deref(), Some("lv0"));
  }

  #[test]
  fn lvm_metadata_accepts_negative_numbers_in_ignored_fields() {
    let image = build_lvm_image_with_raw_metadata(
      r#"
contents = "Text Format Volume Group"
version = 1
creation_time = -1

vg0 {
  id = "vgid"
  seqno = 1
  extent_size = 8
  physical_volumes {
    pv0 {
      id = "aaaaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaaaa"
      pe_start = 2048
      ignored_negative = -2
    }
  }
  logical_volumes {
    lv0 {
      id = "lvid"
      status = ["READ", "WRITE", visible]
      segment_count = 1
      segment1 {
        start_extent = 0
        extent_count = 1
        type = striped
        stripe_count = 1
        stripes = [ "pv0", 0 ]
        ignored_negative = -3
      }
    }
  }
}
"#,
    );

    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();
    assert_eq!(system.volumes().len(), 1);
    assert_eq!(system.volumes()[0].name.as_deref(), Some("lv0"));
  }

  #[test]
  fn lvm_metadata_accepts_extra_root_objects() {
    let image = build_lvm_image_with_raw_metadata(
      r#"
contents = "Text Format Volume Group"
version = 1

archive {
  note = "ignored"
}

vg0 {
  id = "vgid"
  seqno = 1
  extent_size = 8
  physical_volumes {
    pv0 {
      id = "aaaaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaaaa"
      pe_start = 2048
    }
  }
  logical_volumes {
    lv0 {
      id = "lvid"
      segment_count = 1
      segment1 {
        start_extent = 0
        extent_count = 1
        type = striped
        stripe_count = 1
        stripes = [ "pv0", 0 ]
      }
    }
  }
}
"#,
    );

    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();
    assert_eq!(system.volumes().len(), 1);
    assert_eq!(system.volumes()[0].name.as_deref(), Some("lv0"));
  }

  #[test]
  fn lvm_metadata_accepts_large_unsigned_numbers_beyond_i64() {
    let image = build_lvm_image_with_raw_metadata(
      r#"
contents = "Text Format Volume Group"
version = 1
creation_time = 9223372036854775808

vg0 {
  id = "vgid"
  seqno = 1
  extent_size = 8
  physical_volumes {
    pv0 {
      id = "aaaaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaaaa"
      pe_count = 9223372036854775808
    }
  }
  logical_volumes {
    lv0 {
      id = "lvid"
      segment_count = 1
      segment1 {
        start_extent = 0
        extent_count = 1
        type = striped
        stripe_count = 1
        stripes = [ "pv0", 0 ]
      }
    }
  }
}
"#,
    );

    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();

    assert_eq!(system.volumes().len(), 1);
    assert_eq!(system.volumes()[0].name.as_deref(), Some("lv0"));
  }

  #[test]
  fn lvm_caches_opened_volume_sources_and_builds_info_lazily() {
    let image = build_lvm_image(
      vec![("segment1", 0, 1, "pv0", 0), ("segment2", 1, 1, "pv0", 1)],
      &[(0x10000, b"ABCD"), (0x11000, b"WXYZ")],
    );
    let system =
      LvmDriver::open(Arc::new(MemoryDataSource { bytes: image }) as DataSourceHandle).unwrap();

    let first = system.open_volume(0).unwrap();
    let second = system.open_volume(0).unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(system.logical_volumes_info()[0].chunks.len(), 2);
  }

  fn build_lvm_image(
    segments: Vec<(&str, u64, u64, &str, u64)>, payloads: &[(u64, &[u8])],
  ) -> Vec<u8> {
    build_lvm_image_with_gap(segments, payloads, 0)
  }

  fn build_lvm_image_with_gap(
    segments: Vec<(&str, u64, u64, &str, u64)>, payloads: &[(u64, &[u8])], gap: usize,
  ) -> Vec<u8> {
    let mut segment_text = String::new();
    for (segment_name, start_extent, extent_count, pv_name, stripe_start) in segments {
      segment_text.push_str(&format!(
        "      {segment_name} {{\n        start_extent = {start_extent}\n        extent_count = {extent_count}\n        type = \"striped\"\n        stripe_count = 1\n        stripes = [ \"{pv_name}\", {stripe_start} ]\n      }}\n"
      ));
    }

    let metadata = format!(
      "vg0 {{\n  id = \"vgid\"\n  seqno = 1\n  extent_size = 8\n  physical_volumes {{\n    pv0 {{\n      id = \"aaaaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaaaa\"\n      device = \"/dev/sda2\"\n      dev_size = 4096\n    }}\n  }}\n  logical_volumes {{\n    lv0 {{\n      id = \"lvid\"\n      segment_count = 2\n{segment_text}    }}\n  }}\n}}\n"
    );

    let mut image = build_lvm_image_with_raw_metadata_and_gap(&metadata, gap);
    for (offset, payload) in payloads {
      let start = gap + *offset as usize;
      image[start..start + payload.len()].copy_from_slice(payload);
    }
    image
  }

  fn build_lvm_image_with_raw_metadata(metadata: &str) -> Vec<u8> {
    build_lvm_image_with_raw_metadata_and_gap(metadata, 0)
  }

  fn build_lvm_image_with_raw_metadata_and_gap(metadata: &str, gap: usize) -> Vec<u8> {
    let mut image = vec![0u8; gap + 0x30000];
    let label_offset = gap + 512usize;
    let mda_offset = gap + 0x2000usize;
    let raw_metadata_offset = 0x200usize;

    let label = &mut image[label_offset..label_offset + 512];
    label[0..8].copy_from_slice(b"LABELONE");
    label[8..16].copy_from_slice(&1u64.to_le_bytes());
    label[24..32].copy_from_slice(b"LVM2 001");
    label[32..64].copy_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let mut cursor = 72usize;
    label[cursor..cursor + 8].copy_from_slice(&0x10000u64.to_le_bytes());
    label[cursor + 8..cursor + 16].copy_from_slice(&0u64.to_le_bytes());
    cursor += 16;
    cursor += 16;

    label[cursor..cursor + 8].copy_from_slice(&0x2000u64.to_le_bytes());
    label[cursor + 8..cursor + 16].copy_from_slice(&0x1000u64.to_le_bytes());

    let stored_label_checksum = checksum::weak_crc32(&label[20..], 0xF597_A6CF);
    label[16..20].copy_from_slice(&stored_label_checksum.to_le_bytes());

    {
      let mda = &mut image[mda_offset..mda_offset + 512];
      mda[4..20].copy_from_slice(b" LVM2 x[5A%r0N*>");
      mda[20..24].copy_from_slice(&1u32.to_le_bytes());
      mda[24..32].copy_from_slice(&512u64.to_le_bytes());
      mda[32..40].copy_from_slice(&0x1000u64.to_le_bytes());

      let desc = &mut mda[40..64];
      desc[0..8].copy_from_slice(&(raw_metadata_offset as u64).to_le_bytes());
      desc[8..16].copy_from_slice(&(metadata.len() as u64).to_le_bytes());
    }

    let metadata_start = mda_offset + raw_metadata_offset;
    image[metadata_start..metadata_start + metadata.len()].copy_from_slice(metadata.as_bytes());
    let metadata_checksum = checksum::weak_crc32(metadata.as_bytes(), 0xF597_A6CF);
    image[mda_offset + 56..mda_offset + 60].copy_from_slice(&metadata_checksum.to_le_bytes());
    let stored_mda_checksum =
      checksum::weak_crc32(&image[mda_offset + 4..mda_offset + 512], 0xF597_A6CF);
    image[mda_offset..mda_offset + 4].copy_from_slice(&stored_mda_checksum.to_le_bytes());

    image
  }
}
