use super::{
  checksum::weak_crc32,
  constants::{LABEL_SIGNATURE, LABEL_TYPE_LVM2, MDA_SIGNATURE, RAW_DESC_FLAG_IGNORE},
  io_utils::{ascii_trim_end, le_u32, le_u64, read_fully_at, unsupported},
  metadata_text::parse_lvm_metadata,
  model::{
    AreaDescriptor, LvmParsedImage, ParsedMetadata, PhysicalVolumeLabel, RawLocation,
    resolve_current_pv_name,
  },
};
use crate::{ByteSource, Error, Result};

const LABEL_SCAN_LIMIT_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn parse_lvm_image(source: &dyn ByteSource) -> Result<LvmParsedImage> {
  let label = read_label_sector(source)?.ok_or_else(|| unsupported("missing LVM2 label"))?;
  let metadata = read_best_metadata_copy(source, &label)?;
  let current_pv_name = resolve_current_pv_name(&metadata, &label.pv_identifier)
    .ok_or_else(|| unsupported("unable to resolve current physical volume"))?;

  Ok(LvmParsedImage {
    label,
    metadata,
    current_pv_name,
  })
}

fn read_best_metadata_copy(
  source: &dyn ByteSource, label: &PhysicalVolumeLabel,
) -> Result<ParsedMetadata> {
  let mut best_metadata = None::<ParsedMetadata>;
  let mut candidate_error = None::<Error>;

  for area in &label.metadata_areas {
    let raw_locations = match read_metadata_area(source, *area) {
      Ok(raw_locations) => raw_locations,
      Err(error) => {
        if candidate_error.is_none() {
          candidate_error = Some(error);
        }
        continue;
      }
    };
    let Some(committed_location) = raw_locations.first().copied() else {
      continue;
    };

    match read_metadata_text(source, committed_location) {
      Ok(metadata) => {
        if best_metadata
          .as_ref()
          .is_none_or(|current| metadata.seqno > current.seqno)
        {
          best_metadata = Some(metadata);
        }
      }
      Err(error) => {
        if candidate_error.is_none() {
          candidate_error = Some(error);
        }
      }
    }
  }

  best_metadata.ok_or_else(|| {
    candidate_error.unwrap_or_else(|| unsupported("no readable LVM metadata copies were found"))
  })
}

fn read_label_sector(source: &dyn ByteSource) -> Result<Option<PhysicalVolumeLabel>> {
  let source_size = source.size()?;
  let scan_limit = source_size.min(LABEL_SCAN_LIMIT_BYTES);
  let mut candidate_error: Option<Error> = None;

  if scan_limit < 512 {
    return Ok(None);
  }

  let mut sector = [0u8; 512];
  let mut offset = 0u64;
  while offset + 512 <= scan_limit {
    if source.read_at(offset, &mut sector)? != 512 {
      break;
    }
    if &sector[0..8] != LABEL_SIGNATURE || &sector[24..32] != LABEL_TYPE_LVM2 {
      offset += 512;
      continue;
    }

    match parse_label_from_sector(offset, &sector) {
      Ok(label) => return Ok(Some(label)),
      Err(error) => candidate_error = Some(error),
    }

    offset += 512;
  }

  if let Some(error) = candidate_error {
    return Err(error);
  }

  Ok(None)
}

fn parse_label_from_sector(offset: u64, sector: &[u8; 512]) -> Result<PhysicalVolumeLabel> {
  let stored_checksum = le_u32(&sector[16..20]);
  if stored_checksum != 0 {
    let calculated = weak_crc32(&sector[20..], 0xF597_A6CF);
    if calculated != stored_checksum {
      return Err(unsupported(format!(
        "invalid LVM label checksum at sector offset {offset:#x}: stored={stored_checksum:#010x} calculated={calculated:#010x}"
      )));
    }
  }

  let sector_number = le_u64(&sector[8..16]);
  let sector_number_offset = sector_number.checked_mul(512).ok_or_else(|| {
    unsupported(format!(
      "invalid LVM label sector number at offset {offset:#x}: multiplication overflow"
    ))
  })?;
  let pv_base_offset = offset.checked_sub(sector_number_offset).ok_or_else(|| {
    unsupported(format!(
      "invalid LVM label sector number at offset {offset:#x}: stored={sector_number} exceeds scan offset"
    ))
  })?;

  let pv_identifier = ascii_trim_end(&sector[32..64]);
  let mut cursor = 72usize;

  let mut data_areas = Vec::new();
  loop {
    if cursor + 16 > sector.len() {
      return Err(unsupported("truncated LVM data area descriptors"));
    }
    let area_offset = le_u64(&sector[cursor..cursor + 8]);
    let size = le_u64(&sector[cursor + 8..cursor + 16]);
    cursor += 16;
    if area_offset == 0 && size == 0 {
      break;
    }
    data_areas.push(AreaDescriptor {
      offset: pv_base_offset
        .checked_add(area_offset)
        .ok_or_else(|| unsupported("LVM data area offset overflow"))?,
      size,
    });
  }

  let mut metadata_areas = Vec::new();
  loop {
    if cursor + 16 > sector.len() {
      return Err(unsupported("truncated LVM metadata area descriptors"));
    }
    let area_offset = le_u64(&sector[cursor..cursor + 8]);
    let size = le_u64(&sector[cursor + 8..cursor + 16]);
    cursor += 16;
    if area_offset == 0 && size == 0 {
      break;
    }
    metadata_areas.push(AreaDescriptor {
      offset: pv_base_offset
        .checked_add(area_offset)
        .ok_or_else(|| unsupported("LVM metadata area offset overflow"))?,
      size,
    });
  }

  Ok(PhysicalVolumeLabel {
    pv_identifier,
    data_areas,
    metadata_areas,
  })
}

fn read_metadata_area(source: &dyn ByteSource, area: AreaDescriptor) -> Result<Vec<RawLocation>> {
  let mut header = [0u8; 512];
  read_fully_at(source, area.offset, &mut header)?;

  if &header[4..20] != MDA_SIGNATURE {
    return Err(unsupported(format!(
      "unsupported LVM metadata area signature at offset {:#x}",
      area.offset
    )));
  }

  let stored_checksum = le_u32(&header[0..4]);
  if stored_checksum != 0 {
    let calculated = weak_crc32(&header[4..], 0xF597_A6CF);
    if calculated != stored_checksum {
      return Err(unsupported(format!(
        "invalid LVM metadata area checksum at offset {:#x}: stored={stored_checksum:#010x} calculated={calculated:#010x}",
        area.offset
      )));
    }
  }

  let mut raw_locations = Vec::new();
  let mut cursor = 40usize;
  for _ in 0..4 {
    let rel_offset = le_u64(&header[cursor..cursor + 8]);
    let size = le_u64(&header[cursor + 8..cursor + 16]);
    let checksum = le_u32(&header[cursor + 16..cursor + 20]);
    let flags = le_u32(&header[cursor + 20..cursor + 24]);
    cursor += 24;
    if rel_offset == 0 && size == 0 && checksum == 0 && flags == 0 {
      continue;
    }
    if flags & RAW_DESC_FLAG_IGNORE != 0 {
      continue;
    }
    if rel_offset
      .checked_add(size)
      .is_none_or(|end| end > area.size)
    {
      continue;
    }
    raw_locations.push(RawLocation {
      offset: area.offset + rel_offset,
      size,
      checksum,
    });
  }

  Ok(raw_locations)
}

fn read_metadata_text(source: &dyn ByteSource, location: RawLocation) -> Result<ParsedMetadata> {
  let mut data = vec![
    0u8;
    usize::try_from(location.size)
      .map_err(|_| unsupported("LVM metadata area is too large to read"))?
  ];
  read_fully_at(source, location.offset, &mut data)?;

  if location.checksum != 0 {
    let calculated = weak_crc32(&data, 0xF597_A6CF);
    if calculated != location.checksum {
      return Err(unsupported(format!(
        "invalid LVM metadata checksum at offset {:#x}: stored={:#010x} calculated={:#010x}",
        location.offset, location.checksum, calculated
      )));
    }
  }

  if let Some(position) = data.iter().position(|byte| *byte == 0) {
    data.truncate(position);
  }

  let text = std::str::from_utf8(&data).map_err(|_| {
    unsupported(format!(
      "LVM metadata is not UTF-8 at offset {:#x}",
      location.offset
    ))
  })?;
  parse_lvm_metadata(text).map_err(|error| {
    unsupported(format!(
      "failed to parse LVM metadata at offset {:#x}, size {}: {}",
      location.offset, location.size, error
    ))
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl ByteSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = usize::try_from(offset)
        .map_err(|_| Error::InvalidRange("test read offset is too large".to_string()))?;
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
  fn parses_label_sample_fragments() {
    let label_bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/lvm/physical_volume_label.1"
    ))
    .unwrap();
    let header_bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/lvm/physical_volume_header.1"
    ))
    .unwrap();
    let mut sector = [0u8; 512];
    sector[0..32].copy_from_slice(&label_bytes);
    sector[32..72].copy_from_slice(&header_bytes);
    sector[16..20].fill(0);

    let label = parse_label_from_sector(512, &sector).unwrap();

    assert_eq!(label.pv_identifier, "btEzLai0aLsfS8Ae9PQKGUIhtACkpWm7");
    assert!(label.data_areas.is_empty());
    assert!(label.metadata_areas.is_empty());
  }

  #[test]
  fn parses_metadata_area_sample_fragments() {
    let header_bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/lvm/metadata_area.1"
    ))
    .unwrap();
    let desc_bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/lvm/raw_location_descriptor.1"
    ))
    .unwrap();
    let mut image = vec![0u8; 512];
    image[0..40].copy_from_slice(&header_bytes);
    image[40..64].copy_from_slice(&desc_bytes);
    image[0..4].fill(0);
    let source = MemDataSource { data: image };

    let locations = read_metadata_area(
      &source,
      AreaDescriptor {
        offset: 0,
        size: 512,
      },
    )
    .unwrap();

    assert_eq!(locations.len(), 0);
  }

  #[test]
  fn probe_detects_lvm2_label_after_gap() {
    let mut image = vec![0u8; 0x2400];
    let label_offset = 0x200;
    image[label_offset..label_offset + 8].copy_from_slice(LABEL_SIGNATURE);
    image[label_offset + 8..label_offset + 16].copy_from_slice(&1u64.to_le_bytes());
    image[label_offset + 24..label_offset + 32].copy_from_slice(LABEL_TYPE_LVM2);
    image[label_offset + 32..label_offset + 64]
      .copy_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let checksum = weak_crc32(&image[label_offset + 20..label_offset + 512], 0xF597_A6CF);
    image[label_offset + 16..label_offset + 20].copy_from_slice(&checksum.to_le_bytes());

    let parsed = read_label_sector(&MemDataSource { data: image }).unwrap();
    assert!(parsed.is_some());
  }

  #[test]
  fn prefers_the_highest_seqno_across_metadata_areas() {
    let image = build_image_with_metadata_areas(&[
      (0x2000, 0x200, metadata_text(1)),
      (0x3000, 0x200, metadata_text(2)),
    ]);

    let parsed = parse_lvm_image(&MemDataSource { data: image }).unwrap();

    assert_eq!(parsed.metadata.seqno, 2);
    assert_eq!(parsed.current_pv_name, "pv0");
  }

  #[test]
  fn ignores_precommitted_raw_location_slots() {
    let image = build_image_with_metadata_areas(&[(0x2000, 0x200, metadata_text(1))])
      .into_iter()
      .collect::<Vec<_>>();
    let mut image = image;
    write_raw_location_descriptor(&mut image, 0x2000, 1, 0x400, &metadata_text(99), 0, false);

    let parsed = parse_lvm_image(&MemDataSource { data: image }).unwrap();

    assert_eq!(parsed.metadata.seqno, 1);
  }

  fn build_image_with_metadata_areas(areas: &[(u64, u64, String)]) -> Vec<u8> {
    let mut image = vec![0u8; 0x8000];
    let label_offset = 512usize;
    let label = &mut image[label_offset..label_offset + 512];
    label[0..8].copy_from_slice(LABEL_SIGNATURE);
    label[8..16].copy_from_slice(&1u64.to_le_bytes());
    label[24..32].copy_from_slice(LABEL_TYPE_LVM2);
    label[32..64].copy_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let mut cursor = 72usize;
    cursor += 16;
    for (area_offset, ..) in areas {
      label[cursor..cursor + 8].copy_from_slice(&area_offset.to_le_bytes());
      label[cursor + 8..cursor + 16].copy_from_slice(&0x1000u64.to_le_bytes());
      cursor += 16;
    }

    for (area_offset, rel_offset, metadata) in areas {
      let area_start = *area_offset as usize;
      let mda = &mut image[area_start..area_start + 512];
      mda[4..20].copy_from_slice(MDA_SIGNATURE);
      mda[20..24].copy_from_slice(&1u32.to_le_bytes());
      mda[24..32].copy_from_slice(&512u64.to_le_bytes());
      mda[32..40].copy_from_slice(&0x1000u64.to_le_bytes());
      write_raw_location_descriptor(&mut image, *area_offset, 0, *rel_offset, metadata, 0, false);
    }

    image
  }

  fn write_raw_location_descriptor(
    image: &mut [u8], area_offset: u64, index: usize, rel_offset: u64, metadata: &str,
    checksum: u32, ignored: bool,
  ) {
    let area_start = area_offset as usize;
    let desc_offset = area_start + 40 + index * 24;
    image[desc_offset..desc_offset + 8].copy_from_slice(&rel_offset.to_le_bytes());
    image[desc_offset + 8..desc_offset + 16]
      .copy_from_slice(&(metadata.len() as u64).to_le_bytes());
    image[desc_offset + 16..desc_offset + 20].copy_from_slice(&checksum.to_le_bytes());
    image[desc_offset + 20..desc_offset + 24].copy_from_slice(&(u32::from(ignored)).to_le_bytes());
    let metadata_offset = area_start + rel_offset as usize;
    image[metadata_offset..metadata_offset + metadata.len()].copy_from_slice(metadata.as_bytes());
  }

  fn metadata_text(seqno: u64) -> String {
    format!(
      "vg0 {{\n  id = \"vgid\"\n  seqno = {seqno}\n  extent_size = 8\n  physical_volumes {{\n    pv0 {{\n      id = \"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"\n    }}\n  }}\n  logical_volumes {{\n    lv0 {{\n      id = \"lvid\"\n      segment_count = 1\n      segment1 {{\n        start_extent = 0\n        extent_count = 1\n        type = \"striped\"\n        stripe_count = 1\n        stripes = [ \"pv0\", 0 ]\n      }}\n    }}\n  }}\n}}\n"
    )
  }
}
