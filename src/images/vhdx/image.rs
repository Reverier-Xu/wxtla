//! Read-only VHDX image surface.

use std::sync::Arc;

use super::{
  DESCRIPTOR,
  cache::VhdxCache,
  guid::VhdxGuid,
  header::VhdxImageHeader,
  metadata::{VhdxDiskType, VhdxMetadata},
  parent_locator::VhdxParentLocator,
  parser::{
    ParsedVhdx, VhdxBatLayout, VhdxPayloadBlockState, VhdxSectorBitmapState, bat_file_offset,
    parse, payload_bat_index, payload_block_state, read_bat_entry, sector_bitmap_bat_index,
    sector_bitmap_state,
  },
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

const MAX_BLOCK_CACHE_ENTRIES: usize = 64;
const MAX_SECTOR_BITMAP_CACHE_ENTRIES: usize = 64;
const BLOCK_CACHE_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const SECTOR_BITMAP_CACHE_BUDGET_BYTES: usize = 4 * 1024 * 1024;

pub struct VhdxImage {
  source: ByteSourceHandle,
  image_header: VhdxImageHeader,
  metadata: VhdxMetadata,
  bat: VhdxBatLayout,
  payload_block_count: u64,
  entries_per_chunk: u64,
  sector_bitmap_size: u64,
  parent_image: Option<ByteSourceHandle>,
  block_cache: VhdxCache<Vec<u8>>,
  sector_bitmap_cache: VhdxCache<Vec<u8>>,
}

impl VhdxImage {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let parsed = parse(source)?;
    if parsed.metadata.disk_type == VhdxDiskType::Differential {
      return Err(Error::invalid_source_reference(
        "differential vhdx images require source hints and a related-source resolver".to_string(),
      ));
    }
    Self::from_parsed(parsed, None)
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    let parsed = parse(source)?;
    let parent_image = if parsed.metadata.disk_type == VhdxDiskType::Differential {
      let resolver = hints.resolver().ok_or_else(|| {
        Error::invalid_source_reference(
          "differential vhdx images require a related-source resolver".to_string(),
        )
      })?;
      let identity = hints.source_identity().ok_or_else(|| {
        Error::invalid_source_reference(
          "differential vhdx images require a source identity hint".to_string(),
        )
      })?;
      let locator = parsed.metadata.parent_locator.as_ref().ok_or_else(|| {
        Error::invalid_format("differential vhdx images must provide a parent locator")
      })?;
      let expected_parent_identifier = locator.parent_identifier().ok_or_else(|| {
        Error::invalid_format(
          "differential vhdx images must provide a parent linkage identifier".to_string(),
        )
      })?;
      let (parent_source, parent_path) = resolve_parent_source(locator, resolver, identity)?
        .ok_or_else(|| Error::not_found("unable to resolve the parent vhdx image"))?;
      if &parent_path == identity.logical_path() {
        return Err(Error::invalid_format(
          "vhdx parent locator resolves to the same image".to_string(),
        ));
      }

      let parent_identity = crate::SourceIdentity::new(parent_path.clone());
      let parent_image = Self::open_with_hints(
        parent_source,
        SourceHints::new()
          .with_resolver(resolver)
          .with_source_identity(&parent_identity),
      )?;
      if parent_image.data_write_identifier() != expected_parent_identifier {
        return Err(Error::invalid_format(format!(
          "resolved parent data write identifier {} does not match expected {}",
          parent_image.data_write_identifier(),
          expected_parent_identifier
        )));
      }

      Some(Arc::new(parent_image) as ByteSourceHandle)
    } else {
      None
    };

    Self::from_parsed(parsed, parent_image)
  }

  fn from_parsed(parsed: ParsedVhdx, parent_image: Option<ByteSourceHandle>) -> Result<Self> {
    let block_size = usize::try_from(parsed.metadata.block_size)
      .map_err(|_| Error::invalid_range("vhdx block size is too large"))?;
    let sector_bitmap_size = usize::try_from(parsed.sector_bitmap_size)
      .map_err(|_| Error::invalid_range("vhdx sector bitmap size is too large"))?;

    Ok(Self {
      source: parsed.source,
      image_header: parsed.image_header,
      metadata: parsed.metadata,
      bat: parsed.block_allocation_table,
      payload_block_count: parsed.payload_block_count,
      entries_per_chunk: parsed.entries_per_chunk,
      sector_bitmap_size: parsed.sector_bitmap_size,
      parent_image,
      block_cache: VhdxCache::new(bounded_cache_capacity(
        block_size,
        BLOCK_CACHE_BUDGET_BYTES,
        MAX_BLOCK_CACHE_ENTRIES,
      )),
      sector_bitmap_cache: VhdxCache::new(bounded_cache_capacity(
        sector_bitmap_size,
        SECTOR_BITMAP_CACHE_BUDGET_BYTES,
        MAX_SECTOR_BITMAP_CACHE_ENTRIES,
      )),
    })
  }

  pub fn image_header(&self) -> &VhdxImageHeader {
    &self.image_header
  }

  pub fn metadata(&self) -> &VhdxMetadata {
    &self.metadata
  }

  pub fn disk_type(&self) -> VhdxDiskType {
    self.metadata.disk_type
  }

  pub fn data_write_identifier(&self) -> VhdxGuid {
    self.image_header.data_write_identifier
  }

  pub fn parent_locator(&self) -> Option<&VhdxParentLocator> {
    self.metadata.parent_locator.as_ref()
  }

  fn bat_entry(&self, index: usize) -> Result<u64> {
    read_bat_entry(self.source.as_ref(), &self.bat, index)
  }

  fn payload_entry(&self, block_index: u64) -> Result<u64> {
    self.bat_entry(payload_bat_index(
      self.metadata.disk_type,
      block_index,
      self.entries_per_chunk,
    )?)
  }

  fn read_payload_block(&self, block_index: u64) -> Result<Option<Arc<Vec<u8>>>> {
    let entry = self.payload_entry(block_index)?;
    match payload_block_state(entry)? {
      VhdxPayloadBlockState::FullyPresent | VhdxPayloadBlockState::PartiallyPresent => {
        let file_offset = bat_file_offset(entry)?;
        let block_size = usize::try_from(self.metadata.block_size)
          .map_err(|_| Error::invalid_range("vhdx block size is too large"))?;

        self
          .block_cache
          .get_or_load(block_index, || {
            let data = self.source.read_bytes_at(file_offset, block_size)?;
            Ok(Arc::new(data))
          })
          .map(Some)
      }
      VhdxPayloadBlockState::NotPresent
      | VhdxPayloadBlockState::Undefined
      | VhdxPayloadBlockState::Zero
      | VhdxPayloadBlockState::Unmapped => Ok(None),
    }
  }

  fn read_sector_bitmap(&self, block_index: u64) -> Result<Arc<Vec<u8>>> {
    let chunk_index = block_index / self.entries_per_chunk;
    self.sector_bitmap_cache.get_or_load(block_index, || {
      let entry = self.bat_entry(sector_bitmap_bat_index(
        chunk_index,
        self.entries_per_chunk,
      )?)?;
      if sector_bitmap_state(entry)? != VhdxSectorBitmapState::Present {
        return Err(Error::invalid_format(
          "vhdx payload block requires a present sector bitmap".to_string(),
        ));
      }
      let sector_bitmap_base = bat_file_offset(entry)?;
      let offset = sector_bitmap_base
        .checked_add(
          (block_index % self.entries_per_chunk)
            .checked_mul(self.sector_bitmap_size)
            .ok_or_else(|| Error::invalid_range("vhdx sector bitmap offset overflow"))?,
        )
        .ok_or_else(|| Error::invalid_range("vhdx sector bitmap offset overflow"))?;
      let size = usize::try_from(self.sector_bitmap_size)
        .map_err(|_| Error::invalid_range("vhdx sector bitmap size is too large"))?;
      let data = self.source.read_bytes_at(offset, size)?;
      Ok(Arc::new(data))
    })
  }

  fn sector_present(&self, bitmap: &[u8], sector_index: usize) -> Result<bool> {
    let byte = *bitmap.get(sector_index / 8).ok_or_else(|| {
      Error::invalid_format("vhdx sector bitmap does not cover the requested sector")
    })?;
    Ok((byte & (1 << (sector_index % 8))) != 0)
  }

  fn fill_from_parent_or_zero(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
    if let Some(parent_image) = &self.parent_image {
      parent_image.read_exact_at(offset, buf)?;
    } else {
      buf.fill(0);
    }
    Ok(())
  }
}

fn bounded_cache_capacity(entry_size: usize, byte_budget: usize, max_entries: usize) -> usize {
  if entry_size == 0 || max_entries == 0 {
    return 1;
  }

  (byte_budget / entry_size).max(1).min(max_entries)
}

impl ByteSource for VhdxImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.metadata.virtual_disk_size || buf.is_empty() {
      return Ok(0);
    }

    let block_size = u64::from(self.metadata.block_size);
    let sector_size = u64::from(self.metadata.logical_sector_size);
    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::invalid_range("vhdx read offset overflow"))?;
      if absolute_offset >= self.metadata.virtual_disk_size {
        break;
      }
      let block_index = absolute_offset / block_size;
      if block_index >= self.payload_block_count {
        break;
      }
      let within_block = absolute_offset % block_size;
      let block_available = usize::try_from(
        block_size
          .checked_sub(within_block)
          .ok_or_else(|| Error::invalid_range("vhdx block range underflow"))?,
      )
      .map_err(|_| Error::invalid_range("vhdx block size is too large"))?;
      let disk_available = usize::try_from(self.metadata.virtual_disk_size - absolute_offset)
        .map_err(|_| Error::invalid_range("vhdx remaining size is too large"))?;
      let entry = self.payload_entry(block_index)?;
      let state = payload_block_state(entry)?;

      let available = match state {
        VhdxPayloadBlockState::PartiallyPresent => {
          let sector_available = usize::try_from(sector_size - (within_block % sector_size))
            .map_err(|_| Error::invalid_range("vhdx sector size is too large"))?;
          block_available
            .min(buf.len() - copied)
            .min(disk_available)
            .min(sector_available)
        }
        VhdxPayloadBlockState::NotPresent
        | VhdxPayloadBlockState::Undefined
        | VhdxPayloadBlockState::Zero
        | VhdxPayloadBlockState::Unmapped
        | VhdxPayloadBlockState::FullyPresent => {
          block_available.min(buf.len() - copied).min(disk_available)
        }
      };

      match state {
        VhdxPayloadBlockState::FullyPresent => {
          let payload = self.read_payload_block(block_index)?.ok_or_else(|| {
            Error::invalid_format("vhdx fully-present block is missing payload data")
          })?;
          let block_offset = usize::try_from(within_block)
            .map_err(|_| Error::invalid_range("vhdx block offset is too large"))?;
          buf[copied..copied + available]
            .copy_from_slice(&payload[block_offset..block_offset + available]);
        }
        VhdxPayloadBlockState::PartiallyPresent => {
          let payload = self.read_payload_block(block_index)?.ok_or_else(|| {
            Error::invalid_format("vhdx partially-present block is missing payload data")
          })?;
          let bitmap = self.read_sector_bitmap(block_index)?;
          let sector_index = usize::try_from(within_block / sector_size)
            .map_err(|_| Error::invalid_range("vhdx sector index conversion overflow"))?;
          if self.sector_present(&bitmap, sector_index)? {
            let block_offset = usize::try_from(within_block)
              .map_err(|_| Error::invalid_range("vhdx block offset is too large"))?;
            buf[copied..copied + available]
              .copy_from_slice(&payload[block_offset..block_offset + available]);
          } else if self.parent_image.is_some() {
            self.fill_from_parent_or_zero(absolute_offset, &mut buf[copied..copied + available])?;
          } else {
            return Err(Error::invalid_format(
              "vhdx partially-present block requires a resolved parent image".to_string(),
            ));
          }
        }
        VhdxPayloadBlockState::Zero => {
          buf[copied..copied + available].fill(0);
        }
        VhdxPayloadBlockState::NotPresent
        | VhdxPayloadBlockState::Undefined
        | VhdxPayloadBlockState::Unmapped => {
          self.fill_from_parent_or_zero(absolute_offset, &mut buf[copied..copied + available])?;
        }
      }

      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.metadata.virtual_disk_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size(self.metadata.block_size as usize)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.vhdx"
  }
}

impl Image for VhdxImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(self.metadata.logical_sector_size)
  }

  fn physical_sector_size(&self) -> Option<u32> {
    Some(self.metadata.physical_sector_size)
  }

  fn is_sparse(&self) -> bool {
    !matches!(self.metadata.disk_type, VhdxDiskType::Fixed)
  }

  fn has_backing_chain(&self) -> bool {
    self.parent_image.is_some()
  }
}

fn resolve_parent_source(
  locator: &VhdxParentLocator, resolver: &dyn crate::RelatedSourceResolver,
  identity: &crate::SourceIdentity,
) -> Result<Option<(ByteSourceHandle, crate::RelatedPathBuf)>> {
  for candidate in locator.candidate_paths() {
    if let Some(resolution) = resolve_parent_candidate(resolver, identity, candidate)? {
      return Ok(Some(resolution));
    }
  }

  Ok(None)
}

fn resolve_parent_candidate(
  resolver: &dyn crate::RelatedSourceResolver, identity: &crate::SourceIdentity, candidate: &str,
) -> Result<Option<(ByteSourceHandle, crate::RelatedPathBuf)>> {
  if let Ok(relative) = crate::RelatedPathBuf::from_relative_path(candidate)
    && let Some(parent) = identity.logical_path().parent()
  {
    let joined = parent.join(&relative);
    if let Some(source) = resolver.resolve(&crate::RelatedSourceRequest::new(
      crate::RelatedSourcePurpose::BackingFile,
      joined.clone(),
    ))? {
      return Ok(Some((source, joined)));
    }
  }

  let file_name = candidate.rsplit(['\\', '/']).next().unwrap_or(candidate);
  let sibling = identity.sibling_path(file_name)?;
  Ok(
    resolver
      .resolve(&crate::RelatedSourceRequest::new(
        crate::RelatedSourcePurpose::BackingFile,
        sibling.clone(),
      ))?
      .map(|source| (source, sibling)),
  )
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, path::Path, sync::Arc};

  use super::*;
  use crate::{RelatedSourceRequest, RelatedSourceResolver, SourceIdentity};

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl ByteSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = usize::try_from(offset)
        .map_err(|_| Error::invalid_range("test read offset is too large"))?;
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

  struct Resolver {
    files: HashMap<String, ByteSourceHandle>,
  }

  impl RelatedSourceResolver for Resolver {
    fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<ByteSourceHandle>> {
      Ok(self.files.get(&request.path.to_string()).cloned())
    }
  }

  fn sample_source(relative_path: &str) -> ByteSourceHandle {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Arc::new(MemDataSource {
      data: std::fs::read(path).unwrap(),
    })
  }

  #[test]
  fn scales_cache_capacity_to_the_vhdx_block_budget() {
    assert_eq!(
      bounded_cache_capacity(8 * 1024 * 1024, BLOCK_CACHE_BUDGET_BYTES, 64),
      8
    );
    assert_eq!(
      bounded_cache_capacity(256 * 1024 * 1024, BLOCK_CACHE_BUDGET_BYTES, 64),
      1
    );
  }

  fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
  }

  fn overwrite_image_header_checksum(data: &mut [u8], header_offset: usize) {
    let checksum = crc32c::crc32c_append(
      crc32c::crc32c_append(0, &data[header_offset..header_offset + 4]),
      &[0; 4],
    );
    let checksum = crc32c::crc32c_append(checksum, &data[header_offset + 8..header_offset + 4096]);
    data[header_offset + 4..header_offset + 8].copy_from_slice(&checksum.to_le_bytes());
  }

  #[test]
  fn opens_fixed_vhdx_fixture_metadata() {
    let image = VhdxImage::open(sample_source("vhdx/ext2.vhdx")).unwrap();

    assert_eq!(image.disk_type(), VhdxDiskType::Dynamic);
    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(image.logical_sector_size(), Some(512));
    assert_eq!(image.physical_sector_size(), Some(512));
    assert_eq!(image.metadata().block_size, 8_388_608);
    assert_eq!(
      image.data_write_identifier().to_string(),
      "ee10a932-6284-f448-aaab-ab839f90ddef"
    );
  }

  #[test]
  fn reads_full_fixed_ext2_vhdx_fixture() {
    let image = VhdxImage::open(sample_source("vhdx/ext2.vhdx")).unwrap();
    let raw = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("ext/ext2.raw"),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), raw);
  }

  #[test]
  fn reads_full_fixed_ntfs_parent_vhdx_fixture() {
    let image = VhdxImage::open(sample_source("vhdx/ntfs-parent.vhdx")).unwrap();

    assert_eq!(image.disk_type(), VhdxDiskType::Fixed);
    assert_eq!(image.logical_sector_size(), Some(512));
    assert_eq!(image.physical_sector_size(), Some(4096));
    assert_eq!(
      md5_hex(&image.read_all().unwrap()),
      "75537374a81c40e51e6a4b812b36ce89"
    );
  }

  #[test]
  fn reads_full_dynamic_ntfs_vhdx_fixture() {
    let image = VhdxImage::open(sample_source("vhdx/ntfs-dynamic.vhdx")).unwrap();

    assert_eq!(image.disk_type(), VhdxDiskType::Dynamic);
    assert!(image.is_sparse());
    assert_eq!(
      md5_hex(&image.read_all().unwrap()),
      "20158534070142d63ee02c9ad1a9d87e"
    );
  }

  #[test]
  fn reads_differential_vhdx_via_parent_resolution() {
    let child = sample_source("vhdx/ntfs-differential.vhdx");
    let parent = sample_source("vhdx/ntfs-parent.vhdx");
    let resolver = Resolver {
      files: HashMap::from([("vhdx/ntfs-parent.vhdx".to_string(), parent)]),
    };
    let identity = SourceIdentity::from_relative_path("vhdx/ntfs-differential.vhdx").unwrap();

    let image = VhdxImage::open_with_hints(
      child,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.disk_type(), VhdxDiskType::Differential);
    assert!(image.has_backing_chain());
    assert_eq!(
      image.parent_locator().unwrap().entry("relative_path"),
      Some(".\\ntfs-parent.vhdx")
    );
    assert_eq!(
      md5_hex(&image.read_all().unwrap()),
      "a25df0058eecd8aa1975a68eeaa0e178"
    );
  }

  #[test]
  fn differential_vhdx_requires_parent_hints() {
    let result = VhdxImage::open(sample_source("vhdx/ntfs-differential.vhdx"));

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }

  #[test]
  fn differential_vhdx_rejects_parent_identifier_mismatches() {
    let child = sample_source("vhdx/ntfs-differential.vhdx");
    let wrong_parent = sample_source("vhdx/ntfs-dynamic.vhdx");
    let resolver = Resolver {
      files: HashMap::from([("vhdx/ntfs-parent.vhdx".to_string(), wrong_parent)]),
    };
    let identity = SourceIdentity::from_relative_path("vhdx/ntfs-differential.vhdx").unwrap();

    let result = VhdxImage::open_with_hints(
      child,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    );

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_corrupted_image_header_checksums() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("vhdx/ext2.vhdx"),
    )
    .unwrap();
    data[0x10000 + 8] ^= 0x01;
    data[0x20000 + 8] ^= 0x01;

    let result = VhdxImage::open(Arc::new(MemDataSource { data }));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_active_logs_when_the_log_identifier_is_set() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("vhdx/ext2.vhdx"),
    )
    .unwrap();
    data[0x20000 + 48] = 0x01;
    overwrite_image_header_checksum(&mut data, 0x20000);

    let result = VhdxImage::open(Arc::new(MemDataSource { data }));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}

crate::images::driver::impl_image_data_source!(VhdxImage);
