//! Read-only monolithic sparse VMDK image surface.

use std::sync::Arc;

use super::{
  DESCRIPTOR,
  cache::VmdkCache,
  constants,
  descriptor::{VmdkDescriptor, VmdkExtentAccessMode, VmdkExtentType, VmdkFileType},
  header::VmdkSparseHeader,
  parser::{ParsedVmdk, grain_table_entry_count, parse},
};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

pub struct VmdkImage {
  source: DataSourceHandle,
  header: VmdkSparseHeader,
  descriptor: VmdkDescriptor,
  grain_directory: Arc<[u32]>,
  grain_table_cache: VmdkCache<Vec<u32>>,
}

impl VmdkImage {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    if is_sparse_extent(source.as_ref())? {
      let parsed = parse(source.clone())?;
      return Self::from_parsed(source, parsed);
    }

    let descriptor = VmdkDescriptor::from_bytes(&source.read_all()?)?;
    if descriptor.file_type != VmdkFileType::MonolithicSparse {
      return Err(Error::InvalidFormat(format!(
        "unsupported vmdk descriptor create type in the current step: {:?}",
        descriptor.file_type
      )));
    }
    if descriptor.parent_content_id.is_some() || descriptor.parent_file_name_hint.is_some() {
      return Err(Error::InvalidSourceReference(
        "parent-backed vmdk descriptor layers are not supported yet".to_string(),
      ));
    }
    if descriptor.extents.len() != 1 {
      return Err(Error::InvalidFormat(
        "monolithic sparse vmdk descriptors must declare exactly one extent".to_string(),
      ));
    }

    let extent = &descriptor.extents[0];
    if extent.extent_type != VmdkExtentType::Sparse
      || !matches!(
        extent.access_mode,
        VmdkExtentAccessMode::ReadOnly | VmdkExtentAccessMode::ReadWrite
      )
    {
      return Err(Error::InvalidFormat(
        "monolithic sparse vmdk descriptors must point to one sparse extent".to_string(),
      ));
    }

    let resolver = hints.resolver().ok_or_else(|| {
      Error::InvalidSourceReference(
        "descriptor-backed vmdk images require a related-source resolver".to_string(),
      )
    })?;
    let identity = hints.source_identity().ok_or_else(|| {
      Error::InvalidSourceReference(
        "descriptor-backed vmdk images require a source identity hint".to_string(),
      )
    })?;
    let extent_name = extent.file_name.as_deref().ok_or_else(|| {
      Error::InvalidFormat("vmdk sparse descriptor extent is missing a file name".to_string())
    })?;
    let (extent_source, extent_path) = resolve_extent_source(resolver, identity, extent_name)?
      .ok_or_else(|| Error::NotFound("unable to resolve the vmdk sparse extent".to_string()))?;
    if &extent_path == identity.logical_path() {
      return Err(Error::InvalidFormat(
        "vmdk descriptor extent resolves back to the descriptor file".to_string(),
      ));
    }

    let extent_identity = crate::SourceIdentity::new(extent_path);
    let image = Self::open_with_hints(
      extent_source,
      SourceHints::new()
        .with_resolver(resolver)
        .with_source_identity(&extent_identity),
    )?;
    if image.descriptor_data().content_id != descriptor.content_id {
      return Err(Error::InvalidFormat(
        "vmdk descriptor cid does not match the resolved sparse extent".to_string(),
      ));
    }

    Ok(image)
  }

  fn from_parsed(source: DataSourceHandle, parsed: ParsedVmdk) -> Result<Self> {
    Ok(Self {
      source,
      header: parsed.header,
      descriptor: parsed.descriptor,
      grain_directory: parsed.grain_directory,
      grain_table_cache: VmdkCache::new(64),
    })
  }

  pub fn header(&self) -> &VmdkSparseHeader {
    &self.header
  }

  pub fn descriptor_data(&self) -> &VmdkDescriptor {
    &self.descriptor
  }

  fn read_grain_table(&self, directory_index: u64) -> Result<Option<Arc<Vec<u32>>>> {
    let raw_sector =
      *self
        .grain_directory
        .get(usize::try_from(directory_index).map_err(|_| {
          Error::InvalidRange("vmdk grain-directory index is too large".to_string())
        })?)
        .ok_or_else(|| {
          Error::InvalidFormat(format!(
            "vmdk grain-directory entry {directory_index} is out of bounds"
          ))
        })?;

    if raw_sector == 0 || (self.header.uses_zero_grain_entries() && raw_sector == 1) {
      return Ok(None);
    }

    self
      .grain_table_cache
      .get_or_load(directory_index, || {
        let offset = u64::from(raw_sector)
          .checked_mul(constants::BYTES_PER_SECTOR)
          .ok_or_else(|| Error::InvalidRange("vmdk grain-table offset overflow".to_string()))?;
        let byte_count = grain_table_entry_count(self.header)
          .checked_mul(4)
          .ok_or_else(|| Error::InvalidRange("vmdk grain-table size overflow".to_string()))?;
        let raw = self.source.read_bytes_at(
          offset,
          usize::try_from(byte_count)
            .map_err(|_| Error::InvalidRange("vmdk grain-table size is too large".to_string()))?,
        )?;
        let entries = raw
          .chunks_exact(4)
          .map(|chunk| Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
          .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(entries))
      })
      .map(Some)
  }

  fn is_zero_grain(&self, grain_sector: u32) -> bool {
    grain_sector == 0 || (self.header.uses_zero_grain_entries() && grain_sector == 1)
  }
}

impl DataSource for VmdkImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let size = self.size()?;
    if offset >= size || buf.is_empty() {
      return Ok(0);
    }

    let grain_size = self.header.grain_size_bytes()?;
    let table_entries = grain_table_entry_count(self.header);
    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("vmdk read offset overflow".to_string()))?;
      if absolute_offset >= size {
        break;
      }

      let grain_index = absolute_offset / grain_size;
      let within_grain = absolute_offset % grain_size;
      let directory_index = grain_index / table_entries;
      let table_index = usize::try_from(grain_index % table_entries)
        .map_err(|_| Error::InvalidRange("vmdk grain-table index is too large".to_string()))?;
      let available = usize::try_from(
        (grain_size - within_grain)
          .min(size - absolute_offset)
          .min((buf.len() - copied) as u64),
      )
      .map_err(|_| Error::InvalidRange("vmdk read chunk is too large".to_string()))?;

      match self.read_grain_table(directory_index)? {
        None => {
          buf[copied..copied + available].fill(0);
        }
        Some(table) => {
          let grain_sector = *table.get(table_index).ok_or_else(|| {
            Error::InvalidFormat("vmdk grain table does not cover the requested grain".to_string())
          })?;
          if self.is_zero_grain(grain_sector) {
            buf[copied..copied + available].fill(0);
          } else {
            let data_offset = u64::from(grain_sector)
              .checked_mul(constants::BYTES_PER_SECTOR)
              .and_then(|value| value.checked_add(within_grain))
              .ok_or_else(|| Error::InvalidRange("vmdk grain data offset overflow".to_string()))?;
            self
              .source
              .read_exact_at(data_offset, &mut buf[copied..copied + available])?;
          }
        }
      }

      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    self.header.virtual_size_bytes()
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    let preferred_chunk_size =
      usize::try_from(self.header.grain_size_bytes().unwrap_or(64 * 1024)).unwrap_or(64 * 1024);
    DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap)
      .with_preferred_chunk_size(preferred_chunk_size)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.vmdk"
  }
}

impl Image for VmdkImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(constants::BYTES_PER_SECTOR as u32)
  }

  fn physical_sector_size(&self) -> Option<u32> {
    self.logical_sector_size()
  }

  fn is_sparse(&self) -> bool {
    self.descriptor.file_type == VmdkFileType::MonolithicSparse
  }
}

fn is_sparse_extent(source: &dyn DataSource) -> Result<bool> {
  let mut magic = [0u8; 4];
  Ok(source.read_at(0, &mut magic)? == magic.len() && &magic == constants::SPARSE_HEADER_MAGIC)
}

fn resolve_extent_source(
  resolver: &dyn crate::RelatedSourceResolver, identity: &crate::SourceIdentity, extent_name: &str,
) -> Result<Option<(DataSourceHandle, crate::RelatedPathBuf)>> {
  if let Ok(relative) = crate::RelatedPathBuf::from_relative_path(extent_name)
    && let Some(parent) = identity.logical_path().parent()
  {
    let joined = parent.join(&relative);
    if let Some(source) = resolver.resolve(&crate::RelatedSourceRequest::new(
      crate::RelatedSourcePurpose::Extent,
      joined.clone(),
    ))? {
      return Ok(Some((source, joined)));
    }
  }

  let file_name = extent_name
    .rsplit(['\\', '/'])
    .next()
    .unwrap_or(extent_name);
  let sibling = identity.sibling_path(file_name)?;
  Ok(
    resolver
      .resolve(&crate::RelatedSourceRequest::new(
        crate::RelatedSourcePurpose::Extent,
        sibling.clone(),
      ))?
      .map(|source| (source, sibling)),
  )
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, path::Path};

  use super::*;
  use crate::{
    RelatedSourceRequest, RelatedSourceResolver, SourceIdentity,
    images::vmdk::parser::grain_directory_entry_count,
  };

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
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

  struct Resolver {
    files: HashMap<String, DataSourceHandle>,
  }

  impl RelatedSourceResolver for Resolver {
    fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<DataSourceHandle>> {
      Ok(self.files.get(&request.path.to_string()).cloned())
    }
  }

  fn sample_source(relative_path: &str) -> DataSourceHandle {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Arc::new(MemDataSource {
      data: std::fs::read(path).unwrap(),
    })
  }

  #[test]
  fn opens_monolithic_sparse_fixture_metadata() {
    let image = VmdkImage::open(sample_source("vmdk/ext2.vmdk")).unwrap();

    assert_eq!(image.header().format_version, 1);
    assert_eq!(image.header().sectors_per_grain, 128);
    assert_eq!(
      image.descriptor_data().file_type,
      VmdkFileType::MonolithicSparse
    );
    assert_eq!(image.descriptor_data().content_id, 0x4C06_9322);
    assert_eq!(image.descriptor_data().parent_content_id, None);
    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(grain_directory_entry_count(*image.header()).unwrap(), 1);
  }

  #[test]
  fn reads_full_ext2_sparse_vmdk_fixture() {
    let image = VmdkImage::open(sample_source("vmdk/ext2.vmdk")).unwrap();
    let raw = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("ext/ext2.raw"),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), raw);
  }

  #[test]
  fn opens_descriptor_backed_sparse_fixture_via_resolver() {
    let descriptor = sample_source("vmdk/ext2-descriptor.vmdk");
    let extent = sample_source("vmdk/ext2.vmdk");
    let resolver = Resolver {
      files: HashMap::from([("vmdk/ext2.vmdk".to_string(), extent)]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/ext2-descriptor.vmdk").unwrap();
    let raw = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("ext/ext2.raw"),
    )
    .unwrap();

    let image = VmdkImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), raw);
  }

  #[test]
  fn descriptor_backed_sparse_images_require_resolution_hints() {
    let descriptor = sample_source("vmdk/ext2-descriptor.vmdk");

    let result = VmdkImage::open(descriptor);

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }

  #[test]
  fn rejects_parent_backed_descriptors_in_current_step() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("vmdk/ext2.vmdk"),
    )
    .unwrap();
    let descriptor = &mut data[512..512 + 20 * 512];
    let parent = b"parentCID=ffffffff";
    let replacement = b"parentCID=12345678";
    let offset = descriptor
      .windows(parent.len())
      .position(|window| window == parent)
      .unwrap();
    descriptor[offset..offset + replacement.len()].copy_from_slice(replacement);

    let result = VmdkImage::open(Arc::new(MemDataSource { data }));

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }

  #[test]
  fn rejects_compressed_sparse_flags_in_current_step() {
    let mut data = std::fs::read(
      Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("formats")
        .join("vmdk/ext2.vmdk"),
    )
    .unwrap();
    let flags = constants::FLAG_VALID_NEWLINE_TEST | constants::FLAG_HAS_COMPRESSED_GRAINS;
    data[8..12].copy_from_slice(&flags.to_le_bytes());

    let result = VmdkImage::open(Arc::new(MemDataSource { data }));

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
