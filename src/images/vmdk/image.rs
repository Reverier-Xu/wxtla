//! Read-only VMDK image surface.

use std::sync::Arc;

use super::{
  DESCRIPTOR,
  cache::VmdkCache,
  constants,
  descriptor::{
    VmdkDescriptor, VmdkDescriptorExtent, VmdkExtentAccessMode, VmdkExtentType, VmdkFileType,
  },
  header::VmdkSparseHeader,
  parser::{ParsedVmdk, grain_table_entry_count, parse},
};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceSeekCost, Error, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, RelatedSourceResolver, Result, SliceDataSource,
  SourceHints, SourceIdentity, images::Image,
};

pub struct VmdkImage {
  descriptor: VmdkDescriptor,
  size: u64,
  is_sparse: bool,
  backend: VmdkBackend,
}

enum VmdkBackend {
  Sparse(VmdkSparseBackend),
  Descriptor(VmdkDescriptorBackend),
}

struct VmdkSparseBackend {
  source: DataSourceHandle,
  header: VmdkSparseHeader,
  grain_directory: Arc<[u32]>,
  grain_table_cache: VmdkCache<Vec<u32>>,
}

struct VmdkDescriptorBackend {
  extents: Vec<VmdkResolvedExtent>,
}

struct VmdkResolvedExtent {
  guest_offset: u64,
  size: u64,
  kind: VmdkResolvedExtentKind,
}

enum VmdkResolvedExtentKind {
  Source(DataSourceHandle),
  Zero,
}

impl VmdkImage {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    if is_sparse_extent(source.as_ref())? {
      let parsed = parse(source.clone())?;
      return Self::from_sparse_parsed(source, parsed);
    }

    let descriptor = VmdkDescriptor::from_bytes(&source.read_all()?)?;
    Self::from_descriptor(descriptor, hints)
  }

  fn from_sparse_parsed(source: DataSourceHandle, parsed: ParsedVmdk) -> Result<Self> {
    Ok(Self {
      size: parsed.header.virtual_size_bytes()?,
      is_sparse: true,
      descriptor: parsed.descriptor,
      backend: VmdkBackend::Sparse(VmdkSparseBackend {
        source,
        header: parsed.header,
        grain_directory: parsed.grain_directory,
        grain_table_cache: VmdkCache::new(64),
      }),
    })
  }

  fn from_descriptor(descriptor: VmdkDescriptor, hints: SourceHints<'_>) -> Result<Self> {
    validate_descriptor_file_type(descriptor.file_type)?;
    if descriptor.parent_content_id.is_some() || descriptor.parent_file_name_hint.is_some() {
      return Err(Error::InvalidSourceReference(
        "parent-backed vmdk descriptor layers are not supported yet".to_string(),
      ));
    }
    if descriptor.extents.is_empty() {
      return Err(Error::InvalidFormat(
        "vmdk descriptor must declare at least one extent".to_string(),
      ));
    }

    let resolver = hints.resolver();
    let identity = hints.source_identity();
    let mut extents = Vec::with_capacity(descriptor.extents.len());
    let mut guest_offset = 0u64;
    let mut image_is_sparse = false;

    for extent in &descriptor.extents {
      if matches!(
        extent.access_mode,
        VmdkExtentAccessMode::Unknown | VmdkExtentAccessMode::NoAccess
      ) {
        return Err(Error::InvalidFormat(
          "unsupported vmdk extent access mode".to_string(),
        ));
      }
      let extent_size = extent
        .sector_count
        .checked_mul(constants::BYTES_PER_SECTOR)
        .ok_or_else(|| Error::InvalidRange("vmdk extent size overflow".to_string()))?;
      let kind = match extent.extent_type {
        VmdkExtentType::Zero => {
          image_is_sparse = true;
          VmdkResolvedExtentKind::Zero
        }
        VmdkExtentType::Flat | VmdkExtentType::Vmfs => {
          let resolver = resolver.ok_or_else(|| {
            Error::InvalidSourceReference(
              "descriptor-backed vmdk images require a related-source resolver".to_string(),
            )
          })?;
          let identity = identity.ok_or_else(|| {
            Error::InvalidSourceReference(
              "descriptor-backed vmdk images require a source identity hint".to_string(),
            )
          })?;
          resolve_flat_extent(extent, resolver, identity, extent_size)?
        }
        VmdkExtentType::Sparse => {
          let resolver = resolver.ok_or_else(|| {
            Error::InvalidSourceReference(
              "descriptor-backed vmdk images require a related-source resolver".to_string(),
            )
          })?;
          let identity = identity.ok_or_else(|| {
            Error::InvalidSourceReference(
              "descriptor-backed vmdk images require a source identity hint".to_string(),
            )
          })?;
          image_is_sparse = true;
          resolve_sparse_extent(extent, resolver, identity)?
        }
        VmdkExtentType::Unknown => {
          return Err(Error::InvalidFormat(
            "unsupported vmdk descriptor extent type".to_string(),
          ));
        }
        VmdkExtentType::VmfsSparse => {
          return Err(Error::InvalidFormat(
            "vmfs sparse cowd extents are not supported yet".to_string(),
          ));
        }
      };
      extents.push(VmdkResolvedExtent {
        guest_offset,
        size: extent_size,
        kind,
      });
      guest_offset = guest_offset
        .checked_add(extent_size)
        .ok_or_else(|| Error::InvalidRange("vmdk image size overflow".to_string()))?;
    }

    Ok(Self {
      descriptor,
      size: guest_offset,
      is_sparse: image_is_sparse,
      backend: VmdkBackend::Descriptor(VmdkDescriptorBackend { extents }),
    })
  }

  pub fn header(&self) -> Option<&VmdkSparseHeader> {
    match &self.backend {
      VmdkBackend::Sparse(backend) => Some(&backend.header),
      VmdkBackend::Descriptor(_) => None,
    }
  }

  pub fn descriptor_data(&self) -> &VmdkDescriptor {
    &self.descriptor
  }

  fn read_sparse_grain_table(
    backend: &VmdkSparseBackend, directory_index: u64,
  ) -> Result<Option<Arc<Vec<u32>>>> {
    let raw_sector =
      *backend
        .grain_directory
        .get(usize::try_from(directory_index).map_err(|_| {
          Error::InvalidRange("vmdk grain-directory index is too large".to_string())
        })?)
        .ok_or_else(|| {
          Error::InvalidFormat(format!(
            "vmdk grain-directory entry {directory_index} is out of bounds"
          ))
        })?;

    if raw_sector == 0 || (backend.header.uses_zero_grain_entries() && raw_sector == 1) {
      return Ok(None);
    }

    backend
      .grain_table_cache
      .get_or_load(directory_index, || {
        let offset = u64::from(raw_sector)
          .checked_mul(constants::BYTES_PER_SECTOR)
          .ok_or_else(|| Error::InvalidRange("vmdk grain-table offset overflow".to_string()))?;
        let byte_count = grain_table_entry_count(backend.header)
          .checked_mul(4)
          .ok_or_else(|| Error::InvalidRange("vmdk grain-table size overflow".to_string()))?;
        let raw = backend.source.read_bytes_at(
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

  fn read_sparse_at(
    backend: &VmdkSparseBackend, offset: u64, size: u64, buf: &mut [u8],
  ) -> Result<usize> {
    if offset >= size || buf.is_empty() {
      return Ok(0);
    }

    let grain_size = backend.header.grain_size_bytes()?;
    let table_entries = grain_table_entry_count(backend.header);
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

      match Self::read_sparse_grain_table(backend, directory_index)? {
        None => {
          buf[copied..copied + available].fill(0);
        }
        Some(table) => {
          let grain_sector = *table.get(table_index).ok_or_else(|| {
            Error::InvalidFormat("vmdk grain table does not cover the requested grain".to_string())
          })?;
          if grain_sector == 0 || (backend.header.uses_zero_grain_entries() && grain_sector == 1) {
            buf[copied..copied + available].fill(0);
          } else {
            let data_offset = u64::from(grain_sector)
              .checked_mul(constants::BYTES_PER_SECTOR)
              .and_then(|value| value.checked_add(within_grain))
              .ok_or_else(|| Error::InvalidRange("vmdk grain data offset overflow".to_string()))?;
            backend
              .source
              .read_exact_at(data_offset, &mut buf[copied..copied + available])?;
          }
        }
      }

      copied += available;
    }

    Ok(copied)
  }

  fn read_descriptor_at(
    backend: &VmdkDescriptorBackend, offset: u64, size: u64, buf: &mut [u8],
  ) -> Result<usize> {
    if offset >= size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("vmdk read offset overflow".to_string()))?;
      if absolute_offset >= size {
        break;
      }

      let extent = backend
        .extents
        .iter()
        .find(|extent| {
          absolute_offset >= extent.guest_offset
            && absolute_offset < extent.guest_offset.saturating_add(extent.size)
        })
        .ok_or_else(|| {
          Error::InvalidFormat("vmdk extent map does not cover the requested offset".to_string())
        })?;
      let within_extent = absolute_offset - extent.guest_offset;
      let available = usize::try_from(
        (extent.size - within_extent)
          .min(size - absolute_offset)
          .min((buf.len() - copied) as u64),
      )
      .map_err(|_| Error::InvalidRange("vmdk read chunk is too large".to_string()))?;

      match &extent.kind {
        VmdkResolvedExtentKind::Source(source) => {
          source.read_exact_at(within_extent, &mut buf[copied..copied + available])?;
        }
        VmdkResolvedExtentKind::Zero => {
          buf[copied..copied + available].fill(0);
        }
      }

      copied += available;
    }

    Ok(copied)
  }
}

impl DataSource for VmdkImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    match &self.backend {
      VmdkBackend::Sparse(backend) => Self::read_sparse_at(backend, offset, self.size, buf),
      VmdkBackend::Descriptor(backend) => Self::read_descriptor_at(backend, offset, self.size, buf),
    }
  }

  fn size(&self) -> Result<u64> {
    Ok(self.size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    let preferred_chunk_size = match &self.backend {
      VmdkBackend::Sparse(backend) => {
        usize::try_from(backend.header.grain_size_bytes().unwrap_or(64 * 1024)).unwrap_or(64 * 1024)
      }
      VmdkBackend::Descriptor(_) => 64 * 1024,
    };
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
    self.is_sparse
  }
}

fn is_sparse_extent(source: &dyn DataSource) -> Result<bool> {
  let mut magic = [0u8; 4];
  Ok(source.read_at(0, &mut magic)? == magic.len() && &magic == constants::SPARSE_HEADER_MAGIC)
}

fn validate_descriptor_file_type(file_type: VmdkFileType) -> Result<()> {
  match file_type {
    VmdkFileType::Unknown => Err(Error::InvalidFormat(
      "unsupported vmdk descriptor create type".to_string(),
    )),
    VmdkFileType::VmfsSparse | VmdkFileType::VmfsThin => Err(Error::InvalidFormat(
      "vmfs sparse vmdk descriptors are not supported yet".to_string(),
    )),
    VmdkFileType::MonolithicSparse
    | VmdkFileType::MonolithicFlat
    | VmdkFileType::StreamOptimized
    | VmdkFileType::Flat2GbExtent
    | VmdkFileType::Sparse2GbExtent
    | VmdkFileType::Vmfs => Ok(()),
  }
}

fn resolve_flat_extent(
  extent: &VmdkDescriptorExtent, resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity,
  extent_size: u64,
) -> Result<VmdkResolvedExtentKind> {
  let file_name = extent
    .file_name
    .as_deref()
    .ok_or_else(|| Error::InvalidFormat("vmdk flat extent is missing a file name".to_string()))?;
  let (source, path) = resolve_extent_source(resolver, identity, file_name)?
    .ok_or_else(|| Error::NotFound("unable to resolve the vmdk extent file".to_string()))?;
  if &path == identity.logical_path() {
    return Err(Error::InvalidFormat(
      "vmdk descriptor extent resolves back to the descriptor file".to_string(),
    ));
  }

  let base_offset = extent
    .start_sector
    .checked_mul(constants::BYTES_PER_SECTOR)
    .ok_or_else(|| Error::InvalidRange("vmdk flat extent offset overflow".to_string()))?;
  let extent_end = base_offset
    .checked_add(extent_size)
    .ok_or_else(|| Error::InvalidRange("vmdk flat extent range overflow".to_string()))?;
  if extent_end > source.size()? {
    return Err(Error::InvalidFormat(
      "vmdk flat extent exceeds the backing file size".to_string(),
    ));
  }

  Ok(VmdkResolvedExtentKind::Source(
    Arc::new(SliceDataSource::new(source, base_offset, extent_size)) as DataSourceHandle,
  ))
}

fn resolve_sparse_extent(
  extent: &VmdkDescriptorExtent, resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity,
) -> Result<VmdkResolvedExtentKind> {
  if extent.start_sector != 0 {
    return Err(Error::InvalidFormat(
      "vmdk sparse extents must start at sector 0".to_string(),
    ));
  }

  let file_name = extent
    .file_name
    .as_deref()
    .ok_or_else(|| Error::InvalidFormat("vmdk sparse extent is missing a file name".to_string()))?;
  let (source, path) = resolve_extent_source(resolver, identity, file_name)?
    .ok_or_else(|| Error::NotFound("unable to resolve the vmdk sparse extent".to_string()))?;
  if &path == identity.logical_path() {
    return Err(Error::InvalidFormat(
      "vmdk descriptor extent resolves back to the descriptor file".to_string(),
    ));
  }

  let extent_identity = SourceIdentity::new(path);
  let image = VmdkImage::open_with_hints(
    source,
    SourceHints::new()
      .with_resolver(resolver)
      .with_source_identity(&extent_identity),
  )?;
  Ok(VmdkResolvedExtentKind::Source(
    Arc::new(image) as DataSourceHandle
  ))
}

fn resolve_extent_source(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, extent_name: &str,
) -> Result<Option<(DataSourceHandle, RelatedPathBuf)>> {
  if let Ok(relative) = RelatedPathBuf::from_relative_path(extent_name)
    && let Some(parent) = identity.logical_path().parent()
  {
    let joined = parent.join(&relative);
    if let Some(source) = resolver.resolve(&RelatedSourceRequest::new(
      RelatedSourcePurpose::Extent,
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
      .resolve(&RelatedSourceRequest::new(
        RelatedSourcePurpose::Extent,
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
    RelatedSourceRequest, SourceIdentity, images::vmdk::parser::grain_directory_entry_count,
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
    let header = image.header().unwrap();

    assert_eq!(header.format_version, 1);
    assert_eq!(header.sectors_per_grain, 128);
    assert_eq!(
      image.descriptor_data().file_type,
      VmdkFileType::MonolithicSparse
    );
    assert_eq!(image.descriptor_data().content_id, 0x4C06_9322);
    assert_eq!(image.descriptor_data().parent_content_id, None);
    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(grain_directory_entry_count(*header).unwrap(), 1);
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
  fn opens_descriptor_backed_flat_fixture_via_resolver() {
    let descriptor = sample_source("vmdk/ext2-flat-descriptor.vmdk");
    let extent = sample_source("ext/ext2.raw");
    let resolver = Resolver {
      files: HashMap::from([("vmdk/../ext/ext2.raw".to_string(), extent)]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/ext2-flat-descriptor.vmdk").unwrap();
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
    assert!(!image.is_sparse());
    assert!(image.header().is_none());
    assert_eq!(
      image.descriptor_data().file_type,
      VmdkFileType::MonolithicFlat
    );
  }

  #[test]
  fn reads_multi_extent_descriptor_with_zero_gap() {
    let descriptor = Arc::new(MemDataSource {
      data: br#"# Disk DescriptorFile
version=1
CID=89abcdef
parentCID=ffffffff
createType="twoGbMaxExtentFlat"
RW 1 FLAT "part1.bin" 0
RW 1 ZERO
RW 1 FLAT "part2.bin" 0
"#
      .to_vec(),
    }) as DataSourceHandle;
    let part1 = Arc::new(MemDataSource {
      data: vec![b'A'; 512],
    }) as DataSourceHandle;
    let part2 = Arc::new(MemDataSource {
      data: vec![b'B'; 512],
    }) as DataSourceHandle;
    let resolver = Resolver {
      files: HashMap::from([
        ("vmdk/part1.bin".to_string(), part1),
        ("vmdk/part2.bin".to_string(), part2),
      ]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/multi-flat.vmdk").unwrap();

    let image = VmdkImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let mut expected = vec![b'A'; 512];
    expected.extend_from_slice(&vec![0; 512]);
    expected.extend_from_slice(&vec![b'B'; 512]);

    assert_eq!(image.read_all().unwrap(), expected);
    assert!(image.is_sparse());
  }

  #[test]
  fn descriptor_backed_sparse_images_require_resolution_hints() {
    let descriptor = sample_source("vmdk/ext2-descriptor.vmdk");

    let result = VmdkImage::open(descriptor);

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }

  #[test]
  fn flat_descriptor_images_require_resolution_hints() {
    let descriptor = sample_source("vmdk/ext2-flat-descriptor.vmdk");

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
