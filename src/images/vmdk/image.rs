//! Read-only VMDK image surface.

use std::{io::Read, sync::Arc};

use super::{
  DESCRIPTOR,
  cache::VmdkCache,
  constants,
  cowd_header::VmdkCowdHeader,
  descriptor::{
    VmdkDescriptor, VmdkDescriptorExtent, VmdkExtentAccessMode, VmdkExtentType, VmdkFileType,
  },
  header::VmdkSparseHeader,
  parser::{
    ParsedCowdVmdk, cowd_grain_table_entry_count, grain_table_entry_count, parse_cowd,
    parse_sparse_extent,
  },
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
  has_backing_chain: bool,
  backend: VmdkBackend,
}

enum VmdkBackend {
  Sparse(VmdkSparseBackend),
  Cowd(VmdkCowdBackend),
  Descriptor(VmdkDescriptorBackend),
}

struct VmdkSparseBackend {
  source: DataSourceHandle,
  header: VmdkSparseHeader,
  grain_directory: Arc<[u32]>,
  grain_table_cache: VmdkCache<Vec<u32>>,
  grain_cache: VmdkCache<Vec<u8>>,
  parent_source: Option<DataSourceHandle>,
}

struct VmdkDescriptorBackend {
  extents: Vec<VmdkResolvedExtent>,
}

struct VmdkCowdBackend {
  source: DataSourceHandle,
  header: VmdkCowdHeader,
  grain_directory: Arc<[u32]>,
  grain_table_cache: VmdkCache<Vec<u32>>,
  parent_source: Option<DataSourceHandle>,
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
      let parsed = parse_sparse_extent(source.clone())?;
      let descriptor = parsed.embedded_descriptor.clone().ok_or_else(|| {
        Error::InvalidFormat(
          "descriptor-less vmdk sparse extents require an external descriptor".to_string(),
        )
      })?;
      validate_monolithic_sparse_descriptor(&parsed.header, &descriptor)?;
      let parent_source = resolve_descriptor_parent_source(&descriptor, hints)?;
      return Self::from_sparse_parts(
        source,
        parsed.header,
        parsed.grain_directory,
        descriptor,
        parent_source,
      );
    }
    if is_cowd_extent(source.as_ref())? {
      let parsed = parse_cowd(source.clone())?;
      let parent_source = resolve_cowd_parent_source(&parsed.header, hints)?;
      return Self::from_cowd_parsed(source, parsed, parent_source);
    }

    let descriptor = VmdkDescriptor::from_bytes(&source.read_all()?)?;
    Self::from_descriptor(descriptor, hints)
  }

  fn from_sparse_parts(
    source: DataSourceHandle, header: VmdkSparseHeader, grain_directory: Arc<[u32]>,
    descriptor: VmdkDescriptor, parent_source: Option<DataSourceHandle>,
  ) -> Result<Self> {
    let has_backing_chain = parent_source.is_some();

    Ok(Self {
      size: header.virtual_size_bytes()?,
      is_sparse: true,
      has_backing_chain,
      descriptor,
      backend: VmdkBackend::Sparse(VmdkSparseBackend {
        source,
        header,
        grain_directory,
        grain_table_cache: VmdkCache::new(64),
        grain_cache: VmdkCache::new(64),
        parent_source,
      }),
    })
  }

  fn from_cowd_parsed(
    source: DataSourceHandle, parsed: ParsedCowdVmdk, parent_source: Option<DataSourceHandle>,
  ) -> Result<Self> {
    let size = parsed.header.virtual_size_bytes()?;
    let descriptor = VmdkDescriptor {
      version: 1,
      content_id: parsed.header.generation,
      parent_content_id: None,
      file_type: VmdkFileType::VmfsSparse,
      extents: vec![VmdkDescriptorExtent {
        access_mode: VmdkExtentAccessMode::ReadWrite,
        sector_count: u64::from(parsed.header.capacity_sectors),
        extent_type: VmdkExtentType::VmfsSparse,
        file_name: None,
        start_sector: 0,
      }],
      parent_file_name_hint: None,
    };
    let has_backing_chain = parent_source.is_some();

    Ok(Self {
      descriptor,
      size,
      is_sparse: true,
      has_backing_chain,
      backend: VmdkBackend::Cowd(VmdkCowdBackend {
        source,
        header: parsed.header,
        grain_directory: parsed.grain_directory,
        grain_table_cache: VmdkCache::new(64),
        parent_source,
      }),
    })
  }

  fn from_descriptor(descriptor: VmdkDescriptor, hints: SourceHints<'_>) -> Result<Self> {
    validate_descriptor_file_type(descriptor.file_type)?;
    if descriptor.extents.is_empty() {
      return Err(Error::InvalidFormat(
        "vmdk descriptor must declare at least one extent".to_string(),
      ));
    }

    let resolver = hints.resolver();
    let identity = hints.source_identity();
    let parent_source = resolve_descriptor_parent_source(&descriptor, hints)?;
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
      let extent_parent_source = parent_source.as_ref().map(|parent| {
        Arc::new(SliceDataSource::new(
          parent.clone(),
          guest_offset,
          extent_size,
        )) as DataSourceHandle
      });
      let kind = match extent.extent_type {
        VmdkExtentType::Zero => {
          image_is_sparse = true;
          VmdkResolvedExtentKind::Zero
        }
        VmdkExtentType::Flat
        | VmdkExtentType::Vmfs
        | VmdkExtentType::VmfsRaw
        | VmdkExtentType::VmfsRdm => {
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
          resolve_sparse_extent(extent, resolver, identity, extent_parent_source)?
        }
        VmdkExtentType::Unknown => {
          return Err(Error::InvalidFormat(
            "unsupported vmdk descriptor extent type".to_string(),
          ));
        }
        VmdkExtentType::VmfsSparse => {
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
          resolve_vmfs_sparse_extent(extent, resolver, identity, extent_parent_source)?
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
      has_backing_chain: parent_source.is_some(),
      backend: VmdkBackend::Descriptor(VmdkDescriptorBackend { extents }),
    })
  }

  pub fn header(&self) -> Option<&VmdkSparseHeader> {
    match &self.backend {
      VmdkBackend::Sparse(backend) => Some(&backend.header),
      VmdkBackend::Cowd(_) | VmdkBackend::Descriptor(_) => None,
    }
  }

  pub fn cowd_header(&self) -> Option<&VmdkCowdHeader> {
    match &self.backend {
      VmdkBackend::Cowd(backend) => Some(&backend.header),
      VmdkBackend::Sparse(_) | VmdkBackend::Descriptor(_) => None,
    }
  }

  pub fn descriptor_data(&self) -> &VmdkDescriptor {
    &self.descriptor
  }

  fn content_id(&self) -> u32 {
    self.descriptor.content_id
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

  fn read_cowd_grain_table(
    backend: &VmdkCowdBackend, directory_index: u64,
  ) -> Result<Option<Arc<Vec<u32>>>> {
    let raw_sector = *backend
      .grain_directory
      .get(usize::try_from(directory_index).map_err(|_| {
        Error::InvalidRange("vmdk cowd grain-directory index is too large".to_string())
      })?)
      .ok_or_else(|| {
        Error::InvalidFormat(format!(
          "vmdk cowd grain-directory entry {directory_index} is out of bounds"
        ))
      })?;
    if raw_sector == 0 {
      return Ok(None);
    }

    backend
      .grain_table_cache
      .get_or_load(directory_index, || {
        let offset = u64::from(raw_sector)
          .checked_mul(constants::BYTES_PER_SECTOR)
          .ok_or_else(|| {
            Error::InvalidRange("vmdk cowd grain-table offset overflow".to_string())
          })?;
        let byte_count = cowd_grain_table_entry_count()
          .checked_mul(4)
          .ok_or_else(|| Error::InvalidRange("vmdk cowd grain-table size overflow".to_string()))?;
        let raw = backend.source.read_bytes_at(
          offset,
          usize::try_from(byte_count).map_err(|_| {
            Error::InvalidRange("vmdk cowd grain-table size is too large".to_string())
          })?,
        )?;
        let entries = raw
          .chunks_exact(4)
          .map(|chunk| Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
          .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(entries))
      })
      .map(Some)
  }

  fn read_compressed_sparse_grain(
    backend: &VmdkSparseBackend, grain_index: u64, grain_sector: u32, size: u64,
  ) -> Result<Arc<Vec<u8>>> {
    backend.grain_cache.get_or_load(grain_index, || {
      let grain_offset = u64::from(grain_sector)
        .checked_mul(constants::BYTES_PER_SECTOR)
        .ok_or_else(|| Error::InvalidRange("vmdk compressed grain offset overflow".to_string()))?;
      let header_bytes = backend.source.read_bytes_at(grain_offset, 12)?;
      let compressed_size = u32::from_le_bytes([
        header_bytes[8],
        header_bytes[9],
        header_bytes[10],
        header_bytes[11],
      ]);
      if compressed_size == 0 {
        return Err(Error::InvalidFormat(
          "vmdk compressed grain header must carry a non-zero data size".to_string(),
        ));
      }
      let compressed = backend.source.read_bytes_at(
        grain_offset.checked_add(12).ok_or_else(|| {
          Error::InvalidRange("vmdk compressed grain data offset overflow".to_string())
        })?,
        usize::try_from(compressed_size).map_err(|_| {
          Error::InvalidRange("vmdk compressed grain size is too large".to_string())
        })?,
      )?;

      let mut decoder = flate2::read::ZlibDecoder::new(&compressed[..]);
      let mut decompressed = Vec::new();
      decoder.read_to_end(&mut decompressed)?;

      let grain_size = usize::try_from(backend.header.grain_size_bytes()?)
        .map_err(|_| Error::InvalidRange("vmdk grain size is too large".to_string()))?;
      let grain_base_offset = grain_index
        .checked_mul(u64::try_from(grain_size).unwrap_or(u64::MAX))
        .ok_or_else(|| Error::InvalidRange("vmdk grain base offset overflow".to_string()))?;
      let remaining = size.saturating_sub(grain_base_offset);
      let minimum_size = if remaining >= u64::try_from(grain_size).unwrap_or(u64::MAX) {
        grain_size
      } else {
        usize::try_from(remaining)
          .map_err(|_| Error::InvalidRange("vmdk remaining grain size is too large".to_string()))?
      };
      if decompressed.len() > grain_size || decompressed.len() < minimum_size {
        return Err(Error::InvalidFormat(
          "vmdk compressed grain does not expand to the expected size".to_string(),
        ));
      }
      decompressed.resize(grain_size, 0);

      Ok(Arc::new(decompressed))
    })
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
          fill_from_parent_or_zero(
            backend.parent_source.as_ref(),
            absolute_offset,
            &mut buf[copied..copied + available],
          )?;
        }
        Some(table) => {
          let grain_sector = *table.get(table_index).ok_or_else(|| {
            Error::InvalidFormat("vmdk grain table does not cover the requested grain".to_string())
          })?;
          if grain_sector == 0 || (backend.header.uses_zero_grain_entries() && grain_sector == 1) {
            fill_from_parent_or_zero(
              backend.parent_source.as_ref(),
              absolute_offset,
              &mut buf[copied..copied + available],
            )?;
          } else if backend.header.has_compressed_grains() {
            let decompressed =
              Self::read_compressed_sparse_grain(backend, grain_index, grain_sector, size)?;
            let within_grain = usize::try_from(within_grain)
              .map_err(|_| Error::InvalidRange("vmdk grain offset is too large".to_string()))?;
            buf[copied..copied + available]
              .copy_from_slice(&decompressed[within_grain..within_grain + available]);
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

  fn read_cowd_at(
    backend: &VmdkCowdBackend, offset: u64, size: u64, buf: &mut [u8],
  ) -> Result<usize> {
    if offset >= size || buf.is_empty() {
      return Ok(0);
    }

    let grain_size = backend.header.grain_size_bytes()?;
    let table_entries = cowd_grain_table_entry_count();
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
        .map_err(|_| Error::InvalidRange("vmdk cowd grain-table index is too large".to_string()))?;
      let available = usize::try_from(
        (grain_size - within_grain)
          .min(size - absolute_offset)
          .min((buf.len() - copied) as u64),
      )
      .map_err(|_| Error::InvalidRange("vmdk read chunk is too large".to_string()))?;

      match Self::read_cowd_grain_table(backend, directory_index)? {
        None => {
          fill_from_parent_or_zero(
            backend.parent_source.as_ref(),
            absolute_offset,
            &mut buf[copied..copied + available],
          )?;
        }
        Some(table) => {
          let grain_sector = *table.get(table_index).ok_or_else(|| {
            Error::InvalidFormat(
              "vmdk cowd grain table does not cover the requested grain".to_string(),
            )
          })?;
          if grain_sector == 0 {
            fill_from_parent_or_zero(
              backend.parent_source.as_ref(),
              absolute_offset,
              &mut buf[copied..copied + available],
            )?;
          } else {
            let data_offset = u64::from(grain_sector)
              .checked_mul(constants::BYTES_PER_SECTOR)
              .and_then(|value| value.checked_add(within_grain))
              .ok_or_else(|| {
                Error::InvalidRange("vmdk cowd grain data offset overflow".to_string())
              })?;
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
}

impl DataSource for VmdkImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    match &self.backend {
      VmdkBackend::Sparse(backend) => Self::read_sparse_at(backend, offset, self.size, buf),
      VmdkBackend::Cowd(backend) => Self::read_cowd_at(backend, offset, self.size, buf),
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
      VmdkBackend::Cowd(backend) => {
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

  fn has_backing_chain(&self) -> bool {
    self.has_backing_chain
  }
}

fn is_sparse_extent(source: &dyn DataSource) -> Result<bool> {
  let mut magic = [0u8; 4];
  Ok(source.read_at(0, &mut magic)? == magic.len() && &magic == constants::SPARSE_HEADER_MAGIC)
}

fn is_cowd_extent(source: &dyn DataSource) -> Result<bool> {
  let mut magic = [0u8; 4];
  Ok(source.read_at(0, &mut magic)? == magic.len() && &magic == constants::COWD_HEADER_MAGIC)
}

fn fill_from_parent_or_zero(
  parent_source: Option<&DataSourceHandle>, offset: u64, buf: &mut [u8],
) -> Result<()> {
  if let Some(parent_source) = parent_source {
    parent_source.read_exact_at(offset, buf)?;
  } else {
    buf.fill(0);
  }

  Ok(())
}

fn validate_descriptor_file_type(file_type: VmdkFileType) -> Result<()> {
  match file_type {
    VmdkFileType::Unknown => Err(Error::InvalidFormat(
      "unsupported vmdk descriptor create type".to_string(),
    )),
    VmdkFileType::Custom
    | VmdkFileType::FullDevice
    | VmdkFileType::MonolithicSparse
    | VmdkFileType::MonolithicFlat
    | VmdkFileType::PartitionedDevice
    | VmdkFileType::StreamOptimized
    | VmdkFileType::Flat2GbExtent
    | VmdkFileType::Sparse2GbExtent
    | VmdkFileType::Vmfs
    | VmdkFileType::VmfsSparse
    | VmdkFileType::VmfsThin
    | VmdkFileType::VmfsRaw
    | VmdkFileType::VmfsRdm
    | VmdkFileType::VmfsRdmp => Ok(()),
  }
}

fn validate_monolithic_sparse_descriptor(
  header: &VmdkSparseHeader, descriptor: &VmdkDescriptor,
) -> Result<()> {
  if descriptor.file_type != VmdkFileType::MonolithicSparse
    && descriptor.file_type != VmdkFileType::StreamOptimized
  {
    return Err(Error::InvalidFormat(format!(
      "unsupported embedded vmdk create type: {:?}",
      descriptor.file_type
    )));
  }
  if descriptor.extents.len() != 1 {
    return Err(Error::InvalidFormat(
      "monolithic sparse vmdk images must declare exactly one extent".to_string(),
    ));
  }
  let extent = &descriptor.extents[0];
  if matches!(
    extent.access_mode,
    VmdkExtentAccessMode::Unknown | VmdkExtentAccessMode::NoAccess
  ) {
    return Err(Error::InvalidFormat(
      "unsupported vmdk extent access mode".to_string(),
    ));
  }
  if extent.extent_type != VmdkExtentType::Sparse {
    return Err(Error::InvalidFormat(
      "monolithic sparse vmdk images must use a SPARSE extent".to_string(),
    ));
  }
  if extent.start_sector != 0 {
    return Err(Error::InvalidFormat(
      "monolithic sparse vmdk extents must start at sector 0".to_string(),
    ));
  }
  if extent.sector_count != header.capacity_sectors {
    return Err(Error::InvalidFormat(
      "vmdk descriptor extent length does not match the sparse header capacity".to_string(),
    ));
  }

  Ok(())
}

fn resolve_descriptor_parent_source(
  descriptor: &VmdkDescriptor, hints: SourceHints<'_>,
) -> Result<Option<DataSourceHandle>> {
  let has_parent =
    descriptor.parent_content_id.is_some() || descriptor.parent_file_name_hint.is_some();
  if !has_parent {
    return Ok(None);
  }

  let parent_hint = descriptor.parent_file_name_hint.as_deref().ok_or_else(|| {
    Error::InvalidSourceReference(
      "parent-backed vmdk descriptors require parentFileNameHint".to_string(),
    )
  })?;
  let resolver = hints.resolver().ok_or_else(|| {
    Error::InvalidSourceReference(
      "parent-backed vmdk descriptors require a related-source resolver".to_string(),
    )
  })?;
  let identity = hints.source_identity().ok_or_else(|| {
    Error::InvalidSourceReference(
      "parent-backed vmdk descriptors require a source identity hint".to_string(),
    )
  })?;
  let parent_image = resolve_parent_image(
    resolver,
    identity,
    parent_hint,
    descriptor.parent_content_id,
  )?;

  Ok(Some(parent_image as DataSourceHandle))
}

fn resolve_cowd_parent_source(
  header: &VmdkCowdHeader, hints: SourceHints<'_>,
) -> Result<Option<DataSourceHandle>> {
  if header.parent_generation == 0 && header.parent_path.is_empty() {
    return Ok(None);
  }

  let parent_hint = if header.parent_path.is_empty() {
    return Err(Error::InvalidSourceReference(
      "parent-backed vmdk cowd extents require a parent path".to_string(),
    ));
  } else {
    header.parent_path.as_str()
  };
  let resolver = hints.resolver().ok_or_else(|| {
    Error::InvalidSourceReference(
      "parent-backed vmdk cowd extents require a related-source resolver".to_string(),
    )
  })?;
  let identity = hints.source_identity().ok_or_else(|| {
    Error::InvalidSourceReference(
      "parent-backed vmdk cowd extents require a source identity hint".to_string(),
    )
  })?;
  let expected = if header.parent_generation == 0 {
    None
  } else {
    Some(header.parent_generation)
  };
  let parent_image = resolve_parent_image(resolver, identity, parent_hint, expected)?;

  Ok(Some(parent_image as DataSourceHandle))
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
  parent_source: Option<DataSourceHandle>,
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

  let parsed = parse_sparse_extent(source.clone())?;
  let descriptor = parsed
    .embedded_descriptor
    .unwrap_or_else(|| VmdkDescriptor {
      version: 1,
      content_id: 0,
      parent_content_id: None,
      file_type: VmdkFileType::Sparse2GbExtent,
      extents: vec![VmdkDescriptorExtent {
        access_mode: extent.access_mode,
        sector_count: extent.sector_count,
        extent_type: extent.extent_type,
        file_name: None,
        start_sector: 0,
      }],
      parent_file_name_hint: None,
    });
  validate_sparse_extent_matches_descriptor(&parsed.header, extent)?;
  let image = VmdkImage::from_sparse_parts(
    source,
    parsed.header,
    parsed.grain_directory,
    descriptor,
    parent_source,
  )?;
  Ok(VmdkResolvedExtentKind::Source(
    Arc::new(image) as DataSourceHandle
  ))
}

fn resolve_vmfs_sparse_extent(
  extent: &VmdkDescriptorExtent, resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity,
  parent_source: Option<DataSourceHandle>,
) -> Result<VmdkResolvedExtentKind> {
  if extent.start_sector != 0 {
    return Err(Error::InvalidFormat(
      "vmdk vmfssparse extents must start at sector 0".to_string(),
    ));
  }

  let file_name = extent.file_name.as_deref().ok_or_else(|| {
    Error::InvalidFormat("vmdk vmfssparse extent is missing a file name".to_string())
  })?;
  let (source, path) = resolve_extent_source(resolver, identity, file_name)?
    .ok_or_else(|| Error::NotFound("unable to resolve the vmdk vmfssparse extent".to_string()))?;
  if &path == identity.logical_path() {
    return Err(Error::InvalidFormat(
      "vmdk descriptor extent resolves back to the descriptor file".to_string(),
    ));
  }

  let parsed = parse_cowd(source.clone())?;
  if u64::from(parsed.header.capacity_sectors) != extent.sector_count {
    return Err(Error::InvalidFormat(
      "vmdk vmfssparse extent length does not match the cowd header capacity".to_string(),
    ));
  }
  let image = VmdkImage::from_cowd_parsed(source, parsed, parent_source)?;
  Ok(VmdkResolvedExtentKind::Source(
    Arc::new(image) as DataSourceHandle
  ))
}

fn validate_sparse_extent_matches_descriptor(
  header: &VmdkSparseHeader, extent: &VmdkDescriptorExtent,
) -> Result<()> {
  if extent.start_sector != 0 {
    return Err(Error::InvalidFormat(
      "vmdk sparse extents must start at sector 0".to_string(),
    ));
  }
  if header.capacity_sectors != extent.sector_count {
    return Err(Error::InvalidFormat(
      "vmdk sparse extent length does not match the sparse header capacity".to_string(),
    ));
  }

  Ok(())
}

fn resolve_parent_image(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, parent_hint: &str,
  expected_content_id: Option<u32>,
) -> Result<Arc<VmdkImage>> {
  let (parent_source, parent_path) = resolve_named_source(
    resolver,
    identity,
    parent_hint,
    RelatedSourcePurpose::BackingFile,
  )?
  .ok_or_else(|| Error::NotFound("unable to resolve the parent vmdk image".to_string()))?;
  if &parent_path == identity.logical_path() {
    return Err(Error::InvalidFormat(
      "vmdk parent hint resolves to the same image".to_string(),
    ));
  }

  let parent_identity = SourceIdentity::new(parent_path);
  let parent_image = Arc::new(VmdkImage::open_with_hints(
    parent_source,
    SourceHints::new()
      .with_resolver(resolver)
      .with_source_identity(&parent_identity),
  )?);
  if let Some(expected_content_id) = expected_content_id
    && parent_image.content_id() != expected_content_id
  {
    return Err(Error::InvalidFormat(format!(
      "resolved parent content id {} does not match expected {}",
      parent_image.content_id(),
      expected_content_id
    )));
  }

  Ok(parent_image)
}

fn resolve_extent_source(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, extent_name: &str,
) -> Result<Option<(DataSourceHandle, RelatedPathBuf)>> {
  resolve_named_source(
    resolver,
    identity,
    extent_name,
    RelatedSourcePurpose::Extent,
  )
}

fn resolve_named_source(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, name: &str,
  purpose: RelatedSourcePurpose,
) -> Result<Option<(DataSourceHandle, RelatedPathBuf)>> {
  if let Ok(relative) = RelatedPathBuf::from_relative_path(name)
    && let Some(parent) = identity.logical_path().parent()
  {
    let joined = parent.join(&relative);
    if let Some(source) = resolver.resolve(&RelatedSourceRequest::new(purpose, joined.clone()))? {
      return Ok(Some((source, joined)));
    }
  }

  let file_name = name.rsplit(['\\', '/']).next().unwrap_or(name);
  let sibling = identity.sibling_path(file_name)?;
  Ok(
    resolver
      .resolve(&RelatedSourceRequest::new(purpose, sibling.clone()))?
      .map(|source| (source, sibling)),
  )
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, io::Write, path::Path};

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

  const TEST_GRAIN_SECTORS: u64 = 8;
  const TEST_GRAIN_SIZE: usize = (TEST_GRAIN_SECTORS as usize) * 512;
  const TEST_CAPACITY_SECTORS: u64 = TEST_GRAIN_SECTORS * 2;

  fn test_grain(fill: u8) -> Vec<u8> {
    vec![fill; TEST_GRAIN_SIZE]
  }

  fn build_sparse_descriptor_text(
    file_name: &str, create_type: &str, content_id: u32, parent: Option<(&str, u32)>,
  ) -> Vec<u8> {
    let mut text = format!(
      "# Disk DescriptorFile\nversion=1\nCID={content_id:08x}\nparentCID={}\ncreateType=\"{create_type}\"\n",
      parent
        .map(|(_, cid)| format!("{cid:08x}"))
        .unwrap_or_else(|| "ffffffff".to_string())
    );
    if let Some((parent_hint, _)) = parent {
      text.push_str(&format!("parentFileNameHint=\"{parent_hint}\"\n"));
    }
    text.push_str(&format!(
      "\n# Extent description\nRW {} SPARSE \"{file_name}\"\n\n# The Disk Data Base\n#DDB\n",
      TEST_CAPACITY_SECTORS
    ));
    text.into_bytes()
  }

  fn build_sparse_extent_bytes(
    file_name: &str, embedded_descriptor: bool, create_type: &str, content_id: u32,
    parent: Option<(&str, u32)>, grains: [Option<Vec<u8>>; 2],
  ) -> Vec<u8> {
    let descriptor_sectors = if embedded_descriptor { 1u64 } else { 0u64 };
    let grain_directory_sector = 1 + descriptor_sectors;
    let grain_table_sector = grain_directory_sector + 1;
    let mut next_data_sector = grain_table_sector + 1;

    let mut grain_entries = [0u32; 2];
    let mut grain_payloads = Vec::new();
    for (index, grain) in grains.into_iter().enumerate() {
      if let Some(grain) = grain {
        grain_entries[index] = u32::try_from(next_data_sector).unwrap();
        next_data_sector += TEST_GRAIN_SECTORS;
        grain_payloads.push(grain);
      } else {
        grain_payloads.push(Vec::new());
      }
    }

    let mut image = vec![0u8; usize::try_from(next_data_sector * 512).unwrap()];
    image[0..4].copy_from_slice(constants::SPARSE_HEADER_MAGIC);
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[8..12].copy_from_slice(&constants::FLAG_VALID_NEWLINE_TEST.to_le_bytes());
    image[12..20].copy_from_slice(&TEST_CAPACITY_SECTORS.to_le_bytes());
    image[20..28].copy_from_slice(&TEST_GRAIN_SECTORS.to_le_bytes());
    image[28..36].copy_from_slice(&(if embedded_descriptor { 1u64 } else { 0u64 }).to_le_bytes());
    image[36..44].copy_from_slice(&descriptor_sectors.to_le_bytes());
    image[44..48].copy_from_slice(&128u32.to_le_bytes());
    image[56..64].copy_from_slice(&grain_directory_sector.to_le_bytes());
    image[73..77].copy_from_slice(&[0x0A, 0x20, 0x0D, 0x0A]);

    if embedded_descriptor {
      let mut descriptor = build_sparse_descriptor_text(file_name, create_type, content_id, parent);
      descriptor.resize(512, 0);
      image[512..1024].copy_from_slice(&descriptor);
    }

    let grain_directory_offset = usize::try_from(grain_directory_sector * 512).unwrap();
    image[grain_directory_offset..grain_directory_offset + 4]
      .copy_from_slice(&(u32::try_from(grain_table_sector).unwrap()).to_le_bytes());
    let grain_table_offset = usize::try_from(grain_table_sector * 512).unwrap();
    image[grain_table_offset..grain_table_offset + 4]
      .copy_from_slice(&grain_entries[0].to_le_bytes());
    image[grain_table_offset + 4..grain_table_offset + 8]
      .copy_from_slice(&grain_entries[1].to_le_bytes());

    for (index, payload) in grain_payloads.into_iter().enumerate() {
      if payload.is_empty() {
        continue;
      }
      let sector = u64::from(grain_entries[index]);
      let offset = usize::try_from(sector * 512).unwrap();
      image[offset..offset + payload.len()].copy_from_slice(&payload);
    }

    image
  }

  fn build_sparse_descriptor_file(
    file_name: &str, create_type: &str, content_id: u32, parent: Option<(&str, u32)>,
  ) -> DataSourceHandle {
    Arc::new(MemDataSource {
      data: build_sparse_descriptor_text(file_name, create_type, content_id, parent),
    }) as DataSourceHandle
  }

  fn build_cowd_bytes(
    generation: u32, parent: Option<(&str, u32)>, grains: [Option<Vec<u8>>; 2],
  ) -> Vec<u8> {
    let grain_directory_sector = 4u32;
    let grain_table_sector = 5u32;
    let grain_table_sectors = 32u32;
    let mut next_data_sector = grain_table_sector + grain_table_sectors;

    let mut grain_entries = [0u32; 2];
    let mut grain_payloads = Vec::new();
    for (index, grain) in grains.into_iter().enumerate() {
      if let Some(grain) = grain {
        grain_entries[index] = next_data_sector;
        next_data_sector += u32::try_from(TEST_GRAIN_SECTORS).unwrap();
        grain_payloads.push(grain);
      } else {
        grain_payloads.push(Vec::new());
      }
    }

    let mut image = vec![0u8; usize::try_from(u64::from(next_data_sector) * 512).unwrap()];
    image[0..4].copy_from_slice(constants::COWD_HEADER_MAGIC);
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[8..12].copy_from_slice(&3u32.to_le_bytes());
    image[12..16].copy_from_slice(&(u32::try_from(TEST_CAPACITY_SECTORS).unwrap()).to_le_bytes());
    image[16..20].copy_from_slice(&(u32::try_from(TEST_GRAIN_SECTORS).unwrap()).to_le_bytes());
    image[20..24].copy_from_slice(&grain_directory_sector.to_le_bytes());
    image[24..28].copy_from_slice(&1u32.to_le_bytes());
    image[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    if let Some((parent_path, parent_generation)) = parent {
      image[32..32 + parent_path.len()].copy_from_slice(parent_path.as_bytes());
      image[1056..1060].copy_from_slice(&parent_generation.to_le_bytes());
    }
    image[1060..1064].copy_from_slice(&generation.to_le_bytes());

    let grain_directory_offset = usize::try_from(u64::from(grain_directory_sector) * 512).unwrap();
    image[grain_directory_offset..grain_directory_offset + 4]
      .copy_from_slice(&grain_table_sector.to_le_bytes());
    let grain_table_offset = usize::try_from(u64::from(grain_table_sector) * 512).unwrap();
    image[grain_table_offset..grain_table_offset + 4]
      .copy_from_slice(&grain_entries[0].to_le_bytes());
    image[grain_table_offset + 4..grain_table_offset + 8]
      .copy_from_slice(&grain_entries[1].to_le_bytes());

    for (index, payload) in grain_payloads.into_iter().enumerate() {
      if payload.is_empty() {
        continue;
      }
      let offset = usize::try_from(u64::from(grain_entries[index]) * 512).unwrap();
      image[offset..offset + payload.len()].copy_from_slice(&payload);
    }

    image
  }

  fn build_cowd_descriptor_file(content_id: u32, parent: Option<(&str, u32)>) -> DataSourceHandle {
    Arc::new(MemDataSource {
      data: format!(
        "# Disk DescriptorFile\nversion=1\nCID={content_id:08x}\nparentCID={}\ncreateType=\"vmfsSparse\"\n{}\n# Extent description\nRW {} VMFSSPARSE \"child.cowd\"\n\n# The Disk Data Base\n#DDB\n",
        parent.map(|(_, cid)| format!("{cid:08x}")).unwrap_or_else(|| "ffffffff".to_string()),
        parent
          .map(|(hint, _)| format!("parentFileNameHint=\"{hint}\"\n"))
          .unwrap_or_default(),
        TEST_CAPACITY_SECTORS,
      )
      .into_bytes(),
    }) as DataSourceHandle
  }

  fn build_streamoptimized_sparse_bytes(
    file_name: &str, content_id: u32, grain: Vec<u8>,
  ) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&grain).unwrap();
    let compressed = encoder.finish().unwrap();

    let descriptor = format!(
      "# Disk DescriptorFile\nversion=1\nCID={content_id:08x}\nparentCID=ffffffff\ncreateType=\"streamOptimized\"\n\n# Extent description\nRW {} SPARSE \"{file_name}\"\n\n# The Disk Data Base\n#DDB\n",
      TEST_GRAIN_SECTORS,
    )
    .into_bytes();
    let mut descriptor_sector = descriptor;
    descriptor_sector.resize(512, 0);

    let mut image = vec![0u8; 10 * 512];
    image[0..4].copy_from_slice(constants::SPARSE_HEADER_MAGIC);
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[8..12].copy_from_slice(
      &(constants::FLAG_VALID_NEWLINE_TEST
        | constants::FLAG_HAS_COMPRESSED_GRAINS
        | constants::FLAG_HAS_MARKERS)
        .to_le_bytes(),
    );
    image[12..20].copy_from_slice(&TEST_GRAIN_SECTORS.to_le_bytes());
    image[20..28].copy_from_slice(&TEST_GRAIN_SECTORS.to_le_bytes());
    image[28..36].copy_from_slice(&1u64.to_le_bytes());
    image[36..44].copy_from_slice(&1u64.to_le_bytes());
    image[44..48].copy_from_slice(&128u32.to_le_bytes());
    image[56..64].copy_from_slice(&constants::GD_AT_END.to_le_bytes());
    image[73..77].copy_from_slice(&[0x0A, 0x20, 0x0D, 0x0A]);
    image[77..79].copy_from_slice(&1u16.to_le_bytes());
    image[512..1024].copy_from_slice(&descriptor_sector);

    let grain_offset = 2 * 512;
    image[grain_offset..grain_offset + 8].copy_from_slice(&0u64.to_le_bytes());
    image[grain_offset + 8..grain_offset + 12]
      .copy_from_slice(&(u32::try_from(compressed.len()).unwrap()).to_le_bytes());
    image[grain_offset + 12..grain_offset + 12 + compressed.len()].copy_from_slice(&compressed);

    let gt_marker = 3 * 512;
    image[gt_marker + 12..gt_marker + 16].copy_from_slice(&1u32.to_le_bytes());
    let gt_sector = 4 * 512;
    image[gt_sector..gt_sector + 4].copy_from_slice(&2u32.to_le_bytes());

    let gd_marker = 5 * 512;
    image[gd_marker + 12..gd_marker + 16].copy_from_slice(&2u32.to_le_bytes());
    let gd_sector = 6 * 512;
    image[gd_sector..gd_sector + 4].copy_from_slice(&4u32.to_le_bytes());

    let footer_marker = 7 * 512;
    image[footer_marker + 12..footer_marker + 16].copy_from_slice(&3u32.to_le_bytes());
    let footer = 8 * 512;
    let header_copy = image[0..512].to_vec();
    image[footer..footer + 512].copy_from_slice(&header_copy);
    image[footer + 56..footer + 64].copy_from_slice(&6u64.to_le_bytes());

    image
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
  fn opens_cowd_fixture_metadata() {
    let image = VmdkImage::open(sample_source("vmdk/ext2.cowd")).unwrap();
    let header = image.cowd_header().unwrap();

    assert_eq!(header.format_version, 1);
    assert_eq!(header.sectors_per_grain, 128);
    assert_eq!(header.grain_directory_entries, 16);
    assert_eq!(header.parent_path, "");
    assert_eq!(image.descriptor_data().file_type, VmdkFileType::VmfsSparse);
    assert_eq!(image.size().unwrap(), 4_194_304);
  }

  #[test]
  fn reads_streamoptimized_sparse_with_markers_and_footer() {
    let stream = Arc::new(MemDataSource {
      data: build_streamoptimized_sparse_bytes("stream.vmdk", 0x1234_5678, test_grain(b'T')),
    }) as DataSourceHandle;

    let image = VmdkImage::open(stream).unwrap();
    let header = image.header().unwrap();

    assert_eq!(image.read_all().unwrap(), test_grain(b'T'));
    assert_eq!(
      image.descriptor_data().file_type,
      VmdkFileType::StreamOptimized
    );
    assert!(header.has_compressed_grains());
    assert!(header.has_markers());
    assert!(header.uses_gd_at_end());
  }

  #[test]
  fn reads_full_ext2_cowd_fixture() {
    let image = VmdkImage::open(sample_source("vmdk/ext2.cowd")).unwrap();
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
  fn opens_descriptor_backed_cowd_fixture_via_resolver() {
    let descriptor = sample_source("vmdk/ext2-cowd-descriptor.vmdk");
    let extent = sample_source("vmdk/ext2.cowd");
    let resolver = Resolver {
      files: HashMap::from([("vmdk/ext2.cowd".to_string(), extent)]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/ext2-cowd-descriptor.vmdk").unwrap();
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
    assert!(image.is_sparse());
    assert_eq!(image.descriptor_data().file_type, VmdkFileType::VmfsSparse);
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
  fn reads_direct_sparse_child_from_parent_image() {
    let parent = Arc::new(MemDataSource {
      data: build_sparse_extent_bytes(
        "parent.vmdk",
        true,
        "monolithicSparse",
        0x1111_1111,
        None,
        [Some(test_grain(b'P')), Some(test_grain(b'Q'))],
      ),
    }) as DataSourceHandle;
    let child = Arc::new(MemDataSource {
      data: build_sparse_extent_bytes(
        "child.vmdk",
        true,
        "monolithicSparse",
        0x2222_2222,
        Some(("parent.vmdk", 0x1111_1111)),
        [Some(test_grain(b'C')), None],
      ),
    }) as DataSourceHandle;
    let resolver = Resolver {
      files: HashMap::from([("vmdk/parent.vmdk".to_string(), parent)]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/child.vmdk").unwrap();

    let image = VmdkImage::open_with_hints(
      child,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let mut expected = test_grain(b'C');
    expected.extend_from_slice(&test_grain(b'Q'));

    assert_eq!(image.read_all().unwrap(), expected);
    assert!(image.has_backing_chain());
  }

  #[test]
  fn opens_descriptor_backed_split_sparse_with_parent_hint() {
    let parent = Arc::new(MemDataSource {
      data: build_sparse_extent_bytes(
        "parent.vmdk",
        true,
        "monolithicSparse",
        0x3333_3333,
        None,
        [Some(test_grain(b'A')), Some(test_grain(b'B'))],
      ),
    }) as DataSourceHandle;
    let child_extent = Arc::new(MemDataSource {
      data: build_sparse_extent_bytes(
        "child-s001.vmdk",
        false,
        "twoGbMaxExtentSparse",
        0,
        None,
        [None, Some(test_grain(b'S'))],
      ),
    }) as DataSourceHandle;
    let descriptor = build_sparse_descriptor_file(
      "child-s001.vmdk",
      "twoGbMaxExtentSparse",
      0x4444_4444,
      Some(("parent.vmdk", 0x3333_3333)),
    );
    let resolver = Resolver {
      files: HashMap::from([
        ("vmdk/parent.vmdk".to_string(), parent),
        ("vmdk/child-s001.vmdk".to_string(), child_extent),
      ]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/child.vmdk").unwrap();

    let image = VmdkImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let mut expected = test_grain(b'A');
    expected.extend_from_slice(&test_grain(b'S'));

    assert_eq!(image.read_all().unwrap(), expected);
    assert!(image.has_backing_chain());
    assert_eq!(
      image.descriptor_data().file_type,
      VmdkFileType::Sparse2GbExtent
    );
  }

  #[test]
  fn reads_direct_cowd_child_from_parent_image() {
    let parent = Arc::new(MemDataSource {
      data: build_cowd_bytes(
        0x5555_5555,
        None,
        [Some(test_grain(b'R')), Some(test_grain(b'S'))],
      ),
    }) as DataSourceHandle;
    let child = Arc::new(MemDataSource {
      data: build_cowd_bytes(
        0x6666_6666,
        Some(("parent.cowd", 0x5555_5555)),
        [Some(test_grain(b'C')), None],
      ),
    }) as DataSourceHandle;
    let resolver = Resolver {
      files: HashMap::from([("vmdk/parent.cowd".to_string(), parent)]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/child.cowd").unwrap();

    let image = VmdkImage::open_with_hints(
      child,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let mut expected = test_grain(b'C');
    expected.extend_from_slice(&test_grain(b'S'));

    assert_eq!(image.read_all().unwrap(), expected);
    assert!(image.has_backing_chain());
  }

  #[test]
  fn opens_descriptor_backed_cowd_child_with_parent_hint() {
    let parent = Arc::new(MemDataSource {
      data: build_cowd_bytes(
        0x7777_7777,
        None,
        [Some(test_grain(b'P')), Some(test_grain(b'Q'))],
      ),
    }) as DataSourceHandle;
    let child_extent = Arc::new(MemDataSource {
      data: build_cowd_bytes(0x8888_8888, None, [None, Some(test_grain(b'Z'))]),
    }) as DataSourceHandle;
    let descriptor = build_cowd_descriptor_file(0x8888_8888, Some(("parent.cowd", 0x7777_7777)));
    let resolver = Resolver {
      files: HashMap::from([
        ("vmdk/parent.cowd".to_string(), parent),
        ("vmdk/child.cowd".to_string(), child_extent),
      ]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/child-descriptor.vmdk").unwrap();

    let image = VmdkImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let mut expected = test_grain(b'P');
    expected.extend_from_slice(&test_grain(b'Z'));

    assert_eq!(image.read_all().unwrap(), expected);
    assert!(image.has_backing_chain());
  }

  #[test]
  fn descriptor_backed_sparse_images_require_resolution_hints() {
    let descriptor = sample_source("vmdk/ext2-descriptor.vmdk");

    let result = VmdkImage::open(descriptor);

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }

  #[test]
  fn descriptor_backed_cowd_images_require_resolution_hints() {
    let descriptor = sample_source("vmdk/ext2-cowd-descriptor.vmdk");

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
  fn rejects_sparse_parent_content_id_mismatches() {
    let parent = Arc::new(MemDataSource {
      data: build_sparse_extent_bytes(
        "parent.vmdk",
        true,
        "monolithicSparse",
        0x1111_1111,
        None,
        [Some(test_grain(b'P')), Some(test_grain(b'Q'))],
      ),
    }) as DataSourceHandle;
    let child = Arc::new(MemDataSource {
      data: build_sparse_extent_bytes(
        "child.vmdk",
        true,
        "monolithicSparse",
        0x2222_2222,
        Some(("parent.vmdk", 0x9999_9999)),
        [Some(test_grain(b'C')), None],
      ),
    }) as DataSourceHandle;
    let resolver = Resolver {
      files: HashMap::from([("vmdk/parent.vmdk".to_string(), parent)]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/child.vmdk").unwrap();

    let result = VmdkImage::open_with_hints(
      child,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    );

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_invalid_compressed_sparse_headers_without_a_method() {
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

  #[test]
  fn rejects_cowd_parent_generation_mismatches() {
    let parent = Arc::new(MemDataSource {
      data: build_cowd_bytes(
        0xABAB_ABAB,
        None,
        [Some(test_grain(b'P')), Some(test_grain(b'Q'))],
      ),
    }) as DataSourceHandle;
    let child = Arc::new(MemDataSource {
      data: build_cowd_bytes(
        0xCDCD_CCCD,
        Some(("parent.cowd", 0x1111_1111)),
        [Some(test_grain(b'C')), None],
      ),
    }) as DataSourceHandle;
    let resolver = Resolver {
      files: HashMap::from([("vmdk/parent.cowd".to_string(), parent)]),
    };
    let identity = SourceIdentity::from_relative_path("vmdk/child.cowd").unwrap();

    let result = VmdkImage::open_with_hints(
      child,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    );

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
