//! Extent and parent-image resolution helpers for VMDK.

use std::sync::Arc;

use super::{
  constants,
  cowd_header::VmdkCowdHeader,
  descriptor::{
    VmdkDescriptor, VmdkDescriptorExtent, VmdkExtentAccessMode, VmdkExtentType, VmdkFileType,
  },
  header::VmdkSparseHeader,
  image::VmdkImage,
  parser::{parse_cowd, parse_sparse_extent},
};
use crate::{
  ByteSource, ByteSourceHandle, Error, RelatedPathBuf, RelatedSourcePurpose, RelatedSourceRequest,
  RelatedSourceResolver, Result, SliceDataSource, SourceHints, SourceIdentity,
};

pub(super) fn is_sparse_extent(source: &dyn ByteSource) -> Result<bool> {
  let mut magic = [0u8; 4];
  Ok(source.read_at(0, &mut magic)? == magic.len() && &magic == constants::SPARSE_HEADER_MAGIC)
}

pub(super) fn is_cowd_extent(source: &dyn ByteSource) -> Result<bool> {
  let mut magic = [0u8; 4];
  Ok(source.read_at(0, &mut magic)? == magic.len() && &magic == constants::COWD_HEADER_MAGIC)
}

pub(super) fn fill_from_parent_or_zero(
  parent_source: Option<&ByteSourceHandle>, offset: u64, buf: &mut [u8],
) -> Result<()> {
  if let Some(parent_source) = parent_source {
    parent_source.read_exact_at(offset, buf)?;
  } else {
    buf.fill(0);
  }

  Ok(())
}

pub(super) fn bounded_cache_capacity(
  entry_size: usize, byte_budget: usize, max_entries: usize,
) -> usize {
  if entry_size == 0 || max_entries == 0 {
    return 1;
  }

  (byte_budget / entry_size).max(1).min(max_entries)
}

pub(super) fn validate_descriptor_file_type(file_type: VmdkFileType) -> Result<()> {
  match file_type {
    VmdkFileType::Unknown => Err(Error::invalid_format(
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

pub(super) fn validate_monolithic_sparse_descriptor(
  header: &VmdkSparseHeader, descriptor: &VmdkDescriptor,
) -> Result<()> {
  if descriptor.file_type != VmdkFileType::MonolithicSparse
    && descriptor.file_type != VmdkFileType::StreamOptimized
  {
    return Err(Error::invalid_format(format!(
      "unsupported embedded vmdk create type: {:?}",
      descriptor.file_type
    )));
  }
  if descriptor.extents.len() != 1 {
    return Err(Error::invalid_format(
      "monolithic sparse vmdk images must declare exactly one extent".to_string(),
    ));
  }
  let extent = &descriptor.extents[0];
  if matches!(
    extent.access_mode,
    VmdkExtentAccessMode::Unknown | VmdkExtentAccessMode::NoAccess
  ) {
    return Err(Error::invalid_format(
      "unsupported vmdk extent access mode".to_string(),
    ));
  }
  if extent.extent_type != VmdkExtentType::Sparse {
    return Err(Error::invalid_format(
      "monolithic sparse vmdk images must use a SPARSE extent".to_string(),
    ));
  }
  if extent.start_sector != 0 {
    return Err(Error::invalid_format(
      "monolithic sparse vmdk extents must start at sector 0".to_string(),
    ));
  }
  if extent.sector_count != header.capacity_sectors {
    return Err(Error::invalid_format(
      "vmdk descriptor extent length does not match the sparse header capacity".to_string(),
    ));
  }

  Ok(())
}

pub(super) fn resolve_descriptor_parent_source(
  descriptor: &VmdkDescriptor, hints: SourceHints<'_>,
) -> Result<Option<ByteSourceHandle>> {
  let has_parent =
    descriptor.parent_content_id.is_some() || descriptor.parent_file_name_hint.is_some();
  if !has_parent {
    return Ok(None);
  }

  let parent_hint = descriptor.parent_file_name_hint.as_deref().ok_or_else(|| {
    Error::invalid_source_reference(
      "parent-backed vmdk descriptors require parentFileNameHint".to_string(),
    )
  })?;
  let resolver = hints.resolver().ok_or_else(|| {
    Error::invalid_source_reference(
      "parent-backed vmdk descriptors require a related-source resolver".to_string(),
    )
  })?;
  let identity = hints.source_identity().ok_or_else(|| {
    Error::invalid_source_reference(
      "parent-backed vmdk descriptors require a source identity hint".to_string(),
    )
  })?;
  let parent_image = resolve_parent_image(
    resolver,
    identity,
    parent_hint,
    descriptor.parent_content_id,
  )?;

  Ok(Some(parent_image as ByteSourceHandle))
}

pub(super) fn resolve_cowd_parent_source(
  header: &VmdkCowdHeader, hints: SourceHints<'_>,
) -> Result<Option<ByteSourceHandle>> {
  if header.parent_generation == 0 && header.parent_path.is_empty() {
    return Ok(None);
  }

  let parent_hint = if header.parent_path.is_empty() {
    return Err(Error::invalid_source_reference(
      "parent-backed vmdk cowd extents require a parent path".to_string(),
    ));
  } else {
    header.parent_path.as_str()
  };
  let resolver = hints.resolver().ok_or_else(|| {
    Error::invalid_source_reference(
      "parent-backed vmdk cowd extents require a related-source resolver".to_string(),
    )
  })?;
  let identity = hints.source_identity().ok_or_else(|| {
    Error::invalid_source_reference(
      "parent-backed vmdk cowd extents require a source identity hint".to_string(),
    )
  })?;
  let expected = if header.parent_generation == 0 {
    None
  } else {
    Some(header.parent_generation)
  };
  let parent_image = resolve_parent_image(resolver, identity, parent_hint, expected)?;

  Ok(Some(parent_image as ByteSourceHandle))
}

pub(super) fn resolve_flat_extent(
  extent: &VmdkDescriptorExtent, resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity,
  extent_size: u64,
) -> Result<super::image::VmdkResolvedExtentKind> {
  let file_name = extent
    .file_name
    .as_deref()
    .ok_or_else(|| Error::invalid_format("vmdk flat extent is missing a file name"))?;
  let (source, path) = resolve_extent_source(resolver, identity, file_name)?
    .ok_or_else(|| Error::not_found("unable to resolve the vmdk extent file"))?;
  if &path == identity.logical_path() {
    return Err(Error::invalid_format(
      "vmdk descriptor extent resolves back to the descriptor file".to_string(),
    ));
  }

  let base_offset = extent
    .start_sector
    .checked_mul(constants::BYTES_PER_SECTOR)
    .ok_or_else(|| Error::invalid_range("vmdk flat extent offset overflow"))?;
  let extent_end = base_offset
    .checked_add(extent_size)
    .ok_or_else(|| Error::invalid_range("vmdk flat extent range overflow"))?;
  if extent_end > source.size()? {
    return Err(Error::invalid_format(
      "vmdk flat extent exceeds the backing file size".to_string(),
    ));
  }

  Ok(super::image::VmdkResolvedExtentKind::Source(
    Arc::new(SliceDataSource::new(source, base_offset, extent_size)) as ByteSourceHandle,
  ))
}

pub(super) fn resolve_sparse_extent(
  extent: &VmdkDescriptorExtent, resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity,
  parent_source: Option<ByteSourceHandle>,
) -> Result<super::image::VmdkResolvedExtentKind> {
  if extent.start_sector != 0 {
    return Err(Error::invalid_format(
      "vmdk sparse extents must start at sector 0".to_string(),
    ));
  }

  let file_name = extent
    .file_name
    .as_deref()
    .ok_or_else(|| Error::invalid_format("vmdk sparse extent is missing a file name"))?;
  let (source, path) = resolve_extent_source(resolver, identity, file_name)?
    .ok_or_else(|| Error::not_found("unable to resolve the vmdk sparse extent"))?;
  if &path == identity.logical_path() {
    return Err(Error::invalid_format(
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
  Ok(super::image::VmdkResolvedExtentKind::Source(
    Arc::new(image) as ByteSourceHandle,
  ))
}

pub(super) fn resolve_vmfs_sparse_extent(
  extent: &VmdkDescriptorExtent, resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity,
  parent_source: Option<ByteSourceHandle>,
) -> Result<super::image::VmdkResolvedExtentKind> {
  if extent.start_sector != 0 {
    return Err(Error::invalid_format(
      "vmdk vmfssparse extents must start at sector 0".to_string(),
    ));
  }

  let file_name = extent
    .file_name
    .as_deref()
    .ok_or_else(|| Error::invalid_format("vmdk vmfssparse extent is missing a file name"))?;
  let (source, path) = resolve_extent_source(resolver, identity, file_name)?
    .ok_or_else(|| Error::not_found("unable to resolve the vmdk vmfssparse extent"))?;
  if &path == identity.logical_path() {
    return Err(Error::invalid_format(
      "vmdk descriptor extent resolves back to the descriptor file".to_string(),
    ));
  }

  let parsed = parse_cowd(source.clone())?;
  if u64::from(parsed.header.capacity_sectors) != extent.sector_count {
    return Err(Error::invalid_format(
      "vmdk vmfssparse extent length does not match the cowd header capacity".to_string(),
    ));
  }
  let image = VmdkImage::from_cowd_parsed(source, parsed, parent_source)?;
  Ok(super::image::VmdkResolvedExtentKind::Source(
    Arc::new(image) as ByteSourceHandle,
  ))
}

pub(super) fn validate_sparse_extent_matches_descriptor(
  header: &VmdkSparseHeader, extent: &VmdkDescriptorExtent,
) -> Result<()> {
  if extent.start_sector != 0 {
    return Err(Error::invalid_format(
      "vmdk sparse extents must start at sector 0".to_string(),
    ));
  }
  if header.capacity_sectors != extent.sector_count {
    return Err(Error::invalid_format(
      "vmdk sparse extent length does not match the sparse header capacity".to_string(),
    ));
  }

  Ok(())
}

pub(super) fn resolve_parent_image(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, parent_hint: &str,
  expected_content_id: Option<u32>,
) -> Result<Arc<VmdkImage>> {
  let (parent_source, parent_path) = resolve_named_source(
    resolver,
    identity,
    parent_hint,
    RelatedSourcePurpose::BackingFile,
  )?
  .ok_or_else(|| Error::not_found("unable to resolve the parent vmdk image"))?;
  if &parent_path == identity.logical_path() {
    return Err(Error::invalid_format(
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
    return Err(Error::invalid_format(format!(
      "resolved parent content id {} does not match expected {}",
      parent_image.content_id(),
      expected_content_id
    )));
  }

  Ok(parent_image)
}

pub(super) fn resolve_extent_source(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, extent_name: &str,
) -> Result<Option<(ByteSourceHandle, RelatedPathBuf)>> {
  resolve_named_source(
    resolver,
    identity,
    extent_name,
    RelatedSourcePurpose::Extent,
  )
}

pub(super) fn resolve_named_source(
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity, name: &str,
  purpose: RelatedSourcePurpose,
) -> Result<Option<(ByteSourceHandle, RelatedPathBuf)>> {
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
