//! Read-only PDI image surface.

use std::{
  collections::{HashMap, HashSet},
  sync::Arc,
};

use super::{
  DESCRIPTOR,
  descriptor::{
    PdiDescriptor, PdiDescriptorImage, PdiDescriptorImageType, PdiSnapshot, PdiStorageExtent,
  },
  sparse_extent::PdiSparseExtent,
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, RelatedSourceResolver, Result, SourceHints,
  SourceIdentity, images::Image,
};

const FIXED_SECTOR_SIZE: u64 = 512;

#[allow(dead_code)]
pub struct PdiImage {
  active_layer: Arc<PdiLayer>,
  media_size: u64,
  logical_sector_size: u32,
  physical_sector_size: u32,
  has_backing_chain: bool,
  is_sparse: bool,
}

struct PdiLayer {
  extents: Vec<PdiLayerExtent>,
  parent: Option<Arc<PdiLayer>>,
  media_size: u64,
}

struct PdiLayerExtent {
  guest_offset: u64,
  size: u64,
  storage: PdiLayerStorage,
}

enum PdiLayerStorage {
  Raw(ByteSourceHandle),
  Sparse(PdiSparseExtent),
}

impl PdiImage {
  pub fn open(_source: ByteSourceHandle) -> Result<Self> {
    Err(Error::invalid_source_reference(
      "pdi images require source hints, a resolver, and a source identity".to_string(),
    ))
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    let resolver = hints.resolver().ok_or_else(|| {
      Error::invalid_source_reference("pdi images require a related-source resolver")
    })?;
    let identity = hints.source_identity().ok_or_else(|| {
      Error::invalid_source_reference("pdi images require a source identity hint")
    })?;

    let xml = String::from_utf8(source.read_all()?)
      .map_err(|_| Error::invalid_format("pdi descriptors must be valid UTF-8"))?;
    let descriptor = PdiDescriptor::from_xml(&xml)?;
    let media_size = descriptor.media_size()?;
    let active_snapshot = select_active_snapshot(&descriptor)?;
    let mut layers = HashMap::new();
    let active_layer = build_layer(
      active_snapshot,
      &descriptor,
      resolver,
      identity,
      &mut layers,
      &mut HashSet::new(),
    )?;
    let has_backing_chain = active_layer.parent.is_some();
    let is_sparse = layer_is_sparse(&active_layer);

    Ok(Self {
      active_layer,
      media_size,
      logical_sector_size: descriptor.logical_sector_size,
      physical_sector_size: descriptor.physical_sector_size,
      has_backing_chain,
      is_sparse,
    })
  }
}

impl ByteSource for PdiImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    self.active_layer.read_at(offset, buf)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size(64 * 1024)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.pdi"
  }
}

impl Image for PdiImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(self.logical_sector_size)
  }

  fn physical_sector_size(&self) -> Option<u32> {
    Some(self.physical_sector_size)
  }

  fn is_sparse(&self) -> bool {
    self.is_sparse
  }

  fn has_backing_chain(&self) -> bool {
    self.has_backing_chain
  }
}

impl PdiLayer {
  fn read_layer_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::invalid_range("pdi read offset overflow"))?;
      if absolute_offset >= self.media_size {
        break;
      }

      if let Some(extent_index) = self.find_extent_index(absolute_offset) {
        let extent = &self.extents[extent_index];
        let within_extent = absolute_offset - extent.guest_offset;
        let available = usize::try_from(
          match &extent.storage {
            PdiLayerStorage::Sparse(sparse) => (extent.size - within_extent)
              .min(sparse.block_size - (within_extent % sparse.block_size)),
            PdiLayerStorage::Raw(_) => extent.size - within_extent,
          }
          .min(self.media_size - absolute_offset)
          .min((buf.len() - copied) as u64),
        )
        .map_err(|_| Error::invalid_range("pdi read chunk is too large"))?;

        match &extent.storage {
          PdiLayerStorage::Raw(source) => {
            source.read_exact_at(within_extent, &mut buf[copied..copied + available])?;
          }
          PdiLayerStorage::Sparse(sparse) => {
            let read_count =
              sparse.read_present_bytes(within_extent, &mut buf[copied..copied + available])?;
            if read_count < available {
              fill_from_parent_or_zero(
                self.parent.as_ref(),
                absolute_offset + read_count as u64,
                &mut buf[copied + read_count..copied + available],
              )?;
            }
          }
        }

        copied += available;
      } else {
        let next_extent_offset = self
          .extents
          .iter()
          .find(|extent| extent.guest_offset > absolute_offset)
          .map(|extent| extent.guest_offset)
          .unwrap_or(self.media_size);
        let available = usize::try_from(
          (next_extent_offset - absolute_offset)
            .min(self.media_size - absolute_offset)
            .min((buf.len() - copied) as u64),
        )
        .map_err(|_| Error::invalid_range("pdi gap size is too large"))?;
        fill_from_parent_or_zero(
          self.parent.as_ref(),
          absolute_offset,
          &mut buf[copied..copied + available],
        )?;
        copied += available;
      }
    }

    Ok(copied)
  }

  fn find_extent_index(&self, offset: u64) -> Option<usize> {
    let index = self
      .extents
      .partition_point(|extent| extent.guest_offset <= offset);
    if index == 0 {
      return None;
    }
    let extent = &self.extents[index - 1];
    (offset < extent.guest_offset + extent.size).then_some(index - 1)
  }
}

fn build_layer(
  snapshot_id: &str, descriptor: &PdiDescriptor, resolver: &dyn RelatedSourceResolver,
  identity: &SourceIdentity, built_layers: &mut HashMap<String, Arc<PdiLayer>>,
  visiting: &mut HashSet<String>,
) -> Result<Arc<PdiLayer>> {
  if let Some(layer) = built_layers.get(snapshot_id).cloned() {
    return Ok(layer);
  }
  if !visiting.insert(snapshot_id.to_string()) {
    return Err(Error::invalid_format(
      "pdi snapshot graph must not contain cycles".to_string(),
    ));
  }

  let snapshot = find_snapshot(descriptor, snapshot_id)
    .ok_or_else(|| Error::invalid_format(format!("missing pdi snapshot: {snapshot_id}")))?;
  let parent = match snapshot.parent_identifier.as_deref() {
    Some(parent_id) => Some(build_layer(
      parent_id,
      descriptor,
      resolver,
      identity,
      built_layers,
      visiting,
    )?),
    None => None,
  };

  let mut extents = Vec::new();
  for extent in &descriptor.extents {
    if let Some(image) = extent
      .images
      .iter()
      .find(|image| image.snapshot_identifier == snapshot_id)
    {
      extents.push(build_extent(extent, image, resolver, identity)?);
    }
  }
  extents.sort_by_key(|extent| extent.guest_offset);
  for pair in extents.windows(2) {
    let left_end = pair[0]
      .guest_offset
      .checked_add(pair[0].size)
      .ok_or_else(|| Error::invalid_range("pdi extent end overflow"))?;
    if left_end > pair[1].guest_offset {
      return Err(Error::invalid_format(
        "pdi layer extents must not overlap".to_string(),
      ));
    }
  }

  let layer = Arc::new(PdiLayer {
    extents,
    parent,
    media_size: descriptor.media_size()?,
  });
  visiting.remove(snapshot_id);
  built_layers.insert(snapshot_id.to_string(), layer.clone());
  Ok(layer)
}

fn build_extent(
  descriptor_extent: &PdiStorageExtent, descriptor_image: &PdiDescriptorImage,
  resolver: &dyn RelatedSourceResolver, identity: &SourceIdentity,
) -> Result<PdiLayerExtent> {
  let guest_offset = descriptor_extent
    .start_sector
    .checked_mul(FIXED_SECTOR_SIZE)
    .ok_or_else(|| Error::invalid_range("pdi extent guest offset overflow"))?;
  let size = descriptor_extent
    .end_sector
    .checked_sub(descriptor_extent.start_sector)
    .and_then(|sector_count| sector_count.checked_mul(FIXED_SECTOR_SIZE))
    .ok_or_else(|| Error::invalid_range("pdi extent size overflow"))?;

  let source = resolve_named_source(
    resolver,
    identity,
    &descriptor_image.file_name,
    RelatedSourcePurpose::Extent,
  )?
  .ok_or_else(|| {
    Error::not_found(format!(
      "missing pdi extent file: {}",
      descriptor_image.file_name
    ))
  })?
  .0;

  let storage = match descriptor_image.image_type {
    PdiDescriptorImageType::Plain => {
      if source.size()? != size {
        return Err(Error::invalid_format(
          "pdi plain extent size does not match the descriptor range".to_string(),
        ));
      }
      PdiLayerStorage::Raw(source)
    }
    PdiDescriptorImageType::Compressed => PdiLayerStorage::Sparse(PdiSparseExtent::open(
      source,
      descriptor_extent.end_sector - descriptor_extent.start_sector,
      descriptor_extent.block_size_sectors,
    )?),
  };

  Ok(PdiLayerExtent {
    guest_offset,
    size,
    storage,
  })
}

fn select_active_snapshot(descriptor: &PdiDescriptor) -> Result<&str> {
  if descriptor.snapshots.is_empty() {
    return Err(Error::invalid_format(
      "pdi descriptors must contain at least one snapshot".to_string(),
    ));
  }

  let child_parents = descriptor
    .snapshots
    .iter()
    .filter_map(|snapshot| snapshot.parent_identifier.as_deref())
    .collect::<HashSet<_>>();
  let leaves = descriptor
    .snapshots
    .iter()
    .filter(|snapshot| !child_parents.contains(snapshot.identifier.as_str()))
    .collect::<Vec<_>>();
  if leaves.is_empty() {
    return Err(Error::invalid_format(
      "pdi descriptor does not contain a leaf snapshot".to_string(),
    ));
  }
  if leaves.len() == 1 {
    return Ok(leaves[0].identifier.as_str());
  }

  let mut best = None::<(&str, usize)>;
  for leaf in leaves {
    let depth = snapshot_depth(&descriptor.snapshots, &leaf.identifier)?;
    match best {
      Some((_, best_depth)) if depth < best_depth => {}
      Some((_, best_depth)) if depth == best_depth => {
        return Err(Error::invalid_format(
          "pdi descriptors with multiple equally-deep snapshot leaves are ambiguous".to_string(),
        ));
      }
      _ => best = Some((leaf.identifier.as_str(), depth)),
    }
  }

  best
    .map(|(id, _)| id)
    .ok_or_else(|| Error::invalid_format("missing pdi active snapshot"))
}

fn snapshot_depth(snapshots: &[PdiSnapshot], snapshot_id: &str) -> Result<usize> {
  let mut depth = 0usize;
  let mut current = Some(snapshot_id);
  let mut seen = HashSet::new();
  while let Some(identifier) = current {
    if !seen.insert(identifier.to_string()) {
      return Err(Error::invalid_format(
        "pdi snapshot graph must not contain cycles".to_string(),
      ));
    }
    let snapshot = snapshots
      .iter()
      .find(|snapshot| snapshot.identifier == identifier)
      .ok_or_else(|| Error::invalid_format(format!("missing pdi snapshot: {identifier}")))?;
    current = snapshot.parent_identifier.as_deref();
    if current.is_some() {
      depth += 1;
    }
  }
  Ok(depth)
}

fn find_snapshot<'a>(descriptor: &'a PdiDescriptor, snapshot_id: &str) -> Option<&'a PdiSnapshot> {
  descriptor
    .snapshots
    .iter()
    .find(|snapshot| snapshot.identifier == snapshot_id)
}

fn layer_is_sparse(layer: &PdiLayer) -> bool {
  layer
    .extents
    .iter()
    .any(|extent| matches!(extent.storage, PdiLayerStorage::Sparse(_)))
    || layer.parent.is_some()
}

fn fill_from_parent_or_zero(
  parent: Option<&Arc<PdiLayer>>, offset: u64, buf: &mut [u8],
) -> Result<()> {
  if let Some(parent) = parent {
    parent.read_exact_at(offset, buf)?;
  } else {
    buf.fill(0);
  }
  Ok(())
}

impl ByteSource for PdiLayer {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    self.read_layer_at(offset, buf)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size(64 * 1024)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.pdi.layer"
  }
}

fn resolve_named_source(
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

  let file_name = name.rsplit(['/', '\\']).next().unwrap_or(name);
  let sibling = identity.sibling_path(file_name)?;
  Ok(
    resolver
      .resolve(&RelatedSourceRequest::new(purpose, sibling.clone()))?
      .map(|source| (source, sibling)),
  )
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;

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

  fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
  }

  fn descriptor_xml(
    images: &[(&str, &str, u64, u64, u32, &str)], snapshots: &[(&str, Option<&str>)],
  ) -> String {
    let mut storage_xml = String::new();
    for (guid, file_name, start, end, blocksize, image_type) in images {
      storage_xml.push_str(&format!(
        "<Storage><Start>{start}</Start><End>{end}</End><Blocksize>{blocksize}</Blocksize><Image><GUID>{{{guid}}}</GUID><Type>{image_type}</Type><File>{file_name}</File></Image></Storage>"
      ));
    }

    let mut snapshots_xml = String::new();
    for (guid, parent) in snapshots {
      let parent = parent.unwrap_or("00000000-0000-0000-0000-000000000000");
      snapshots_xml.push_str(&format!(
        "<Shot><GUID>{{{guid}}}</GUID><ParentGUID>{{{parent}}}</ParentGUID></Shot>"
      ));
    }

    format!(
      "<?xml version='1.0' encoding='UTF-8'?><Parallels_disk_image Version=\"1.0\"><Disk_Parameters><Disk_size>4</Disk_size><PhysicalSectorSize>4096</PhysicalSectorSize><LogicSectorSize>512</LogicSectorSize></Disk_Parameters><StorageData>{storage_xml}</StorageData><Snapshots>{snapshots_xml}</Snapshots></Parallels_disk_image>"
    )
  }

  fn plain_extent(fill: u8) -> ByteSourceHandle {
    Arc::new(MemDataSource {
      data: vec![fill; 2048],
    })
  }

  fn sparse_extent(first_block: Option<u8>, second_block: Option<u8>) -> ByteSourceHandle {
    let mut data = vec![0u8; 2560];
    data[0..16].copy_from_slice(b"WithoutFreeSpace");
    data[16..20].copy_from_slice(&2u32.to_le_bytes());
    data[28..32].copy_from_slice(&2u32.to_le_bytes());
    data[32..36].copy_from_slice(&2u32.to_le_bytes());
    data[36..44].copy_from_slice(&4u64.to_le_bytes());
    data[48..52].copy_from_slice(&1u32.to_le_bytes());
    data[64..68].copy_from_slice(&1u32.to_le_bytes());
    data[68..72].copy_from_slice(&(u32::from(second_block.is_some()) * 3).to_le_bytes());
    if let Some(fill) = first_block {
      data[512..1536].fill(fill);
    }
    if let Some(fill) = second_block {
      data[1536..2560].fill(fill);
    }
    Arc::new(MemDataSource { data })
  }

  #[test]
  fn opens_fixture_metadata_and_reads_full_media() {
    let descriptor = sample_source("pdi/hfsplus.hdd/DiskDescriptor.xml");
    let extent =
      sample_source("pdi/hfsplus.hdd/hfsplus.hdd.0.{5fbaabe3-6958-40ff-92a7-860e329aab41}.hds");
    let resolver = Resolver {
      files: HashMap::from([(
        "pdi/hfsplus.hdd/hfsplus.hdd.0.{5fbaabe3-6958-40ff-92a7-860e329aab41}.hds".to_string(),
        extent,
      )]),
    };
    let identity =
      SourceIdentity::from_relative_path("pdi/hfsplus.hdd/DiskDescriptor.xml").unwrap();

    let image = PdiImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.size().unwrap(), 33_554_432);
    assert_eq!(image.logical_sector_size(), Some(512));
    assert_eq!(image.physical_sector_size(), Some(4096));
    assert!(image.is_sparse());
    assert_eq!(
      md5_hex(&image.read_all().unwrap()),
      "ecaef634016fc699807cec47cef11dda"
    );
  }

  #[test]
  fn opens_plain_pdi_images() {
    let descriptor = Arc::new(MemDataSource {
      data: descriptor_xml(
        &[(
          "11111111-1111-1111-1111-111111111111",
          "disk.raw",
          0,
          4,
          2,
          "Plain",
        )],
        &[("11111111-1111-1111-1111-111111111111", None)],
      )
      .into_bytes(),
    }) as ByteSourceHandle;
    let resolver = Resolver {
      files: HashMap::from([("bundle/disk.raw".to_string(), plain_extent(0x5A))]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/DiskDescriptor.xml").unwrap();

    let image = PdiImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), vec![0x5A; 2048]);
    assert!(!image.has_backing_chain());
  }

  #[test]
  fn overlays_sparse_child_layers_on_top_of_parents() {
    let descriptor = Arc::new(MemDataSource {
      data: descriptor_xml(
        &[
          (
            "11111111-1111-1111-1111-111111111111",
            "base.hds",
            0,
            4,
            2,
            "Compressed",
          ),
          (
            "22222222-2222-2222-2222-222222222222",
            "child.hds",
            0,
            4,
            2,
            "Compressed",
          ),
        ],
        &[
          ("11111111-1111-1111-1111-111111111111", None),
          (
            "22222222-2222-2222-2222-222222222222",
            Some("11111111-1111-1111-1111-111111111111"),
          ),
        ],
      )
      .into_bytes(),
    }) as ByteSourceHandle;
    let resolver = Resolver {
      files: HashMap::from([
        (
          "bundle/base.hds".to_string(),
          sparse_extent(Some(0x41), None),
        ),
        (
          "bundle/child.hds".to_string(),
          sparse_extent(Some(0x42), None),
        ),
      ]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/DiskDescriptor.xml").unwrap();

    let image = PdiImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let mut expected = vec![0x42; 1024];
    expected.extend_from_slice(&vec![0; 1024]);
    assert_eq!(image.read_all().unwrap(), expected);
    assert!(image.has_backing_chain());
  }

  #[test]
  fn rejects_missing_resolver_hints() {
    let result = PdiImage::open(sample_source("pdi/hfsplus.hdd/DiskDescriptor.xml"));

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }

  #[test]
  fn rejects_ambiguous_leaf_snapshots() {
    let descriptor = Arc::new(MemDataSource {
      data: descriptor_xml(
        &[
          (
            "11111111-1111-1111-1111-111111111111",
            "base.hds",
            0,
            4,
            2,
            "Compressed",
          ),
          (
            "22222222-2222-2222-2222-222222222222",
            "child-a.hds",
            0,
            4,
            2,
            "Compressed",
          ),
          (
            "33333333-3333-3333-3333-333333333333",
            "child-b.hds",
            0,
            4,
            2,
            "Compressed",
          ),
        ],
        &[
          ("11111111-1111-1111-1111-111111111111", None),
          (
            "22222222-2222-2222-2222-222222222222",
            Some("11111111-1111-1111-1111-111111111111"),
          ),
          (
            "33333333-3333-3333-3333-333333333333",
            Some("11111111-1111-1111-1111-111111111111"),
          ),
        ],
      )
      .into_bytes(),
    }) as ByteSourceHandle;
    let resolver = Resolver {
      files: HashMap::new(),
    };
    let identity = SourceIdentity::from_relative_path("bundle/DiskDescriptor.xml").unwrap();

    let result = PdiImage::open_with_hints(
      descriptor,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    );

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}

crate::images::driver::impl_image_data_source!(PdiImage);
