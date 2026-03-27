//! APFS container opening and volume enumeration.

use std::{
  cmp::Ordering,
  sync::{Arc, Mutex},
};

use super::{DESCRIPTOR, btree::ApfsBTree, keybag::ApfsUnlockState, ondisk::*};
use crate::{
  ByteSource, ByteSourceHandle, DataSource, DataSourceFacets, DataViewId, DataViewKind,
  DataViewRecord, DataViewSelector, Error, Result,
};

#[derive(Debug, Clone)]
pub struct ApfsVolumeInfo {
  slot_index: usize,
  fs_oid: u64,
  superblock_address: u64,
  superblock: ApfsVolumeSuperblock,
}

#[derive(Clone)]
pub(crate) struct ApfsVolumeOpenContext {
  pub source: ByteSourceHandle,
  pub block_size: u32,
  pub container_xid: u64,
  pub container_uuid: [u8; 16],
  pub container_keybag_prange: Option<ApfsPrange>,
}

impl ApfsVolumeInfo {
  pub(crate) fn new(
    slot_index: usize, fs_oid: u64, superblock_address: u64, superblock: ApfsVolumeSuperblock,
  ) -> Self {
    Self {
      slot_index,
      fs_oid,
      superblock_address,
      superblock,
    }
  }

  pub fn slot_index(&self) -> usize {
    self.slot_index
  }

  pub fn object_id(&self) -> u64 {
    self.fs_oid
  }

  pub fn superblock_address(&self) -> u64 {
    self.superblock_address
  }

  pub fn superblock_xid(&self) -> u64 {
    self.superblock.header.xid
  }

  pub fn fs_index(&self) -> u32 {
    self.superblock.fs_index
  }

  pub fn name(&self) -> &str {
    &self.superblock.volume_name
  }

  pub fn uuid_string(&self) -> String {
    format_uuid_le(&self.superblock.volume_uuid)
  }

  pub fn role(&self) -> u16 {
    self.superblock.role
  }

  pub fn role_names(&self) -> Vec<String> {
    apfs_role_names(self.superblock.role)
      .into_iter()
      .map(str::to_string)
      .collect()
  }

  pub fn volume_group_id_string(&self) -> Option<String> {
    (self.superblock.volume_group_id != [0; 16])
      .then(|| format_uuid_le(&self.superblock.volume_group_id))
  }

  pub fn is_case_insensitive(&self) -> bool {
    self.superblock.is_case_insensitive()
  }

  pub fn is_normalization_insensitive(&self) -> bool {
    self.superblock.is_normalization_insensitive()
  }

  pub fn is_sealed(&self) -> bool {
    self.superblock.is_sealed()
  }

  pub fn has_dataless_snapshots(&self) -> bool {
    self.superblock.has_dataless_snapshots()
  }

  pub fn has_secondary_fs_root(&self) -> bool {
    self.superblock.has_secondary_fs_root()
  }

  pub fn uses_volume_group_system_inode_space(&self) -> bool {
    self.superblock.uses_volume_group_system_inode_space()
  }

  pub fn is_encrypted(&self) -> bool {
    self.superblock.is_encrypted()
  }

  pub fn omap_oid(&self) -> u64 {
    self.superblock.omap_oid
  }

  pub fn root_tree_oid(&self) -> u64 {
    self.superblock.root_tree_oid
  }

  pub fn snap_meta_tree_oid(&self) -> u64 {
    self.superblock.snap_meta_tree_oid
  }

  pub fn fext_tree_oid(&self) -> u64 {
    self.superblock.fext_tree_oid
  }

  pub fn secondary_root_tree_oid(&self) -> u64 {
    self.superblock.secondary_root_tree_oid
  }

  pub fn integrity_meta_oid(&self) -> u64 {
    self.superblock.integrity_meta_oid
  }

  pub fn incompatible_features(&self) -> u64 {
    self.superblock.incompatible_features
  }

  pub(crate) fn volume_uuid_raw(&self) -> [u8; 16] {
    self.superblock.volume_uuid
  }

  pub(crate) fn fs_flags(&self) -> u64 {
    self.superblock.fs_flags
  }

  pub fn number_of_snapshots(&self) -> u64 {
    self.superblock.number_of_snapshots
  }

  fn to_view_record(&self) -> DataViewRecord {
    let mut record = DataViewRecord::new(
      DataViewId::from_u64(self.fs_oid),
      DataViewKind::Volume,
      DataSourceFacets::none(),
    )
    .with_tag("index", self.slot_index.to_string())
    .with_tag("fs_index", self.superblock.fs_index.to_string())
    .with_tag("fs_oid", self.fs_oid.to_string())
    .with_tag("xid", self.superblock.header.xid.to_string())
    .with_tag("uuid", self.uuid_string())
    .with_tag("role", self.role_names().join(","))
    .with_tag("role_mask", format!("0x{:04x}", self.superblock.role))
    .with_tag("superblock_address", self.superblock_address.to_string())
    .with_tag("case_insensitive", self.is_case_insensitive().to_string())
    .with_tag(
      "normalization_insensitive",
      self.is_normalization_insensitive().to_string(),
    )
    .with_tag("sealed", self.is_sealed().to_string())
    .with_tag("encrypted", self.is_encrypted().to_string())
    .with_tag(
      "dataless_snapshots",
      self.has_dataless_snapshots().to_string(),
    )
    .with_tag(
      "secondary_fs_root",
      self.has_secondary_fs_root().to_string(),
    )
    .with_tag(
      "volgrp_system_ino_space",
      self.uses_volume_group_system_inode_space().to_string(),
    );
    if let Some(group_id) = self.volume_group_id_string() {
      record = record.with_tag("volume_group_id", group_id);
    }
    if self.secondary_root_tree_oid() != 0 {
      record = record.with_tag(
        "secondary_root_tree_oid",
        self.secondary_root_tree_oid().to_string(),
      );
    }
    if !self.name().is_empty() {
      record = record.with_name(self.name().to_string());
    }
    record
  }
}

#[derive(Clone)]
pub struct ApfsVolume {
  pub(crate) source: ByteSourceHandle,
  pub(crate) block_size: u32,
  container_xid: u64,
  info: ApfsVolumeInfo,
  pub(crate) container_uuid: [u8; 16],
  pub(crate) container_keybag_prange: Option<ApfsPrange>,
  pub(crate) omap_oid_override: Option<u64>,
  pub(crate) unlock_state: Option<Arc<ApfsUnlockState>>,
  pub(crate) namespace_index: Arc<Mutex<Option<Arc<super::filesystem::ApfsVolumeIndex>>>>,
  pub(crate) snapshot_index: Arc<Mutex<Option<Arc<[super::filesystem::ApfsSnapshotInfo]>>>>,
  pub(crate) snapshot_info: Option<super::filesystem::ApfsSnapshotInfo>,
}

impl ApfsVolume {
  pub(crate) fn new(
    context: ApfsVolumeOpenContext, info: ApfsVolumeInfo,
    snapshot_info: Option<super::filesystem::ApfsSnapshotInfo>, omap_oid_override: Option<u64>,
    unlock_state: Option<Arc<ApfsUnlockState>>,
  ) -> Self {
    Self {
      source: context.source,
      block_size: context.block_size,
      container_xid: context.container_xid,
      info,
      container_uuid: context.container_uuid,
      container_keybag_prange: context.container_keybag_prange,
      omap_oid_override,
      unlock_state,
      namespace_index: Arc::new(Mutex::new(None)),
      snapshot_index: Arc::new(Mutex::new(None)),
      snapshot_info,
    }
  }

  pub fn info(&self) -> &ApfsVolumeInfo {
    &self.info
  }

  pub fn container_xid(&self) -> u64 {
    self.container_xid
  }

  pub fn snapshot_info(&self) -> Option<&super::filesystem::ApfsSnapshotInfo> {
    self.snapshot_info.as_ref()
  }

  pub(crate) fn open_context(&self) -> ApfsVolumeOpenContext {
    ApfsVolumeOpenContext {
      source: self.source.clone(),
      block_size: self.block_size,
      container_xid: self.container_xid,
      container_uuid: self.container_uuid,
      container_keybag_prange: self.container_keybag_prange,
    }
  }
}

#[derive(Clone)]
pub struct ApfsContainer {
  source: ByteSourceHandle,
  #[allow(dead_code)]
  primary_superblock: ApfsContainerSuperblock,
  current_superblock: ApfsContainerSuperblock,
  #[allow(dead_code)]
  current_omap: ApfsObjectMap,
  checkpoint_superblock_xids: Vec<u64>,
  volumes: Vec<ApfsVolumeInfo>,
}

impl ApfsContainer {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let (primary_superblock, primary_block) = read_primary_superblock(source.as_ref())?;
    primary_superblock.validate(&primary_block, primary_superblock.header.oid)?;

    let (checkpoint_superblock_xids, checkpoint_superblocks) =
      read_checkpoint_superblocks(source.clone(), &primary_superblock)?;

    let mut current_superblock = primary_superblock.clone();
    for candidate in checkpoint_superblocks {
      if candidate.header.xid < current_superblock.header.xid {
        continue;
      }
      if candidate.compare_layout(&primary_superblock).is_err() {
        continue;
      }
      if validate_object_map(source.as_ref(), candidate.block_size, candidate.omap_oid).is_err() {
        continue;
      }
      current_superblock = candidate;
      break;
    }

    let current_omap = read_object_map(
      source.as_ref(),
      current_superblock.block_size,
      current_superblock.omap_oid,
    )?;
    let volumes = enumerate_volumes(source.clone(), &current_superblock, &current_omap)?;

    Ok(Self {
      source,
      primary_superblock,
      current_superblock,
      current_omap,
      checkpoint_superblock_xids,
      volumes,
    })
  }

  #[allow(dead_code)]
  pub(crate) fn primary_superblock(&self) -> &ApfsContainerSuperblock {
    &self.primary_superblock
  }

  #[allow(dead_code)]
  pub(crate) fn current_superblock(&self) -> &ApfsContainerSuperblock {
    &self.current_superblock
  }

  #[allow(dead_code)]
  pub(crate) fn current_omap(&self) -> &ApfsObjectMap {
    &self.current_omap
  }

  pub fn xid(&self) -> u64 {
    self.current_superblock.header.xid
  }

  pub fn checkpoint_superblock_xids(&self) -> &[u64] {
    &self.checkpoint_superblock_xids
  }

  pub fn volumes(&self) -> &[ApfsVolumeInfo] {
    &self.volumes
  }

  pub fn open_volume_by_index(&self, index: usize) -> Result<ApfsVolume> {
    let info = self
      .volumes
      .get(index)
      .cloned()
      .ok_or_else(|| Error::NotFound(format!("apfs volume index {index} is out of bounds")))?;
    Ok(ApfsVolume::new(
      ApfsVolumeOpenContext {
        source: self.source.clone(),
        block_size: self.current_superblock.block_size,
        container_xid: self.xid(),
        container_uuid: self.current_superblock.uuid,
        container_keybag_prange: self.current_superblock.container_keybag_prange,
      },
      info,
      None,
      None,
      None,
    ))
  }

  pub fn open_volume_by_name(&self, name: &str) -> Result<ApfsVolume> {
    let info = self
      .volumes
      .iter()
      .find(|volume| volume.name() == name)
      .cloned()
      .ok_or_else(|| Error::NotFound(format!("apfs volume name was not found: {name}")))?;
    Ok(ApfsVolume::new(
      ApfsVolumeOpenContext {
        source: self.source.clone(),
        block_size: self.current_superblock.block_size,
        container_xid: self.xid(),
        container_uuid: self.current_superblock.uuid,
        container_keybag_prange: self.current_superblock.container_keybag_prange,
      },
      info,
      None,
      None,
      None,
    ))
  }

  fn open_volume_with_selector(&self, selector: &DataViewSelector<'_>) -> Result<ApfsVolume> {
    if let DataViewSelector::Name(name) = selector {
      return self.open_volume_by_name(name);
    }

    let info = self
      .volumes
      .iter()
      .find(|volume| selector.matches(&volume.to_view_record()))
      .cloned()
      .ok_or_else(|| {
        Error::NotFound(format!(
          "apfs volume selector did not match any volume: {selector:?}"
        ))
      })?;
    Ok(ApfsVolume::new(
      ApfsVolumeOpenContext {
        source: self.source.clone(),
        block_size: self.current_superblock.block_size,
        container_xid: self.xid(),
        container_uuid: self.current_superblock.uuid,
        container_keybag_prange: self.current_superblock.container_keybag_prange,
      },
      info,
      None,
      None,
      None,
    ))
  }
}

impl DataSource for ApfsContainer {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn facets(&self) -> DataSourceFacets {
    DataSourceFacets::none().with_views()
  }

  fn views(&self) -> Result<Vec<DataViewRecord>> {
    Ok(
      self
        .volumes
        .iter()
        .map(ApfsVolumeInfo::to_view_record)
        .collect(),
    )
  }

  fn open_view(
    &self, selector: &DataViewSelector<'_>, options: crate::OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    let volume = self.open_volume_with_selector(selector)?;
    if options.credentials.is_empty() {
      Ok(Box::new(volume))
    } else {
      volume.reopen(options)
    }
  }
}

pub(crate) fn probe_apfs_container(source: &dyn ByteSource) -> Result<bool> {
  let Ok((superblock, block)) = read_primary_superblock(source) else {
    return Ok(false);
  };
  Ok(superblock.validate(&block, superblock.header.oid).is_ok())
}

fn enumerate_volumes(
  source: ByteSourceHandle, superblock: &ApfsContainerSuperblock, omap: &ApfsObjectMap,
) -> Result<Vec<ApfsVolumeInfo>> {
  let omap_tree = ApfsBTree::open(source.clone(), superblock.block_size, omap.tree_oid)?;
  let mut volumes = Vec::with_capacity(superblock.file_system_oids.len());
  for (slot_index, fs_oid) in superblock.file_system_oids.iter().copied().enumerate() {
    let superblock_address = lookup_omap_address(&omap_tree, fs_oid, superblock.header.xid)?;
    let block = read_blocks(
      source.as_ref(),
      superblock.block_size,
      superblock_address,
      1,
    )?;
    let volume_superblock = ApfsVolumeSuperblock::parse(&block)?;
    volume_superblock.validate(&block)?;
    volumes.push(ApfsVolumeInfo::new(
      slot_index,
      fs_oid,
      superblock_address,
      volume_superblock,
    ));
  }
  Ok(volumes)
}

fn read_primary_superblock(source: &dyn ByteSource) -> Result<(ApfsContainerSuperblock, Vec<u8>)> {
  let initial = source.read_bytes_at(0, DEFAULT_BLOCK_SIZE)?;
  if initial.len() < 40 {
    return Err(Error::InvalidFormat(
      "apfs source is too small to contain a container superblock".to_string(),
    ));
  }
  let initial_superblock = ApfsContainerSuperblock::parse(&initial)?;
  let block = if usize::try_from(initial_superblock.block_size)
    .map_err(|_| Error::InvalidRange("apfs block size exceeds usize".to_string()))?
    == initial.len()
  {
    initial
  } else {
    source.read_bytes_at(
      0,
      usize::try_from(initial_superblock.block_size)
        .map_err(|_| Error::InvalidRange("apfs block size exceeds usize".to_string()))?,
    )?
  };
  let superblock = ApfsContainerSuperblock::parse(&block)?;
  Ok((superblock, block))
}

fn read_checkpoint_superblocks(
  source: ByteSourceHandle, primary: &ApfsContainerSuperblock,
) -> Result<(Vec<u64>, Vec<ApfsContainerSuperblock>)> {
  let mut objects = read_checkpoint_object_blocks(source.clone(), primary)?;
  let mut xids = Vec::new();
  let mut superblocks = Vec::new();
  for (address, block) in objects.drain(..) {
    let Ok(header) = ApfsObjectHeader::parse(&block) else {
      continue;
    };
    if header.type_code() != OBJECT_TYPE_NX_SUPERBLOCK {
      continue;
    }
    xids.push(header.xid);

    let Ok(superblock) = ApfsContainerSuperblock::parse(&block) else {
      continue;
    };
    if superblock.validate(&block, address).is_err() {
      continue;
    }
    superblocks.push(superblock);
  }

  superblocks.sort_by_key(|superblock| std::cmp::Reverse(superblock.header.xid));
  xids.sort_by(|left, right| right.cmp(left));
  Ok((xids, superblocks))
}

fn read_checkpoint_object_blocks(
  source: ByteSourceHandle, superblock: &ApfsContainerSuperblock,
) -> Result<Vec<(u64, Vec<u8>)>> {
  let block_size = superblock.block_size;
  if superblock.descriptor_area_block_count() == 0 {
    return Ok(Vec::new());
  }

  if !superblock.descriptor_area_is_btree() {
    return (0..u64::from(superblock.descriptor_area_block_count()))
      .map(|index| {
        let address = superblock
          .checkpoint_descriptor_base
          .checked_add(index)
          .ok_or_else(|| Error::InvalidRange("apfs checkpoint address overflow".to_string()))?;
        Ok((
          address,
          read_blocks(source.as_ref(), block_size, address, 1)?,
        ))
      })
      .collect();
  }

  let tree = ApfsBTree::open(
    source.clone(),
    block_size,
    superblock.checkpoint_descriptor_base,
  )?;
  let mut objects = Vec::new();
  for (_, value) in tree.walk_records()? {
    let prange = ApfsPrange::parse(&value)?;
    if prange.block_count == 0 {
      continue;
    }
    objects.push((
      prange.start_paddr,
      read_blocks(
        source.as_ref(),
        block_size,
        prange.start_paddr,
        prange.block_count,
      )?,
    ));
  }
  Ok(objects)
}

fn validate_object_map(source: &dyn ByteSource, block_size: u32, address: u64) -> Result<()> {
  let block = read_blocks(source, block_size, address, 1)?;
  let omap = ApfsObjectMap::parse(&block)?;
  omap.validate(&block, address)
}

pub(crate) fn read_object_map(
  source: &dyn ByteSource, block_size: u32, address: u64,
) -> Result<ApfsObjectMap> {
  let block = read_blocks(source, block_size, address, 1)?;
  let omap = ApfsObjectMap::parse(&block)?;
  omap.validate(&block, address)?;
  Ok(omap)
}

pub(crate) fn lookup_omap_address(tree: &ApfsBTree, oid: u64, xid: u64) -> Result<u64> {
  let (key, value) = tree.search_floor(|other| compare_omap_key(other, oid, xid))?;
  if key.len() != 16 {
    return Err(Error::InvalidFormat(
      "apfs omap key must be 16 bytes".to_string(),
    ));
  }
  let key_oid = read_u64_le(&key, 0)?;
  if key_oid != oid {
    return Err(Error::NotFound(format!(
      "apfs omap entry was not found for oid {oid}"
    )));
  }
  if value.len() < 16 {
    return Err(Error::InvalidFormat(
      "apfs omap value must be at least 16 bytes".to_string(),
    ));
  }
  let flags = read_u32_le(&value, 0)?;
  if (flags & OMAP_VAL_DELETED) != 0 {
    return Err(Error::NotFound(format!(
      "apfs omap entry for oid {oid} is marked deleted"
    )));
  }
  read_u64_le(&value, 8)
}

fn compare_omap_key(other: &[u8], oid: u64, xid: u64) -> Ordering {
  let other_oid = read_u64_le(other, 0).unwrap_or(0);
  let other_xid = read_u64_le(other, 8).unwrap_or(0);
  match other_oid.cmp(&oid) {
    Ordering::Equal => other_xid.cmp(&xid),
    ordering => ordering,
  }
}

pub(crate) fn read_blocks(
  source: &dyn ByteSource, block_size: u32, address: u64, count: u64,
) -> Result<Vec<u8>> {
  let byte_offset = address
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("apfs block offset overflow".to_string()))?;
  let byte_count = count
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::InvalidRange("apfs block byte count overflow".to_string()))?;
  let byte_count = usize::try_from(byte_count)
    .map_err(|_| Error::InvalidRange("apfs block byte count exceeds usize".to_string()))?;
  source.read_bytes_at(byte_offset, byte_count)
}
