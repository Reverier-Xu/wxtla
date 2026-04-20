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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApfsObjectMapInfo {
  pub flags: u32,
  pub snapshot_count: u32,
  pub tree_type: u32,
  pub snapshot_tree_type: u32,
  pub tree_oid: u64,
  pub snapshot_tree_oid: u64,
  pub most_recent_snapshot_xid: u64,
}

impl ApfsObjectMapInfo {
  pub fn flag_names(&self) -> Vec<&'static str> {
    apfs_omap_flag_names(self.flags)
  }

  pub fn tree_type_name(&self) -> &'static str {
    apfs_object_type_name(self.tree_type)
  }

  pub fn tree_storage_kind_name(&self) -> &'static str {
    apfs_object_storage_kind_name(self.tree_type)
  }

  pub fn tree_flag_names(&self) -> Vec<&'static str> {
    apfs_object_flag_names(self.tree_type)
  }

  pub fn snapshot_tree_type_name(&self) -> &'static str {
    apfs_object_type_name(self.snapshot_tree_type)
  }

  pub fn snapshot_tree_storage_kind_name(&self) -> &'static str {
    apfs_object_storage_kind_name(self.snapshot_tree_type)
  }
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

  pub fn meta_crypto(&self) -> super::ondisk::ApfsMetaCryptoState {
    self.superblock.meta_crypto
  }

  pub fn unmount_time(&self) -> u64 {
    self.superblock.unmount_time
  }

  pub fn reserve_block_count(&self) -> u64 {
    self.superblock.reserve_block_count
  }

  pub fn quota_block_count(&self) -> u64 {
    self.superblock.quota_block_count
  }

  pub fn alloc_block_count(&self) -> u64 {
    self.superblock.alloc_block_count
  }

  pub fn number_of_files(&self) -> u64 {
    self.superblock.number_of_files
  }

  pub fn number_of_directories(&self) -> u64 {
    self.superblock.number_of_directories
  }

  pub fn number_of_symlinks(&self) -> u64 {
    self.superblock.number_of_symlinks
  }

  pub fn number_of_other_fsobjects(&self) -> u64 {
    self.superblock.number_of_other_fsobjects
  }

  pub fn total_blocks_allocated(&self) -> u64 {
    self.superblock.total_blocks_allocated
  }

  pub fn total_blocks_freed(&self) -> u64 {
    self.superblock.total_blocks_freed
  }

  pub fn formatted_by(&self) -> Option<super::ondisk::ApfsChangeInfo> {
    (!self.superblock.formatted_by.is_empty()).then(|| self.superblock.formatted_by.clone())
  }

  pub fn modified_by(&self) -> Vec<super::ondisk::ApfsChangeInfo> {
    self
      .superblock
      .modified_by
      .iter()
      .filter(|entry| !entry.is_empty())
      .cloned()
      .collect()
  }

  pub fn uses_volume_group_system_inode_space(&self) -> bool {
    self.superblock.uses_volume_group_system_inode_space()
  }

  pub fn feature_names(&self) -> Vec<&'static str> {
    apfs_feature_names(self.superblock.features)
  }

  pub fn incompat_feature_names(&self) -> Vec<&'static str> {
    apfs_incompat_feature_names(self.superblock.incompatible_features)
  }

  pub fn fs_flag_names(&self) -> Vec<&'static str> {
    apfs_fs_flag_names(self.superblock.fs_flags)
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

  pub fn root_tree_type(&self) -> u32 {
    self.superblock.root_tree_type
  }

  pub fn extentref_tree_type(&self) -> u32 {
    self.superblock.extentref_tree_type
  }

  pub fn snap_meta_tree_type(&self) -> u32 {
    self.superblock.snap_meta_tree_type
  }

  pub fn snap_meta_tree_oid(&self) -> u64 {
    self.superblock.snap_meta_tree_oid
  }

  pub fn revert_to_xid(&self) -> u64 {
    self.superblock.revert_to_xid
  }

  pub fn revert_to_superblock_oid(&self) -> u64 {
    self.superblock.revert_to_sblock_oid
  }

  pub fn next_object_id(&self) -> u64 {
    self.superblock.next_object_id
  }

  pub fn last_modification_time(&self) -> u64 {
    self.superblock.last_modification_time
  }

  pub fn next_document_id(&self) -> u32 {
    self.superblock.next_document_id
  }

  pub fn root_to_xid(&self) -> u64 {
    self.superblock.root_to_xid
  }

  pub fn encryption_rolling_state_oid(&self) -> u64 {
    self.superblock.encryption_rolling_state_oid
  }

  pub fn snap_meta_ext_oid(&self) -> u64 {
    self.superblock.snap_meta_ext_oid
  }

  pub fn fext_tree_oid(&self) -> u64 {
    self.superblock.fext_tree_oid
  }

  pub fn fext_tree_type(&self) -> u32 {
    self.superblock.fext_tree_type
  }

  pub fn pfkur_tree_type(&self) -> u32 {
    self.superblock.pfkur_tree_type
  }

  pub fn pfkur_tree_oid(&self) -> u64 {
    self.superblock.pfkur_tree_oid
  }

  pub fn secondary_root_tree_oid(&self) -> u64 {
    self.superblock.secondary_root_tree_oid
  }

  pub fn clone_group_tree_flags(&self) -> u32 {
    self.superblock.clone_group_tree_flags
  }

  pub fn doc_id_index_xid(&self) -> u64 {
    self.superblock.doc_id_index_xid
  }

  pub fn doc_id_index_flags(&self) -> u32 {
    self.superblock.doc_id_index_flags
  }

  pub fn doc_id_tree_type(&self) -> u32 {
    self.superblock.doc_id_tree_type
  }

  pub fn doc_id_tree_oid(&self) -> u64 {
    self.superblock.doc_id_tree_oid
  }

  pub fn previous_doc_id_tree_oid(&self) -> u64 {
    self.superblock.prev_doc_id_tree_oid
  }

  pub fn doc_id_fixup_cursor(&self) -> u64 {
    self.superblock.doc_id_fixup_cursor
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
    .with_tag("features", self.feature_names().join(","))
    .with_tag("incompat_features", self.incompat_feature_names().join(","))
    .with_tag("fs_flags", self.fs_flag_names().join(","))
    .with_tag("role_mask", format!("0x{:04x}", self.superblock.role))
    .with_tag("root_tree_type", self.root_tree_type().to_string())
    .with_tag(
      "extentref_tree_type",
      self.extentref_tree_type().to_string(),
    )
    .with_tag(
      "snap_meta_tree_type",
      self.snap_meta_tree_type().to_string(),
    )
    .with_tag("superblock_address", self.superblock_address.to_string())
    .with_tag("case_insensitive", self.is_case_insensitive().to_string())
    .with_tag(
      "normalization_insensitive",
      self.is_normalization_insensitive().to_string(),
    )
    .with_tag("sealed", self.is_sealed().to_string())
    .with_tag("encrypted", self.is_encrypted().to_string())
    .with_tag(
      "last_modification_time",
      self.last_modification_time().to_string(),
    )
    .with_tag("next_object_id", self.next_object_id().to_string())
    .with_tag("next_document_id", self.next_document_id().to_string())
    .with_tag("root_to_xid", self.root_to_xid().to_string())
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
      record = record.with_tag(
        "secondary_root_tree_type",
        self.superblock.secondary_root_tree_type.to_string(),
      );
    }
    if self.pfkur_tree_oid() != 0 {
      record = record
        .with_tag("pfkur_tree_type", self.pfkur_tree_type().to_string())
        .with_tag("pfkur_tree_oid", self.pfkur_tree_oid().to_string());
    }
    if self.doc_id_tree_oid() != 0 {
      record = record
        .with_tag("doc_id_tree_type", self.doc_id_tree_type().to_string())
        .with_tag("doc_id_tree_oid", self.doc_id_tree_oid().to_string())
        .with_tag(
          "previous_doc_id_tree_oid",
          self.previous_doc_id_tree_oid().to_string(),
        )
        .with_tag(
          "doc_id_fixup_cursor",
          self.doc_id_fixup_cursor().to_string(),
        );
    }
    if self.doc_id_index_xid() != 0
      || self.doc_id_index_flags() != 0
      || self.doc_id_tree_type() != 0
    {
      record = record
        .with_tag("doc_id_index_xid", self.doc_id_index_xid().to_string())
        .with_tag("doc_id_index_flags", self.doc_id_index_flags().to_string())
        .with_tag("doc_id_tree_type", self.doc_id_tree_type().to_string());
    }
    if self.fext_tree_oid() != 0 {
      record = record.with_tag("fext_tree_type", self.fext_tree_type().to_string());
    }
    if self.snap_meta_ext_oid() != 0 {
      record = record.with_tag("snap_meta_ext_oid", self.snap_meta_ext_oid().to_string());
    }
    if self.encryption_rolling_state_oid() != 0 {
      record = record.with_tag(
        "encryption_rolling_state_oid",
        self.encryption_rolling_state_oid().to_string(),
      );
    }
    if self.revert_to_xid() != 0 || self.revert_to_superblock_oid() != 0 {
      record = record
        .with_tag("revert_to_xid", self.revert_to_xid().to_string())
        .with_tag(
          "revert_to_superblock_oid",
          self.revert_to_superblock_oid().to_string(),
        );
    }
    if self.clone_group_tree_flags() != 0 {
      record = record.with_tag(
        "clone_group_tree_flags",
        self.clone_group_tree_flags().to_string(),
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
  checkpoint_maps: Vec<ApfsCheckpointMap>,
  volumes: Vec<ApfsVolumeInfo>,
}

impl ApfsContainer {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let (primary_superblock, primary_block) = read_primary_superblock(source.as_ref())?;
    primary_superblock.validate(&primary_block, primary_superblock.header.oid)?;

    let (checkpoint_superblock_xids, checkpoint_superblocks, checkpoint_maps) =
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
      checkpoint_maps,
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

  pub fn block_size(&self) -> u32 {
    self.current_superblock.block_size
  }

  pub fn block_count(&self) -> u64 {
    self.current_superblock.block_count
  }

  pub fn uuid_string(&self) -> String {
    format_uuid_le(&self.current_superblock.uuid)
  }

  pub fn features(&self) -> u64 {
    self.current_superblock.features
  }

  pub fn readonly_compatible_features(&self) -> u64 {
    self.current_superblock.readonly_compatible_features
  }

  pub fn incompatible_features(&self) -> u64 {
    self.current_superblock.incompatible_features
  }

  pub fn feature_names(&self) -> Vec<&'static str> {
    nx_feature_names(self.current_superblock.features)
  }

  pub fn incompat_feature_names(&self) -> Vec<&'static str> {
    nx_incompat_feature_names(self.current_superblock.incompatible_features)
  }

  pub fn flag_names(&self) -> Vec<&'static str> {
    nx_flag_names(self.current_superblock.flags)
  }

  pub fn current_object_map(&self) -> ApfsObjectMapInfo {
    ApfsObjectMapInfo {
      flags: self.current_omap.flags,
      snapshot_count: self.current_omap.snapshot_count,
      tree_type: self.current_omap.tree_type,
      snapshot_tree_type: self.current_omap.snapshot_tree_type,
      tree_oid: self.current_omap.tree_oid,
      snapshot_tree_oid: self.current_omap.snapshot_tree_oid,
      most_recent_snapshot_xid: self.current_omap.most_recent_snapshot_xid,
    }
  }

  pub fn test_type(&self) -> u32 {
    self.current_superblock.test_type
  }

  pub fn counters(&self) -> &[u64; 32] {
    &self.current_superblock.counters
  }

  pub fn checksum_set_count(&self) -> u64 {
    self.current_superblock.counters[0]
  }

  pub fn checksum_failure_count(&self) -> u64 {
    self.current_superblock.counters[1]
  }

  pub fn evict_mapping_tree_oid(&self) -> u64 {
    self.current_superblock.evict_mapping_tree_oid
  }

  pub fn test_oid(&self) -> u64 {
    self.current_superblock.test_oid
  }

  pub fn ephemeral_info(&self) -> &[u64; 4] {
    &self.current_superblock.ephemeral_info
  }

  pub fn container_keybag_prange(&self) -> Option<ApfsPrange> {
    self.current_superblock.container_keybag_prange
  }

  pub fn is_fusion(&self) -> bool {
    self.current_superblock.is_fusion()
  }

  pub fn uses_software_crypto(&self) -> bool {
    self.current_superblock.uses_software_crypto()
  }

  pub fn blocked_out_prange(&self) -> Option<ApfsPrange> {
    self.current_superblock.blocked_out_prange
  }

  pub fn fusion_uuid_string(&self) -> Option<String> {
    (self.current_superblock.fusion_uuid != [0; 16])
      .then(|| format_uuid_le(&self.current_superblock.fusion_uuid))
  }

  pub fn fusion_middle_tree_oid(&self) -> u64 {
    self.current_superblock.fusion_middle_tree_oid
  }

  pub fn fusion_wbc_oid(&self) -> u64 {
    self.current_superblock.fusion_wbc_oid
  }

  pub fn fusion_wbc_prange(&self) -> Option<ApfsPrange> {
    self.current_superblock.fusion_wbc_prange
  }

  pub fn newest_mounted_version(&self) -> u64 {
    self.current_superblock.newest_mounted_version
  }

  pub fn media_keybag_prange(&self) -> Option<ApfsPrange> {
    self.current_superblock.media_keybag_prange
  }

  pub fn checkpoint_superblock_xids(&self) -> &[u64] {
    &self.checkpoint_superblock_xids
  }

  pub fn checkpoint_maps(&self) -> &[ApfsCheckpointMap] {
    &self.checkpoint_maps
  }

  pub fn volumes(&self) -> &[ApfsVolumeInfo] {
    &self.volumes
  }

  pub fn open_volume_by_index(&self, index: usize) -> Result<ApfsVolume> {
    let info = self
      .volumes
      .get(index)
      .cloned()
      .ok_or_else(|| Error::not_found(format!("apfs volume index {index} is out of bounds")))?;
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
      .ok_or_else(|| Error::not_found(format!("apfs volume name was not found: {name}")))?;
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

  pub fn open_volume_by_uuid(&self, uuid: &str) -> Result<ApfsVolume> {
    let normalized = uuid.to_ascii_lowercase();
    let info = self
      .volumes
      .iter()
      .find(|volume| volume.uuid_string().to_ascii_lowercase() == normalized)
      .cloned()
      .ok_or_else(|| Error::not_found(format!("apfs volume uuid was not found: {uuid}")))?;
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

  pub fn open_volume_by_role_name(&self, role_name: &str) -> Result<ApfsVolume> {
    let normalized = role_name.to_ascii_lowercase();
    let info = self
      .volumes
      .iter()
      .find(|volume| volume.role_names().iter().any(|role| role == &normalized))
      .cloned()
      .ok_or_else(|| Error::not_found(format!("apfs volume role was not found: {role_name}")))?;
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

  pub fn open_only_volume(&self) -> Result<ApfsVolume> {
    match self.volumes.len() {
      1 => self.open_volume_by_index(0),
      0 => Err(Error::not_found(
        "apfs container has no readable volumes".to_string(),
      )),
      count => Err(Error::unsupported(format!(
        "apfs container exposes {count} volumes; choose one explicitly"
      ))),
    }
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
        Error::not_found(format!(
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
    return Err(Error::invalid_format(
      "apfs source is too small to contain a container superblock".to_string(),
    ));
  }
  let initial_superblock = ApfsContainerSuperblock::parse(&initial)?;
  let block = if usize::try_from(initial_superblock.block_size)
    .map_err(|_| Error::invalid_range("apfs block size exceeds usize"))?
    == initial.len()
  {
    initial
  } else {
    source.read_bytes_at(
      0,
      usize::try_from(initial_superblock.block_size)
        .map_err(|_| Error::invalid_range("apfs block size exceeds usize"))?,
    )?
  };
  let superblock = ApfsContainerSuperblock::parse(&block)?;
  Ok((superblock, block))
}

fn read_checkpoint_superblocks(
  source: ByteSourceHandle, primary: &ApfsContainerSuperblock,
) -> Result<(
  Vec<u64>,
  Vec<ApfsContainerSuperblock>,
  Vec<ApfsCheckpointMap>,
)> {
  let mut objects = read_checkpoint_object_blocks(source.clone(), primary)?;
  let mut xids = Vec::new();
  let mut superblocks = Vec::new();
  let mut maps = Vec::new();
  for (address, block) in objects.drain(..) {
    let Ok(header) = ApfsObjectHeader::parse(&block) else {
      continue;
    };
    match header.type_code() {
      OBJECT_TYPE_NX_SUPERBLOCK => {
        xids.push(header.xid);

        let Ok(superblock) = ApfsContainerSuperblock::parse(&block) else {
          continue;
        };
        if superblock.validate(&block, address).is_err() {
          continue;
        }
        superblocks.push(superblock);
      }
      OBJECT_TYPE_CHECKPOINT_MAP => {
        let Ok(map) = ApfsCheckpointMap::parse(&block) else {
          continue;
        };
        if map.validate(&block).is_err() {
          continue;
        }
        maps.push(map);
      }
      _ => {}
    }
  }

  superblocks.sort_by_key(|superblock| std::cmp::Reverse(superblock.header.xid));
  maps.sort_by_key(|map| std::cmp::Reverse(map.xid()));
  xids.sort_by(|left, right| right.cmp(left));
  Ok((xids, superblocks, maps))
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
          .ok_or_else(|| Error::invalid_range("apfs checkpoint address overflow"))?;
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
    return Err(Error::invalid_format(
      "apfs omap key must be 16 bytes".to_string(),
    ));
  }
  let key_oid = read_u64_le(&key, 0)?;
  if key_oid != oid {
    return Err(Error::not_found(format!(
      "apfs omap entry was not found for oid {oid}"
    )));
  }
  if value.len() < 16 {
    return Err(Error::invalid_format(
      "apfs omap value must be at least 16 bytes".to_string(),
    ));
  }
  let flags = read_u32_le(&value, 0)?;
  if (flags & OMAP_VAL_DELETED) != 0 {
    return Err(Error::not_found(format!(
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
    .ok_or_else(|| Error::invalid_range("apfs block offset overflow"))?;
  let byte_count = count
    .checked_mul(u64::from(block_size))
    .ok_or_else(|| Error::invalid_range("apfs block byte count overflow"))?;
  let byte_count = usize::try_from(byte_count)
    .map_err(|_| Error::invalid_range("apfs block byte count exceeds usize"))?;
  source.read_bytes_at(byte_offset, byte_count)
}
