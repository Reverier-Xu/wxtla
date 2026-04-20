//! APFS live-volume namespace and stream access.

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use lzvn::decode_decmpfs as decode_lzvn_decmpfs;

use super::{
  DESCRIPTOR,
  btree::ApfsBTree,
  container::{ApfsVolume, ApfsVolumeInfo, lookup_omap_address, read_blocks, read_object_map},
  datasource::{
    ApfsDecmpfsDataSource, ApfsExtent, ApfsExtentDataSource, DECMPFS_LZFSE_ATTR,
    DECMPFS_LZFSE_RSRC, DECMPFS_LZVN_ATTR, DECMPFS_LZVN_RSRC, DECMPFS_PLAIN_ATTR,
    DECMPFS_PLAIN_RSRC, DECMPFS_SPARSE_ATTR, DECMPFS_ZLIB_ATTR, DECMPFS_ZLIB_RSRC,
    XATTR_DECMPFS_NAME, decode_compressed_chunk, parse_compressed_resource_entries,
    parse_decmpfs_header,
  },
  helpers::{
    apfs_lookup_name_key, build_path_index, decode_node_id, ensure_openable_content_node,
    special_file_kind_from_mode,
  },
  keybag::{password_hint_for_volume, unlock_volume},
  ondisk::ApfsIntegrityMetadata,
  records::{
    APFS_ROOT_DIRECTORY_OBJECT_ID, APFS_TYPE_DIR_REC, APFS_TYPE_FILE_EXTENT, APFS_TYPE_FILE_INFO,
    APFS_TYPE_INODE, APFS_TYPE_SNAP_METADATA, APFS_TYPE_XATTR, ApfsDirectoryRecord, ApfsFextRecord,
    ApfsFileExtentRecord, ApfsFileInfoRecord, ApfsFsKeyHeader, ApfsInodeRecord,
    ApfsSnapshotMetadataRecord, ApfsStreamStorageSpec, ApfsXattrRecord, UF_COMPRESSED,
    XATTR_RESOURCE_FORK_NAME, XATTR_SYMLINK_NAME, directory_kind_from_flags, node_kind_from_mode,
  },
};
use crate::{
  ByteSourceHandle, BytesDataSource, DataSource, DataSourceFacets, DataViewId, DataViewKind,
  DataViewRecord, DataViewSelector, Error, FormatDescriptor, NamespaceDirectoryEntry,
  NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord, NamespaceSource, NamespaceStreamId,
  NamespaceStreamKind, NamespaceStreamRecord, OpenOptions, Result, filesystems::driver::FileSystem,
};

type ApfsNodeMap = Arc<HashMap<u64, Arc<ApfsNode>>>;
type ApfsChildrenMap = Arc<HashMap<u64, Arc<[NamespaceDirectoryEntry]>>>;
type ApfsXattrMap = Arc<HashMap<u64, Arc<[ApfsStoredXattr]>>>;
type ApfsExtentMap = Arc<HashMap<u64, Arc<[ApfsExtent]>>>;
type ApfsPathMap = Arc<HashMap<u64, Arc<[String]>>>;

#[derive(Clone)]
pub struct ApfsExtendedAttribute {
  pub name: String,
  pub value: Arc<[u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApfsSpecialFileKind {
  BlockDevice,
  CharacterDevice,
  Fifo,
  Socket,
  Whiteout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsNodeDetails {
  pub object_id: u64,
  pub parent_id: u64,
  pub private_id: u64,
  pub create_time: u64,
  pub modification_time: u64,
  pub change_time: u64,
  pub access_time: u64,
  pub children_or_links: u32,
  pub protection_class: u32,
  pub write_generation_counter: u32,
  pub owner: u32,
  pub group: u32,
  pub mode: u16,
  pub internal_flags: u64,
  pub bsd_flags: u32,
  pub compressed: bool,
  pub data_size: u64,
  pub snapshot_xid: Option<u64>,
  pub document_id: Option<u32>,
  pub sparse_bytes: Option<u64>,
  pub rdev: Option<u32>,
  pub names: Vec<String>,
  pub paths: Vec<String>,
  pub special_file_kind: Option<ApfsSpecialFileKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsSnapshotInfo {
  parent_volume_object_id: u64,
  xid: u64,
  superblock_address: u64,
  name: String,
  create_time: u64,
  change_time: u64,
}

impl ApfsSnapshotInfo {
  fn new(
    parent_volume_object_id: u64, xid: u64, superblock_address: u64, name: String,
    create_time: u64, change_time: u64,
  ) -> Self {
    Self {
      parent_volume_object_id,
      xid,
      superblock_address,
      name,
      create_time,
      change_time,
    }
  }

  pub fn xid(&self) -> u64 {
    self.xid
  }

  pub fn name(&self) -> &str {
    &self.name
  }

  pub fn superblock_address(&self) -> u64 {
    self.superblock_address
  }

  pub fn create_time(&self) -> u64 {
    self.create_time
  }

  pub fn change_time(&self) -> u64 {
    self.change_time
  }

  fn to_view_record(&self) -> DataViewRecord {
    DataViewRecord::new(
      DataViewId::from_u64(self.xid),
      DataViewKind::Snapshot,
      DataSourceFacets::namespace(),
    )
    .with_name(self.name.clone())
    .with_parent_id(DataViewId::from_u64(self.parent_volume_object_id))
    .with_tag("xid", self.xid.to_string())
    .with_tag("superblock_address", self.superblock_address.to_string())
  }
}

pub(crate) struct ApfsVolumeIndex {
  nodes: ApfsNodeMap,
  children: ApfsChildrenMap,
  xattrs: ApfsXattrMap,
  extents: ApfsExtentMap,
  paths: ApfsPathMap,
}

pub(super) struct ApfsNode {
  pub(super) record: NamespaceNodeRecord,
  pub(super) parent_id: u64,
  pub(super) create_time: u64,
  pub(super) modification_time: u64,
  pub(super) change_time: u64,
  pub(super) access_time: u64,
  pub(super) children_or_links: u32,
  pub(super) protection_class: u32,
  pub(super) write_generation_counter: u32,
  pub(super) private_id: u64,
  pub(super) owner: u32,
  pub(super) group: u32,
  pub(super) mode: u16,
  pub(super) internal_flags: u64,
  pub(super) data_size: u64,
  pub(super) bsd_flags: u32,
  pub(super) snapshot_xid: Option<u64>,
  pub(super) document_id: Option<u32>,
  pub(super) sparse_bytes: Option<u64>,
  pub(super) rdev: Option<u32>,
  pub(super) compressed: bool,
}

#[derive(Clone)]
struct ApfsStoredXattr {
  name: String,
  storage: ApfsStreamStorageSpec,
}

impl ApfsVolume {
  pub fn symlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    let node = self.lookup_node(node_id)?;
    if node.record.kind != NamespaceNodeKind::Symlink {
      return Ok(None);
    }

    let xattr = self.lookup_xattr(node_id, XATTR_SYMLINK_NAME)?;
    let data = self.open_storage(&xattr.storage)?.read_all()?;
    Ok(Some(
      String::from_utf8_lossy(&data)
        .trim_end_matches('\0')
        .to_string(),
    ))
  }

  pub fn firmlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    let firmlink_flag = (self.lookup_node(node_id)?.bsd_flags & super::records::SF_FIRMLINK) != 0;
    let target = match self.lookup_xattr(node_id, super::records::XATTR_FIRMLINK_NAME) {
      Ok(xattr) => self.open_storage(&xattr.storage)?.read_all()?,
      Err(Error::NotFound(_)) if !firmlink_flag => return Ok(None),
      Err(Error::NotFound(_)) => {
        return Err(Error::invalid_format(
          "apfs firmlink inode is missing the firmlink xattr".to_string(),
        ));
      }
      Err(error) => return Err(error),
    };
    Ok(Some(
      String::from_utf8_lossy(&target)
        .trim_end_matches('\0')
        .to_string(),
    ))
  }

  pub fn is_dataless(&self, node_id: &NamespaceNodeId) -> Result<bool> {
    Ok((self.lookup_node(node_id)?.bsd_flags & super::records::SF_DATALESS) != 0)
  }

  pub fn open_resource_fork(&self, node_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let xattr = self.lookup_xattr(node_id, XATTR_RESOURCE_FORK_NAME)?;
    self.open_storage(&xattr.storage)
  }

  pub fn extended_attributes(
    &self, node_id: &NamespaceNodeId,
  ) -> Result<Vec<ApfsExtendedAttribute>> {
    let identifier = decode_node_id(node_id)?;
    let index = self.namespace_index()?;
    let Some(attributes) = index.xattrs.get(&identifier) else {
      return Ok(Vec::new());
    };

    attributes
      .iter()
      .map(|attribute| {
        Ok(ApfsExtendedAttribute {
          name: attribute.name.clone(),
          value: Arc::from(
            self
              .open_storage(&attribute.storage)?
              .read_all()?
              .into_boxed_slice(),
          ),
        })
      })
      .collect()
  }

  pub fn paths(&self, node_id: &NamespaceNodeId) -> Result<Vec<String>> {
    let identifier = decode_node_id(node_id)?;
    Ok(
      self
        .namespace_index()?
        .paths
        .get(&identifier)
        .map_or_else(Vec::new, |paths| paths.iter().cloned().collect()),
    )
  }

  pub fn names(&self, node_id: &NamespaceNodeId) -> Result<Vec<String>> {
    let node = self.lookup_node(node_id)?;
    let mut names = self
      .paths(node_id)?
      .into_iter()
      .map(|path| {
        path
          .rsplit('/')
          .find(|component| !component.is_empty())
          .map_or_else(|| node.record.path.clone(), str::to_string)
      })
      .collect::<Vec<_>>();
    if names.is_empty() {
      names.push(node.record.path.clone());
    }
    names.sort();
    names.dedup();
    Ok(names)
  }

  pub fn node_details(&self, node_id: &NamespaceNodeId) -> Result<ApfsNodeDetails> {
    let identifier = decode_node_id(node_id)?;
    let node = self.lookup_node(node_id)?;
    let names = self.names(node_id)?;
    let paths = self.paths(node_id)?;

    Ok(ApfsNodeDetails {
      object_id: identifier,
      parent_id: node.parent_id,
      private_id: node.private_id,
      create_time: node.create_time,
      modification_time: node.modification_time,
      change_time: node.change_time,
      access_time: node.access_time,
      children_or_links: node.children_or_links,
      protection_class: node.protection_class,
      write_generation_counter: node.write_generation_counter,
      owner: node.owner,
      group: node.group,
      mode: node.mode,
      internal_flags: node.internal_flags,
      bsd_flags: node.bsd_flags,
      compressed: node.compressed,
      data_size: node.data_size,
      snapshot_xid: node.snapshot_xid,
      document_id: node.document_id,
      sparse_bytes: node.sparse_bytes,
      rdev: node.rdev,
      names,
      paths,
      special_file_kind: special_file_kind_from_mode(node.mode),
    })
  }

  pub fn snapshots(&self) -> Result<Vec<ApfsSnapshotInfo>> {
    Ok(self.snapshot_index()?.as_ref().to_vec())
  }

  pub fn open_snapshot_by_name(&self, name: &str) -> Result<ApfsVolume> {
    let snapshot = self
      .snapshots()?
      .into_iter()
      .find(|snapshot| snapshot.name() == name)
      .ok_or_else(|| Error::not_found(format!("apfs snapshot name was not found: {name}")))?;
    self.open_snapshot(snapshot)
  }

  pub fn open_snapshot_by_xid(&self, xid: u64) -> Result<ApfsVolume> {
    let snapshot = self
      .snapshots()?
      .into_iter()
      .find(|snapshot| snapshot.xid() == xid)
      .ok_or_else(|| Error::not_found(format!("apfs snapshot xid was not found: {xid}")))?;
    self.open_snapshot(snapshot)
  }

  pub fn is_unlocked(&self) -> bool {
    !self.info().is_encrypted() || self.unlock_state.is_some()
  }

  pub fn password_hint(&self) -> Result<Option<String>> {
    if let Some(password_hint) = self
      .unlock_state
      .as_ref()
      .and_then(|state| state.password_hint.clone())
    {
      return Ok(Some(password_hint));
    }

    if !self.info().is_encrypted() {
      return Ok(None);
    }

    password_hint_for_volume(
      self.source.clone(),
      self.block_size,
      self.container_uuid,
      self.container_keybag_prange,
      self.info().volume_uuid_raw(),
    )
  }

  pub fn is_onekey(&self) -> bool {
    (self.info().fs_flags() & crate::filesystems::apfs::ondisk::APFS_FS_ONEKEY) != 0
  }

  pub fn object_map(&self) -> Result<super::container::ApfsObjectMapInfo> {
    let volume_omap = read_object_map(
      self.source.as_ref(),
      self.block_size,
      self
        .omap_oid_override
        .unwrap_or_else(|| self.info().omap_oid()),
    )?;
    Ok(super::container::ApfsObjectMapInfo {
      flags: volume_omap.flags,
      snapshot_count: volume_omap.snapshot_count,
      tree_type: volume_omap.tree_type,
      snapshot_tree_type: volume_omap.snapshot_tree_type,
      tree_oid: volume_omap.tree_oid,
      snapshot_tree_oid: volume_omap.snapshot_tree_oid,
      most_recent_snapshot_xid: volume_omap.most_recent_snapshot_xid,
    })
  }

  pub fn integrity_metadata(&self) -> Result<Option<ApfsIntegrityMetadata>> {
    if self.info().integrity_meta_oid() == 0 {
      return Ok(None);
    }
    let block = read_blocks(
      self.source.as_ref(),
      self.block_size,
      self.info().integrity_meta_oid(),
      1,
    )?;
    Ok(Some(ApfsIntegrityMetadata::parse(&block)?))
  }

  pub fn file_info_records(&self) -> Result<Vec<ApfsFileInfoRecord>> {
    if self.info().is_encrypted() && self.unlock_state.is_none() {
      return Err(Error::invalid_source_reference(
        "apfs volume is locked; reopen the volume with credentials".to_string(),
      ));
    }

    let volume_omap = read_object_map(
      self.source.as_ref(),
      self.block_size,
      self
        .omap_oid_override
        .unwrap_or_else(|| self.info().omap_oid()),
    )?;
    let omap_tree = ApfsBTree::open(self.source.clone(), self.block_size, volume_omap.tree_oid)?;
    let root_tree_address = lookup_omap_address(
      &omap_tree,
      self.info().root_tree_oid(),
      self.info().superblock_xid(),
    )?;
    let fs_tree = ApfsBTree::open_virtual(
      self.source.clone(),
      self.block_size,
      root_tree_address,
      omap_tree,
      self.info().superblock_xid(),
      if self.info().is_sealed() {
        self.info().root_tree_oid()
      } else {
        0
      },
      self.unlock_state.as_ref().map(|state| state.cipher.clone()),
    )?;

    let mut records = Vec::new();
    for (key, value) in fs_tree.walk_records()? {
      let header = ApfsFsKeyHeader::parse(&key)?;
      if header.record_type == APFS_TYPE_FILE_INFO {
        records.push(ApfsFileInfoRecord::parse(&key, &value)?);
      }
    }
    Ok(records)
  }

  pub(crate) fn clone_with_credentials(
    &self, credentials: &[crate::Credential<'_>],
  ) -> Result<ApfsVolume> {
    if credentials.is_empty() || !self.info().is_encrypted() {
      return Ok(self.clone());
    }

    let unlock_state = unlock_volume(
      self.source.clone(),
      self.block_size,
      self.container_uuid,
      self.container_keybag_prange,
      self.info().volume_uuid_raw(),
      self.info().fs_flags(),
      credentials,
    )?;

    Ok(ApfsVolume::new(
      self.open_context(),
      self.info().clone(),
      self.snapshot_info.clone(),
      self.omap_oid_override,
      Some(Arc::new(unlock_state)),
    ))
  }

  fn namespace_index(&self) -> Result<Arc<ApfsVolumeIndex>> {
    if let Some(index) = self
      .namespace_index
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .as_ref()
      .cloned()
    {
      return Ok(index);
    }

    if self.info().is_encrypted() && self.unlock_state.is_none() {
      return Err(Error::invalid_source_reference(
        "apfs volume is locked; reopen the volume with credentials".to_string(),
      ));
    }

    let volume_omap = read_object_map(
      self.source.as_ref(),
      self.block_size,
      self
        .omap_oid_override
        .unwrap_or_else(|| self.info().omap_oid()),
    )?;
    let omap_tree = ApfsBTree::open(self.source.clone(), self.block_size, volume_omap.tree_oid)?;
    let root_tree_address = lookup_omap_address(
      &omap_tree,
      self.info().root_tree_oid(),
      self.info().superblock_xid(),
    )?;
    let fs_tree = ApfsBTree::open_virtual(
      self.source.clone(),
      self.block_size,
      root_tree_address,
      omap_tree,
      self.info().superblock_xid(),
      if self.info().is_sealed() {
        self.info().root_tree_oid()
      } else {
        0
      },
      self.unlock_state.as_ref().map(|state| state.cipher.clone()),
    )?;

    let mut nodes = HashMap::new();
    let mut children = HashMap::new();
    let mut xattrs = HashMap::new();
    let mut extents = HashMap::new();

    for (key, value) in fs_tree.walk_records()? {
      let header = ApfsFsKeyHeader::parse(&key)?;
      match header.record_type {
        APFS_TYPE_INODE => {
          let inode = ApfsInodeRecord::parse(&key, &value)?;
          let kind = node_kind_from_mode(inode.mode);
          let size = if (inode.bsd_flags & UF_COMPRESSED) != 0 {
            inode.uncompressed_size
          } else {
            inode.dstream.map_or(0, |dstream| dstream.size)
          };
          nodes.insert(
            inode.object_id,
            Arc::new(ApfsNode {
              record: NamespaceNodeRecord::new(
                NamespaceNodeId::from_u64(inode.object_id),
                kind,
                size,
              )
              .with_path(inode.name.unwrap_or_default()),
              parent_id: inode.parent_id,
              create_time: inode.create_time,
              modification_time: inode.modification_time,
              change_time: inode.change_time,
              access_time: inode.access_time,
              children_or_links: inode.children_or_links,
              protection_class: inode.protection_class,
              write_generation_counter: inode.write_generation_counter,
              private_id: inode.private_id,
              owner: inode.owner,
              group: inode.group,
              mode: inode.mode,
              internal_flags: inode.internal_flags,
              data_size: inode.dstream.map_or(0, |dstream| dstream.size),
              bsd_flags: inode.bsd_flags,
              snapshot_xid: inode.snapshot_xid,
              document_id: inode.document_id,
              sparse_bytes: inode.sparse_bytes,
              rdev: inode.rdev,
              compressed: (inode.bsd_flags & UF_COMPRESSED) != 0,
            }),
          );
        }
        APFS_TYPE_DIR_REC => {
          let entry = ApfsDirectoryRecord::parse(&key, &value)?;
          children
            .entry(entry.parent_id)
            .or_insert_with(Vec::new)
            .push(NamespaceDirectoryEntry::new(
              entry.name,
              NamespaceNodeId::from_u64(entry.file_id),
              directory_kind_from_flags(entry.flags),
            ));
        }
        APFS_TYPE_XATTR => {
          let attribute = ApfsXattrRecord::parse(&key, &value)?;
          xattrs
            .entry(attribute.object_id)
            .or_insert_with(Vec::new)
            .push(ApfsStoredXattr {
              name: attribute.name,
              storage: attribute.storage,
            });
        }
        APFS_TYPE_FILE_EXTENT => {
          let extent = ApfsFileExtentRecord::parse(&key, &value)?;
          extents
            .entry(extent.object_id)
            .or_insert_with(Vec::new)
            .push(ApfsExtent {
              logical_address: extent.logical_address,
              length: extent.length,
              physical_block_number: extent.physical_block_number,
              crypto_id: extent.crypto_id,
            });
        }
        _ => {}
      }
    }

    if self.info().is_sealed() && self.info().fext_tree_oid() != 0 {
      let fext_tree = ApfsBTree::open(
        self.source.clone(),
        self.block_size,
        self.info().fext_tree_oid(),
      )?;
      for (key, value) in fext_tree.walk_records()? {
        let extent = ApfsFextRecord::parse(&key, &value)?;
        extents
          .entry(extent.private_id)
          .or_insert_with(Vec::new)
          .push(ApfsExtent {
            logical_address: extent.logical_address,
            length: extent.length,
            physical_block_number: extent.physical_block_number,
            crypto_id: 0,
          });
      }
    }

    let nodes = Arc::new(nodes);
    let children = Arc::new(
      children
        .into_iter()
        .map(|(key, value)| (key, Arc::from(value.into_boxed_slice())))
        .collect::<HashMap<_, _>>(),
    );
    let xattrs = Arc::new(
      xattrs
        .into_iter()
        .map(|(key, value)| (key, Arc::from(value.into_boxed_slice())))
        .collect::<HashMap<_, _>>(),
    );
    let extents = Arc::new(
      extents
        .into_iter()
        .map(|(key, mut value)| {
          value.sort_by_key(|extent| extent.logical_address);
          (key, Arc::from(value.into_boxed_slice()))
        })
        .collect::<HashMap<_, _>>(),
    );
    let paths = Arc::new(
      build_path_index(&children)
        .into_iter()
        .map(|(key, mut value)| {
          value.sort();
          (key, Arc::from(value.into_boxed_slice()))
        })
        .collect::<HashMap<_, _>>(),
    );

    if !nodes.contains_key(&APFS_ROOT_DIRECTORY_OBJECT_ID) {
      return Err(Error::invalid_format(
        "apfs root inode is missing from the fs tree".to_string(),
      ));
    }

    let built = Arc::new(ApfsVolumeIndex {
      nodes,
      children,
      xattrs,
      extents,
      paths,
    });
    let mut cached = self
      .namespace_index
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cached.as_ref().cloned() {
      return Ok(existing);
    }
    *cached = Some(built.clone());
    Ok(built)
  }

  fn snapshot_index(&self) -> Result<Arc<[ApfsSnapshotInfo]>> {
    if let Some(index) = self
      .snapshot_index
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .as_ref()
      .cloned()
    {
      return Ok(index);
    }

    let built: Arc<[ApfsSnapshotInfo]> = if self.snapshot_info.is_some()
      || self.info().snap_meta_tree_oid() == 0
      || self.info().number_of_snapshots() == 0
    {
      Arc::from(Vec::<ApfsSnapshotInfo>::new().into_boxed_slice())
    } else {
      let tree = ApfsBTree::open(
        self.source.clone(),
        self.block_size,
        self.info().snap_meta_tree_oid(),
      )?;
      let mut snapshots = Vec::new();
      for (key, value) in tree.walk_records()? {
        let header = ApfsFsKeyHeader::parse(&key)?;
        if header.record_type != APFS_TYPE_SNAP_METADATA {
          continue;
        }

        let metadata = ApfsSnapshotMetadataRecord::parse(&key, &value)?;
        snapshots.push(ApfsSnapshotInfo::new(
          self.info().object_id(),
          metadata.xid,
          metadata.superblock_address,
          metadata.name,
          metadata.create_time,
          metadata.change_time,
        ));
      }
      snapshots.sort_by_key(ApfsSnapshotInfo::xid);
      Arc::from(snapshots.into_boxed_slice())
    };

    let mut cached = self
      .snapshot_index
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = cached.as_ref().cloned() {
      return Ok(existing);
    }
    *cached = Some(built.clone());
    Ok(built)
  }

  fn lookup_node(&self, node_id: &NamespaceNodeId) -> Result<Arc<ApfsNode>> {
    let identifier = decode_node_id(node_id)?;
    self
      .namespace_index()?
      .nodes
      .get(&identifier)
      .cloned()
      .ok_or_else(|| Error::not_found(format!("apfs inode {identifier} was not found")))
  }

  fn lookup_xattr(&self, node_id: &NamespaceNodeId, name: &str) -> Result<ApfsStoredXattr> {
    let identifier = decode_node_id(node_id)?;
    self
      .namespace_index()?
      .xattrs
      .get(&identifier)
      .and_then(|attributes| attributes.iter().find(|attribute| attribute.name == name))
      .cloned()
      .ok_or_else(|| {
        Error::not_found(format!(
          "apfs extended attribute {name} was not found on inode {identifier}"
        ))
      })
  }

  fn open_storage(&self, storage: &ApfsStreamStorageSpec) -> Result<ByteSourceHandle> {
    match storage {
      ApfsStreamStorageSpec::Inline(bytes) => {
        Ok(Arc::new(BytesDataSource::new(bytes.clone())) as ByteSourceHandle)
      }
      ApfsStreamStorageSpec::DataStream { object_id, size } => {
        self.open_extent_stream(*object_id, *size)
      }
    }
  }

  fn open_extent_stream(&self, object_id: u64, size: u64) -> Result<ByteSourceHandle> {
    if size == 0 {
      return Ok(
        Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as ByteSourceHandle,
      );
    }
    let index = self.namespace_index()?;
    let extents = index.extents.get(&object_id).cloned().ok_or_else(|| {
      Error::not_found(format!(
        "apfs extents were not found for object id {object_id}"
      ))
    })?;
    Ok(Arc::new(ApfsExtentDataSource {
      source: self.source.clone(),
      block_size: u64::from(self.block_size),
      sectors_per_block: u64::from(self.block_size / 512),
      file_size: size,
      extents,
      decryptor: self.unlock_state.as_ref().map(|state| state.cipher.clone()),
    }) as ByteSourceHandle)
  }

  fn open_snapshot(&self, snapshot: ApfsSnapshotInfo) -> Result<ApfsVolume> {
    let block = read_blocks(
      self.source.as_ref(),
      self.block_size,
      snapshot.superblock_address(),
      1,
    )?;
    let superblock = super::ondisk::ApfsVolumeSuperblock::parse(&block)?;
    superblock.validate(&block)?;
    let info = ApfsVolumeInfo::new(
      self.info().slot_index(),
      self.info().object_id(),
      snapshot.superblock_address(),
      superblock,
    );
    Ok(ApfsVolume::new(
      self.open_context(),
      info,
      Some(snapshot),
      Some(self.info().omap_oid()),
      self.unlock_state.clone(),
    ))
  }

  fn open_snapshot_with_selector(&self, selector: &DataViewSelector<'_>) -> Result<ApfsVolume> {
    if let DataViewSelector::Name(name) = selector {
      return self.open_snapshot_by_name(name);
    }
    let snapshot = self
      .snapshots()?
      .into_iter()
      .find(|snapshot| selector.matches(&snapshot.to_view_record()))
      .ok_or_else(|| {
        Error::not_found(format!(
          "apfs snapshot selector did not match any snapshot: {selector:?}"
        ))
      })?;
    self.open_snapshot(snapshot)
  }
}

impl FileSystem for ApfsVolume {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(APFS_ROOT_DIRECTORY_OBJECT_ID)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let identifier = decode_node_id(node_id)?;
    let index = self.namespace_index()?;
    let mut record = index
      .nodes
      .get(&identifier)
      .cloned()
      .ok_or_else(|| Error::not_found(format!("apfs inode {identifier} was not found")))?
      .record
      .clone();
    if let Some(paths) = index.paths.get(&identifier).and_then(|paths| paths.first()) {
      record.path = paths.clone();
    }
    Ok(record)
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let node = self.lookup_node(directory_id)?;
    if node.record.kind != NamespaceNodeKind::Directory {
      return Err(Error::invalid_format(
        "apfs directory reads require a directory inode".to_string(),
      ));
    }

    Ok(
      self
        .namespace_index()?
        .children
        .get(&decode_node_id(directory_id)?)
        .map_or_else(Vec::new, |entries| entries.to_vec()),
    )
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    self.open_content_stream(file_id)
  }

  fn data_streams(&self, node_id: &NamespaceNodeId) -> Result<Vec<NamespaceStreamRecord>> {
    let node = self.lookup_node(node_id)?;
    let identifier = decode_node_id(node_id)?;
    let mut streams = Vec::new();
    if matches!(
      node.record.kind,
      NamespaceNodeKind::File | NamespaceNodeKind::Symlink
    ) {
      streams.push(NamespaceStreamRecord::new(
        NamespaceStreamId::data(),
        node.record.size,
      ));
    }

    if let Some(attributes) = self.namespace_index()?.xattrs.get(&identifier) {
      for attribute in attributes.iter() {
        let (stream_id, size) = match &attribute.storage {
          ApfsStreamStorageSpec::Inline(value) => {
            if attribute.name == XATTR_RESOURCE_FORK_NAME {
              (NamespaceStreamId::fork("ResourceFork"), value.len() as u64)
            } else {
              (
                NamespaceStreamId::xattr(attribute.name.clone()),
                value.len() as u64,
              )
            }
          }
          ApfsStreamStorageSpec::DataStream { size, .. } => {
            if attribute.name == XATTR_RESOURCE_FORK_NAME {
              (NamespaceStreamId::fork("ResourceFork"), *size)
            } else {
              (NamespaceStreamId::xattr(attribute.name.clone()), *size)
            }
          }
        };
        streams.push(NamespaceStreamRecord::new(stream_id, size));
      }
    }
    Ok(streams)
  }

  fn open_stream(
    &self, node_id: &NamespaceNodeId, stream_id: &NamespaceStreamId,
  ) -> Result<ByteSourceHandle> {
    match stream_id.kind {
      NamespaceStreamKind::Data => self.open_content_stream(node_id),
      NamespaceStreamKind::Fork => {
        if stream_id.name.as_deref() != Some("ResourceFork") {
          return Err(Error::not_found(format!(
            "apfs fork was not found: {:?}",
            stream_id.name
          )));
        }
        self.open_resource_fork(node_id)
      }
      NamespaceStreamKind::ExtendedAttribute => {
        let name = stream_id
          .name
          .as_deref()
          .ok_or_else(|| Error::not_found("apfs xattr stream requires a name"))?;
        let xattr = self.lookup_xattr(node_id, name)?;
        self.open_storage(&xattr.storage)
      }
      NamespaceStreamKind::NamedData | NamespaceStreamKind::Other => Err(Error::not_found(
        "apfs does not expose this stream kind".to_string(),
      )),
    }
  }
}

impl NamespaceSource for ApfsVolume {
  fn root_node_id(&self) -> NamespaceNodeId {
    FileSystem::root_node_id(self)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    FileSystem::node(self, node_id)
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    FileSystem::read_dir(self, directory_id)
  }

  fn lookup_name(
    &self, directory_id: &NamespaceNodeId, name: &str,
  ) -> Result<NamespaceDirectoryEntry> {
    let node = self.lookup_node(directory_id)?;
    if node.record.kind != NamespaceNodeKind::Directory {
      return Err(Error::invalid_format(
        "apfs directory lookups require a directory inode".to_string(),
      ));
    }

    let entries = NamespaceSource::read_dir(self, directory_id)?;
    if !self.info().is_case_insensitive() && !self.info().is_normalization_insensitive() {
      return entries
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| Error::not_found(format!("apfs entry not found: {name}")));
    }

    let wanted = apfs_lookup_name_key(
      name,
      self.info().is_case_insensitive(),
      self.info().is_normalization_insensitive(),
    );
    entries
      .into_iter()
      .find(|entry| {
        apfs_lookup_name_key(
          &entry.name,
          self.info().is_case_insensitive(),
          self.info().is_normalization_insensitive(),
        ) == wanted
      })
      .ok_or_else(|| Error::not_found(format!("apfs entry not found: {name}")))
  }

  fn data_streams(&self, node_id: &NamespaceNodeId) -> Result<Vec<NamespaceStreamRecord>> {
    FileSystem::data_streams(self, node_id)
  }

  fn open_stream(
    &self, node_id: &NamespaceNodeId, stream_id: &NamespaceStreamId,
  ) -> Result<ByteSourceHandle> {
    FileSystem::open_stream(self, node_id, stream_id)
  }
}

impl DataSource for ApfsVolume {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn facets(&self) -> DataSourceFacets {
    if self.snapshot_info.is_none() && self.info().number_of_snapshots() != 0 {
      DataSourceFacets::namespace().with_views()
    } else {
      DataSourceFacets::namespace()
    }
  }

  fn namespace(&self) -> Option<&dyn NamespaceSource> {
    Some(self)
  }

  fn views(&self) -> Result<Vec<DataViewRecord>> {
    Ok(
      self
        .snapshots()?
        .into_iter()
        .map(|snapshot| snapshot.to_view_record())
        .collect(),
    )
  }

  fn open_view(
    &self, selector: &DataViewSelector<'_>, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    let volume = self.clone_with_credentials(options.credentials)?;
    Ok(Box::new(volume.open_snapshot_with_selector(selector)?))
  }

  fn reopen(&self, options: OpenOptions<'_>) -> Result<Box<dyn DataSource>> {
    Ok(Box::new(self.clone_with_credentials(options.credentials)?))
  }
}

impl ApfsVolume {
  fn open_content_stream(&self, node_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let node = self.lookup_node(node_id)?;
    ensure_openable_content_node(&node)?;

    if node.compressed {
      return self.open_compressed_stream(node_id);
    }

    self.open_extent_stream(node.private_id, node.data_size)
  }

  fn open_compressed_stream(&self, node_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let decmpfs = self.lookup_xattr(node_id, XATTR_DECMPFS_NAME)?;
    let header_and_payload = self.open_storage(&decmpfs.storage)?.read_all()?;
    let header = parse_decmpfs_header(&header_and_payload)?;
    let payload = header_and_payload
      .get(16..)
      .ok_or_else(|| Error::invalid_format("apfs decmpfs payload is truncated"))?;

    match header.algorithm {
      DECMPFS_ZLIB_ATTR | DECMPFS_SPARSE_ATTR | DECMPFS_PLAIN_ATTR | DECMPFS_LZFSE_ATTR => {
        let decoded: Arc<[u8]> = Arc::from(
          decode_compressed_chunk(header.algorithm, payload, header.uncompressed_size)?
            .into_boxed_slice(),
        );
        Ok(Arc::new(BytesDataSource::new(decoded)) as ByteSourceHandle)
      }
      DECMPFS_ZLIB_RSRC | DECMPFS_PLAIN_RSRC | DECMPFS_LZFSE_RSRC => {
        let resource_fork = self.open_resource_fork(node_id)?;
        Ok(Arc::new(ApfsDecmpfsDataSource {
          source: resource_fork.clone(),
          algorithm: header.algorithm,
          file_size: header.uncompressed_size,
          entries: Arc::from(
            parse_compressed_resource_entries(
              resource_fork.as_ref(),
              header.algorithm,
              header.uncompressed_size,
            )?
            .into_boxed_slice(),
          ),
          cache: Mutex::new(HashMap::new()),
        }) as ByteSourceHandle)
      }
      DECMPFS_LZVN_ATTR | DECMPFS_LZVN_RSRC => {
        let resource_fork = if header.algorithm == DECMPFS_LZVN_RSRC {
          Some(self.open_resource_fork(node_id)?.read_all()?)
        } else {
          None
        };
        let decoded: Arc<[u8]> = Arc::from(
          decode_lzvn_decmpfs(&header_and_payload, resource_fork.as_deref())
            .map_err(|error| {
              Error::invalid_format(format!("apfs lzvn decmpfs decode failed: {error}"))
            })?
            .into_boxed_slice(),
        );
        Ok(Arc::new(BytesDataSource::new(decoded)) as ByteSourceHandle)
      }
      algorithm => Err(Error::unsupported(format!(
        "unsupported apfs decmpfs algorithm: {algorithm}"
      ))),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dataless_nodes_reject_regular_content_opens() {
    let node = ApfsNode {
      record: NamespaceNodeRecord::new(NamespaceNodeId::from_u64(1), NamespaceNodeKind::File, 0),
      parent_id: 0,
      create_time: 0,
      modification_time: 0,
      change_time: 0,
      access_time: 0,
      children_or_links: 0,
      protection_class: 0,
      write_generation_counter: 0,
      private_id: 0,
      owner: 0,
      group: 0,
      mode: 0,
      internal_flags: 0,
      data_size: 0,
      bsd_flags: crate::filesystems::apfs::records::SF_DATALESS,
      snapshot_xid: None,
      document_id: None,
      sparse_bytes: None,
      rdev: None,
      compressed: false,
    };

    assert!(matches!(
      ensure_openable_content_node(&node),
      Err(Error::InvalidSourceReference(_))
    ));
  }
}
