//! APFS volume-group and firmlink helpers.

use std::collections::BTreeMap;

use super::container::{ApfsContainer, ApfsVolume, ApfsVolumeInfo};
use crate::{
  ByteSourceHandle, Credential, Error, NamespaceDirectoryEntry, NamespaceNodeKind,
  NamespaceNodeRecord, NamespaceSource, OpenOptions, Result,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsFirmlink {
  pub source_path: String,
  pub target_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsVolumeGroupMember {
  pub index: usize,
  pub object_id: u64,
  pub name: String,
  pub uuid: String,
  pub role_mask: u16,
  pub role_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsVolumeGroupInfo {
  group_id: String,
  members: Vec<ApfsVolumeGroupMember>,
}

impl ApfsVolumeGroupInfo {
  fn new(group_id: String, members: Vec<ApfsVolumeGroupMember>) -> Self {
    Self { group_id, members }
  }

  pub fn group_id(&self) -> &str {
    &self.group_id
  }

  pub fn members(&self) -> &[ApfsVolumeGroupMember] {
    &self.members
  }

  pub fn system_member(&self) -> Option<&ApfsVolumeGroupMember> {
    self
      .members
      .iter()
      .find(|member| member.role_mask & super::ondisk::APFS_VOL_ROLE_SYSTEM != 0)
  }

  pub fn data_member(&self) -> Option<&ApfsVolumeGroupMember> {
    self
      .members
      .iter()
      .find(|member| member.role_mask & super::ondisk::APFS_VOL_ROLE_DATA != 0)
  }
}

#[derive(Clone)]
pub struct ApfsVolumeGroupView {
  group_id: String,
  system: ApfsVolume,
  data: Option<ApfsVolume>,
}

impl ApfsVolumeGroupView {
  fn new(group_id: String, system: ApfsVolume, data: Option<ApfsVolume>) -> Self {
    Self {
      group_id,
      system,
      data,
    }
  }

  pub fn group_id(&self) -> &str {
    &self.group_id
  }

  pub fn system_volume(&self) -> &ApfsVolume {
    &self.system
  }

  pub fn data_volume(&self) -> Option<&ApfsVolume> {
    self.data.as_ref()
  }

  pub fn firmlinks(&self) -> Result<Vec<ApfsFirmlink>> {
    collect_firmlinks(&self.system)
  }

  pub fn resolve_path(&self, path: &str) -> Result<NamespaceNodeRecord> {
    let overlay = resolve_firmlink_overlay(path, &self.firmlinks()?)?;
    match overlay {
      ResolvedOverlayPath::System(path) => self.system.resolve_path(path.trim_start_matches('/')),
      ResolvedOverlayPath::Data(path) => self
        .data
        .as_ref()
        .ok_or_else(|| Error::NotFound("apfs volume group has no data volume member".to_string()))?
        .resolve_path(path.trim_start_matches('/')),
    }
  }

  pub fn read_dir(&self, path: &str) -> Result<Vec<NamespaceDirectoryEntry>> {
    let overlay = resolve_firmlink_overlay(path, &self.firmlinks()?)?;
    match overlay {
      ResolvedOverlayPath::System(path) => {
        let node = self.system.resolve_path(path.trim_start_matches('/'))?;
        self.system.read_dir(&node.id)
      }
      ResolvedOverlayPath::Data(path) => {
        let data = self.data.as_ref().ok_or_else(|| {
          Error::NotFound("apfs volume group has no data volume member".to_string())
        })?;
        let node = data.resolve_path(path.trim_start_matches('/'))?;
        data.read_dir(&node.id)
      }
    }
  }

  pub fn open_content(&self, path: &str) -> Result<ByteSourceHandle> {
    let overlay = resolve_firmlink_overlay(path, &self.firmlinks()?)?;
    match overlay {
      ResolvedOverlayPath::System(path) => {
        let node = self.system.resolve_path(path.trim_start_matches('/'))?;
        self.system.open_content(&node.id)
      }
      ResolvedOverlayPath::Data(path) => {
        let data = self.data.as_ref().ok_or_else(|| {
          Error::NotFound("apfs volume group has no data volume member".to_string())
        })?;
        let node = data.resolve_path(path.trim_start_matches('/'))?;
        data.open_content(&node.id)
      }
    }
  }
}

impl ApfsContainer {
  pub fn volume_groups(&self) -> Vec<ApfsVolumeGroupInfo> {
    build_volume_groups(self.volumes())
  }

  pub fn open_volume_group_by_id(
    &self, group_id: &str, options: OpenOptions<'_>,
  ) -> Result<ApfsVolumeGroupView> {
    let group = self
      .volume_groups()
      .into_iter()
      .find(|group| group.group_id() == group_id)
      .ok_or_else(|| Error::NotFound(format!("apfs volume group id was not found: {group_id}")))?;

    let system_member = group.system_member().ok_or_else(|| {
      Error::NotFound(format!("apfs volume group {group_id} has no system member"))
    })?;
    let system = self.open_group_member(system_member.index, options.credentials)?;
    let data = group
      .data_member()
      .map(|member| self.open_group_member(member.index, options.credentials))
      .transpose()?;

    Ok(ApfsVolumeGroupView::new(
      group.group_id().to_string(),
      system,
      data,
    ))
  }

  fn open_group_member(&self, index: usize, credentials: &[Credential<'_>]) -> Result<ApfsVolume> {
    let volume = self.open_volume_by_index(index)?;
    if credentials.is_empty() {
      Ok(volume)
    } else {
      volume.clone_with_credentials(credentials)
    }
  }
}

pub(crate) fn build_volume_groups(volumes: &[ApfsVolumeInfo]) -> Vec<ApfsVolumeGroupInfo> {
  let mut groups = BTreeMap::<String, Vec<ApfsVolumeGroupMember>>::new();
  for volume in volumes {
    let Some(group_id) = volume.volume_group_id_string() else {
      continue;
    };
    groups
      .entry(group_id)
      .or_default()
      .push(ApfsVolumeGroupMember {
        index: volume.slot_index(),
        object_id: volume.object_id(),
        name: volume.name().to_string(),
        uuid: volume.uuid_string(),
        role_mask: volume.role(),
        role_names: volume.role_names(),
      });
  }

  groups
    .into_iter()
    .map(|(group_id, mut members)| {
      members.sort_by_key(|member| member.index);
      ApfsVolumeGroupInfo::new(group_id, members)
    })
    .collect()
}

pub(crate) fn collect_firmlinks(volume: &ApfsVolume) -> Result<Vec<ApfsFirmlink>> {
  fn walk(
    volume: &ApfsVolume, node_id: &crate::NamespaceNodeId, current_path: &str,
    firmlinks: &mut Vec<ApfsFirmlink>,
  ) -> Result<()> {
    for entry in volume.read_dir(node_id)? {
      let path = if current_path.is_empty() {
        format!("/{}", entry.name)
      } else {
        format!("{current_path}/{}", entry.name)
      };
      if let Some(target) = volume.firmlink_target(&entry.node_id)? {
        firmlinks.push(ApfsFirmlink {
          source_path: path.clone(),
          target_path: normalize_overlay_path(&target),
        });
      }
      if entry.kind == NamespaceNodeKind::Directory {
        walk(volume, &entry.node_id, &path, firmlinks)?;
      }
    }
    Ok(())
  }

  let mut firmlinks = Vec::new();
  walk(volume, &volume.root_node_id(), "", &mut firmlinks)?;
  firmlinks.sort_by(|left, right| left.source_path.cmp(&right.source_path));
  Ok(firmlinks)
}

pub(crate) enum ResolvedOverlayPath {
  System(String),
  Data(String),
}

pub(crate) fn resolve_firmlink_overlay(
  path: &str, firmlinks: &[ApfsFirmlink],
) -> Result<ResolvedOverlayPath> {
  let normalized_path = normalize_overlay_path(path);
  let best = firmlinks
    .iter()
    .filter(|firmlink| {
      normalized_path == firmlink.source_path
        || normalized_path
          .strip_prefix(firmlink.source_path.as_str())
          .is_some_and(|suffix| suffix.starts_with('/'))
    })
    .max_by_key(|firmlink| firmlink.source_path.len());

  if let Some(firmlink) = best {
    let suffix = normalized_path
      .strip_prefix(firmlink.source_path.as_str())
      .unwrap_or_default();
    return Ok(ResolvedOverlayPath::Data(format!(
      "{}{}",
      firmlink.target_path, suffix
    )));
  }

  Ok(ResolvedOverlayPath::System(normalized_path))
}

fn normalize_overlay_path(path: &str) -> String {
  let trimmed = path.trim();
  if trimmed.is_empty() || trimmed == "/" {
    return "/".to_string();
  }

  let mut normalized = String::from("/");
  normalized.push_str(trimmed.trim_matches('/'));
  normalized
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::filesystems::apfs::ondisk::{ApfsObjectHeader, ApfsVolumeSuperblock};

  fn synthetic_volume_info(index: usize, name: &str, role: u16, group: [u8; 16]) -> ApfsVolumeInfo {
    ApfsVolumeInfo::new(
      index,
      1000 + index as u64,
      2000 + index as u64,
      ApfsVolumeSuperblock {
        header: ApfsObjectHeader {
          checksum: 0,
          oid: 1,
          xid: 1,
          object_type: 0,
          subtype: 0,
        },
        fs_index: index as u32,
        features: 0,
        readonly_compatible_features: 0,
        incompatible_features: 0,
        volume_uuid: [index as u8; 16],
        omap_oid: 0,
        root_tree_oid: 0,
        extentref_tree_oid: 0,
        snap_meta_tree_oid: 0,
        next_object_id: 0,
        number_of_snapshots: 0,
        last_modification_time: 0,
        fs_flags: 0,
        volume_name: name.to_string(),
        next_document_id: 0,
        role,
        root_to_xid: 0,
        encryption_rolling_state_oid: 0,
        snap_meta_ext_oid: 0,
        volume_group_id: group,
        integrity_meta_oid: 0,
        fext_tree_oid: 0,
        fext_tree_type: 0,
      },
    )
  }

  #[test]
  fn builds_volume_groups_from_shared_group_ids() {
    let group = [0x11; 16];
    let volumes = vec![
      synthetic_volume_info(
        0,
        "Macintosh HD",
        super::super::ondisk::APFS_VOL_ROLE_SYSTEM,
        group,
      ),
      synthetic_volume_info(
        1,
        "Macintosh HD - Data",
        super::super::ondisk::APFS_VOL_ROLE_DATA,
        group,
      ),
      synthetic_volume_info(2, "Ungrouped", 0, [0; 16]),
    ];

    let groups = build_volume_groups(&volumes);

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members().len(), 2);
    assert_eq!(groups[0].system_member().unwrap().name, "Macintosh HD");
    assert_eq!(groups[0].data_member().unwrap().name, "Macintosh HD - Data");
  }

  #[test]
  fn resolves_longest_matching_firmlink_prefix() {
    let firmlinks = vec![
      ApfsFirmlink {
        source_path: "/System/Library".to_string(),
        target_path: "/System/Volumes/Data/System/Library".to_string(),
      },
      ApfsFirmlink {
        source_path: "/Users".to_string(),
        target_path: "/System/Volumes/Data/Users".to_string(),
      },
    ];

    match resolve_firmlink_overlay("/Users/alice/Desktop", &firmlinks).unwrap() {
      ResolvedOverlayPath::Data(path) => {
        assert_eq!(path, "/System/Volumes/Data/Users/alice/Desktop")
      }
      ResolvedOverlayPath::System(_) => panic!("expected data overlay resolution"),
    }

    match resolve_firmlink_overlay("/Applications", &firmlinks).unwrap() {
      ResolvedOverlayPath::System(path) => assert_eq!(path, "/Applications"),
      ResolvedOverlayPath::Data(_) => panic!("expected system path resolution"),
    }
  }
}
