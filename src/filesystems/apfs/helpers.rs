use std::collections::{HashMap, HashSet};

use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

use super::filesystem::{ApfsNode, ApfsSpecialFileKind};
use crate::{
  Error, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, Result,
  filesystems::apfs::{ondisk::read_u64_le, records::APFS_ROOT_DIRECTORY_OBJECT_ID},
};

pub(super) fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u64> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::invalid_format(
      "apfs node identifiers must be 8 bytes".to_string(),
    ));
  }
  read_u64_le(bytes, 0)
}

pub(super) fn align_up_512(value: u64) -> u64 {
  (value + 511) & !511
}

pub(super) fn apfs_lookup_name_key(
  name: &str, case_insensitive: bool, normalization_insensitive: bool,
) -> String {
  let normalized = if case_insensitive || normalization_insensitive {
    name.nfd().collect::<String>()
  } else {
    name.to_string()
  };
  if case_insensitive {
    normalized.case_fold().collect::<String>()
  } else {
    normalized
  }
}

pub(super) fn special_file_kind_from_mode(mode: u16) -> Option<ApfsSpecialFileKind> {
  match mode & 0xF000 {
    0x1000 => Some(ApfsSpecialFileKind::Fifo),
    0x2000 => Some(ApfsSpecialFileKind::CharacterDevice),
    0x6000 => Some(ApfsSpecialFileKind::BlockDevice),
    0xC000 => Some(ApfsSpecialFileKind::Socket),
    0xE000 => Some(ApfsSpecialFileKind::Whiteout),
    _ => None,
  }
}

pub(super) fn ensure_openable_content_node(node: &ApfsNode) -> Result<()> {
  match node.record.kind {
    NamespaceNodeKind::Directory | NamespaceNodeKind::Special => {
      return Err(Error::invalid_format(
        "apfs file opens require a regular file or symlink inode".to_string(),
      ));
    }
    NamespaceNodeKind::Symlink => {
      return Err(Error::invalid_format(
        "apfs symlink content is stored in com.apple.fs.symlink".to_string(),
      ));
    }
    NamespaceNodeKind::File => {}
  }

  if (node.bsd_flags & crate::filesystems::apfs::records::SF_DATALESS) != 0 {
    return Err(Error::invalid_source_reference(
      "apfs dataless file content is not locally present".to_string(),
    ));
  }

  Ok(())
}

type ApfsChildrenMap = std::sync::Arc<HashMap<u64, std::sync::Arc<[NamespaceDirectoryEntry]>>>;

pub(super) fn build_path_index(children: &ApfsChildrenMap) -> HashMap<u64, Vec<String>> {
  fn walk(
    children: &ApfsChildrenMap, directory_id: u64, current_path: &str,
    visited_dirs: &mut HashSet<u64>, paths: &mut HashMap<u64, Vec<String>>,
  ) {
    if !visited_dirs.insert(directory_id) {
      return;
    }
    let Some(entries) = children.get(&directory_id) else {
      return;
    };
    for entry in entries.iter() {
      let child_id = decode_node_id(&entry.node_id).unwrap_or_default();
      let path = if current_path == "/" {
        format!("/{name}", name = entry.name)
      } else {
        format!("{current_path}/{name}", name = entry.name)
      };
      paths.entry(child_id).or_default().push(path.clone());
      if entry.kind == NamespaceNodeKind::Directory {
        walk(children, child_id, &path, visited_dirs, paths);
      }
    }
  }

  let mut paths = HashMap::new();
  paths.insert(APFS_ROOT_DIRECTORY_OBJECT_ID, vec!["/".to_string()]);
  let mut visited_dirs = HashSet::new();
  walk(
    children,
    APFS_ROOT_DIRECTORY_OBJECT_ID,
    "/",
    &mut visited_dirs,
    &mut paths,
  );
  paths
}
