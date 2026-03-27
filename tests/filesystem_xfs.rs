mod support;

use std::sync::Arc;

use support::{FileDataSource, fixture_path};
use wxtla::{
  ByteSourceHandle,
  filesystems::{
    NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceSource, xfs::XfsDriver,
  },
};

fn open_fixture_file_system() -> wxtla::Result<wxtla::filesystems::xfs::XfsFileSystem> {
  let source: ByteSourceHandle = Arc::new(FileDataSource::open(fixture_path("xfs/xfs.raw"))?);
  XfsDriver::open(source)
}

fn child_named(
  file_system: &dyn NamespaceSource, directory_id: &NamespaceNodeId, name: &str,
) -> wxtla::Result<NamespaceDirectoryEntry> {
  file_system
    .read_dir(directory_id)?
    .into_iter()
    .find(|entry| entry.name == name)
    .ok_or_else(|| wxtla::Error::NotFound(format!("missing directory entry: {name}")))
}

#[test]
fn xfs_fixture_exposes_root_entries_and_directory_children() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let root = file_system.node(&root_id).unwrap();
  let root_entries = file_system.read_dir(&root_id).unwrap();

  assert_eq!(root.kind, NamespaceNodeKind::Directory);
  for expected in ["a_directory", "a_link", "passwords.txt"] {
    assert!(
      root_entries.iter().any(|entry| entry.name == expected),
      "missing root entry: {expected}"
    );
  }

  let directory_entry = child_named(&file_system, &root_id, "a_directory").unwrap();
  let directory_entries = file_system.read_dir(&directory_entry.node_id).unwrap();
  assert_eq!(directory_entries.len(), 2);
  assert!(directory_entries.iter().any(|entry| entry.name == "a_file"));
  assert!(
    directory_entries
      .iter()
      .any(|entry| entry.name == "another_file")
  );
}

#[test]
fn xfs_fixture_reads_files_and_symlink_targets() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let passwords_entry = child_named(&file_system, &root_id, "passwords.txt").unwrap();
  let link_entry = child_named(&file_system, &root_id, "a_link").unwrap();
  let directory_entry = child_named(&file_system, &root_id, "a_directory").unwrap();
  let file_entry = child_named(&file_system, &directory_entry.node_id, "a_file").unwrap();
  let another_entry = child_named(&file_system, &directory_entry.node_id, "another_file").unwrap();

  let file_data = file_system
    .open_content(&file_entry.node_id)
    .unwrap()
    .read_all()
    .unwrap();
  assert_eq!(
    String::from_utf8(file_data).unwrap(),
    "This is a text file.\n\nWe should be able to parse it.\n"
  );

  let another_data = file_system
    .open_content(&another_entry.node_id)
    .unwrap()
    .read_all()
    .unwrap();
  assert_eq!(
    String::from_utf8(another_data).unwrap(),
    "This is another file.\n"
  );

  let passwords_data = file_system
    .open_content(&passwords_entry.node_id)
    .unwrap()
    .read_all()
    .unwrap();
  let passwords_text = String::from_utf8(passwords_data).unwrap();
  assert!(passwords_text.contains("uber secret laire,admin,admin"));
  assert!(passwords_text.contains("treasure chest,-,1111"));

  assert_eq!(
    file_system.node(&link_entry.node_id).unwrap().kind,
    NamespaceNodeKind::Symlink
  );
  assert_eq!(
    file_system
      .symlink_target(&link_entry.node_id)
      .unwrap()
      .as_deref(),
    Some("a_directory/another_file")
  );
}

#[test]
fn xfs_fixture_exposes_inode_metadata() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let directory_entry = child_named(&file_system, &root_id, "a_directory").unwrap();
  let file_entry = child_named(&file_system, &directory_entry.node_id, "a_file").unwrap();
  let details = file_system.node_details(&file_entry.node_id).unwrap();

  assert_eq!(details.mode, 0o100664);
  assert_eq!(details.uid, 1000);
  assert_eq!(details.gid, 1000);
  assert_eq!(details.link_count, 1);
}
