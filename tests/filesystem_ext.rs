mod support;

use std::sync::Arc;

use support::{FileDataSource, fixture_path};
use wxtla::{
  DataSourceHandle,
  filesystems::{DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, ext::ExtDriver},
};

const INITIAL_SPARSE_SUFFIX: &[u8] = b"File with an initial sparse extent\n";
const TRAILING_SPARSE_PREFIX: &[u8] = b"File with a trailing sparse extent\n";

fn open_fixture_file_system(
  relative_path: &str,
) -> wxtla::Result<wxtla::filesystems::ext::ExtFileSystem> {
  let source: DataSourceHandle = Arc::new(FileDataSource::open(fixture_path(relative_path))?);
  ExtDriver::open(source)
}

fn child_named(
  file_system: &dyn FileSystem, directory_id: &FileSystemNodeId, name: &str,
) -> wxtla::Result<DirectoryEntry> {
  file_system
    .read_dir(directory_id)?
    .into_iter()
    .find(|entry| entry.name == name)
    .ok_or_else(|| wxtla::Error::NotFound(format!("missing directory entry: {name}")))
}

#[test]
fn ext_fixtures_expose_root_entries_and_node_kinds() {
  for relative_path in ["ext/ext2.raw", "ext/ext3.raw", "ext/ext4.raw"] {
    let file_system = open_fixture_file_system(relative_path).unwrap();
    let root_id = file_system.root_node_id();
    let root_entries = file_system.read_dir(&root_id).unwrap();

    assert!(
      root_entries.iter().any(|entry| entry.name == "emptyfile"),
      "fixture: {relative_path}"
    );
    assert!(
      root_entries.iter().any(|entry| entry.name == "testdir1"),
      "fixture: {relative_path}"
    );
    assert!(
      root_entries
        .iter()
        .any(|entry| entry.name == "file_hardlink1"),
      "fixture: {relative_path}"
    );
    assert!(
      root_entries
        .iter()
        .any(|entry| entry.name == "file_symboliclink1"),
      "fixture: {relative_path}"
    );
    assert!(
      root_entries
        .iter()
        .any(|entry| entry.name == "directory_symboliclink1"),
      "fixture: {relative_path}"
    );

    let file_symlink = child_named(&file_system, &root_id, "file_symboliclink1").unwrap();
    let directory_symlink = child_named(&file_system, &root_id, "directory_symboliclink1").unwrap();
    assert_eq!(
      file_system.node(&file_symlink.node_id).unwrap().kind,
      FileSystemNodeKind::Symlink,
      "fixture: {relative_path}"
    );
    assert_eq!(
      file_system.node(&directory_symlink.node_id).unwrap().kind,
      FileSystemNodeKind::Symlink,
      "fixture: {relative_path}"
    );

    let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
    let testdir_entries = file_system.read_dir(&testdir_entry.node_id).unwrap();
    for expected in [
      "testfile1",
      "TestFile2",
      "initial_sparse1",
      "trailing_sparse1",
      "uninitialized1",
    ] {
      assert!(
        testdir_entries.iter().any(|entry| entry.name == expected),
        "fixture: {relative_path}, missing: {expected}"
      );
    }
  }
}

#[test]
fn ext_fixtures_read_regular_files_and_hardlinks() {
  for relative_path in ["ext/ext2.raw", "ext/ext3.raw", "ext/ext4.raw"] {
    let file_system = open_fixture_file_system(relative_path).unwrap();
    let root_id = file_system.root_node_id();
    let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
    let testfile_entry = child_named(&file_system, &testdir_entry.node_id, "testfile1").unwrap();
    let hardlink_entry = child_named(&file_system, &root_id, "file_hardlink1").unwrap();
    let license_entry = child_named(&file_system, &testdir_entry.node_id, "TestFile2").unwrap();

    assert_eq!(
      testfile_entry.node_id, hardlink_entry.node_id,
      "fixture: {relative_path}"
    );
    assert_eq!(
      file_system
        .open_file(&testfile_entry.node_id)
        .unwrap()
        .read_all()
        .unwrap(),
      b"Keramics\n",
      "fixture: {relative_path}"
    );
    assert_eq!(
      file_system
        .open_file(&hardlink_entry.node_id)
        .unwrap()
        .read_all()
        .unwrap(),
      b"Keramics\n",
      "fixture: {relative_path}"
    );

    let license_data = file_system
      .open_file(&license_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap();
    assert!(
      license_data.starts_with(b"                                 Apache License")
        || license_data.starts_with(b"\n                                 Apache License"),
      "fixture: {relative_path}"
    );
    assert!(
      license_data.ends_with(b"under the License.\n"),
      "fixture: {relative_path}"
    );
  }
}

#[test]
fn ext_fixtures_preserve_sparse_ranges() {
  for relative_path in ["ext/ext2.raw", "ext/ext3.raw", "ext/ext4.raw"] {
    let file_system = open_fixture_file_system(relative_path).unwrap();
    let root_id = file_system.root_node_id();
    let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
    let initial_sparse =
      child_named(&file_system, &testdir_entry.node_id, "initial_sparse1").unwrap();
    let trailing_sparse =
      child_named(&file_system, &testdir_entry.node_id, "trailing_sparse1").unwrap();

    let initial_data = file_system
      .open_file(&initial_sparse.node_id)
      .unwrap()
      .read_all()
      .unwrap();
    assert_eq!(initial_data.len(), 1_048_611, "fixture: {relative_path}");
    assert!(
      initial_data[..1024].iter().all(|byte| *byte == 0),
      "fixture: {relative_path}"
    );
    assert_eq!(
      &initial_data[initial_data.len() - INITIAL_SPARSE_SUFFIX.len()..],
      INITIAL_SPARSE_SUFFIX,
      "fixture: {relative_path}"
    );

    let trailing_data = file_system
      .open_file(&trailing_sparse.node_id)
      .unwrap()
      .read_all()
      .unwrap();
    assert_eq!(trailing_data.len(), 1_048_576, "fixture: {relative_path}");
    assert_eq!(
      &trailing_data[..TRAILING_SPARSE_PREFIX.len()],
      TRAILING_SPARSE_PREFIX,
      "fixture: {relative_path}"
    );
    assert!(
      trailing_data[TRAILING_SPARSE_PREFIX.len()..]
        .iter()
        .all(|byte| *byte == 0),
      "fixture: {relative_path}"
    );
  }
}
