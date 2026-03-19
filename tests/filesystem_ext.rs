mod support;

use std::sync::Arc;

use support::{FileDataSource, fixture_path};
use wxtla::{
  DataSourceHandle, DataSourceReadStats, ObservedDataSource,
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

fn open_observed_fixture_file_system(
  relative_path: &str,
) -> wxtla::Result<(wxtla::filesystems::ext::ExtFileSystem, DataSourceReadStats)> {
  let observed = Arc::new(ObservedDataSource::new(Arc::new(FileDataSource::open(
    fixture_path(relative_path),
  )?)));
  let stats = observed.stats();
  let source: DataSourceHandle = observed;

  Ok((ExtDriver::open(source)?, stats))
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
fn ext_fixtures_expose_symlink_targets_and_inode_metadata() {
  for relative_path in ["ext/ext2.raw", "ext/ext3.raw", "ext/ext4.raw"] {
    let file_system = open_fixture_file_system(relative_path).unwrap();
    let root_id = file_system.root_node_id();
    let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
    let testfile_entry = child_named(&file_system, &testdir_entry.node_id, "testfile1").unwrap();
    let file_symlink = child_named(&file_system, &root_id, "file_symboliclink1").unwrap();
    let directory_symlink = child_named(&file_system, &root_id, "directory_symboliclink1").unwrap();

    let details = file_system.node_details(&testfile_entry.node_id).unwrap();
    assert_eq!(details.mode, 0o100644, "fixture: {relative_path}");
    assert_eq!(details.owner_id, 1000, "fixture: {relative_path}");
    assert_eq!(details.group_id, 1000, "fixture: {relative_path}");
    assert_eq!(details.link_count, 2, "fixture: {relative_path}");
    assert!(details.access_time > 0, "fixture: {relative_path}");
    assert!(details.change_time > 0, "fixture: {relative_path}");
    assert!(details.modification_time > 0, "fixture: {relative_path}");
    if relative_path == "ext/ext2.raw" {
      assert_eq!(
        details.access_time, 1_735_977_482,
        "fixture: {relative_path}"
      );
      assert_eq!(
        details.change_time, 1_735_977_481,
        "fixture: {relative_path}"
      );
      assert_eq!(
        details.modification_time, 1_735_977_481,
        "fixture: {relative_path}"
      );
    }

    assert_eq!(
      file_system
        .symlink_target(&file_symlink.node_id)
        .unwrap()
        .as_deref(),
      Some("/mnt/keramics/testdir1/testfile1"),
      "fixture: {relative_path}"
    );
    assert_eq!(
      file_system
        .symlink_target(&directory_symlink.node_id)
        .unwrap()
        .as_deref(),
      Some("/mnt/keramics/testdir1"),
      "fixture: {relative_path}"
    );
  }
}

#[test]
fn ext_fixtures_expose_extended_attributes() {
  for relative_path in ["ext/ext2.raw", "ext/ext3.raw", "ext/ext4.raw"] {
    let file_system = open_fixture_file_system(relative_path).unwrap();
    let root_id = file_system.root_node_id();
    let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
    let testfile_entry = child_named(&file_system, &testdir_entry.node_id, "testfile1").unwrap();
    let xattr1_entry = child_named(&file_system, &testdir_entry.node_id, "xattr1").unwrap();

    let file_attributes = file_system
      .extended_attributes(&testfile_entry.node_id)
      .unwrap();
    assert_eq!(file_attributes.len(), 1, "fixture: {relative_path}");
    assert_eq!(
      file_attributes[0].name, "security.selinux",
      "fixture: {relative_path}"
    );
    assert_eq!(
      file_attributes[0].value.as_ref(),
      b"unconfined_u:object_r:unlabeled_t:s0\0",
      "fixture: {relative_path}"
    );

    let xattr1_attributes = file_system
      .extended_attributes(&xattr1_entry.node_id)
      .unwrap();
    assert!(
      xattr1_attributes
        .iter()
        .any(|attribute| attribute.name == "user.myxattr1"
          && attribute.value.as_ref() == b"My 1st extended attribute"),
      "fixture: {relative_path}"
    );
    assert!(
      xattr1_attributes
        .iter()
        .any(|attribute| attribute.name == "security.selinux"
          && attribute.value.as_ref() == b"unconfined_u:object_r:unlabeled_t:s0\0"),
      "fixture: {relative_path}"
    );
  }
}

#[test]
fn ext_open_defers_directory_scans_until_requested() {
  let (file_system, stats) = open_observed_fixture_file_system("ext/ext4.raw").unwrap();
  let after_open = stats.snapshot();
  let root_id = file_system.root_node_id();

  let root_entries = file_system.read_dir(&root_id).unwrap();
  let after_root = stats.snapshot();
  let testdir_entry = root_entries
    .into_iter()
    .find(|entry| entry.name == "testdir1")
    .unwrap();

  file_system.read_dir(&testdir_entry.node_id).unwrap();
  let after_subdir = stats.snapshot();

  file_system.read_dir(&testdir_entry.node_id).unwrap();
  let after_cached = stats.snapshot();

  assert!(after_root.read_count > after_open.read_count);
  assert!(after_subdir.read_count > after_root.read_count);
  assert_eq!(after_cached.read_count, after_subdir.read_count);
  assert_eq!(after_cached.read_bytes, after_subdir.read_bytes);
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
