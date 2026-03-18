mod support;

use std::sync::Arc;

use support::{FileDataSource, fixture_path};
use wxtla::{
  DataSourceHandle,
  filesystems::{DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, fat::FatDriver},
  images::qcow::QcowDriver,
};

fn open_raw_fixture_file_system(
  relative_path: &str,
) -> wxtla::Result<wxtla::filesystems::fat::FatFileSystem> {
  let source: DataSourceHandle = Arc::new(FileDataSource::open(fixture_path(relative_path))?);
  FatDriver::open(source)
}

fn open_qcow_fixture_file_system(
  relative_path: &str,
) -> wxtla::Result<wxtla::filesystems::fat::FatFileSystem> {
  let source: DataSourceHandle = Arc::new(FileDataSource::open(fixture_path(relative_path))?);
  let image = QcowDriver::open(source)?;
  FatDriver::open(Arc::new(image) as DataSourceHandle)
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
fn fat12_fixture_exposes_root_and_directory_entries() {
  let file_system = open_raw_fixture_file_system("fat/fat12.raw").unwrap();
  let root_id = file_system.root_node_id();
  let root = file_system.node(&root_id).unwrap();
  let root_entries = file_system.read_dir(&root_id).unwrap();

  assert_eq!(root.kind, FileSystemNodeKind::Directory);
  assert!(root_entries.iter().any(|entry| entry.name == "emptyfile"));
  assert!(root_entries.iter().any(|entry| entry.name == "testdir1"));

  let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
  let child_names = file_system
    .read_dir(&testdir_entry.node_id)
    .unwrap()
    .into_iter()
    .map(|entry| entry.name)
    .collect::<Vec<_>>();
  assert_eq!(
    child_names,
    vec![
      "My long, very long file name, so very long".to_string(),
      "TestFile2".to_string(),
      "testfile1".to_string(),
    ]
  );
}

#[test]
fn fat12_fixture_reads_regular_and_empty_files() {
  let file_system = open_raw_fixture_file_system("fat/fat12.raw").unwrap();
  let root_id = file_system.root_node_id();

  let empty_entry = child_named(&file_system, &root_id, "emptyfile").unwrap();
  let empty_node = file_system.node(&empty_entry.node_id).unwrap();
  assert_eq!(empty_node.kind, FileSystemNodeKind::File);
  assert_eq!(empty_node.size, 0);
  assert_eq!(
    file_system
      .open_file(&empty_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    Vec::<u8>::new()
  );

  let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
  let testfile_entry = child_named(&file_system, &testdir_entry.node_id, "testfile1").unwrap();
  let testfile = file_system.open_file(&testfile_entry.node_id).unwrap();
  assert_eq!(file_system.node(&testfile_entry.node_id).unwrap().size, 9);
  assert_eq!(testfile.read_all().unwrap(), b"Keramics\n");

  let long_name_entry = child_named(
    &file_system,
    &testdir_entry.node_id,
    "My long, very long file name, so very long",
  )
  .unwrap();
  assert_eq!(file_system.node(&long_name_entry.node_id).unwrap().size, 0);
  assert_eq!(
    file_system
      .open_file(&long_name_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    Vec::<u8>::new()
  );
}

#[test]
fn fat16_and_fat32_qcow_fixtures_open_and_read_files() {
  for relative_path in ["qcow/fat16.qcow2", "qcow/fat32.qcow2"] {
    let file_system = open_qcow_fixture_file_system(relative_path).unwrap();
    let root_id = file_system.root_node_id();
    let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
    let testfile_entry = child_named(&file_system, &testdir_entry.node_id, "testfile1").unwrap();
    let license_entry = child_named(&file_system, &testdir_entry.node_id, "TestFile2").unwrap();
    let long_name_entry = child_named(
      &file_system,
      &testdir_entry.node_id,
      "My long, very long file name, so very long",
    )
    .unwrap();

    assert_eq!(
      file_system.node(&testfile_entry.node_id).unwrap().size,
      9,
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

    assert_eq!(
      file_system.node(&long_name_entry.node_id).unwrap().size,
      0,
      "fixture: {relative_path}"
    );
  }
}
