mod support;

use std::sync::Arc;

use support::{FileDataSource, fixture_path};
use wxtla::{
  DataSourceHandle,
  filesystems::{DirectoryEntry, FileSystem, FileSystemNodeId, FileSystemNodeKind, hfs::HfsDriver},
};

fn open_fixture_file_system(
  relative_path: &str,
) -> wxtla::Result<wxtla::filesystems::hfs::HfsFileSystem> {
  let source: DataSourceHandle = Arc::new(FileDataSource::open(fixture_path(relative_path))?);
  HfsDriver::open(source)
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
fn hfs_fixture_reads_basic_directory_and_file_contents() {
  let file_system = open_fixture_file_system("hfs/hfs.raw").unwrap();
  let root_id = file_system.root_node_id();
  let root_entries = file_system.read_dir(&root_id).unwrap();

  assert!(root_entries.iter().any(|entry| entry.name == "emptyfile"));
  assert!(root_entries.iter().any(|entry| entry.name == "testdir1"));

  let empty_entry = child_named(&file_system, &root_id, "emptyfile").unwrap();
  assert_eq!(file_system.node(&empty_entry.node_id).unwrap().size, 0);
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
  let license_entry = child_named(&file_system, &testdir_entry.node_id, "TestFile2").unwrap();

  assert_eq!(
    file_system
      .open_file(&testfile_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"Keramics\n"
  );
  let license_data = file_system
    .open_file(&license_entry.node_id)
    .unwrap()
    .read_all()
    .unwrap();
  assert!(
    license_data.starts_with(b"                                 Apache License")
      || license_data.starts_with(b"\n                                 Apache License")
  );
  assert!(license_data.ends_with(b"under the License.\n"));
}

#[test]
fn hfsplus_fixture_reads_regular_files_and_resolves_hardlinks() {
  let file_system = open_fixture_file_system("hfs/hfsplus.raw").unwrap();
  let root_id = file_system.root_node_id();
  let root_entries = file_system.read_dir(&root_id).unwrap();

  assert!(root_entries.iter().any(|entry| entry.name == "emptyfile"));
  assert!(root_entries.iter().any(|entry| entry.name == "testdir1"));
  assert!(
    root_entries
      .iter()
      .any(|entry| entry.name == "file_hardlink1")
  );
  assert!(
    root_entries
      .iter()
      .any(|entry| entry.name == "file_symboliclink1")
  );
  assert!(
    root_entries
      .iter()
      .any(|entry| entry.name == "directory_symboliclink1")
  );

  let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
  let testfile_entry = child_named(&file_system, &testdir_entry.node_id, "testfile1").unwrap();
  let hardlink_entry = child_named(&file_system, &root_id, "file_hardlink1").unwrap();
  let file_symlink = child_named(&file_system, &root_id, "file_symboliclink1").unwrap();
  let directory_symlink = child_named(&file_system, &root_id, "directory_symboliclink1").unwrap();

  assert_eq!(
    file_system
      .open_file(&testfile_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"Keramics\n"
  );
  assert_eq!(
    file_system
      .open_file(&hardlink_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"Keramics\n"
  );
  assert_eq!(
    file_system.node(&file_symlink.node_id).unwrap().kind,
    FileSystemNodeKind::Symlink
  );
  assert_eq!(
    file_system.node(&directory_symlink.node_id).unwrap().kind,
    FileSystemNodeKind::Symlink
  );
  assert!(file_system.open_file(&file_symlink.node_id).is_err());
}
