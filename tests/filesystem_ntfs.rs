mod support;

use std::{path::Path, sync::Arc};

use support::{FileDataSource, child_named, fixture_path};
use wxtla::{
  ByteSourceHandle, NamespaceNodeKind, NamespaceSource, ObservedDataSource,
  filesystems::ntfs::NtfsDriver,
};

fn open_fixture_file_system() -> wxtla::Result<wxtla::filesystems::ntfs::NtfsFileSystem> {
  let source: ByteSourceHandle = Arc::new(FileDataSource::open(fixture_path("ntfs/ntfs.raw"))?);
  NtfsDriver::open(source)
}

fn open_observed_fixture_file_system() -> wxtla::Result<(
  wxtla::filesystems::ntfs::NtfsFileSystem,
  wxtla::ByteSourceReadStats,
)> {
  let observed = Arc::new(ObservedDataSource::new(Arc::new(FileDataSource::open(
    fixture_path("ntfs/ntfs.raw"),
  )?)));
  let stats = observed.stats();
  let source: ByteSourceHandle = observed;

  Ok((NtfsDriver::open(source)?, stats))
}

#[test]
fn ntfs_fixture_exposes_root_and_directory_entries() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let root = file_system.node(&root_id).unwrap();
  let root_entries = file_system.read_dir(&root_id).unwrap();

  assert_eq!(root.kind, NamespaceNodeKind::Directory);
  assert!(root_entries.iter().any(|entry| entry.name == "emptyfile"));
  assert!(root_entries.iter().any(|entry| entry.name == "testdir1"));
  assert!(root_entries.iter().any(|entry| entry.name == "$UpCase"));

  let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
  let testdir = file_system.node(&testdir_entry.node_id).unwrap();
  let child_names = file_system
    .read_dir(&testdir_entry.node_id)
    .unwrap()
    .into_iter()
    .map(|entry| entry.name)
    .collect::<Vec<_>>();

  assert_eq!(testdir.kind, NamespaceNodeKind::Directory);
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
fn ntfs_fixture_reads_regular_and_empty_files() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();

  let empty_entry = child_named(&file_system, &root_id, "emptyfile").unwrap();
  let empty_node = file_system.node(&empty_entry.node_id).unwrap();
  let empty_data = file_system.open_content(&empty_entry.node_id).unwrap();
  assert_eq!(empty_node.kind, NamespaceNodeKind::File);
  assert_eq!(empty_node.size, 0);
  assert_eq!(empty_data.read_all().unwrap(), Vec::<u8>::new());

  let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
  let testfile_entry = child_named(&file_system, &testdir_entry.node_id, "testfile1").unwrap();
  let testfile_node = file_system.node(&testfile_entry.node_id).unwrap();
  let testfile_data = file_system.open_content(&testfile_entry.node_id).unwrap();

  assert_eq!(testfile_node.kind, NamespaceNodeKind::File);
  assert_eq!(testfile_node.size, 9);
  assert_eq!(testfile_data.read_all().unwrap(), b"Keramics\n");

  let long_name_entry = child_named(
    &file_system,
    &testdir_entry.node_id,
    "My long, very long file name, so very long",
  )
  .unwrap();
  let long_name_node = file_system.node(&long_name_entry.node_id).unwrap();
  let long_name_data = file_system.open_content(&long_name_entry.node_id).unwrap();
  assert_eq!(long_name_node.size, 0);
  assert_eq!(long_name_data.read_all().unwrap(), Vec::<u8>::new());
}

#[test]
fn ntfs_fixture_reads_large_nonresident_and_metadata_files() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();

  let license_entry = child_named(&file_system, &testdir_entry.node_id, "TestFile2").unwrap();
  let license_node = file_system.node(&license_entry.node_id).unwrap();
  let license_data = file_system.open_content(&license_entry.node_id).unwrap();
  let expected =
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("LICENSE.apache2.0"))
      .unwrap()
      .replace("\r\n", "\n")
      .into_bytes();
  let expected = [b"\n".as_slice(), expected.as_slice()].concat();

  assert_eq!(license_node.kind, NamespaceNodeKind::File);
  assert_eq!(license_node.size, expected.len() as u64);
  assert_eq!(license_data.read_all().unwrap(), expected);

  let upcase_entry = child_named(&file_system, &root_id, "$UpCase").unwrap();
  let upcase_node = file_system.node(&upcase_entry.node_id).unwrap();
  let upcase_data = file_system.open_content(&upcase_entry.node_id).unwrap();
  let mut prefix = [0u8; 16];

  assert_eq!(upcase_node.size, 131072);
  assert_eq!(upcase_data.read_at(0, &mut prefix).unwrap(), prefix.len());
  assert!(prefix.iter().any(|byte| *byte != 0));
}

#[test]
fn ntfs_fixture_exposes_named_data_streams() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let upcase_entry = child_named(&file_system, &root_id, "$UpCase").unwrap();

  let streams = file_system.data_streams(&upcase_entry.node_id).unwrap();
  assert_eq!(streams.len(), 2);
  assert!(
    streams
      .iter()
      .any(|stream| stream.name.is_none() && stream.size == 131072)
  );
  assert!(
    streams
      .iter()
      .any(|stream| stream.name.as_deref() == Some("$Info") && stream.size == 32)
  );

  let info_stream = file_system
    .open_data_stream(&upcase_entry.node_id, Some("$Info"))
    .unwrap();
  let info_data = info_stream.read_all().unwrap();

  assert_eq!(info_data.len(), 32);
  assert!(info_data.iter().any(|byte| *byte != 0));
}

#[test]
fn ntfs_open_defers_the_full_mft_scan_until_directory_enumeration() {
  let (file_system, stats) = open_observed_fixture_file_system().unwrap();
  let after_open = stats.snapshot();

  file_system.read_dir(&file_system.root_node_id()).unwrap();
  let after_read_dir = stats.snapshot();

  assert!(after_open.read_count > 0);
  assert!(after_read_dir.read_count > after_open.read_count * 2);
  assert!(after_read_dir.read_bytes > after_open.read_bytes * 2);
}
