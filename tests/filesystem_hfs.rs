mod support;

use std::sync::Arc;

use support::{FileDataSource, child_named, fixture_path};
use wxtla::{
  ByteSourceHandle, ByteSourceReadStats, NamespaceNodeKind, NamespaceSource, ObservedDataSource,
  filesystems::hfs::HfsDriver,
};

fn open_fixture_file_system(
  relative_path: &str,
) -> wxtla::Result<wxtla::filesystems::hfs::HfsFileSystem> {
  let source: ByteSourceHandle = Arc::new(FileDataSource::open(fixture_path(relative_path))?);
  HfsDriver::open(source)
}

fn open_observed_fixture_file_system(
  relative_path: &str,
) -> wxtla::Result<(wxtla::filesystems::hfs::HfsFileSystem, ByteSourceReadStats)> {
  let observed = Arc::new(ObservedDataSource::new(Arc::new(FileDataSource::open(
    fixture_path(relative_path),
  )?)));
  let stats = observed.stats();
  let source: ByteSourceHandle = observed;

  Ok((HfsDriver::open(source)?, stats))
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
      .open_content(&empty_entry.node_id)
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
      .open_content(&testfile_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"Keramics\n"
  );
  let license_data = file_system
    .open_content(&license_entry.node_id)
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
      .open_content(&testfile_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"Keramics\n"
  );
  assert_eq!(
    file_system
      .open_content(&hardlink_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"Keramics\n"
  );
  assert_eq!(
    file_system.node(&file_symlink.node_id).unwrap().kind,
    NamespaceNodeKind::Symlink
  );
  assert_eq!(
    file_system.node(&directory_symlink.node_id).unwrap().kind,
    NamespaceNodeKind::Symlink
  );
  assert!(file_system.open_content(&file_symlink.node_id).is_err());
}

#[test]
fn hfsplus_fixture_exposes_unicode_names_symlink_targets_and_forks() {
  let file_system = open_fixture_file_system("hfs/hfsplus.raw").unwrap();
  let root_id = file_system.root_node_id();
  let root_entries = file_system.read_dir(&root_id).unwrap();

  for expected in [
    "forward:slash",
    "case_folding_µ",
    "nfc_téstfilè",
    "nfd_téstfilè",
    "nfd_¾",
    "nfkd_3⁄4",
    "file_symboliclink2",
  ] {
    assert!(
      root_entries.iter().any(|entry| entry.name == expected),
      "missing root entry: {expected}"
    );
  }
  assert!(
    !root_entries
      .iter()
      .any(|entry| entry.name.contains("Private Data"))
  );

  let file_symlink = child_named(&file_system, &root_id, "file_symboliclink1").unwrap();
  let file_symlink2 = child_named(&file_system, &root_id, "file_symboliclink2").unwrap();
  let directory_symlink = child_named(&file_system, &root_id, "directory_symboliclink1").unwrap();
  assert_eq!(
    file_system
      .symlink_target(&file_symlink.node_id)
      .unwrap()
      .as_deref(),
    Some("/Volumes/hfsplus_test/testdir1/testfile1")
  );
  assert_eq!(
    file_system
      .symlink_target(&file_symlink2.node_id)
      .unwrap()
      .as_deref(),
    Some("/Volumes/hfsplus_test/forward:slash")
  );
  assert_eq!(
    file_system
      .symlink_target(&directory_symlink.node_id)
      .unwrap()
      .as_deref(),
    Some("/Volumes/hfsplus_test/testdir1")
  );

  let testdir_entry = child_named(&file_system, &root_id, "testdir1").unwrap();
  let resource_entry = child_named(&file_system, &testdir_entry.node_id, "resourcefork1").unwrap();
  let xattr1_entry = child_named(&file_system, &testdir_entry.node_id, "xattr1").unwrap();
  let xattr2_entry = child_named(&file_system, &testdir_entry.node_id, "xattr2").unwrap();

  let resource_data = file_system
    .open_resource_fork(&resource_entry.node_id)
    .unwrap()
    .read_all()
    .unwrap();
  assert_eq!(resource_data, b"My resource fork\n");

  let xattr1 = file_system
    .extended_attributes(&xattr1_entry.node_id)
    .unwrap();
  assert!(xattr1.iter().any(|attribute| {
    attribute.name == "myxattr1" && attribute.value.as_ref() == b"My 1st extended attribute"
  }));

  let xattr2 = file_system
    .extended_attributes(&xattr2_entry.node_id)
    .unwrap();
  assert!(xattr2.iter().any(|attribute| {
    attribute.name == "myxattr2" && attribute.value.as_ref() == b"My 2nd extended attribute"
  }));
}

#[test]
fn hfsplus_open_defers_catalog_and_xattr_scans_until_requested() {
  let (file_system, stats) = open_observed_fixture_file_system("hfs/hfsplus.raw").unwrap();
  let after_open = stats.snapshot();
  let root_id = file_system.root_node_id();

  let root_entries = file_system.read_dir(&root_id).unwrap();
  let after_root = stats.snapshot();
  let testdir_entry = root_entries
    .iter()
    .find(|entry| entry.name == "testdir1")
    .unwrap()
    .clone();

  file_system.read_dir(&testdir_entry.node_id).unwrap();
  let after_cached_catalog = stats.snapshot();

  let xattr1_entry = file_system
    .read_dir(&testdir_entry.node_id)
    .unwrap()
    .into_iter()
    .find(|entry| entry.name == "xattr1")
    .unwrap();
  file_system
    .extended_attributes(&xattr1_entry.node_id)
    .unwrap();
  let after_xattr = stats.snapshot();

  file_system
    .extended_attributes(&xattr1_entry.node_id)
    .unwrap();
  let after_cached_xattr = stats.snapshot();

  assert!(after_root.read_count > after_open.read_count);
  assert_eq!(after_cached_catalog.read_count, after_root.read_count);
  assert_eq!(after_cached_catalog.read_bytes, after_root.read_bytes);
  assert!(after_xattr.read_count > after_cached_catalog.read_count);
  assert_eq!(after_cached_xattr.read_count, after_xattr.read_count);
  assert_eq!(after_cached_xattr.read_bytes, after_xattr.read_bytes);
}
