mod support;

use std::sync::Arc;

use support::{FileDataSource, child_named, fixture_path};
use wxtla::{
  ByteSourceHandle, NamespaceNodeKind, NamespaceSource, filesystems::cramfs::CramFsDriver,
};

fn open_fixture() -> wxtla::Result<wxtla::filesystems::cramfs::CramFsFileSystem> {
  let source: ByteSourceHandle = Arc::new(FileDataSource::open(fixture_path("cramfs/cramfs.raw"))?);
  CramFsDriver::open(source)
}

#[test]
fn cramfs_exposes_root_entries() {
  let fs = open_fixture().unwrap();
  let root_id = fs.root_node_id();
  let root = fs.node(&root_id).unwrap();
  assert_eq!(root.kind, NamespaceNodeKind::Directory);

  let entries = fs.read_dir(&root_id).unwrap();
  assert!(entries.iter().any(|e| e.name == "hello.txt"));
  assert!(entries.iter().any(|e| e.name == "subdir"));
}

#[test]
fn cramfs_reads_regular_file() {
  let fs = open_fixture().unwrap();
  let root_id = fs.root_node_id();
  let hello = child_named(&fs, &root_id, "hello.txt").unwrap();
  assert_eq!(
    fs.node(&hello.node_id).unwrap().kind,
    NamespaceNodeKind::File
  );

  let data = fs.open_content(&hello.node_id).unwrap().read_all().unwrap();
  assert_eq!(String::from_utf8(data).unwrap(), "Hello from cramfs!\n");
}

#[test]
fn cramfs_reads_subdirectory() {
  let fs = open_fixture().unwrap();
  let root_id = fs.root_node_id();
  let subdir = child_named(&fs, &root_id, "subdir").unwrap();
  assert_eq!(
    fs.node(&subdir.node_id).unwrap().kind,
    NamespaceNodeKind::Directory
  );

  let entries = fs.read_dir(&subdir.node_id).unwrap();
  assert!(entries.iter().any(|e| e.name == "nested.txt"));

  let nested = child_named(&fs, &subdir.node_id, "nested.txt").unwrap();
  let data = fs
    .open_content(&nested.node_id)
    .unwrap()
    .read_all()
    .unwrap();
  assert_eq!(String::from_utf8(data).unwrap(), "Nested file\n");
}
