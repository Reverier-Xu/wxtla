mod support;

use std::sync::Arc;

use support::{FileDataSource, child_named, fixture_path};
use wxtla::{
  ByteSourceHandle, NamespaceNodeKind, NamespaceSource, filesystems::squashfs::SquashFsDriver,
};

fn open_fixture() -> wxtla::Result<wxtla::filesystems::squashfs::SquashFsFileSystem> {
  let source: ByteSourceHandle =
    Arc::new(FileDataSource::open(fixture_path("squashfs/squashfs.raw"))?);
  SquashFsDriver::open(source)
}

#[test]
fn squashfs_exposes_root_entries() {
  let fs = open_fixture().unwrap();
  let root_id = fs.root_node_id();
  let root = fs.node(&root_id).unwrap();
  assert_eq!(root.kind, NamespaceNodeKind::Directory);

  let entries = fs.read_dir(&root_id).unwrap();
  assert!(entries.iter().any(|e| e.name == "hello.txt"));
  assert!(entries.iter().any(|e| e.name == "subdir"));
  assert!(entries.iter().any(|e| e.name == "link.txt"));
}

#[test]
fn squashfs_reads_regular_file() {
  let fs = open_fixture().unwrap();
  let root_id = fs.root_node_id();
  let hello = child_named(&fs, &root_id, "hello.txt").unwrap();
  assert_eq!(
    fs.node(&hello.node_id).unwrap().kind,
    NamespaceNodeKind::File
  );

  let data = fs.open_content(&hello.node_id).unwrap().read_all().unwrap();
  assert_eq!(String::from_utf8(data).unwrap(), "Hello from squashfs!\n");
}

#[test]
fn squashfs_reads_symlink() {
  let fs = open_fixture().unwrap();
  let root_id = fs.root_node_id();
  let link = child_named(&fs, &root_id, "link.txt").unwrap();
  assert_eq!(
    fs.node(&link.node_id).unwrap().kind,
    NamespaceNodeKind::Symlink
  );

  let target = fs.symlink_target(&link.node_id).unwrap();
  assert_eq!(target.as_deref(), Some("hello.txt"));
}

#[test]
fn squashfs_reads_subdirectory() {
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
  assert_eq!(
    String::from_utf8(data).unwrap(),
    "Another file in subdirectory\n"
  );
}
