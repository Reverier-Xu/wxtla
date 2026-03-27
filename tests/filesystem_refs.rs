mod support;

use std::sync::Arc;

use support::{FileDataSource, fixture_path};
use wxtla::{
  ByteSourceHandle, SliceDataSource,
  filesystems::{
    NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceSource, refs::RefsDriver,
  },
  images::ewf::EwfDriver,
};

const REFS_VOLUME_OFFSET: u64 = 34_603_008;

fn open_fixture_file_system() -> wxtla::Result<wxtla::filesystems::refs::RefsFileSystem> {
  let source: ByteSourceHandle =
    Arc::new(FileDataSource::open(fixture_path("refs/refs-v1_2-3.E01"))?);
  let image = EwfDriver::open(source)?;
  let image: ByteSourceHandle = Arc::new(image);
  let volume_header = wxtla::filesystems::refs::RefsVolumeHeader::from_bytes(
    &image.read_bytes_at(REFS_VOLUME_OFFSET, 512)?,
  )?;
  RefsDriver::open(Arc::new(SliceDataSource::new(
    image,
    REFS_VOLUME_OFFSET,
    volume_header.volume_size,
  )) as ByteSourceHandle)
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
fn refs_fixture_opens_and_lists_root() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let root = file_system.node(&root_id).unwrap();
  let root_entries = file_system.read_dir(&root_id).unwrap();

  assert_eq!(root.kind, NamespaceNodeKind::Directory);
  assert_eq!(
    root_entries
      .iter()
      .map(|entry| (entry.name.clone(), entry.kind))
      .collect::<Vec<_>>(),
    vec![
      ("$RECYCLE.BIN".to_string(), NamespaceNodeKind::Directory),
      ("NotDeleted.txt".to_string(), NamespaceNodeKind::File),
      (
        "System Volume Information".to_string(),
        NamespaceNodeKind::Directory,
      ),
    ]
  );

  let deleted = child_named(&file_system, &root_id, "$RECYCLE.BIN").unwrap();
  let recycle_entries = file_system.read_dir(&deleted.node_id).unwrap();
  assert_eq!(
    recycle_entries
      .iter()
      .map(|entry| (entry.name.clone(), entry.kind))
      .collect::<Vec<_>>(),
    vec![(
      "S-1-5-21-1814885685-2275487565-1242746162-1001".to_string(),
      NamespaceNodeKind::Directory,
    )]
  );

  let recycle_user = &recycle_entries[0];
  let recycle_user_entries = file_system.read_dir(&recycle_user.node_id).unwrap();
  assert_eq!(
    recycle_user_entries
      .iter()
      .map(|entry| (entry.name.clone(), entry.kind))
      .collect::<Vec<_>>(),
    vec![("desktop.ini".to_string(), NamespaceNodeKind::File)]
  );
}

#[test]
fn refs_fixture_reads_regular_files() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let deleted = child_named(&file_system, &root_id, "$RECYCLE.BIN").unwrap();
  let recycle_user = child_named(
    &file_system,
    &deleted.node_id,
    "S-1-5-21-1814885685-2275487565-1242746162-1001",
  )
  .unwrap();
  let desktop_ini = child_named(&file_system, &recycle_user.node_id, "desktop.ini").unwrap();

  assert_eq!(
    String::from_utf8(
      file_system
        .open_content(&desktop_ini.node_id)
        .unwrap()
        .read_all()
        .unwrap()
    )
    .unwrap(),
    "[.ShellClassInfo]\r\nCLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-8964\r\n"
  );

  let not_deleted = child_named(&file_system, &root_id, "NotDeleted.txt").unwrap();
  let streams = file_system.data_streams(&not_deleted.node_id).unwrap();
  assert_eq!(streams.len(), 1);
  assert_eq!(streams[0].name, None);
  assert_eq!(
    streams[0].size,
    file_system.node(&not_deleted.node_id).unwrap().size
  );
  assert_eq!(
    String::from_utf8(
      file_system
        .open_content(&not_deleted.node_id)
        .unwrap()
        .read_all()
        .unwrap()
    )
    .unwrap(),
    "This file has never been deleted"
  );
}

#[test]
fn refs_fixture_exposes_node_metadata() {
  let file_system = open_fixture_file_system().unwrap();
  let root_id = file_system.root_node_id();
  let not_deleted = child_named(&file_system, &root_id, "NotDeleted.txt").unwrap();
  let details = file_system.node_details(&not_deleted.node_id).unwrap();

  assert_eq!(details.attribute_flags, 0x20);
  assert!(details.creation_time > 0);
  assert!(details.modification_time > 0);
  assert_eq!(details.modification_time, details.entry_modification_time);
}
