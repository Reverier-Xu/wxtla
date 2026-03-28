mod support;

use std::{fs::File, io::Read, sync::Arc};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use support::{FileDataSource, fixture_path};
use wxtla::{
  ByteSourceHandle, BytesDataSource, Credential, DataSource, DataViewSelector, OpenOptions,
  filesystems::{
    ApfsSpecialFileKind, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceSource,
    NamespaceStreamKind, apfs::ApfsDriver,
  },
  volumes::gpt::GptDriver,
};

fn open_gzip_fixture(
  relative_path: &str,
) -> wxtla::Result<wxtla::filesystems::apfs::ApfsContainer> {
  let file = File::open(fixture_path(relative_path))?;
  let mut decoder = GzDecoder::new(file);
  let mut bytes = Vec::new();
  decoder.read_to_end(&mut bytes)?;
  ApfsDriver::open(Arc::new(BytesDataSource::new(bytes)) as ByteSourceHandle)
}

fn open_gzip_volume(relative_path: &str) -> wxtla::Result<wxtla::filesystems::apfs::ApfsVolume> {
  open_gzip_fixture(relative_path)?.open_volume_by_index(0)
}

fn open_gzip_volume_with_password(
  relative_path: &str, password: &str,
) -> wxtla::Result<Box<dyn DataSource>> {
  let container = open_gzip_fixture(relative_path)?;
  let credentials = [Credential::Password(password)];
  container.open_view(
    &DataViewSelector::Index(0),
    OpenOptions::new().with_credentials(&credentials),
  )
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
fn apfs_enumerates_volume_metadata_from_gzip_fixtures() {
  for (relative_path, expected_name, case_insensitive, normalization_insensitive, encrypted) in [
    (
      "apfs/dissect.apfs/case_insensitive.bin.gz",
      "Case Insensitive",
      true,
      false,
      false,
    ),
    (
      "apfs/dissect.apfs/case_sensitive.bin.gz",
      "Case Sensitive",
      false,
      true,
      false,
    ),
    (
      "apfs/dissect.apfs/jhfs_converted.bin.gz",
      "JHFS+ Converted",
      true,
      false,
      false,
    ),
    (
      "apfs/dissect.apfs/encrypted.bin.gz",
      "Encrypted",
      true,
      false,
      true,
    ),
  ] {
    let container = open_gzip_fixture(relative_path).unwrap();
    let views = container.views().unwrap();

    assert_eq!(container.volumes().len(), 1, "fixture: {relative_path}");
    assert_eq!(views.len(), 1, "fixture: {relative_path}");

    let info = &container.volumes()[0];
    assert_eq!(info.name(), expected_name, "fixture: {relative_path}");
    assert_eq!(
      info.is_case_insensitive(),
      case_insensitive,
      "fixture: {relative_path}"
    );
    assert_eq!(
      info.is_normalization_insensitive(),
      normalization_insensitive,
      "fixture: {relative_path}"
    );
    assert_eq!(info.is_encrypted(), encrypted, "fixture: {relative_path}");
    assert_eq!(
      views[0].name.as_deref(),
      Some(expected_name),
      "fixture: {relative_path}"
    );

    let opened = container.open_volume_by_index(0).unwrap();
    assert_eq!(
      opened.info().name(),
      expected_name,
      "fixture: {relative_path}"
    );
    assert_eq!(
      container
        .open_volume_by_uuid(&info.uuid_string())
        .unwrap()
        .info()
        .name(),
      expected_name,
      "fixture: {relative_path}"
    );
    assert_eq!(
      container
        .open_volume_by_role_name("none")
        .unwrap()
        .info()
        .name(),
      expected_name,
      "fixture: {relative_path}"
    );
    assert_eq!(
      container.open_only_volume().unwrap().info().name(),
      expected_name
    );
  }
}

#[test]
fn apfs_prefers_latest_valid_checkpoint_superblock() {
  let container = open_gzip_fixture("apfs/dissect.apfs/corrupt.bin.gz").unwrap();

  assert_eq!(container.xid(), 302);
  assert_eq!(
    container.checkpoint_superblock_xids(),
    &[304, 303, 302, 301]
  );
  assert!(!container.checkpoint_maps().is_empty());
  assert!(container.checkpoint_maps()[0].is_last());
  assert_eq!(container.volumes().len(), 1);
}

#[test]
fn apfs_opens_through_gpt_stack_from_raw_dmg_fixture() {
  let source: ByteSourceHandle =
    Arc::new(FileDataSource::open(fixture_path("apfs/apfs.dmg")).unwrap());
  let gpt = GptDriver::open(source).unwrap();

  assert_eq!(gpt.volumes().len(), 1);

  let container = ApfsDriver::open(gpt.open_volume(0).unwrap()).unwrap();
  assert_eq!(container.volumes().len(), 1);
  assert_eq!(container.volumes()[0].name(), "SingleVolume");
}

#[test]
fn apfs_fixture_reads_regular_files_symlinks_and_streams() {
  let file_system = open_gzip_volume("apfs/dissect.apfs/case_insensitive.bin.gz").unwrap();
  let root_id = file_system.root_node_id();
  assert_eq!(file_system.node(&root_id).unwrap().path, "/");
  let root_entries = file_system.read_dir(&root_id).unwrap();

  assert!(root_entries.iter().any(|entry| entry.name == "dir"));
  assert!(root_entries.iter().any(|entry| entry.name == "empty"));
  assert!(root_entries.iter().any(|entry| entry.name == "hardlink"));
  assert!(
    root_entries
      .iter()
      .any(|entry| entry.name == "symlink-file")
  );

  let empty_entry = child_named(&file_system, &root_id, "empty").unwrap();
  assert_eq!(file_system.node(&empty_entry.node_id).unwrap().size, 0);
  assert_eq!(
    file_system
      .open_content(&empty_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    Vec::<u8>::new()
  );

  let dir_entry = child_named(&file_system, &root_id, "dir").unwrap();
  let file_entry = child_named(&file_system, &dir_entry.node_id, "file").unwrap();
  assert_eq!(
    file_system
      .open_content(&file_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"\xef\xa3\xbf File System\n"
  );

  let symlink_file = child_named(&file_system, &root_id, "symlink-file").unwrap();
  let symlink_dir = child_named(&file_system, &root_id, "symlink-dir").unwrap();
  assert_eq!(
    file_system
      .symlink_target(&symlink_file.node_id)
      .unwrap()
      .as_deref(),
    Some("dir/file")
  );
  assert_eq!(
    file_system
      .symlink_target(&symlink_dir.node_id)
      .unwrap()
      .as_deref(),
    Some("dir")
  );

  let resource_entry = child_named(&file_system, &dir_entry.node_id, "resourcefork").unwrap();
  assert_eq!(
    file_system
      .open_resource_fork(&resource_entry.node_id)
      .unwrap()
      .read_all()
      .unwrap(),
    b"Resource fork data\n"
  );

  let streams = file_system.data_streams(&resource_entry.node_id).unwrap();
  assert!(streams.iter().any(|stream| {
    stream.id.kind == NamespaceStreamKind::Fork && stream.id.name.as_deref() == Some("ResourceFork")
  }));
}

#[test]
fn apfs_fixture_exposes_embedded_and_stream_backed_xattrs() {
  let file_system = open_gzip_volume("apfs/dissect.apfs/case_insensitive.bin.gz").unwrap();
  let root_id = file_system.root_node_id();
  let dir_entry = child_named(&file_system, &root_id, "dir").unwrap();
  let small_entry = child_named(&file_system, &dir_entry.node_id, "xattr-small").unwrap();
  let dir_xattr_entry = child_named(&file_system, &dir_entry.node_id, "xattr-dir").unwrap();
  let large_entry = child_named(&file_system, &dir_entry.node_id, "xattr-large").unwrap();

  let small_attributes = file_system
    .extended_attributes(&small_entry.node_id)
    .unwrap();
  assert!(small_attributes.iter().any(|attribute| {
    attribute.name == "xattr-small" && attribute.value.as_ref() == b"Small xattr data"
  }));

  let dir_attributes = file_system
    .extended_attributes(&dir_xattr_entry.node_id)
    .unwrap();
  assert!(dir_attributes.iter().any(|attribute| {
    attribute.name == "xattr-dir" && attribute.value.as_ref() == b"xattr data on directory"
  }));

  let large_attributes = file_system
    .extended_attributes(&large_entry.node_id)
    .unwrap();
  let large_value = large_attributes
    .iter()
    .find(|attribute| attribute.name == "xattr-large")
    .unwrap();
  let digest = Sha256::digest(large_value.value.as_ref())
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
  assert_eq!(
    digest,
    "a11c957142c3fd8ebf2bee1ed0cf184a246033a3874d060acd28c319b323466e"
  );

  let streams = file_system.data_streams(&large_entry.node_id).unwrap();
  assert!(streams.iter().any(|stream| {
    stream.id.kind == NamespaceStreamKind::ExtendedAttribute
      && stream.id.name.as_deref() == Some("xattr-large")
      && stream.size == large_value.value.len() as u64
  }));
}

#[test]
fn apfs_fixture_reads_supported_compressed_files() {
  let file_system = open_gzip_volume("apfs/dissect.apfs/case_insensitive.bin.gz").unwrap();
  let root_id = file_system.root_node_id();
  let dir_entry = child_named(&file_system, &root_id, "dir").unwrap();

  for name in [
    "compressed-zlib-xattr",
    "compressed-zlib-fork",
    "compressed-lzvn-xattr",
    "compressed-lzvn-fork",
    "compressed-lzfse-xattr",
    "compressed-lzfse-fork",
  ] {
    let entry = child_named(&file_system, &dir_entry.node_id, name).unwrap();
    let data = file_system
      .open_content(&entry.node_id)
      .unwrap()
      .read_all()
      .unwrap();
    if name.ends_with("xattr") {
      assert_eq!(
        data,
        b"Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
      );
    } else {
      let digest = Sha256::digest(&data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
      assert_eq!(
        digest,
        "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f"
      );
    }
  }
}

#[test]
fn apfs_fixture_exposes_snapshot_views() {
  let file_system = open_gzip_volume("apfs/dissect.apfs/snapshot.bin.gz").unwrap();
  let root_id = file_system.root_node_id();

  assert_eq!(file_system.info().name(), "Snapshots");
  assert!(child_named(&file_system, &root_id, "file").is_err());

  let snapshots = file_system.views().unwrap();
  assert_eq!(
    snapshots.len(),
    usize::try_from(file_system.info().number_of_snapshots()).unwrap()
  );
  assert_eq!(snapshots[0].kind, wxtla::DataViewKind::Snapshot);
  assert_eq!(snapshots[0].name.as_deref(), Some("Snapshot 0"));
  let last_name = format!("Snapshot {}", snapshots.len() - 1);
  assert_eq!(
    snapshots.last().unwrap().name.as_deref(),
    Some(last_name.as_str())
  );

  for index in [0usize, 1, snapshots.len() - 1] {
    let expected_name = format!("Snapshot {index}");
    let snapshot = file_system
      .open_view(&DataViewSelector::Name(&expected_name), OpenOptions::new())
      .unwrap();
    let namespace = snapshot.namespace().unwrap();
    let file_entry = child_named(namespace, &namespace.root_node_id(), "file").unwrap();
    assert_eq!(
      String::from_utf8(
        namespace
          .open_content(&file_entry.node_id)
          .unwrap()
          .read_all()
          .unwrap(),
      )
      .unwrap(),
      format!("Snapshot {index}\n"),
    );
  }
}

#[test]
fn apfs_namespace_lookup_respects_case_and_normalization_rules() {
  let case_insensitive = open_gzip_volume("apfs/dissect.apfs/case_insensitive.bin.gz").unwrap();
  let case_sensitive = open_gzip_volume("apfs/dissect.apfs/case_sensitive.bin.gz").unwrap();

  let empty = case_insensitive.resolve_path("EMPTY").unwrap();
  assert_eq!(empty.id, case_insensitive.resolve_path("empty").unwrap().id);

  assert!(matches!(
    case_sensitive.resolve_path("EMPTY"),
    Err(wxtla::Error::NotFound(_))
  ));

  let normalized = case_sensitive.resolve_path("nfd_téstfilè").unwrap();
  assert_eq!(normalized.path, "/nfd_téstfilè");

  let micro = case_insensitive.resolve_path("case_folding_Μ").unwrap();
  assert_eq!(micro.path, "/case_folding_µ");

  assert!(matches!(
    case_sensitive.resolve_path("nfkd_¾"),
    Err(wxtla::Error::NotFound(_))
  ));
}

#[test]
fn apfs_hardlinks_resolve_to_the_same_inode() {
  let file_system = open_gzip_volume("apfs/dissect.apfs/case_insensitive.bin.gz").unwrap();

  let direct = file_system.resolve_path("dir/file").unwrap();
  let hardlink = file_system.resolve_path("hardlink").unwrap();

  assert_eq!(direct.id, hardlink.id);
  assert_eq!(
    file_system.paths(&direct.id).unwrap(),
    vec!["/dir/file", "/hardlink"]
  );
  assert_eq!(
    file_system.names(&direct.id).unwrap(),
    vec!["file", "hardlink"]
  );
  assert_eq!(file_system.node(&direct.id).unwrap().path, "/dir/file");
}

#[test]
fn apfs_special_files_are_classified_without_regular_content_streams() {
  let file_system = open_gzip_volume("apfs/dissect.apfs/case_insensitive.bin.gz").unwrap();

  for (path, expected_kind, expect_rdev) in [
    ("dir/fifo", ApfsSpecialFileKind::Fifo, false),
    ("dir/blockdev", ApfsSpecialFileKind::BlockDevice, true),
    (
      "dir/chardev-linux",
      ApfsSpecialFileKind::CharacterDevice,
      true,
    ),
  ] {
    let node = file_system.resolve_path(path).unwrap();
    let details = file_system.node_details(&node.id).unwrap();

    assert_eq!(node.kind, wxtla::NamespaceNodeKind::Special);
    assert_eq!(details.special_file_kind, Some(expected_kind));
    assert_eq!(details.rdev.is_some(), expect_rdev);
    assert!(matches!(
      file_system.open_content(&node.id),
      Err(wxtla::Error::InvalidFormat(_))
    ));
  }
}

#[test]
fn apfs_fixture_unlocks_encrypted_volumes_with_password() {
  for relative_path in [
    "apfs/dissect.apfs/encrypted.bin.gz",
    "apfs/dissect.apfs/jhfs_encrypted.bin.gz",
  ] {
    let container = open_gzip_fixture(relative_path).unwrap();
    let metadata_only = container.open_volume_by_index(0).unwrap();
    assert!(metadata_only.is_onekey());
    let expected_hint = if relative_path == "apfs/dissect.apfs/encrypted.bin.gz" {
      Some("It's 'password'")
    } else {
      None
    };
    assert_eq!(
      metadata_only.password_hint().unwrap().as_deref(),
      expected_hint
    );

    let volume = open_gzip_volume_with_password(relative_path, "password").unwrap();
    let namespace = volume.namespace().unwrap();
    let root_id = namespace.root_node_id();
    let dir_entry = child_named(namespace, &root_id, "dir").unwrap();
    let file_entry = child_named(namespace, &dir_entry.node_id, "file").unwrap();
    assert_eq!(
      namespace
        .open_content(&file_entry.node_id)
        .unwrap()
        .read_all()
        .unwrap(),
      b"\xef\xa3\xbf File System\n"
    );
  }
}

#[test]
fn apfs_fixture_rejects_incorrect_password() {
  let container = open_gzip_fixture("apfs/dissect.apfs/encrypted.bin.gz").unwrap();
  let credentials = [Credential::Password("wrong-password")];
  let result = container.open_view(
    &DataViewSelector::Index(0),
    OpenOptions::new().with_credentials(&credentials),
  );

  assert!(matches!(
    result,
    Err(wxtla::Error::InvalidSourceReference(_))
  ));
}

#[test]
fn apfs_encrypted_dmg_opens_through_gpt_with_password() {
  let source: ByteSourceHandle =
    Arc::new(FileDataSource::open(fixture_path("apfs/apfs_encrypted.dmg")).unwrap());
  let gpt = GptDriver::open(source).unwrap();
  let container = ApfsDriver::open(gpt.open_volume(0).unwrap()).unwrap();
  let volume_meta = container.open_volume_by_index(0).unwrap();
  assert!(volume_meta.is_onekey());
  assert_eq!(volume_meta.password_hint().unwrap(), None);
  let credentials = [Credential::Password("apfs-TEST")];
  let volume = container
    .open_view(
      &DataViewSelector::Index(0),
      OpenOptions::new().with_credentials(&credentials),
    )
    .unwrap();
  let namespace = volume.namespace().unwrap();

  assert!(
    !namespace
      .read_dir(&namespace.root_node_id())
      .unwrap()
      .is_empty()
  );
}
