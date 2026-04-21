mod support;

use std::sync::Arc;

use support::fixture_path;
use wxtla::{ByteSourceHandle, filesystems::ffs::FfsDriver};

#[test]
fn ffs_rejects_non_ffs_image() {
  let source: ByteSourceHandle = Arc::new(wxtla::BytesDataSource::new(vec![0u8; 65536 + 8192]));
  let result = FfsDriver::open(source);
  assert!(result.is_err());
}

#[test]
fn ffs_probe_accepts_xfs_image() {
  let source: ByteSourceHandle =
    Arc::new(support::FileDataSource::open(fixture_path("xfs/xfs.raw")).unwrap());
  let result = FfsDriver::open(source);
  assert!(result.is_err());
}
