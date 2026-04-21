mod support;

use std::sync::Arc;

use wxtla::{ByteSourceHandle, filesystems::qnxfs::QnxFsDriver};

#[test]
fn qnxfs_rejects_non_qnx4_image() {
  let source: ByteSourceHandle = Arc::new(wxtla::BytesDataSource::new(vec![0u8; 2048]));
  let result = QnxFsDriver::open(source);
  assert!(result.is_err());
}

#[test]
fn qnxfs_probe_matches_synthetic_superblock() {
  let mut data = vec![0u8; 1024];
  data[512] = b'/';
  let source: ByteSourceHandle = Arc::new(wxtla::BytesDataSource::new(data));
  let result = QnxFsDriver::open(source);
  assert!(result.is_ok());
}
