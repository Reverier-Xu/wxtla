use std::{collections::HashMap, path::Path, sync::Arc};

use crate::{
  ByteSource, ByteSourceHandle, Error, RelatedSourceRequest, RelatedSourceResolver, Result,
};

pub struct MemDataSource {
  data: Vec<u8>,
}

impl MemDataSource {
  pub fn new(data: Vec<u8>) -> Self {
    Self { data }
  }

  pub fn from_fixture(relative_path: &str) -> Self {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Self {
      data: std::fs::read(path).unwrap(),
    }
  }
}

impl ByteSource for MemDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let offset = usize::try_from(offset)
      .map_err(|_| Error::InvalidRange("offset does not fit in usize".to_string()))?;
    if offset >= self.data.len() {
      return Ok(0);
    }
    let read = buf.len().min(self.data.len() - offset);
    buf[..read].copy_from_slice(&self.data[offset..offset + read]);
    Ok(read)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.data.len() as u64)
  }
}

pub fn sample_source(relative_path: &str) -> ByteSourceHandle {
  Arc::new(MemDataSource::from_fixture(relative_path))
}

pub fn synthetic_source(data: Vec<u8>) -> ByteSourceHandle {
  Arc::new(MemDataSource::new(data))
}

pub fn md5_hex(data: &[u8]) -> String {
  format!("{:x}", md5::compute(data))
}

pub struct Resolver {
  files: HashMap<String, ByteSourceHandle>,
}

impl Resolver {
  pub fn new(files: HashMap<String, ByteSourceHandle>) -> Self {
    Self { files }
  }
}

impl RelatedSourceResolver for Resolver {
  fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<ByteSourceHandle>> {
    Ok(self.files.get(&request.path.to_string()).cloned())
  }
}
