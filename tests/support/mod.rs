#![allow(dead_code)]

use std::{
  fs::File,
  path::{Path, PathBuf},
  sync::Arc,
};

use wxtla::{
  ByteSource, ByteSourceHandle, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceSource,
  RelatedSourceRequest, RelatedSourceResolver, Result, SourceIdentity,
};

pub fn fixture_path(relative: impl AsRef<Path>) -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("formats")
    .join(relative)
}

pub fn fixture_identity(relative: impl AsRef<Path>) -> SourceIdentity {
  SourceIdentity::from_relative_path(&relative.as_ref().to_string_lossy()).unwrap()
}

pub fn child_named(
  file_system: &dyn NamespaceSource, directory_id: &NamespaceNodeId, name: &str,
) -> wxtla::Result<NamespaceDirectoryEntry> {
  file_system
    .read_dir(directory_id)?
    .into_iter()
    .find(|entry| entry.name == name)
    .ok_or_else(|| wxtla::Error::not_found(format!("missing directory entry: {name}")))
}

pub struct FileDataSource {
  file: File,
  size: u64,
}

impl FileDataSource {
  pub fn open(path: impl AsRef<Path>) -> Result<Self> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let size = file.metadata()?.len();

    Ok(Self { file, size })
  }
}

pub struct FixtureResolver {
  root: PathBuf,
}

impl FixtureResolver {
  pub fn new(root: impl AsRef<Path>) -> Self {
    Self {
      root: root.as_ref().to_path_buf(),
    }
  }
}

impl RelatedSourceResolver for FixtureResolver {
  fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<ByteSourceHandle>> {
    let mut path = self.root.clone();
    for component in request.path.components() {
      path.push(component);
    }

    if !path.exists() || !path.is_file() {
      return Ok(None);
    }

    Ok(Some(Arc::new(FileDataSource::open(path)?)))
  }

  fn telemetry_name(&self) -> &'static str {
    "tests.fixture_resolver"
  }
}

impl ByteSource for FileDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    read_file_at(&self.file, offset, buf)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.size)
  }

  fn telemetry_name(&self) -> &'static str {
    "tests.file_data_source"
  }
}

#[cfg(unix)]
fn read_file_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
  use std::os::unix::fs::FileExt as _;

  Ok(file.read_at(buf, offset)?)
}

#[cfg(windows)]
fn read_file_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
  use std::os::windows::fs::FileExt as _;

  Ok(file.seek_read(buf, offset)?)
}

#[cfg(not(any(unix, windows)))]
fn read_file_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
  use std::io::{Read, Seek, SeekFrom};

  let mut clone = file.try_clone()?;
  clone.seek(SeekFrom::Start(offset))?;
  Ok(clone.read(buf)?)
}
