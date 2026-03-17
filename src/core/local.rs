//! Local file backed data sources.

use std::{
  fs,
  path::{Path, PathBuf},
};

#[cfg(not(any(unix, windows)))]
use std::{
  io::{Read, Seek, SeekFrom},
  sync::Mutex,
};

use super::{DataSource, DataSourceCapabilities, DataSourceSeekCost, Error, Result};

/// A `DataSource` backed by a host file.
pub struct LocalDataSource {
  reader: LocalReadHandle,
  path: PathBuf,
  size: u64,
}

impl LocalDataSource {
  /// Open a host file for concurrent read-only access.
  pub fn open(path: impl AsRef<Path>) -> Result<Self> {
    let path = path.as_ref();
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
      return Err(Error::NotAFile(path.display().to_string()));
    }

    let file = fs::File::open(path)?;
    Ok(Self {
      reader: LocalReadHandle::new(file),
      path: path.to_path_buf(),
      size: meta.len(),
    })
  }

  /// Return the underlying host path.
  pub fn path(&self) -> &Path {
    &self.path
  }
}

/// Open a host file as a boxed `DataSource`.
pub fn open_local_file(path: impl AsRef<Path>) -> Result<Box<dyn DataSource>> {
  Ok(Box::new(LocalDataSource::open(path)?))
}

fn local_data_source_capabilities() -> DataSourceCapabilities {
  #[cfg(any(unix, windows))]
  {
    DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap)
  }

  #[cfg(not(any(unix, windows)))]
  {
    DataSourceCapabilities::serialized(DataSourceSeekCost::Cheap)
  }
}

#[cfg(any(unix, windows))]
fn local_data_source_backend_name() -> &'static str {
  "local.positional_file"
}

#[cfg(not(any(unix, windows)))]
fn local_data_source_backend_name() -> &'static str {
  "local.seek_file"
}

#[cfg(any(unix, windows))]
struct LocalReadHandle {
  file: fs::File,
}

#[cfg(any(unix, windows))]
impl LocalReadHandle {
  fn new(file: fs::File) -> Self {
    Self { file }
  }
}

#[cfg(unix)]
impl LocalReadHandle {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    use std::os::unix::fs::FileExt as _;

    Ok(self.file.read_at(buf, offset)?)
  }
}

#[cfg(windows)]
impl LocalReadHandle {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    use std::os::windows::fs::FileExt as _;

    Ok(self.file.seek_read(buf, offset)?)
  }
}

#[cfg(not(any(unix, windows)))]
struct LocalReadHandle {
  file: Mutex<fs::File>,
}

#[cfg(not(any(unix, windows)))]
impl LocalReadHandle {
  fn new(file: fs::File) -> Self {
    Self {
      file: Mutex::new(file),
    }
  }

  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let mut file = self.file.lock().map_err(|_| Error::LockPoisoned)?;
    file.seek(SeekFrom::Start(offset))?;
    Ok(file.read(buf)?)
  }
}

impl DataSource for LocalDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    self.reader.read_at(offset, buf)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    local_data_source_capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    local_data_source_backend_name()
  }

  fn origin_path(&self) -> Option<&Path> {
    Some(&self.path)
  }
}

#[cfg(test)]
mod tests {
  use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
  };

  use super::*;

  static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

  struct TestTempDir {
    path: PathBuf,
  }

  impl TestTempDir {
    fn new() -> Self {
      let mut path = std::env::temp_dir();
      let unique = format!(
        "wxtla-test-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .unwrap()
          .as_nanos(),
        TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed),
      );
      path.push(unique);
      fs::create_dir_all(&path).unwrap();
      Self { path }
    }

    fn path(&self) -> &Path {
      &self.path
    }
  }

  impl Drop for TestTempDir {
    fn drop(&mut self) {
      let _ = fs::remove_dir_all(&self.path);
    }
  }

  #[test]
  fn local_data_source_reads_host_file_content() {
    let temp = TestTempDir::new();
    let path = temp.path().join("sample.bin");
    fs::write(&path, b"hello world").unwrap();

    let source = LocalDataSource::open(&path).unwrap();
    let mut buf = [0u8; 5];
    let read = source.read_at(6, &mut buf).unwrap();

    assert_eq!(source.size().unwrap(), 11);
    assert_eq!(source.origin_path(), Some(path.as_path()));
    assert_eq!(source.telemetry_name(), local_data_source_backend_name());
    assert_eq!(read, 5);
    assert_eq!(&buf, b"world");
  }

  #[test]
  fn local_data_source_rejects_directories() {
    let temp = TestTempDir::new();
    let result = LocalDataSource::open(temp.path());

    assert!(matches!(result, Err(Error::NotAFile(_))));
  }

  #[test]
  fn open_local_file_returns_a_boxed_data_source() {
    let temp = TestTempDir::new();
    let path = temp.path().join("boxed.bin");
    fs::write(&path, b"boxed").unwrap();

    let source = open_local_file(&path).unwrap();
    let mut buf = [0u8; 5];
    let read = source.read_at(0, &mut buf).unwrap();

    assert_eq!(read, 5);
    assert_eq!(&buf, b"boxed");
  }
}
