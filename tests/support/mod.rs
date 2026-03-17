use std::{
  fs::File,
  path::{Path, PathBuf},
};

use wxtla::{DataSource, Result};

pub fn fixture_path(relative: impl AsRef<Path>) -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("formats")
    .join(relative)
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

impl DataSource for FileDataSource {
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
