//! Shared cache helpers for archive backends that need host extraction.

use std::{
  fs,
  io::Write,
  path::{Path, PathBuf},
  time::{SystemTime, UNIX_EPOCH},
};

use sha1_smol::Sha1;

use crate::{DataSource, Error, Result};

pub(crate) struct ArchiveCachePaths {
  pub source_path: PathBuf,
  pub extract_dir: PathBuf,
}

pub(crate) fn prepare_archive_cache(
  source: &dyn DataSource, namespace: &str,
) -> Result<ArchiveCachePaths> {
  let root = cache_root()?.join(namespace);
  fs::create_dir_all(&root)?;

  let size = source.size()?;
  let unique = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| {
      Error::InvalidSourceReference("archive cache clock is before UNIX epoch".to_string())
    })?
    .as_nanos();
  let source_path = root.join(format!("source-{}-{unique}.bin", std::process::id()));
  let mut file = fs::File::create(&source_path)?;
  let mut hash = Sha1::new();
  let mut offset = 0u64;
  while offset < size {
    let chunk_size = usize::try_from((size - offset).min(1024 * 1024))
      .map_err(|_| Error::InvalidRange("archive cache chunk size is too large".to_string()))?;
    let bytes = source.read_bytes_at(offset, chunk_size)?;
    hash.update(&bytes);
    file.write_all(&bytes)?;
    offset = offset
      .checked_add(chunk_size as u64)
      .ok_or_else(|| Error::InvalidRange("archive cache offset overflow".to_string()))?;
  }

  let hash_root = cache_root()?.join(namespace).join(hash.hexdigest());
  fs::create_dir_all(&hash_root)?;
  let final_source_path = hash_root.join("archive.bin");
  if final_source_path.exists() {
    fs::remove_file(&final_source_path)?;
  }
  fs::rename(&source_path, &final_source_path)?;

  Ok(ArchiveCachePaths {
    source_path: final_source_path,
    extract_dir: hash_root.join("files"),
  })
}

pub(crate) fn reset_extract_dir(path: &Path) -> Result<()> {
  if path.exists() {
    fs::remove_dir_all(path)?;
  }
  fs::create_dir_all(path)?;
  Ok(())
}

pub(crate) fn ensure_cache_space(path: &Path, required_bytes: u64) -> Result<()> {
  let existing_path = path
    .ancestors()
    .find(|candidate| candidate.exists())
    .ok_or_else(|| {
      Error::InvalidSourceReference(
        "unable to determine an existing archive cache path for free-space checks".to_string(),
      )
    })?;
  let available = available_cache_space(existing_path)?;
  if required_bytes > available {
    return Err(Error::InvalidSourceReference(format!(
      "archive cache requires {required_bytes} bytes but only {available} bytes are available"
    )));
  }
  Ok(())
}

fn cache_root() -> Result<PathBuf> {
  #[cfg(target_os = "windows")]
  {
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
      return Ok(PathBuf::from(local_app_data).join("wxtla").join("cache"));
    }
  }

  #[cfg(target_os = "macos")]
  {
    if let Some(home) = std::env::var_os("HOME") {
      return Ok(
        PathBuf::from(home)
          .join("Library")
          .join("Caches")
          .join("wxtla"),
      );
    }
  }

  if let Some(xdg_cache_home) = std::env::var_os("XDG_CACHE_HOME") {
    return Ok(PathBuf::from(xdg_cache_home).join("wxtla"));
  }
  if let Some(home) = std::env::var_os("HOME") {
    return Ok(PathBuf::from(home).join(".cache").join("wxtla"));
  }

  Err(Error::InvalidSourceReference(
    "unable to determine the host cache directory for archive extraction".to_string(),
  ))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn available_cache_space(path: &Path) -> Result<u64> {
  use std::{ffi::CString, os::unix::ffi::OsStrExt};

  let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
    Error::InvalidSourceReference("archive cache path contains interior null bytes".to_string())
  })?;
  let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
  let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
  if result != 0 {
    return Err(Error::Io(std::io::Error::last_os_error()));
  }
  let stats = unsafe { stats.assume_init() };
  let available_blocks = stats.f_bavail;
  let fragment_size = stats.f_frsize;
  Ok(available_blocks.saturating_mul(fragment_size))
}

#[cfg(target_os = "macos")]
fn available_cache_space(path: &Path) -> Result<u64> {
  use std::{ffi::CString, os::unix::ffi::OsStrExt};

  let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
    Error::InvalidSourceReference("archive cache path contains interior null bytes".to_string())
  })?;
  let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
  let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
  if result != 0 {
    return Err(Error::Io(std::io::Error::last_os_error()));
  }
  let stats = unsafe { stats.assume_init() };
  let available_blocks = u64::from(stats.f_bavail);
  let fragment_size = u64::from(stats.f_frsize);
  Ok(available_blocks.saturating_mul(fragment_size))
}

#[cfg(windows)]
fn available_cache_space(path: &Path) -> Result<u64> {
  use std::{os::windows::ffi::OsStrExt, ptr};

  #[link(name = "Kernel32")]
  unsafe extern "system" {
    fn GetDiskFreeSpaceExW(
      directory_name: *const u16, free_bytes_available: *mut u64, total_number_of_bytes: *mut u64,
      total_number_of_free_bytes: *mut u64,
    ) -> i32;
  }

  let wide_path = path
    .as_os_str()
    .encode_wide()
    .chain(std::iter::once(0))
    .collect::<Vec<_>>();
  let mut free_bytes = 0u64;
  let result = unsafe {
    GetDiskFreeSpaceExW(
      wide_path.as_ptr(),
      &mut free_bytes,
      ptr::null_mut(),
      ptr::null_mut(),
    )
  };
  if result == 0 {
    return Err(Error::Io(std::io::Error::last_os_error()));
  }
  Ok(free_bytes)
}

#[cfg(not(any(unix, windows)))]
fn available_cache_space(_path: &Path) -> Result<u64> {
  Err(Error::InvalidSourceReference(
    "archive cache free-space checks are not implemented on this host".to_string(),
  ))
}
