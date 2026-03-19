//! Read-only RAR archive surface backed by cached extraction.

use std::{
  collections::{BTreeMap, HashMap},
  io::Read,
  path::{Path, PathBuf},
  process::{Command, ExitStatus, Stdio},
  thread,
  time::{Duration, Instant},
};

use super::DESCRIPTOR;
use crate::{
  DataSourceHandle, Error, FileDataSource, Result, SourceHints,
  archives::{
    Archive, ArchiveDirectoryEntry, ArchiveEntryId, ArchiveEntryKind, ArchiveEntryRecord,
    cache::{ArchiveCachePaths, ensure_cache_space, prepare_archive_cache, reset_extract_dir},
  },
};

const ROOT_ENTRY_ID: u64 = 0;
const LIST_TIMEOUT: Duration = Duration::from_secs(15);
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct RarArchive {
  entries: Vec<RarEntry>,
  path_to_id: HashMap<String, ArchiveEntryId>,
  cache: ArchiveCachePaths,
  total_uncompressed_size: u64,
  locked: bool,
  headers_locked: bool,
}

#[derive(Clone)]
struct RarEntry {
  record: ArchiveEntryRecord,
  children: Vec<ArchiveDirectoryEntry>,
  extracted_path: Option<PathBuf>,
}

#[derive(Clone)]
struct RarListingEntry {
  path: String,
  kind: ArchiveEntryKind,
  size: u64,
  encrypted: bool,
}

impl RarArchive {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let cache = prepare_archive_cache(source.as_ref(), "rar")?;
    match list_archive(&cache.source_path, None) {
      Ok(listing) => {
        let total_uncompressed_size = listing.iter().map(|entry| entry.size).sum();
        let locked = listing.iter().any(|entry| entry.encrypted);
        let (entries, path_to_id) = build_tree(&listing, Some(&cache.extract_dir))?;
        let mut archive = Self {
          entries,
          path_to_id,
          cache,
          total_uncompressed_size,
          locked,
          headers_locked: false,
        };
        if !archive.locked {
          archive.extract(None)?;
        }
        Ok(archive)
      }
      Err(Error::InvalidSourceReference(message))
        if message.contains("encrypted headers") || message.contains("Wrong password") =>
      {
        Ok(Self {
          entries: vec![RarEntry {
            record: ArchiveEntryRecord::new(
              ArchiveEntryId::from_u64(ROOT_ENTRY_ID),
              ArchiveEntryKind::Directory,
              String::new(),
              0,
            ),
            children: Vec::new(),
            extracted_path: None,
          }],
          path_to_id: HashMap::new(),
          cache,
          total_uncompressed_size: 0,
          locked: true,
          headers_locked: true,
        })
      }
      Err(error) => Err(error),
    }
  }

  pub fn find_entry_by_path(&self, path: &str) -> Option<ArchiveEntryId> {
    self.path_to_id.get(path).cloned()
  }

  fn populate_listing(&mut self, password: &str) -> Result<()> {
    let listing = list_archive(&self.cache.source_path, Some(password))?;
    self.total_uncompressed_size = listing.iter().map(|entry| entry.size).sum();
    let (entries, path_to_id) = build_tree(&listing, Some(&self.cache.extract_dir))?;
    self.entries = entries;
    self.path_to_id = path_to_id;
    self.headers_locked = false;
    Ok(())
  }

  fn extract(&mut self, password: Option<&str>) -> Result<()> {
    ensure_cache_space(&self.cache.extract_dir, self.total_uncompressed_size)?;
    reset_extract_dir(&self.cache.extract_dir)?;

    let mut command = archive_tool_command();
    command
      .arg("x")
      .arg("-y")
      .arg("-bb0")
      .arg("-bso0")
      .arg("-bsp0")
      .arg(format!("-o{}", self.cache.extract_dir.display()));
    if let Some(password) = password {
      command.arg(format!("-p{password}"));
    }
    command.arg(&self.cache.source_path);
    command.stdout(Stdio::null());
    let output = run_command_with_timeout(command, EXTRACT_TIMEOUT)?;
    if !output.status.success() {
      return Err(Error::InvalidSourceReference(if password.is_some() {
        "rar archive password unlock failed".to_string()
      } else {
        format!(
          "unable to extract rar archive into cache: {}",
          String::from_utf8_lossy(&output.stderr)
        )
      }));
    }

    self.locked = false;
    self.refresh_extracted_paths();
    Ok(())
  }

  fn refresh_extracted_paths(&mut self) {
    for entry in self.entries.iter_mut().skip(1) {
      entry.extracted_path = if entry.record.kind == ArchiveEntryKind::File {
        Some(self.cache.extract_dir.join(&entry.record.path))
      } else {
        None
      };
    }
  }

  fn entry_ref(&self, entry_id: &ArchiveEntryId) -> Result<&RarEntry> {
    let index = entry_id_to_index(entry_id)?;
    self
      .entries
      .get(index)
      .ok_or_else(|| Error::NotFound(format!("missing rar archive entry index: {index}")))
  }
}

impl Archive for RarArchive {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_entry_id(&self) -> ArchiveEntryId {
    ArchiveEntryId::from_u64(ROOT_ENTRY_ID)
  }

  fn entry(&self, entry_id: &ArchiveEntryId) -> Result<ArchiveEntryRecord> {
    if self.headers_locked {
      return Err(Error::InvalidSourceReference(
        "rar archive headers are encrypted; unlock the archive before reading entries".to_string(),
      ));
    }
    Ok(self.entry_ref(entry_id)?.record.clone())
  }

  fn read_dir(&self, directory_id: &ArchiveEntryId) -> Result<Vec<ArchiveDirectoryEntry>> {
    if self.headers_locked {
      return Err(Error::InvalidSourceReference(
        "rar archive headers are encrypted; unlock the archive before listing entries".to_string(),
      ));
    }
    let entry = self.entry_ref(directory_id)?;
    if entry.record.kind != ArchiveEntryKind::Directory {
      return Err(Error::InvalidFormat(
        "rar directory reads require a directory entry".to_string(),
      ));
    }
    Ok(entry.children.clone())
  }

  fn open_file(&self, entry_id: &ArchiveEntryId) -> Result<DataSourceHandle> {
    if self.locked {
      return Err(Error::InvalidSourceReference(
        "rar archive is locked; unlock it with a password before opening files".to_string(),
      ));
    }
    let entry = self.entry_ref(entry_id)?;
    if entry.record.kind != ArchiveEntryKind::File {
      return Err(Error::InvalidFormat(
        "rar file opens require a regular file entry".to_string(),
      ));
    }
    let path = entry.extracted_path.as_ref().ok_or_else(|| {
      Error::InvalidFormat("rar file entry does not have a cached extraction path".to_string())
    })?;
    Ok(std::sync::Arc::new(FileDataSource::open(path)?) as DataSourceHandle)
  }

  fn is_locked(&self) -> bool {
    self.locked || self.headers_locked
  }

  fn unlock_with_password(&mut self, password: &str) -> Result<bool> {
    if !self.headers_locked && !self.locked {
      return Ok(true);
    }
    if self.headers_locked {
      match self.populate_listing(password) {
        Ok(()) => {}
        Err(Error::InvalidSourceReference(_)) => return Ok(false),
        Err(error) => return Err(error),
      }
    }
    match self.extract(Some(password)) {
      Ok(()) => Ok(true),
      Err(Error::InvalidSourceReference(_)) => Ok(false),
      Err(error) => Err(error),
    }
  }
}

fn list_archive(source_path: &Path, password: Option<&str>) -> Result<Vec<RarListingEntry>> {
  let mut command = archive_tool_command();
  command.arg("l").arg("-slt");
  if let Some(password) = password {
    command.arg(format!("-p{password}"));
  }
  command.arg(source_path);
  let output = run_command_with_timeout(command, LIST_TIMEOUT)?;
  if !output.status.success() {
    return Err(Error::InvalidSourceReference(format!(
      "unable to list rar archive contents: {}",
      String::from_utf8_lossy(&output.stderr)
    )));
  }
  parse_rar_listing(&String::from_utf8_lossy(&output.stdout))
}

fn archive_tool_command() -> Command {
  Command::new(select_archive_tool())
}

fn select_archive_tool() -> &'static str {
  if command_exists("7z") { "7z" } else { "7zz" }
}

fn command_exists(command: &str) -> bool {
  let Some(path) = std::env::var_os("PATH") else {
    return false;
  };
  let candidates = if cfg!(windows) {
    vec![
      format!("{command}.exe"),
      format!("{command}.cmd"),
      command.to_string(),
    ]
  } else {
    vec![command.to_string()]
  };

  std::env::split_paths(&path).any(|dir| {
    candidates
      .iter()
      .any(|candidate| dir.join(candidate).is_file())
  })
}

fn run_command_with_timeout(mut command: Command, timeout: Duration) -> Result<CommandOutput> {
  command.stdout(Stdio::piped());
  command.stderr(Stdio::piped());

  let mut child = command.spawn()?;
  let mut stdout = child
    .stdout
    .take()
    .ok_or_else(|| Error::InvalidSourceReference("missing command stdout pipe".to_string()))?;
  let mut stderr = child
    .stderr
    .take()
    .ok_or_else(|| Error::InvalidSourceReference("missing command stderr pipe".to_string()))?;
  let start = Instant::now();

  loop {
    if let Some(status) = child.try_wait()? {
      let mut stdout_bytes = Vec::new();
      let mut stderr_bytes = Vec::new();
      stdout.read_to_end(&mut stdout_bytes)?;
      stderr.read_to_end(&mut stderr_bytes)?;
      return Ok(CommandOutput {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
      });
    }

    if start.elapsed() >= timeout {
      let _ = child.kill();
      let _ = child.wait();
      return Err(Error::InvalidSourceReference(format!(
        "rar helper command timed out after {} seconds",
        timeout.as_secs()
      )));
    }

    thread::sleep(Duration::from_millis(50));
  }
}

struct CommandOutput {
  status: ExitStatus,
  stdout: Vec<u8>,
  stderr: Vec<u8>,
}

fn parse_rar_listing(text: &str) -> Result<Vec<RarListingEntry>> {
  let mut entries = Vec::new();
  let mut current = BTreeMap::<String, String>::new();
  let mut in_entries = false;
  for line in text.lines() {
    let line = line.trim_end();
    if line == "----------" {
      in_entries = true;
      continue;
    }
    if !in_entries {
      continue;
    }
    if line.is_empty() {
      if let Some(entry) = listing_entry_from_map(&current)? {
        entries.push(entry);
      }
      current.clear();
      continue;
    }
    if let Some((key, value)) = line.split_once(" = ") {
      current.insert(key.to_string(), value.to_string());
    }
  }
  if let Some(entry) = listing_entry_from_map(&current)? {
    entries.push(entry);
  }
  Ok(entries)
}

fn listing_entry_from_map(map: &BTreeMap<String, String>) -> Result<Option<RarListingEntry>> {
  let Some(path) = map.get("Path") else {
    return Ok(None);
  };
  if map.get("Type").is_some() {
    return Ok(None);
  }
  let is_dir = map.get("Folder").is_some_and(|value| value == "+")
    || map
      .get("Attributes")
      .is_some_and(|value| value.starts_with('D'));
  let normalized = normalize_path(path, is_dir)?;
  if normalized.is_empty() {
    return Ok(None);
  }
  let size = map
    .get("Size")
    .and_then(|value| value.parse().ok())
    .unwrap_or(0);
  Ok(Some(RarListingEntry {
    path: normalized,
    kind: if is_dir {
      ArchiveEntryKind::Directory
    } else {
      ArchiveEntryKind::File
    },
    size,
    encrypted: map.get("Encrypted").is_some_and(|value| value == "+")
      || map
        .get("Flags")
        .is_some_and(|value| value.to_ascii_lowercase().contains("encrypted"))
      || map
        .get("Method")
        .is_some_and(|value| value.contains("AES") || value.contains("Crypt")),
  }))
}

fn build_tree(
  listing: &[RarListingEntry], extract_root: Option<&Path>,
) -> Result<(Vec<RarEntry>, HashMap<String, ArchiveEntryId>)> {
  let mut builders = BTreeMap::<String, RarListingEntry>::new();
  for entry in listing {
    ensure_parent_directories(&mut builders, &entry.path)?;
    builders.insert(entry.path.clone(), entry.clone());
  }

  let mut path_to_id = HashMap::new();
  let ordered_paths = builders.keys().cloned().collect::<Vec<_>>();
  for (index, path) in ordered_paths.iter().enumerate() {
    path_to_id.insert(path.clone(), ArchiveEntryId::from_u64(index as u64 + 1));
  }

  let mut entries = Vec::with_capacity(ordered_paths.len() + 1);
  entries.push(RarEntry {
    record: ArchiveEntryRecord::new(
      ArchiveEntryId::from_u64(ROOT_ENTRY_ID),
      ArchiveEntryKind::Directory,
      String::new(),
      0,
    ),
    children: Vec::new(),
    extracted_path: None,
  });
  for path in &ordered_paths {
    let entry = builders
      .get(path)
      .ok_or_else(|| Error::InvalidFormat(format!("missing rar entry builder for path: {path}")))?;
    let id = path_to_id.get(path).cloned().ok_or_else(|| {
      Error::InvalidFormat(format!("missing rar entry identifier for path: {path}"))
    })?;
    entries.push(RarEntry {
      record: ArchiveEntryRecord::new(id, entry.kind, path.clone(), entry.size),
      children: Vec::new(),
      extracted_path: extract_root
        .and_then(|root| (entry.kind == ArchiveEntryKind::File).then(|| root.join(path))),
    });
  }

  for path in &ordered_paths {
    let child_id = path_to_id
      .get(path)
      .cloned()
      .ok_or_else(|| Error::InvalidFormat(format!("missing rar path mapping for path: {path}")))?;
    let child_index = entry_id_to_index(&child_id)?;
    let child_kind = entries[child_index].record.kind;
    let name = relative_name(path);
    let parent_index = match parent_path(path) {
      Some(parent) => entry_id_to_index(path_to_id.get(parent).ok_or_else(|| {
        Error::InvalidFormat(format!("missing rar parent directory mapping: {parent}"))
      })?)?,
      None => 0,
    };
    entries[parent_index]
      .children
      .push(ArchiveDirectoryEntry::new(name, child_id, child_kind));
  }
  for entry in &mut entries {
    entry
      .children
      .sort_by(|left, right| left.name.cmp(&right.name));
  }
  Ok((entries, path_to_id))
}

fn ensure_parent_directories(
  builders: &mut BTreeMap<String, RarListingEntry>, path: &str,
) -> Result<()> {
  let mut current = path;
  while let Some(parent) = parent_path(current) {
    builders
      .entry(parent.to_string())
      .or_insert_with(|| RarListingEntry {
        path: parent.to_string(),
        kind: ArchiveEntryKind::Directory,
        size: 0,
        encrypted: false,
      });
    current = parent;
  }
  Ok(())
}

fn normalize_path(path: &str, is_dir: bool) -> Result<String> {
  let path = path.trim_matches(' ').trim();
  let path = path.strip_prefix("./").unwrap_or(path);
  let components = path
    .split('/')
    .filter(|component| !component.is_empty() && *component != ".")
    .collect::<Vec<_>>();
  if components.contains(&"..") {
    return Err(Error::InvalidFormat(
      "rar paths must not contain parent directory traversals".to_string(),
    ));
  }
  let normalized = components.join("/");
  if normalized.is_empty() && !is_dir {
    return Err(Error::InvalidFormat(
      "rar file entries must have a non-empty path".to_string(),
    ));
  }
  Ok(normalized)
}

fn parent_path(path: &str) -> Option<&str> {
  path.rsplit_once('/').map(|(parent, _)| parent)
}

fn relative_name(path: &str) -> String {
  path
    .rsplit_once('/')
    .map_or_else(|| path.to_string(), |(_, name)| name.to_string())
}

fn entry_id_to_index(entry_id: &ArchiveEntryId) -> Result<usize> {
  let bytes: [u8; 8] = entry_id.as_bytes().try_into().map_err(|_| {
    Error::InvalidFormat("rar archive entry identifiers must be native u64 values".to_string())
  })?;
  usize::try_from(u64::from_le_bytes(bytes))
    .map_err(|_| Error::InvalidRange("rar archive entry index is too large".to_string()))
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;
  use crate::DataSource;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = usize::try_from(offset)
        .map_err(|_| Error::InvalidRange("test read offset is too large".to_string()))?;
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

  fn sample_source(relative_path: &str) -> DataSourceHandle {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Arc::new(MemDataSource {
      data: std::fs::read(path).unwrap(),
    })
  }

  fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
  }

  #[test]
  fn opens_plain_fixture_metadata_and_contents() {
    let archive = RarArchive::open(sample_source("rar/version.rar")).unwrap();
    let id = archive.find_entry_by_path("VERSION").unwrap();
    let data = archive.open_file(&id).unwrap().read_all().unwrap();
    assert_eq!(std::str::from_utf8(&data).unwrap(), "unrar-0.4.0");
  }

  #[test]
  fn unlocks_encrypted_fixture_with_password() {
    let mut archive = RarArchive::open(sample_source("rar/crypted.rar")).unwrap();
    assert!(archive.is_locked());
    assert!(!archive.unlock_with_password("wrong").unwrap());
    assert!(archive.unlock_with_password("unrar").unwrap());

    let id = archive.find_entry_by_path(".gitignore").unwrap();
    let data = archive.open_file(&id).unwrap().read_all().unwrap();
    assert_eq!(std::str::from_utf8(&data).unwrap(), "target\nCargo.lock\n");
  }

  #[test]
  fn unlocks_header_encrypted_fixture_with_password() {
    let mut archive = RarArchive::open(sample_source("rar/comment-hpw-password.rar")).unwrap();
    assert!(archive.is_locked());
    assert!(archive.read_dir(&archive.root_entry_id()).is_err());
    assert!(archive.unlock_with_password("password").unwrap());

    let id = archive.find_entry_by_path(".gitignore").unwrap();
    let data = archive.open_file(&id).unwrap().read_all().unwrap();
    assert_eq!(md5_hex(&data), md5_hex(b"target\nCargo.lock\n"));
  }
}
