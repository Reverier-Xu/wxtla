//! Read-only ZIP archive surface backed by cached extraction.

use std::{
  collections::{BTreeMap, HashMap},
  path::{Path, PathBuf},
  process::Command,
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

pub struct ZipArchive {
  entries: Vec<ZipEntry>,
  path_to_id: HashMap<String, ArchiveEntryId>,
  cache: ArchiveCachePaths,
  total_uncompressed_size: u64,
  locked: bool,
}

#[derive(Clone)]
struct ZipEntry {
  record: ArchiveEntryRecord,
  children: Vec<ArchiveDirectoryEntry>,
  extracted_path: Option<PathBuf>,
}

#[derive(Clone)]
struct ZipListingEntry {
  path: String,
  kind: ArchiveEntryKind,
  size: u64,
  encrypted: bool,
}

impl ZipArchive {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let cache = prepare_archive_cache(source.as_ref(), "zip")?;
    let listing = list_archive(&cache.source_path)?;
    let total_uncompressed_size = listing.iter().map(|entry| entry.size).sum();
    let locked = listing.iter().any(|entry| entry.encrypted);
    let (entries, path_to_id) = build_tree(&listing, Some(&cache.extract_dir))?;
    let mut archive = Self {
      entries,
      path_to_id,
      cache,
      total_uncompressed_size,
      locked,
    };
    if !archive.locked {
      archive.extract(None)?;
    }
    Ok(archive)
  }

  pub fn find_entry_by_path(&self, path: &str) -> Option<ArchiveEntryId> {
    self.path_to_id.get(path).cloned()
  }

  fn extract(&mut self, password: Option<&str>) -> Result<()> {
    ensure_cache_space(&self.cache.extract_dir, self.total_uncompressed_size)?;
    reset_extract_dir(&self.cache.extract_dir)?;

    let mut command = Command::new("7z");
    command
      .arg("x")
      .arg("-y")
      .arg(format!("-o{}", self.cache.extract_dir.display()));
    if let Some(password) = password {
      command.arg(format!("-p{password}"));
    }
    command.arg(&self.cache.source_path);
    let output = command.output()?;
    if !output.status.success() {
      return Err(Error::InvalidSourceReference(if password.is_some() {
        "zip archive password unlock failed".to_string()
      } else {
        format!(
          "unable to extract zip archive into cache: {}",
          String::from_utf8_lossy(&output.stderr)
        )
      }));
    }

    self.locked = false;
    self.refresh_extracted_paths()?;
    Ok(())
  }

  fn refresh_extracted_paths(&mut self) -> Result<()> {
    for entry in self.entries.iter_mut().skip(1) {
      entry.extracted_path = if entry.record.kind == ArchiveEntryKind::File {
        Some(self.cache.extract_dir.join(&entry.record.path))
      } else {
        None
      };
    }
    Ok(())
  }

  fn entry_ref(&self, entry_id: &ArchiveEntryId) -> Result<&ZipEntry> {
    let index = entry_id_to_index(entry_id)?;
    self
      .entries
      .get(index)
      .ok_or_else(|| Error::NotFound(format!("missing zip archive entry index: {index}")))
  }
}

impl Archive for ZipArchive {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_entry_id(&self) -> ArchiveEntryId {
    ArchiveEntryId::from_u64(ROOT_ENTRY_ID)
  }

  fn entry(&self, entry_id: &ArchiveEntryId) -> Result<ArchiveEntryRecord> {
    Ok(self.entry_ref(entry_id)?.record.clone())
  }

  fn read_dir(&self, directory_id: &ArchiveEntryId) -> Result<Vec<ArchiveDirectoryEntry>> {
    let entry = self.entry_ref(directory_id)?;
    if entry.record.kind != ArchiveEntryKind::Directory {
      return Err(Error::InvalidFormat(
        "zip directory reads require a directory entry".to_string(),
      ));
    }
    Ok(entry.children.clone())
  }

  fn open_file(&self, entry_id: &ArchiveEntryId) -> Result<DataSourceHandle> {
    if self.locked {
      return Err(Error::InvalidSourceReference(
        "zip archive is locked; unlock it with a password before opening files".to_string(),
      ));
    }
    let entry = self.entry_ref(entry_id)?;
    if entry.record.kind != ArchiveEntryKind::File {
      return Err(Error::InvalidFormat(
        "zip file opens require a regular file entry".to_string(),
      ));
    }
    let path = entry.extracted_path.as_ref().ok_or_else(|| {
      Error::InvalidFormat("zip file entry does not have a cached extraction path".to_string())
    })?;
    Ok(std::sync::Arc::new(FileDataSource::open(path)?) as DataSourceHandle)
  }

  fn is_locked(&self) -> bool {
    self.locked
  }

  fn unlock_with_password(&mut self, password: &str) -> Result<bool> {
    if !self.locked {
      return Ok(true);
    }
    match self.extract(Some(password)) {
      Ok(()) => Ok(true),
      Err(Error::InvalidSourceReference(_)) => Ok(false),
      Err(error) => Err(error),
    }
  }
}

fn list_archive(source_path: &Path) -> Result<Vec<ZipListingEntry>> {
  let output = Command::new("7z")
    .arg("l")
    .arg("-slt")
    .arg(source_path)
    .output()?;
  if !output.status.success() {
    return Err(Error::InvalidFormat(format!(
      "unable to list zip archive contents: {}",
      String::from_utf8_lossy(&output.stderr)
    )));
  }

  parse_7z_slt_listing(&String::from_utf8_lossy(&output.stdout))
}

fn parse_7z_slt_listing(text: &str) -> Result<Vec<ZipListingEntry>> {
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

fn listing_entry_from_map(map: &BTreeMap<String, String>) -> Result<Option<ZipListingEntry>> {
  let Some(path) = map.get("Path") else {
    return Ok(None);
  };
  if map.get("Type").is_some() {
    return Ok(None);
  }
  let is_dir = map.get("Folder").is_some_and(|value| value == "+");
  let normalized = normalize_path(path, is_dir)?;
  if normalized.is_empty() {
    return Ok(None);
  }
  let size = map
    .get("Size")
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or(0);
  Ok(Some(ZipListingEntry {
    path: normalized,
    kind: if is_dir {
      ArchiveEntryKind::Directory
    } else {
      ArchiveEntryKind::File
    },
    size,
    encrypted: map.get("Encrypted").is_some_and(|value| value == "+")
      || map
        .get("Method")
        .is_some_and(|value| value.contains("ZipCrypto") || value.contains("AES"))
      || map
        .get("Characteristics")
        .is_some_and(|value| value.contains("Encrypt")),
  }))
}

fn build_tree(
  listing: &[ZipListingEntry], extract_root: Option<&Path>,
) -> Result<(Vec<ZipEntry>, HashMap<String, ArchiveEntryId>)> {
  let mut builders = BTreeMap::<String, ZipListingEntry>::new();
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
  entries.push(ZipEntry {
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
      .ok_or_else(|| Error::InvalidFormat(format!("missing zip entry builder for path: {path}")))?;
    let id = path_to_id.get(path).cloned().ok_or_else(|| {
      Error::InvalidFormat(format!("missing zip entry identifier for path: {path}"))
    })?;
    entries.push(ZipEntry {
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
      .ok_or_else(|| Error::InvalidFormat(format!("missing zip path mapping for path: {path}")))?;
    let child_index = entry_id_to_index(&child_id)?;
    let child_kind = entries[child_index].record.kind;
    let name = relative_name(path);
    let parent_index = match parent_path(path) {
      Some(parent) => entry_id_to_index(path_to_id.get(parent).ok_or_else(|| {
        Error::InvalidFormat(format!("missing zip parent directory mapping: {parent}"))
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
  builders: &mut BTreeMap<String, ZipListingEntry>, path: &str,
) -> Result<()> {
  let mut current = path;
  while let Some(parent) = parent_path(current) {
    builders
      .entry(parent.to_string())
      .or_insert_with(|| ZipListingEntry {
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
      "zip paths must not contain parent directory traversals".to_string(),
    ));
  }
  let normalized = components.join("/");
  if normalized.is_empty() && !is_dir {
    return Err(Error::InvalidFormat(
      "zip file entries must have a non-empty path".to_string(),
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
    Error::InvalidFormat("zip archive entry identifiers must be native u64 values".to_string())
  })?;
  usize::try_from(u64::from_le_bytes(bytes))
    .map_err(|_| Error::InvalidRange("zip archive entry index is too large".to_string()))
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

  fn text_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
  }

  #[test]
  fn opens_fixture_metadata_and_contents() {
    let archive = ZipArchive::open(sample_source("zip/sample.zip")).unwrap();

    let root = archive.read_dir(&archive.root_entry_id()).unwrap();
    assert!(root.iter().any(|entry| entry.name == "hello.txt"));
    assert!(root.iter().any(|entry| entry.name == "dir"));

    let hello_id = archive.find_entry_by_path("hello.txt").unwrap();
    let hello = archive.open_file(&hello_id).unwrap().read_all().unwrap();
    assert_eq!(hello, b"hello from zip\n");
  }

  #[test]
  fn unlocks_encrypted_fixture_with_password() {
    let mut archive = ZipArchive::open(sample_source("zip/secret.zip")).unwrap();
    assert!(archive.is_locked());
    assert!(!archive.unlock_with_password("wrong").unwrap());
    assert!(archive.unlock_with_password("secret").unwrap());

    let hello_id = archive.find_entry_by_path("hello.txt").unwrap();
    let hello = archive.open_file(&hello_id).unwrap().read_all().unwrap();
    assert_eq!(text_hex(&hello), text_hex(b"hello from zip\n"));
  }

  #[test]
  fn parses_listing_blocks() {
    let listing = parse_7z_slt_listing(
      "----------\nPath = dir\nFolder = +\nSize = 0\nEncrypted = -\n\nPath = dir/file.txt\nFolder = -\nSize = 4\nEncrypted = +\n",
    )
    .unwrap();

    assert_eq!(listing.len(), 2);
    assert_eq!(listing[0].kind, ArchiveEntryKind::Directory);
    assert!(listing[1].encrypted);
  }
}
