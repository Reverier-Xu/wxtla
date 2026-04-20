//! Read-only TAR archive surface.

use std::{
  collections::{BTreeMap, HashMap, HashSet},
  sync::Arc,
};

use super::DESCRIPTOR;
use crate::{
  ByteSourceHandle, Error, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind,
  NamespaceNodeRecord, Result, SliceDataSource, SourceHints, archives::Archive,
};

const BLOCK_SIZE: u64 = 512;
const HEADER_SIZE: usize = 512;
const ROOT_ENTRY_ID: u64 = 0;
const TYPE_FILE: u8 = b'0';
const TYPE_HARD_LINK: u8 = b'1';
const TYPE_SYMLINK: u8 = b'2';
const TYPE_CHAR: u8 = b'3';
const TYPE_BLOCK: u8 = b'4';
const TYPE_DIR: u8 = b'5';
const TYPE_FIFO: u8 = b'6';
const TYPE_CONTIGUOUS: u8 = b'7';
const TYPE_PAX_LOCAL: u8 = b'x';
const TYPE_PAX_GLOBAL: u8 = b'g';
const TYPE_GNU_LONG_NAME: u8 = b'L';
const TYPE_GNU_LONG_LINK: u8 = b'K';

pub struct TarArchive {
  source: ByteSourceHandle,
  entries: Vec<TarEntry>,
  path_to_id: HashMap<String, NamespaceNodeId>,
}

#[derive(Clone)]
struct TarEntry {
  record: NamespaceNodeRecord,
  children: Vec<NamespaceDirectoryEntry>,
  data: TarEntryData,
}

#[derive(Clone)]
enum TarEntryData {
  None,
  File { offset: u64, size: u64 },
  HardLink { target_path: String },
}

#[derive(Clone)]
struct TarEntryBuilder {
  kind: NamespaceNodeKind,
  size: u64,
  data: TarEntryData,
}

#[derive(Clone, Debug)]
pub(crate) struct TarHeader {
  pub name: String,
  pub size: u64,
  pub typeflag: u8,
  pub link_name: String,
  pub has_ustar_magic: bool,
}

impl TarArchive {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let source_size = source.size()?;
    let mut offset = 0u64;
    let mut pending_long_name = None::<String>;
    let mut pending_long_link = None::<String>;
    let mut pending_pax = BTreeMap::<String, String>::new();
    let mut global_pax = BTreeMap::<String, String>::new();
    let mut builders = BTreeMap::<String, TarEntryBuilder>::new();

    while offset
      .checked_add(BLOCK_SIZE)
      .is_some_and(|end| end <= source_size)
    {
      let header_bytes = source.read_bytes_at(offset, HEADER_SIZE)?;
      if header_bytes.iter().all(|byte| *byte == 0) {
        break;
      }

      let header = TarHeader::from_bytes(&header_bytes)?;
      let data_offset = offset
        .checked_add(BLOCK_SIZE)
        .ok_or_else(|| Error::InvalidRange("tar data offset overflow".to_string()))?;
      let padded_size = round_up(header.size, BLOCK_SIZE)?;
      let next_offset = data_offset
        .checked_add(padded_size)
        .ok_or_else(|| Error::InvalidRange("tar entry end overflow".to_string()))?;
      if next_offset > source_size {
        return Err(Error::InvalidFormat(
          "tar entry payload exceeds the source size".to_string(),
        ));
      }

      match header.typeflag {
        TYPE_PAX_GLOBAL | TYPE_PAX_LOCAL => {
          let raw = source.read_bytes_at(
            data_offset,
            usize::try_from(header.size)
              .map_err(|_| Error::InvalidRange("tar pax payload is too large".to_string()))?,
          )?;
          let parsed = parse_pax_records(&raw)?;
          if header.typeflag == TYPE_PAX_GLOBAL {
            global_pax.extend(parsed);
          } else {
            pending_pax = parsed;
          }
        }
        TYPE_GNU_LONG_NAME => {
          let raw = source.read_bytes_at(
            data_offset,
            usize::try_from(header.size)
              .map_err(|_| Error::InvalidRange("tar long name payload is too large".to_string()))?,
          )?;
          pending_long_name = Some(read_c_string(&raw));
        }
        TYPE_GNU_LONG_LINK => {
          let raw = source.read_bytes_at(
            data_offset,
            usize::try_from(header.size)
              .map_err(|_| Error::InvalidRange("tar long link payload is too large".to_string()))?,
          )?;
          pending_long_link = Some(read_c_string(&raw));
        }
        _ => {
          let mut effective_pax = global_pax.clone();
          effective_pax.extend(pending_pax.clone());
          let mut path = effective_pax
            .get("path")
            .cloned()
            .or_else(|| pending_long_name.clone())
            .unwrap_or_else(|| header.name.clone());
          let mut link_name = effective_pax
            .get("linkpath")
            .cloned()
            .or_else(|| pending_long_link.clone())
            .unwrap_or_else(|| header.link_name.clone());
          let size = effective_pax
            .get("size")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(header.size);

          let kind = classify_kind(header.typeflag);
          let is_dir = kind == NamespaceNodeKind::Directory;
          path = normalize_path(&path, is_dir)?;
          link_name = normalize_link_path(&link_name)?;
          if path.is_empty() {
            return Err(Error::InvalidFormat(
              "tar archive entries must have a non-empty path".to_string(),
            ));
          }

          ensure_parent_directories(&mut builders, &path)?;
          let data = match header.typeflag {
            0 | TYPE_FILE | TYPE_CONTIGUOUS => TarEntryData::File {
              offset: data_offset,
              size,
            },
            TYPE_HARD_LINK => TarEntryData::HardLink {
              target_path: link_name,
            },
            TYPE_SYMLINK | TYPE_DIR | TYPE_CHAR | TYPE_BLOCK | TYPE_FIFO => TarEntryData::None,
            other => {
              return Err(Error::InvalidFormat(format!(
                "unsupported tar entry typeflag: 0x{other:02x}"
              )));
            }
          };

          let builder = builders.entry(path).or_insert_with(|| TarEntryBuilder {
            kind,
            size,
            data: TarEntryData::None,
          });
          builder.kind = kind;
          builder.size = size;
          builder.data = data;

          pending_long_name = None;
          pending_long_link = None;
          pending_pax.clear();
        }
      }

      offset = next_offset;
    }

    let mut path_to_id = HashMap::new();
    let mut ordered_paths = builders.keys().cloned().collect::<Vec<_>>();
    ordered_paths.sort();
    for (index, path) in ordered_paths.iter().enumerate() {
      path_to_id.insert(path.clone(), NamespaceNodeId::from_u64(index as u64 + 1));
    }

    let mut entries = Vec::with_capacity(ordered_paths.len() + 1);
    entries.push(TarEntry {
      record: NamespaceNodeRecord::new(
        NamespaceNodeId::from_u64(ROOT_ENTRY_ID),
        NamespaceNodeKind::Directory,
        0,
      ),
      children: Vec::new(),
      data: TarEntryData::None,
    });

    for path in &ordered_paths {
      let builder = builders.get(path).ok_or_else(|| {
        Error::InvalidFormat(format!("missing tar entry builder for path: {path}"))
      })?;
      let id = path_to_id.get(path).cloned().ok_or_else(|| {
        Error::InvalidFormat(format!("missing tar entry identifier for path: {path}"))
      })?;
      entries.push(TarEntry {
        record: NamespaceNodeRecord::new(id, builder.kind, builder.size).with_path(path.clone()),
        children: Vec::new(),
        data: builder.data.clone(),
      });
    }

    for path in &ordered_paths {
      let child_id = path_to_id.get(path).cloned().ok_or_else(|| {
        Error::InvalidFormat(format!("missing tar path mapping for path: {path}"))
      })?;
      let child_index = entry_id_to_index(&child_id)?;
      let child_kind = entries
        .get(child_index)
        .ok_or_else(|| Error::NotFound(format!("missing tar child entry index: {child_index}")))?
        .record
        .kind;
      let name = relative_name(path);
      let parent_index = match parent_path(path) {
        Some(parent) => entry_id_to_index(path_to_id.get(parent).ok_or_else(|| {
          Error::InvalidFormat(format!("missing tar parent directory mapping: {parent}"))
        })?)?,
        None => 0,
      };
      entries[parent_index]
        .children
        .push(NamespaceDirectoryEntry::new(name, child_id, child_kind));
    }
    for entry in &mut entries {
      entry
        .children
        .sort_by(|left, right| left.name.cmp(&right.name));
    }

    Ok(Self {
      source,
      entries,
      path_to_id,
    })
  }

  pub fn find_entry_by_path(&self, path: &str) -> Option<NamespaceNodeId> {
    self.path_to_id.get(path).cloned()
  }

  fn entry_ref(&self, entry_id: &NamespaceNodeId) -> Result<&TarEntry> {
    let index = entry_id_to_index(entry_id)?;
    self
      .entries
      .get(index)
      .ok_or_else(|| Error::NotFound(format!("missing tar archive entry index: {index}")))
  }

  fn open_file_resolved(
    &self, entry_id: &NamespaceNodeId, seen: &mut HashSet<usize>,
  ) -> Result<ByteSourceHandle> {
    let index = entry_id_to_index(entry_id)?;
    if !seen.insert(index) {
      return Err(Error::InvalidFormat(
        "tar hard links must not form cycles".to_string(),
      ));
    }
    let entry = self.entry_ref(entry_id)?;
    match &entry.data {
      TarEntryData::File { offset, size } => {
        Ok(Arc::new(SliceDataSource::new(self.source.clone(), *offset, *size)) as ByteSourceHandle)
      }
      TarEntryData::HardLink { target_path } => {
        let target = self
          .path_to_id
          .get(target_path)
          .ok_or_else(|| Error::NotFound(format!("missing tar hard-link target: {target_path}")))?;
        self.open_file_resolved(target, seen)
      }
      TarEntryData::None => Err(Error::InvalidFormat(
        "tar entry does not expose readable file data".to_string(),
      )),
    }
  }
}

impl Archive for TarArchive {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_entry_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(ROOT_ENTRY_ID)
  }

  fn entry(&self, entry_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    Ok(self.entry_ref(entry_id)?.record.clone())
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let entry = self.entry_ref(directory_id)?;
    if entry.record.kind != NamespaceNodeKind::Directory {
      return Err(Error::InvalidFormat(
        "tar directory reads require a directory entry".to_string(),
      ));
    }
    Ok(entry.children.clone())
  }

  fn open_file(&self, entry_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let entry = self.entry_ref(entry_id)?;
    if !matches!(entry.record.kind, NamespaceNodeKind::File) {
      return Err(Error::InvalidFormat(
        "tar file opens require a regular file or hard link entry".to_string(),
      ));
    }
    self.open_file_resolved(entry_id, &mut HashSet::new())
  }
}

impl TarHeader {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != HEADER_SIZE {
      return Err(Error::InvalidFormat(
        "tar headers must be exactly 512 bytes".to_string(),
      ));
    }
    if data.iter().all(|byte| *byte == 0) {
      return Err(Error::InvalidFormat(
        "tar headers must not be all zeroes".to_string(),
      ));
    }

    let stored_checksum = parse_numeric_field(&data[148..156])?;
    let mut checksum_header = [0u8; HEADER_SIZE];
    checksum_header.copy_from_slice(data);
    checksum_header[148..156].fill(b' ');
    let calculated_checksum = checksum_header
      .iter()
      .map(|byte| u64::from(*byte))
      .sum::<u64>();
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "invalid tar header checksum: stored={stored_checksum} calculated={calculated_checksum}"
      )));
    }

    let typeflag = data[156];
    let name = read_c_string(&data[0..100]);
    let prefix = read_c_string(&data[345..500]);
    let full_name = if prefix.is_empty() {
      name.clone()
    } else if name.is_empty() {
      prefix
    } else {
      format!("{prefix}/{name}")
    };
    Ok(Self {
      name: full_name,
      size: parse_numeric_field(&data[124..136])?,
      typeflag,
      link_name: read_c_string(&data[157..257]),
      has_ustar_magic: &data[257..263] == b"ustar\0" || &data[257..263] == b"ustar ",
    })
  }
}

fn parse_pax_records(data: &[u8]) -> Result<BTreeMap<String, String>> {
  let mut offset = 0usize;
  let mut records = BTreeMap::new();
  while offset < data.len() {
    let len_end = data[offset..]
      .iter()
      .position(|byte| *byte == b' ')
      .ok_or_else(|| Error::InvalidFormat("invalid tar pax record length".to_string()))?
      + offset;
    let record_len = std::str::from_utf8(&data[offset..len_end])
      .map_err(|_| Error::InvalidFormat("tar pax lengths must be ASCII".to_string()))?
      .parse::<usize>()
      .map_err(|_| Error::InvalidFormat("invalid tar pax length value".to_string()))?;
    if record_len == 0 || offset + record_len > data.len() {
      return Err(Error::InvalidFormat(
        "tar pax record extends beyond the payload".to_string(),
      ));
    }
    let record = &data[len_end + 1..offset + record_len - 1];
    let separator = record
      .iter()
      .position(|byte| *byte == b'=')
      .ok_or_else(|| Error::InvalidFormat("invalid tar pax record contents".to_string()))?;
    let key = &record[..separator];
    let value = &record[separator + 1..];
    let key = std::str::from_utf8(key)
      .map_err(|_| Error::InvalidFormat("tar pax keys must be UTF-8".to_string()))?;
    let value = String::from_utf8(value.to_vec())
      .map_err(|_| Error::InvalidFormat("tar pax values must be UTF-8".to_string()))?;
    records.insert(key.to_string(), value);
    offset += record_len;
  }
  Ok(records)
}

fn classify_kind(typeflag: u8) -> NamespaceNodeKind {
  match typeflag {
    0 | TYPE_FILE | TYPE_CONTIGUOUS | TYPE_HARD_LINK => NamespaceNodeKind::File,
    TYPE_DIR => NamespaceNodeKind::Directory,
    TYPE_SYMLINK => NamespaceNodeKind::Symlink,
    TYPE_CHAR | TYPE_BLOCK | TYPE_FIFO => NamespaceNodeKind::Special,
    _ => NamespaceNodeKind::Special,
  }
}

fn parse_numeric_field(field: &[u8]) -> Result<u64> {
  if field.is_empty() {
    return Ok(0);
  }
  if field[0] & 0x80 != 0 {
    if field[0] & 0x40 != 0 {
      return Err(Error::InvalidFormat(
        "negative base-256 tar numbers are not supported".to_string(),
      ));
    }
    let mut value = u64::from(field[0] & 0x3F);
    for byte in &field[1..] {
      value = (value << 8) | u64::from(*byte);
    }
    return Ok(value);
  }

  let trimmed = field
    .iter()
    .copied()
    .skip_while(|byte| *byte == b' ')
    .take_while(|byte| *byte != 0 && *byte != b' ')
    .collect::<Vec<_>>();
  if trimmed.is_empty() {
    return Ok(0);
  }
  let text = std::str::from_utf8(&trimmed)
    .map_err(|_| Error::InvalidFormat("tar numeric fields must be ASCII".to_string()))?;
  u64::from_str_radix(text, 8)
    .map_err(|_| Error::InvalidFormat(format!("invalid tar numeric field: {text}")))
}

fn read_c_string(field: &[u8]) -> String {
  let end = field
    .iter()
    .position(|byte| *byte == 0)
    .unwrap_or(field.len());
  String::from_utf8_lossy(&field[..end])
    .trim_end()
    .to_string()
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
      "tar paths must not contain parent directory traversals".to_string(),
    ));
  }
  let normalized = components.join("/");
  if normalized.is_empty() && !is_dir {
    return Err(Error::InvalidFormat(
      "tar file entries must contain a non-empty path".to_string(),
    ));
  }
  Ok(normalized)
}

fn normalize_link_path(path: &str) -> Result<String> {
  if path.is_empty() {
    return Ok(String::new());
  }
  normalize_path(path, false)
}

fn ensure_parent_directories(
  builders: &mut BTreeMap<String, TarEntryBuilder>, path: &str,
) -> Result<()> {
  let mut current = path;
  while let Some(parent) = parent_path(current) {
    let entry = builders
      .entry(parent.to_string())
      .or_insert_with(|| TarEntryBuilder {
        kind: NamespaceNodeKind::Directory,
        size: 0,
        data: TarEntryData::None,
      });
    if entry.kind != NamespaceNodeKind::Directory {
      return Err(Error::InvalidFormat(
        "tar parent path collides with a non-directory entry".to_string(),
      ));
    }
    current = parent;
  }
  Ok(())
}

fn parent_path(path: &str) -> Option<&str> {
  path.rsplit_once('/').map(|(parent, _)| parent)
}

fn relative_name(path: &str) -> String {
  path
    .rsplit_once('/')
    .map_or_else(|| path.to_string(), |(_, name)| name.to_string())
}

fn entry_id_to_index(entry_id: &NamespaceNodeId) -> Result<usize> {
  let bytes: [u8; 8] = entry_id.as_bytes().try_into().map_err(|_| {
    Error::InvalidFormat("tar archive entry identifiers must be native u64 values".to_string())
  })?;
  usize::try_from(u64::from_le_bytes(bytes))
    .map_err(|_| Error::InvalidRange("tar archive entry index is too large".to_string()))
}

fn round_up(value: u64, alignment: u64) -> Result<u64> {
  if value == 0 {
    return Ok(0);
  }
  let remainder = value % alignment;
  if remainder == 0 {
    return Ok(value);
  }
  value
    .checked_add(alignment - remainder)
    .ok_or_else(|| Error::InvalidRange("tar padded size overflow".to_string()))
}

#[cfg(test)]
mod tests {
  use std::{path::Path, sync::Arc};

  use super::*;
  use crate::ByteSource;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl ByteSource for MemDataSource {
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

  fn sample_source(relative_path: &str) -> ByteSourceHandle {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path);
    Arc::new(MemDataSource {
      data: std::fs::read(path).unwrap(),
    })
  }

  fn append_tar_header(
    archive: &mut Vec<u8>, name: &str, typeflag: u8, data: &[u8], link_name: Option<&str>,
  ) {
    let mut header = [0u8; HEADER_SIZE];
    let (prefix, basename) = split_name(name);
    header[0..basename.len()].copy_from_slice(basename.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    write_octal(&mut header[124..136], data.len() as u64);
    write_octal(&mut header[136..148], 0);
    header[156] = typeflag;
    if let Some(link_name) = link_name {
      header[157..157 + link_name.len()].copy_from_slice(link_name.as_bytes());
    }
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    header[148..156].fill(b' ');
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    write_octal(&mut header[148..156], checksum);

    archive.extend_from_slice(&header);
    archive.extend_from_slice(data);
    archive.resize(
      round_up(archive.len() as u64, BLOCK_SIZE).unwrap() as usize,
      0,
    );
  }

  fn split_name(name: &str) -> (String, String) {
    if name.len() <= 100 {
      return (String::new(), name.to_string());
    }
    let split_index = name.rfind('/').unwrap();
    (
      name[..split_index].to_string(),
      name[split_index + 1..].to_string(),
    )
  }

  fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let text = format!("{value:0width$o}\0", width = width - 1);
    let start = field.len() - text.len();
    field.fill(b' ');
    field[start..start + text.len()].copy_from_slice(text.as_bytes());
  }

  fn synthetic_tar(
    entries: impl IntoIterator<Item = (String, u8, Vec<u8>, Option<String>)>,
  ) -> Vec<u8> {
    let mut archive = Vec::new();
    for (name, typeflag, data, link_name) in entries {
      append_tar_header(&mut archive, &name, typeflag, &data, link_name.as_deref());
    }
    archive.extend_from_slice(&[0u8; HEADER_SIZE * 2]);
    archive
  }

  fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let mut len = key.len() + value.len() + 3;
    loop {
      let record = format!("{len} {key}={value}\n");
      if record.len() == len {
        return record.into_bytes();
      }
      len = record.len();
    }
  }

  fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
  }

  #[test]
  fn opens_fixture_metadata_and_contents() {
    let archive = TarArchive::open(sample_source("tar/sample.tar")).unwrap();

    let root = archive.read_dir(&archive.root_entry_id()).unwrap();
    assert_eq!(root.len(), 2);
    assert_eq!(root[0].name, "dir");
    assert_eq!(root[1].kind, NamespaceNodeKind::Symlink);

    let hello_id = archive.find_entry_by_path("dir/hello.txt").unwrap();
    let hello_data = archive.open_file(&hello_id).unwrap().read_all().unwrap();
    assert_eq!(hello_data, b"hello from tar\n");
  }

  #[test]
  fn synthesizes_missing_parent_directories() {
    let archive = TarArchive::open(Arc::new(MemDataSource {
      data: synthetic_tar([("a/b/c.txt".to_string(), TYPE_FILE, b"nested".to_vec(), None)]),
    }) as ByteSourceHandle)
    .unwrap();

    let root = archive.read_dir(&archive.root_entry_id()).unwrap();
    assert_eq!(root[0].name, "a");
    let a_id = archive.find_entry_by_path("a").unwrap();
    let a_children = archive.read_dir(&a_id).unwrap();
    assert_eq!(a_children[0].name, "b");
  }

  #[test]
  fn supports_pax_paths_and_hard_links() {
    let long_path = "very/long/path/name/that/exceeds/the/legacy/header/field/limit/file.txt";
    let pax_payload = pax_record("path", long_path);
    let archive_bytes = synthetic_tar([
      ("paxheader".to_string(), TYPE_PAX_LOCAL, pax_payload, None),
      (
        "ignored.txt".to_string(),
        TYPE_FILE,
        b"payload".to_vec(),
        None,
      ),
      (
        "copy.txt".to_string(),
        TYPE_HARD_LINK,
        Vec::new(),
        Some(long_path.to_string()),
      ),
    ]);
    let archive = TarArchive::open(Arc::new(MemDataSource {
      data: archive_bytes,
    }) as ByteSourceHandle)
    .unwrap();

    let file_id = archive.find_entry_by_path(long_path).unwrap();
    let copy_id = archive.find_entry_by_path("copy.txt").unwrap();
    assert_eq!(
      archive.open_file(&file_id).unwrap().read_all().unwrap(),
      b"payload"
    );
    assert_eq!(
      archive.open_file(&copy_id).unwrap().read_all().unwrap(),
      b"payload"
    );
  }

  #[test]
  fn supports_gnu_long_names() {
    let long_path = "this/is/a/gnu/long/path/that/exceeds/the/legacy/header/limit/by/design.txt";
    let archive_bytes = synthetic_tar([
      (
        "././@LongLink".to_string(),
        TYPE_GNU_LONG_NAME,
        [long_path.as_bytes(), &[0]].concat(),
        None,
      ),
      (
        "placeholder".to_string(),
        TYPE_FILE,
        b"gnu-data".to_vec(),
        None,
      ),
    ]);
    let archive = TarArchive::open(Arc::new(MemDataSource {
      data: archive_bytes,
    }) as ByteSourceHandle)
    .unwrap();

    let file_id = archive.find_entry_by_path(long_path).unwrap();
    assert_eq!(
      md5_hex(&archive.open_file(&file_id).unwrap().read_all().unwrap()),
      md5_hex(b"gnu-data")
    );
  }

  #[test]
  fn rejects_bad_header_checksums() {
    let mut archive_bytes =
      synthetic_tar([("file.txt".to_string(), TYPE_FILE, b"bad".to_vec(), None)]);
    archive_bytes[148] ^= 0x01;

    let result = TarArchive::open(Arc::new(MemDataSource {
      data: archive_bytes,
    }) as ByteSourceHandle);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}

crate::archives::driver::impl_archive_data_source!(TarArchive);
