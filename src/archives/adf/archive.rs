//! AccessData AD1 archive reader.

use std::{collections::HashMap, io::Read, sync::Arc};

use flate2::read::ZlibDecoder;
use sha1_smol::Sha1;

use super::{DESCRIPTOR, IMAGE_HEADER_SIGNATURE, MARGIN_SIZE, SEGMENT_MARGIN_SIGNATURE};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, Result,
  SourceHints,
  archives::{
    Archive, NamespaceDirectoryEntry, NamespaceNodeId, NamespaceNodeKind, NamespaceNodeRecord,
  },
};

const ROOT_ENTRY_ID: u64 = 0;
const HEADER_SIGNATURE_LENGTH: usize = 16;
const FOOTER_SIZE: usize = 512;
const FOOTER_HASH_SIZE: usize = 372;
const MULTI_IMAGE_PATH: &[u8] = b"Custom Content Image([Multi])";

pub struct AdfArchive {
  logical_image_path: String,
  sha1_checksum: String,
  entries: Vec<AdfEntry>,
}

#[derive(Clone)]
struct AdfEntry {
  record: NamespaceNodeRecord,
  children: Vec<NamespaceDirectoryEntry>,
  content: Option<Arc<[u8]>>,
}

#[derive(Clone, Copy)]
struct Ad1Margin {
  segment_number: u32,
  number_of_segments: u32,
}

struct SegmentPayload {
  joined: Vec<u8>,
}

struct JoinedReader<'a> {
  data: &'a [u8],
  offset: usize,
  meta_digest: Sha1,
  content_digest: Sha1,
}

impl AdfArchive {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    let joined = read_segments(source, hints)?;
    let footer_base = joined
      .joined
      .len()
      .checked_sub(FOOTER_SIZE)
      .ok_or_else(|| Error::InvalidFormat("ad1 payload is too small for a footer".to_string()))?;
    let item_limit = footer_base;

    let mut reader = JoinedReader::new(&joined.joined);
    let image_header = reader.read_bytes(HEADER_SIGNATURE_LENGTH, true)?;
    if &image_header[0..14] != IMAGE_HEADER_SIGNATURE {
      return Err(Error::InvalidFormat(
        "ad1 image header signature is missing".to_string(),
      ));
    }
    let version = read_u32_le(&reader.read_bytes(4, true)?)?;
    if version != 3 && version != 4 {
      return Err(Error::InvalidFormat(format!(
        "unsupported ad1 image version: {version}"
      )));
    }
    reader.read_bytes(4, true)?;
    let _zlib_chunk_size = read_u32_le(&reader.read_bytes(4, true)?)?;
    let _image_header_length = read_u64_le(&reader.read_bytes(8, true)?)?;
    let image_header_info_length = read_u64_le(&reader.read_bytes(8, true)?)?;
    let path_length = usize::try_from(read_u32_le(&reader.read_bytes(4, true)?)?)
      .map_err(|_| Error::InvalidRange("ad1 path length is too large".to_string()))?;
    if version == 4 {
      reader.read_bytes(44, true)?;
      let footer_hash_start = joined
        .joined
        .len()
        .checked_sub(FOOTER_HASH_SIZE)
        .ok_or_else(|| {
          Error::InvalidFormat("ad1 payload is too small for the footer hash".to_string())
        })?;
      reader
        .meta_digest
        .update(&joined.joined[footer_hash_start..]);
    }
    let logical_image_path_bytes = reader.read_bytes(path_length, true)?;
    let logical_image_path = String::from_utf8(logical_image_path_bytes.clone()).map_err(|_| {
      Error::InvalidFormat("ad1 logical image path must be valid UTF-8".to_string())
    })?;
    if logical_image_path_bytes.as_slice() != MULTI_IMAGE_PATH {
      let target = usize::try_from(image_header_info_length)
        .map_err(|_| Error::InvalidRange("ad1 image header length is too large".to_string()))?;
      if target < reader.offset {
        return Err(Error::InvalidFormat(
          "ad1 image header length points before the current reader position".to_string(),
        ));
      }
      reader.read_bytes(target - reader.offset, true)?;
    }

    let mut entries = vec![AdfEntry {
      record: NamespaceNodeRecord::new(
        NamespaceNodeId::from_u64(ROOT_ENTRY_ID),
        NamespaceNodeKind::Directory,
        0,
      ),
      children: Vec::new(),
      content: None,
    }];
    let mut folder_map = HashMap::new();

    while reader.offset < item_limit {
      let block_start = reader.offset + MARGIN_SIZE;
      let next_group = read_i64_le(&reader.read_bytes(8, true)?)?;
      let next_in_group = read_i64_le(&reader.read_bytes(8, true)?)?;
      let next_metadata = read_i64_le(&reader.read_bytes(8, true)?)?;
      let _data_start = read_i64_le(&reader.read_bytes(8, true)?)?;
      let decompressed_size = read_i64_le(&reader.read_bytes(8, true)?)?;
      let item_type = read_u32_le(&reader.read_bytes(4, true)?)?;
      let name_length = usize::try_from(read_u32_le(&reader.read_bytes(4, true)?)?)
        .map_err(|_| Error::InvalidRange("ad1 item name length is too large".to_string()))?;
      let name_bytes = reader.read_bytes(name_length, true)?;
      let name = String::from_utf8(name_bytes)
        .map_err(|_| Error::InvalidFormat("ad1 item names must be valid UTF-8".to_string()))?;
      let group_index = read_i64_le(&reader.read_bytes(8, true)?)?;
      let parent_id = if group_index == 0 {
        ROOT_ENTRY_ID
      } else {
        entry_id_to_u64(
          folder_map
            .get(
              &(u64::try_from(group_index).map_err(|_| {
                Error::InvalidFormat("ad1 group index must be non-negative".to_string())
              })?
                + MARGIN_SIZE as u64),
            )
            .ok_or_else(|| Error::InvalidFormat("ad1 folder reference is missing".to_string()))?,
        )?
      };
      let parent_path = entries[parent_id as usize].record.path.clone();
      let path = if parent_path.is_empty() {
        name.clone()
      } else {
        format!("{parent_path}/{name}")
      };

      let content = if decompressed_size > 0 {
        Some(read_compressed_item(
          &mut reader,
          u64::try_from(decompressed_size)
            .map_err(|_| Error::InvalidFormat("ad1 item size must be non-negative".to_string()))?,
        )?)
      } else {
        None
      };
      let size = content.as_ref().map_or(0, |content| content.len() as u64);

      let mut metadata_link = next_metadata;
      while metadata_link > 0 {
        metadata_link = read_i64_le(&reader.read_bytes(8, true)?)?;
        let _category = read_u32_le(&reader.read_bytes(4, true)?)?;
        let _key = read_u32_le(&reader.read_bytes(4, true)?)?;
        let value_length = usize::try_from(read_u32_le(&reader.read_bytes(4, true)?)?)
          .map_err(|_| Error::InvalidRange("ad1 metadata value length is too large".to_string()))?;
        reader.read_bytes(value_length, true)?;
      }

      let entry_id = NamespaceNodeId::from_u64(entries.len() as u64);
      let kind = match item_type {
        0 => NamespaceNodeKind::File,
        5 => NamespaceNodeKind::Directory,
        _ => NamespaceNodeKind::Special,
      };
      entries[parent_id as usize]
        .children
        .push(NamespaceDirectoryEntry::new(
          name.clone(),
          entry_id.clone(),
          kind,
        ));
      if kind == NamespaceNodeKind::Directory {
        folder_map.insert(block_start as u64, entry_id.clone());
      }

      entries.push(AdfEntry {
        record: NamespaceNodeRecord::new(entry_id, kind, size).with_path(path),
        children: Vec::new(),
        content,
      });

      if next_group < 0 || next_in_group < 0 {
        return Err(Error::InvalidFormat(
          "ad1 item offsets must be non-negative".to_string(),
        ));
      }
    }

    reader
      .meta_digest
      .update(&reader.content_digest.digest().bytes());

    Ok(Self {
      logical_image_path,
      sha1_checksum: reader.meta_digest.hexdigest(),
      entries,
    })
  }

  pub fn logical_image_path(&self) -> &str {
    &self.logical_image_path
  }

  pub fn sha1_checksum(&self) -> &str {
    &self.sha1_checksum
  }

  pub fn find_entry_by_path(&self, path: &str) -> Option<NamespaceNodeId> {
    self
      .entries
      .iter()
      .find(|entry| entry.record.path == path)
      .map(|entry| entry.record.id.clone())
  }
}

impl Archive for AdfArchive {
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
        "ad1 directory reads require a directory entry".to_string(),
      ));
    }
    Ok(entry.children.clone())
  }

  fn open_file(&self, entry_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let entry = self.entry_ref(entry_id)?;
    if entry.record.kind != NamespaceNodeKind::File {
      return Err(Error::InvalidFormat(
        "ad1 file opens require a regular file entry".to_string(),
      ));
    }
    let content = entry.content.clone().ok_or_else(|| {
      Error::InvalidFormat("ad1 file entries must carry content bytes".to_string())
    })?;
    Ok(Arc::new(BytesDataSource { data: content }) as ByteSourceHandle)
  }
}

impl AdfArchive {
  fn entry_ref(&self, entry_id: &NamespaceNodeId) -> Result<&AdfEntry> {
    let index = usize::try_from(entry_id_to_u64(entry_id)?)
      .map_err(|_| Error::InvalidRange("ad1 entry index is too large".to_string()))?;
    self.entries.get(index).ok_or_else(|| {
      Error::NotFound(format!(
        "missing ad1 archive entry: {}",
        entry_id_to_u64(entry_id).unwrap_or(0)
      ))
    })
  }
}

fn read_segments(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<SegmentPayload> {
  let first_margin = source.read_bytes_at(0, MARGIN_SIZE)?;
  let first = Ad1Margin::from_bytes(&first_margin)?;
  if first.segment_number != 1 {
    return Err(Error::InvalidSourceReference(
      "ad1 archives must be opened from the first segment".to_string(),
    ));
  }

  let mut joined = source.read_all()?;
  if joined.len() < MARGIN_SIZE {
    return Err(Error::InvalidFormat(
      "ad1 segment is smaller than the margin".to_string(),
    ));
  }
  let mut joined_payload = joined.split_off(MARGIN_SIZE);

  if first.number_of_segments > 1 {
    let resolver = hints.resolver().ok_or_else(|| {
      Error::InvalidSourceReference(
        "multi-segment ad1 archives require a related-source resolver".to_string(),
      )
    })?;
    let identity = hints.source_identity().ok_or_else(|| {
      Error::InvalidSourceReference(
        "multi-segment ad1 archives require a source identity hint".to_string(),
      )
    })?;
    let set = Ad1SegmentSet::parse(identity.entry_name().ok_or_else(|| {
      Error::InvalidSourceReference("ad1 archives require a segment file name".to_string())
    })?)
    .ok_or_else(|| {
      Error::InvalidSourceReference("ad1 segment names must look like *.ad1".to_string())
    })?;

    for segment_number in 2..=first.number_of_segments {
      let segment_name = set.segment_name(segment_number);
      let segment_path = identity.sibling_path(segment_name)?;
      let request = crate::RelatedSourceRequest::new(
        crate::RelatedSourcePurpose::Segment,
        segment_path.clone(),
      );
      let segment_source = resolver
        .resolve(&request)?
        .ok_or_else(|| Error::NotFound(format!("missing ad1 segment: {segment_path}")))?;
      let segment_bytes = segment_source.read_all()?;
      if segment_bytes.len() < MARGIN_SIZE {
        return Err(Error::InvalidFormat(
          "ad1 segment is smaller than the margin".to_string(),
        ));
      }
      let margin = Ad1Margin::from_bytes(&segment_bytes[..MARGIN_SIZE])?;
      if margin.segment_number != segment_number {
        return Err(Error::InvalidFormat(format!(
          "ad1 segment number mismatch: expected {segment_number}, found {}",
          margin.segment_number
        )));
      }
      if margin.number_of_segments != first.number_of_segments {
        return Err(Error::InvalidFormat(
          "ad1 segment count mismatch across segments".to_string(),
        ));
      }
      joined_payload.extend_from_slice(&segment_bytes[MARGIN_SIZE..]);
    }
  }

  Ok(SegmentPayload {
    joined: joined_payload,
  })
}

fn read_compressed_item(reader: &mut JoinedReader<'_>, declared_size: u64) -> Result<Arc<[u8]>> {
  let chunk_count_minus_one = read_i64_le(&reader.read_bytes(8, false)?)?;
  if chunk_count_minus_one < 0 {
    return Err(Error::InvalidFormat(
      "ad1 chunk count must be non-negative".to_string(),
    ));
  }
  let chunk_count = usize::try_from(chunk_count_minus_one + 1)
    .map_err(|_| Error::InvalidRange("ad1 chunk count is too large".to_string()))?;
  let mut chunk_offsets = Vec::with_capacity(chunk_count);
  for _ in 0..chunk_count {
    let offset = read_i64_le(&reader.read_bytes(8, false)?)?;
    if offset < 0 {
      return Err(Error::InvalidFormat(
        "ad1 chunk offsets must be non-negative".to_string(),
      ));
    }
    chunk_offsets.push(offset as u64);
  }

  let mut content = Vec::new();
  for window in chunk_offsets.windows(2) {
    let compressed_size = window[1]
      .checked_sub(window[0])
      .ok_or_else(|| Error::InvalidFormat("ad1 chunk offsets must be increasing".to_string()))?;
    let compressed = reader.read_bytes(
      usize::try_from(compressed_size)
        .map_err(|_| Error::InvalidRange("ad1 compressed chunk is too large".to_string()))?,
      false,
    )?;
    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    reader.content_digest.update(&decompressed);
    content.extend_from_slice(&decompressed);
  }

  if content.len() as u64 != declared_size {
    return Err(Error::InvalidFormat(
      "ad1 decompressed item size does not match its header".to_string(),
    ));
  }

  Ok(Arc::from(content))
}

fn read_u32_le(data: &[u8]) -> Result<u32> {
  Ok(u32::from_le_bytes(data.try_into().map_err(|_| {
    Error::InvalidFormat("ad1 integer length mismatch".to_string())
  })?))
}

fn read_u64_le(data: &[u8]) -> Result<u64> {
  Ok(u64::from_le_bytes(data.try_into().map_err(|_| {
    Error::InvalidFormat("ad1 integer length mismatch".to_string())
  })?))
}

fn read_i64_le(data: &[u8]) -> Result<i64> {
  Ok(i64::from_le_bytes(data.try_into().map_err(|_| {
    Error::InvalidFormat("ad1 integer length mismatch".to_string())
  })?))
}

fn entry_id_to_u64(entry_id: &NamespaceNodeId) -> Result<u64> {
  let bytes: [u8; 8] = entry_id.as_bytes().try_into().map_err(|_| {
    Error::InvalidFormat("ad1 archive entry identifiers must be native u64 values".to_string())
  })?;
  Ok(u64::from_le_bytes(bytes))
}

impl Ad1Margin {
  fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() != MARGIN_SIZE {
      return Err(Error::InvalidFormat(
        "ad1 margin must be exactly 512 bytes".to_string(),
      ));
    }
    if &data[0..15] != SEGMENT_MARGIN_SIGNATURE {
      return Err(Error::InvalidFormat(
        "ad1 segment margin signature is missing".to_string(),
      ));
    }

    Ok(Self {
      segment_number: read_u32_le(&data[24..28])?,
      number_of_segments: read_u32_le(&data[28..32])?,
    })
  }
}

impl<'a> JoinedReader<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self {
      data,
      offset: 0,
      meta_digest: Sha1::new(),
      content_digest: Sha1::new(),
    }
  }

  fn read_bytes(&mut self, len: usize, digest_meta: bool) -> Result<Vec<u8>> {
    let end = self
      .offset
      .checked_add(len)
      .ok_or_else(|| Error::InvalidRange("ad1 reader offset overflow".to_string()))?;
    let bytes = self
      .data
      .get(self.offset..end)
      .ok_or_else(|| Error::UnexpectedEof {
        offset: self.offset as u64,
        expected: len,
        actual: self.data.len().saturating_sub(self.offset),
      })?;
    if digest_meta {
      self.meta_digest.update(bytes);
    }
    self.offset = end;
    Ok(bytes.to_vec())
  }
}

struct BytesDataSource {
  data: Arc<[u8]>,
}

impl ByteSource for BytesDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let offset = usize::try_from(offset)
      .map_err(|_| Error::InvalidRange("ad1 file offset is too large".to_string()))?;
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

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
  }

  fn telemetry_name(&self) -> &'static str {
    "archive.ad1.file"
  }
}

struct Ad1SegmentSet<'a> {
  prefix: &'a str,
}

impl<'a> Ad1SegmentSet<'a> {
  fn parse(entry_name: &'a str) -> Option<Self> {
    let (prefix, suffix) = entry_name.rsplit_once(".ad")?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
      return None;
    }
    (suffix == "1").then_some(Self {
      prefix: &entry_name[..prefix.len() + 3],
    })
  }

  fn segment_name(&self, segment_number: u32) -> String {
    format!("{}{segment_number}", self.prefix)
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, path::Path, sync::Arc};

  use super::*;
  use crate::RelatedSourceResolver;

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

  struct Resolver {
    files: HashMap<String, ByteSourceHandle>,
  }

  impl RelatedSourceResolver for Resolver {
    fn resolve(&self, request: &crate::RelatedSourceRequest) -> Result<Option<ByteSourceHandle>> {
      Ok(self.files.get(&request.path.to_string()).cloned())
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

  fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
  }

  #[test]
  fn opens_fixture_metadata_and_root_listing() {
    let resolver = Resolver {
      files: HashMap::from([
        (
          "adf/text-and-pictures.ad2".to_string(),
          sample_source("adf/text-and-pictures.ad2"),
        ),
        (
          "adf/text-and-pictures.ad3".to_string(),
          sample_source("adf/text-and-pictures.ad3"),
        ),
        (
          "adf/text-and-pictures.ad4".to_string(),
          sample_source("adf/text-and-pictures.ad4"),
        ),
      ]),
    };
    let identity = crate::SourceIdentity::from_relative_path("adf/text-and-pictures.ad1").unwrap();
    let archive = AdfArchive::open_with_hints(
      sample_source("adf/text-and-pictures.ad1"),
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let root = archive.read_dir(&archive.root_entry_id()).unwrap();
    assert_eq!(archive.logical_image_path(), r"C:\Users\pcbje\Desktop\Data");
    assert_eq!(archive.sha1_checksum().len(), 40);
    assert_eq!(root.len(), 2);
    assert_eq!(root[0].name, "Pictures");
    assert_eq!(root[1].name, "Text");
  }

  #[test]
  fn opens_fixture_files_and_contents() {
    let resolver = Resolver {
      files: HashMap::from([
        (
          "adf/text-and-pictures.ad2".to_string(),
          sample_source("adf/text-and-pictures.ad2"),
        ),
        (
          "adf/text-and-pictures.ad3".to_string(),
          sample_source("adf/text-and-pictures.ad3"),
        ),
        (
          "adf/text-and-pictures.ad4".to_string(),
          sample_source("adf/text-and-pictures.ad4"),
        ),
      ]),
    };
    let identity = crate::SourceIdentity::from_relative_path("adf/text-and-pictures.ad1").unwrap();
    let archive = AdfArchive::open_with_hints(
      sample_source("adf/text-and-pictures.ad1"),
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let text_id = archive.find_entry_by_path("Text/norvig-big.txt").unwrap();
    let text_record = archive.entry(&text_id).unwrap();
    let text_data = archive.open_file(&text_id).unwrap().read_all().unwrap();
    assert_eq!(text_record.size, 6_488_666);
    assert_eq!(
      std::str::from_utf8(&text_data[..27]).unwrap(),
      "The Project Gutenberg EBook"
    );

    let picture_id = archive
      .find_entry_by_path("Pictures/0-0-581-Hydrangeas.jpg")
      .unwrap();
    let picture_data = archive.open_file(&picture_id).unwrap().read_all().unwrap();
    assert_eq!(md5_hex(&picture_data), "bdf3bf1da3405725be763540d6601144");
  }

  #[test]
  fn rejects_missing_additional_segments() {
    let resolver = Resolver {
      files: HashMap::new(),
    };
    let identity = crate::SourceIdentity::from_relative_path("adf/text-and-pictures.ad1").unwrap();

    let result = AdfArchive::open_with_hints(
      sample_source("adf/text-and-pictures.ad1"),
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    );

    assert!(matches!(result, Err(Error::NotFound(_))));
  }
}

crate::archives::driver::impl_archive_data_source!(AdfArchive);
