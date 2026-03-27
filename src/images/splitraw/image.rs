//! Read-only split raw image surface.

use std::{collections::HashSet, sync::Arc};

use super::{DESCRIPTOR, SplitSegmentSequence};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, Result,
  SourceHints, images::Image,
};

pub struct SplitRawImage {
  segments: Arc<[ByteSourceHandle]>,
  segment_offsets: Arc<[u64]>,
  segment_size: u64,
  media_size: u64,
}

impl SplitRawImage {
  pub fn open(_source: ByteSourceHandle) -> Result<Self> {
    Err(Error::InvalidSourceReference(
      "split raw images require source hints, a resolver, and a source identity".to_string(),
    ))
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    let resolver = hints.resolver().ok_or_else(|| {
      Error::InvalidSourceReference(
        "split raw images require a related-source resolver".to_string(),
      )
    })?;
    let identity = hints.source_identity().ok_or_else(|| {
      Error::InvalidSourceReference("split raw images require a source identity hint".to_string())
    })?;
    let entry_name = identity.entry_name().ok_or_else(|| {
      Error::InvalidSourceReference("split raw images require a segment entry name".to_string())
    })?;
    let sequence = SplitSegmentSequence::parse(entry_name).ok_or_else(|| {
      Error::InvalidSourceReference("source does not look like a split raw segment".to_string())
    })?;
    if !sequence.is_first_segment() {
      return Err(Error::InvalidSourceReference(
        "split raw images must be opened from the first segment".to_string(),
      ));
    }

    let mut segments = vec![source];
    let mut media_size = segments[0].size()?;
    let first_segment_size = media_size;
    let mut segment_index = 1u64;
    let mut seen_paths = HashSet::new();
    seen_paths.insert(identity.logical_path().to_string());

    loop {
      if let Some(total_segments) = sequence.expected_total_segments()
        && segment_index >= total_segments
      {
        break;
      }

      let segment_name = sequence.segment_name(segment_index)?;
      let segment_path = identity.sibling_path(segment_name)?;
      let request = crate::RelatedSourceRequest::new(
        crate::RelatedSourcePurpose::Segment,
        segment_path.clone(),
      );
      let Some(segment_source) = resolver.resolve(&request)? else {
        if sequence.expected_total_segments().is_some() {
          return Err(Error::NotFound(format!(
            "missing split raw segment: {}",
            segment_path
          )));
        }

        let lookahead_name = sequence.segment_name(segment_index + 1)?;
        let lookahead_path = identity.sibling_path(lookahead_name)?;
        let lookahead_request =
          crate::RelatedSourceRequest::new(crate::RelatedSourcePurpose::Segment, lookahead_path);
        if resolver.resolve(&lookahead_request)?.is_some() {
          return Err(Error::InvalidFormat(
            "split raw segment sequence contains a gap".to_string(),
          ));
        }
        break;
      };

      if !seen_paths.insert(segment_path.to_string()) {
        return Err(Error::InvalidFormat(
          "split raw segment sequence must not repeat segment names".to_string(),
        ));
      }

      let segment_size = segment_source.size()?;
      if segment_index > 0
        && segment_index + 1 < sequence.expected_total_segments().unwrap_or(u64::MAX)
        && segment_size != first_segment_size
      {
        return Err(Error::InvalidFormat(
          "all non-final split raw segments must have the same size".to_string(),
        ));
      }

      media_size = media_size
        .checked_add(segment_size)
        .ok_or_else(|| Error::InvalidRange("split raw media size overflow".to_string()))?;
      segments.push(segment_source);
      segment_index += 1;
    }

    if segments.len() < 2 {
      return Err(Error::InvalidSourceReference(
        "split raw images require at least two segments".to_string(),
      ));
    }
    if segments.len() > 2 {
      for segment in &segments[1..segments.len() - 1] {
        if segment.size()? != first_segment_size {
          return Err(Error::InvalidFormat(
            "all non-final split raw segments must have the same size".to_string(),
          ));
        }
      }
    }

    let mut offsets = Vec::with_capacity(segments.len());
    let mut current_offset = 0u64;
    for segment in &segments {
      offsets.push(current_offset);
      current_offset = current_offset
        .checked_add(segment.size()?)
        .ok_or_else(|| Error::InvalidRange("split raw offset overflow".to_string()))?;
    }

    Ok(Self {
      segments: Arc::from(segments),
      segment_offsets: Arc::from(offsets),
      segment_size: first_segment_size,
      media_size,
    })
  }

  pub fn segment_count(&self) -> usize {
    self.segments.len()
  }
}

impl ByteSource for SplitRawImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("split raw read offset overflow".to_string()))?;
      if absolute_offset >= self.media_size {
        break;
      }

      let index = self
        .segment_offsets
        .partition_point(|segment_offset| *segment_offset <= absolute_offset)
        .checked_sub(1)
        .ok_or_else(|| Error::InvalidFormat("split raw segment offsets are empty".to_string()))?;
      let segment = &self.segments[index];
      let segment_offset = self.segment_offsets[index];
      let within_segment = absolute_offset - segment_offset;
      let available = usize::try_from(
        (segment.size()? - within_segment)
          .min(self.media_size - absolute_offset)
          .min((buf.len() - copied) as u64),
      )
      .map_err(|_| Error::InvalidRange("split raw read size is too large".to_string()))?;
      segment.read_exact_at(within_segment, &mut buf[copied..copied + available])?;
      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    let preferred_chunk_size = usize::try_from(self.segment_size).unwrap_or(1024 * 1024);
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size(preferred_chunk_size)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.splitraw"
  }
}

impl Image for SplitRawImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, path::Path, sync::Arc};

  use super::*;
  use crate::{RelatedSourceResolver, SourceIdentity};

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
  fn opens_fixture_metadata_and_reads_full_media() {
    let source = sample_source("splitraw/ext2.raw.000");
    let resolver = Resolver {
      files: HashMap::from([
        (
          "splitraw/ext2.raw.001".to_string(),
          sample_source("splitraw/ext2.raw.001"),
        ),
        (
          "splitraw/ext2.raw.002".to_string(),
          sample_source("splitraw/ext2.raw.002"),
        ),
        (
          "splitraw/ext2.raw.003".to_string(),
          sample_source("splitraw/ext2.raw.003"),
        ),
      ]),
    };
    let identity = SourceIdentity::from_relative_path("splitraw/ext2.raw.000").unwrap();

    let image = SplitRawImage::open_with_hints(
      source,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.segment_count(), 4);
    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(
      md5_hex(&image.read_all().unwrap()),
      "b1760d0b35a512ef56970df4e6f8c5d6"
    );
  }

  #[test]
  fn reads_across_synthetic_segments() {
    let resolver = Resolver {
      files: HashMap::from([(
        "bundle/disk.raw.001".to_string(),
        Arc::new(MemDataSource {
          data: vec![b'B'; 4],
        }) as ByteSourceHandle,
      )]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/disk.raw.000").unwrap();
    let image = SplitRawImage::open_with_hints(
      Arc::new(MemDataSource {
        data: vec![b'A'; 4],
      }) as ByteSourceHandle,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), b"AAAABBBB");
  }

  #[test]
  fn rejects_missing_intermediate_segments() {
    let resolver = Resolver {
      files: HashMap::from([(
        "bundle/disk.raw.002".to_string(),
        Arc::new(MemDataSource {
          data: vec![b'C'; 4],
        }) as ByteSourceHandle,
      )]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/disk.raw.000").unwrap();

    let result = SplitRawImage::open_with_hints(
      Arc::new(MemDataSource {
        data: vec![b'A'; 4],
      }) as ByteSourceHandle,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    );

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }

  #[test]
  fn rejects_non_first_segments() {
    let resolver = Resolver {
      files: HashMap::from([(
        "bundle/disk.raw.002".to_string(),
        Arc::new(MemDataSource {
          data: vec![b'C'; 4],
        }) as ByteSourceHandle,
      )]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/disk.raw.002").unwrap();

    let result = SplitRawImage::open_with_hints(
      Arc::new(MemDataSource {
        data: vec![b'B'; 4],
      }) as ByteSourceHandle,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    );

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }

  #[test]
  fn supports_xofn_segments() {
    let resolver = Resolver {
      files: HashMap::from([(
        "bundle/disk.2of2".to_string(),
        Arc::new(MemDataSource {
          data: vec![b'Z'; 4],
        }) as ByteSourceHandle,
      )]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/disk.1of2").unwrap();
    let image = SplitRawImage::open_with_hints(
      Arc::new(MemDataSource {
        data: vec![b'Y'; 4],
      }) as ByteSourceHandle,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), b"YYYYZZZZ");
  }

  #[test]
  fn supports_alphabetic_segments() {
    let resolver = Resolver {
      files: HashMap::from([(
        "bundle/diskab".to_string(),
        Arc::new(MemDataSource {
          data: vec![b'B'; 4],
        }) as ByteSourceHandle,
      )]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/diskaa").unwrap();
    let image = SplitRawImage::open_with_hints(
      Arc::new(MemDataSource {
        data: vec![b'A'; 4],
      }) as ByteSourceHandle,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.read_all().unwrap(), b"AAAABBBB");
  }

  #[test]
  fn requires_resolver_hints() {
    let result =
      SplitRawImage::open(Arc::new(MemDataSource { data: vec![0; 4] }) as ByteSourceHandle);

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }
}

crate::images::driver::impl_image_data_source!(SplitRawImage);
