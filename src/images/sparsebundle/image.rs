//! Read-only sparsebundle image surface.

use std::{
  collections::{HashMap, VecDeque},
  sync::{Arc, Mutex},
};

use super::{DESCRIPTOR, parser::parse_info_plist};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, RelatedSourceResolver, Result, SourceHints,
  images::Image,
};

const BAND_CACHE_CAPACITY: usize = 64;

pub struct SparseBundleImage {
  band_size: u64,
  media_size: u64,
  bands: SparseBundleBands,
}

enum SparseBundleBands {
  Eager(HashMap<u64, SparseBundleBand>),
  Lazy(SparseBundleLazyBands),
}

#[derive(Clone)]
struct SparseBundleBand {
  source: ByteSourceHandle,
  size: u64,
}

struct SparseBundleLazyBands {
  resolver: Arc<dyn RelatedSourceResolver>,
  bands_root: RelatedPathBuf,
  cache: Mutex<SparseBundleBandCacheState>,
}

#[derive(Default)]
struct SparseBundleBandCacheState {
  order: VecDeque<u64>,
  bands: HashMap<u64, Option<SparseBundleBand>>,
}

impl SparseBundleImage {
  pub fn open(_source: ByteSourceHandle) -> Result<Self> {
    Err(Error::invalid_source_reference(
      "sparsebundle images require source hints, a resolver, and a source identity".to_string(),
    ))
  }

  pub fn open_with_hints(source: ByteSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    let source_identity = hints.source_identity().ok_or_else(|| {
      Error::invalid_source_reference(
        "sparsebundle images require a source identity hint".to_string(),
      )
    })?;
    let parsed = parse_info_plist(&source.read_all()?)?;
    let band_count = parsed.media_size.div_ceil(parsed.band_size);
    let parent = source_identity.logical_path().parent().ok_or_else(|| {
      Error::invalid_source_reference(
        "sparsebundle source identity must have a lexical parent path".to_string(),
      )
    })?;
    let bands = if let Some(resolver) = hints.shared_resolver() {
      SparseBundleBands::Lazy(SparseBundleLazyBands {
        resolver,
        bands_root: parent.join(&RelatedPathBuf::from_relative_path("bands")?),
        cache: Mutex::new(SparseBundleBandCacheState::default()),
      })
    } else {
      let resolver = hints.resolver().ok_or_else(|| {
        Error::invalid_source_reference(
          "sparsebundle images require a related-source resolver".to_string(),
        )
      })?;
      let mut band_sources = HashMap::new();
      for band_index in 0..band_count {
        let band_name = format!("bands/{band_index:x}");
        let relative = RelatedPathBuf::from_relative_path(&band_name)?;
        let band_path = parent.join(&relative);
        let band = resolver.resolve(&RelatedSourceRequest::new(
          RelatedSourcePurpose::Band,
          band_path,
        ))?;
        if let Some(band_source) = band {
          let size = band_source.size()?;
          if size > parsed.band_size {
            return Err(Error::invalid_format(
              "sparsebundle band file exceeds the declared band size".to_string(),
            ));
          }
          band_sources.insert(
            band_index,
            SparseBundleBand {
              source: band_source,
              size,
            },
          );
        }
      }
      SparseBundleBands::Eager(band_sources)
    };

    Ok(Self {
      band_size: parsed.band_size,
      media_size: parsed.media_size,
      bands,
    })
  }

  pub fn band_size(&self) -> u64 {
    self.band_size
  }

  fn band_source(&self, band_index: u64) -> Result<Option<SparseBundleBand>> {
    match &self.bands {
      SparseBundleBands::Eager(bands) => Ok(bands.get(&band_index).cloned()),
      SparseBundleBands::Lazy(bands) => bands.get_or_resolve(band_index, self.band_size),
    }
  }
}

impl SparseBundleLazyBands {
  fn get_or_resolve(&self, band_index: u64, band_size: u64) -> Result<Option<SparseBundleBand>> {
    if let Some(cached) = self
      .cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .bands
      .get(&band_index)
      .cloned()
    {
      return Ok(cached);
    }

    let resolved = self.resolve_band(band_index, band_size)?;

    let mut state = self
      .cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = state.bands.get(&band_index).cloned() {
      return Ok(cached);
    }
    if state.order.len() >= BAND_CACHE_CAPACITY
      && let Some(evicted) = state.order.pop_front()
    {
      state.bands.remove(&evicted);
    }
    state.order.push_back(band_index);
    state.bands.insert(band_index, resolved.clone());

    Ok(resolved)
  }

  fn resolve_band(&self, band_index: u64, band_size: u64) -> Result<Option<SparseBundleBand>> {
    let relative = RelatedPathBuf::from_relative_path(&format!("{band_index:x}"))?;
    let band_path = self.bands_root.join(&relative);
    let band = self.resolver.resolve(&RelatedSourceRequest::new(
      RelatedSourcePurpose::Band,
      band_path,
    ))?;

    band
      .map(|source| {
        let size = source.size()?;
        if size > band_size {
          return Err(Error::invalid_format(
            "sparsebundle band file exceeds the declared band size".to_string(),
          ));
        }

        Ok(SparseBundleBand { source, size })
      })
      .transpose()
  }
}

impl ByteSource for SparseBundleImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::invalid_range("sparsebundle read offset overflow"))?;
      if absolute_offset >= self.media_size {
        break;
      }

      let band_index = absolute_offset / self.band_size;
      let within_band = absolute_offset % self.band_size;
      let available = usize::try_from(
        (self.band_size - within_band)
          .min(self.media_size - absolute_offset)
          .min((buf.len() - copied) as u64),
      )
      .map_err(|_| Error::invalid_range("sparsebundle read chunk is too large"))?;

      match self.band_source(band_index)? {
        Some(band) => {
          if within_band >= band.size {
            buf[copied..copied + available].fill(0);
          } else {
            let readable = usize::try_from(band.size - within_band)
              .map_err(|_| Error::invalid_range("sparsebundle band tail is too large"))?
              .min(available);
            band
              .source
              .read_exact_at(within_band, &mut buf[copied..copied + readable])?;
            if readable < available {
              buf[copied + readable..copied + available].fill(0);
            }
          }
        }
        None => {
          buf[copied..copied + available].fill(0);
        }
      }

      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    let preferred_chunk_size = usize::try_from(self.band_size).unwrap_or(8 * 1024 * 1024);
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Cheap)
      .with_preferred_chunk_size(preferred_chunk_size)
  }

  fn telemetry_name(&self) -> &'static str {
    "image.sparsebundle"
  }
}

impl Image for SparseBundleImage {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn logical_sector_size(&self) -> Option<u32> {
    Some(512)
  }

  fn physical_sector_size(&self) -> Option<u32> {
    self.logical_sector_size()
  }

  fn is_sparse(&self) -> bool {
    true
  }
}

#[cfg(test)]
mod tests {
  use std::{
    collections::HashMap,
    path::Path,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
  };

  use super::*;
  use crate::{RelatedSourceResolver, SourceIdentity};

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl ByteSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = usize::try_from(offset)
        .map_err(|_| Error::invalid_range("test read offset is too large"))?;
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

  struct CountingResolver {
    files: HashMap<String, ByteSourceHandle>,
    calls: AtomicUsize,
  }

  impl RelatedSourceResolver for Resolver {
    fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<ByteSourceHandle>> {
      Ok(self.files.get(&request.path.to_string()).cloned())
    }
  }

  impl RelatedSourceResolver for CountingResolver {
    fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<ByteSourceHandle>> {
      self.calls.fetch_add(1, Ordering::Relaxed);
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

  fn sparsebundle_info_plist(band_size: u64, media_size: u64) -> ByteSourceHandle {
    Arc::new(MemDataSource {
      data: format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n<key>band-size</key><integer>{band_size}</integer>\n<key>bundle-backingstore-version</key><integer>1</integer>\n<key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string>\n<key>size</key><integer>{media_size}</integer>\n</dict>\n</plist>"
      )
      .into_bytes(),
    }) as ByteSourceHandle
  }

  #[test]
  fn opens_sparsebundle_fixture_metadata() {
    let info = sample_source("sparsebundle/hfsplus.sparsebundle/Info.plist");
    let band = sample_source("sparsebundle/hfsplus.sparsebundle/bands/0");
    let resolver = Resolver {
      files: HashMap::from([(
        "sparsebundle/hfsplus.sparsebundle/bands/0".to_string(),
        band,
      )]),
    };
    let identity =
      SourceIdentity::from_relative_path("sparsebundle/hfsplus.sparsebundle/Info.plist").unwrap();

    let image = SparseBundleImage::open_with_hints(
      info,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(image.size().unwrap(), 4_194_304);
    assert_eq!(image.band_size(), 8_388_608);
  }

  #[test]
  fn reads_full_sparsebundle_fixture() {
    let info = sample_source("sparsebundle/hfsplus.sparsebundle/Info.plist");
    let band = sample_source("sparsebundle/hfsplus.sparsebundle/bands/0");
    let resolver = Resolver {
      files: HashMap::from([(
        "sparsebundle/hfsplus.sparsebundle/bands/0".to_string(),
        band,
      )]),
    };
    let identity =
      SourceIdentity::from_relative_path("sparsebundle/hfsplus.sparsebundle/Info.plist").unwrap();

    let image = SparseBundleImage::open_with_hints(
      info,
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    assert_eq!(
      md5_hex(&image.read_all().unwrap()),
      "7adf013daec71e509669a9315a6a173c"
    );
  }

  #[test]
  fn treats_missing_bands_as_sparse_zeroes() {
    let resolver = Resolver {
      files: HashMap::from([(
        "bundle/bands/0".to_string(),
        Arc::new(MemDataSource {
          data: vec![0xA5; 1024],
        }) as ByteSourceHandle,
      )]),
    };
    let identity = SourceIdentity::from_relative_path("bundle/Info.plist").unwrap();
    let image = SparseBundleImage::open_with_hints(
      sparsebundle_info_plist(1024, 2048),
      SourceHints::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap();

    let mut expected = vec![0xA5; 1024];
    expected.extend_from_slice(&vec![0; 1024]);
    assert_eq!(image.read_all().unwrap(), expected);
  }

  #[test]
  fn shared_resolver_defers_and_caches_band_resolution() {
    let resolver = Arc::new(CountingResolver {
      files: HashMap::from([(
        "bundle/bands/0".to_string(),
        Arc::new(MemDataSource {
          data: vec![0xA5; 1024],
        }) as ByteSourceHandle,
      )]),
      calls: AtomicUsize::new(0),
    });
    let shared_resolver: Arc<dyn RelatedSourceResolver> = resolver.clone();
    let identity = SourceIdentity::from_relative_path("bundle/Info.plist").unwrap();
    let image = SparseBundleImage::open_with_hints(
      sparsebundle_info_plist(1024, 2048),
      SourceHints::new()
        .with_shared_resolver(&shared_resolver)
        .with_source_identity(&identity),
    )
    .unwrap();
    let mut buf = [0u8; 128];

    assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);

    image.read_exact_at(128, &mut buf).unwrap();
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
    assert_eq!(buf, [0xA5; 128]);

    image.read_exact_at(512, &mut buf).unwrap();
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);

    image.read_exact_at(1408, &mut buf).unwrap();
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);
    assert_eq!(buf, [0u8; 128]);

    image.read_exact_at(1664, &mut buf).unwrap();
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);
  }

  #[test]
  fn requires_resolver_hints() {
    let result = SparseBundleImage::open(sparsebundle_info_plist(1024, 1024));

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }
}

crate::images::driver::impl_image_data_source!(SparseBundleImage);
