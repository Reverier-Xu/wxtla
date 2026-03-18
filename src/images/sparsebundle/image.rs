//! Read-only sparsebundle image surface.

use std::sync::Arc;

use super::{DESCRIPTOR, parser::parse_info_plist};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceSeekCost, Error, RelatedPathBuf,
  RelatedSourcePurpose, RelatedSourceRequest, Result, SourceHints, images::Image,
};

pub struct SparseBundleImage {
  band_size: u64,
  media_size: u64,
  band_sources: Arc<[Option<DataSourceHandle>]>,
}

impl SparseBundleImage {
  pub fn open(_source: DataSourceHandle) -> Result<Self> {
    Err(Error::InvalidSourceReference(
      "sparsebundle images require source hints, a resolver, and a source identity".to_string(),
    ))
  }

  pub fn open_with_hints(source: DataSourceHandle, hints: SourceHints<'_>) -> Result<Self> {
    let resolver = hints.resolver().ok_or_else(|| {
      Error::InvalidSourceReference(
        "sparsebundle images require a related-source resolver".to_string(),
      )
    })?;
    let source_identity = hints.source_identity().ok_or_else(|| {
      Error::InvalidSourceReference(
        "sparsebundle images require a source identity hint".to_string(),
      )
    })?;
    let parsed = parse_info_plist(&source.read_all()?)?;
    let band_count = parsed.media_size.div_ceil(parsed.band_size);
    let parent = source_identity.logical_path().parent().ok_or_else(|| {
      Error::InvalidSourceReference(
        "sparsebundle source identity must have a lexical parent path".to_string(),
      )
    })?;
    let mut band_sources = Vec::with_capacity(
      usize::try_from(band_count)
        .map_err(|_| Error::InvalidRange("sparsebundle band count is too large".to_string()))?,
    );
    for band_index in 0..band_count {
      let band_name = format!("bands/{band_index:x}");
      let relative = RelatedPathBuf::from_relative_path(&band_name)?;
      let band_path = parent.join(&relative);
      let band = resolver.resolve(&RelatedSourceRequest::new(
        RelatedSourcePurpose::Band,
        band_path,
      ))?;
      if let Some(band_source) = &band
        && band_source.size()? > parsed.band_size
      {
        return Err(Error::InvalidFormat(
          "sparsebundle band file exceeds the declared band size".to_string(),
        ));
      }
      band_sources.push(band);
    }

    Ok(Self {
      band_size: parsed.band_size,
      media_size: parsed.media_size,
      band_sources: Arc::from(band_sources),
    })
  }

  pub fn band_size(&self) -> u64 {
    self.band_size
  }

  fn band_source(&self, band_index: u64) -> Result<Option<DataSourceHandle>> {
    Ok(
      self
        .band_sources
        .get(
          usize::try_from(band_index)
            .map_err(|_| Error::InvalidRange("sparsebundle band index is too large".to_string()))?,
        )
        .cloned()
        .flatten(),
    )
  }
}

impl DataSource for SparseBundleImage {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("sparsebundle read offset overflow".to_string()))?;
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
      .map_err(|_| Error::InvalidRange("sparsebundle read chunk is too large".to_string()))?;

      match self.band_source(band_index)? {
        Some(band_source) => {
          let band_size = band_source.size()?;
          if within_band >= band_size {
            buf[copied..copied + available].fill(0);
          } else {
            let readable = usize::try_from(band_size - within_band)
              .map_err(|_| Error::InvalidRange("sparsebundle band tail is too large".to_string()))?
              .min(available);
            band_source.read_exact_at(within_band, &mut buf[copied..copied + readable])?;
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

  fn capabilities(&self) -> DataSourceCapabilities {
    let preferred_chunk_size = usize::try_from(self.band_size).unwrap_or(8 * 1024 * 1024);
    DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap)
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
  use std::{collections::HashMap, path::Path, sync::Arc};

  use super::*;
  use crate::{RelatedSourceResolver, SourceIdentity};

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

  struct Resolver {
    files: HashMap<String, DataSourceHandle>,
  }

  impl RelatedSourceResolver for Resolver {
    fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<DataSourceHandle>> {
      Ok(self.files.get(&request.path.to_string()).cloned())
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

  fn sparsebundle_info_plist(band_size: u64, media_size: u64) -> DataSourceHandle {
    Arc::new(MemDataSource {
      data: format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n<key>band-size</key><integer>{band_size}</integer>\n<key>bundle-backingstore-version</key><integer>1</integer>\n<key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string>\n<key>size</key><integer>{media_size}</integer>\n</dict>\n</plist>"
      )
      .into_bytes(),
    }) as DataSourceHandle
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
        }) as DataSourceHandle,
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
  fn requires_resolver_hints() {
    let result = SparseBundleImage::open(sparsebundle_info_plist(1024, 1024));

    assert!(matches!(result, Err(Error::InvalidSourceReference(_))));
  }
}
