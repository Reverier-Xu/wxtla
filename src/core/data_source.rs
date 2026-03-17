//! Concurrent read abstractions and helpers for parser backends.

use std::{
  collections::HashMap,
  path::Path,
  sync::{Arc, Mutex, RwLock},
  time::Instant,
};

use super::{Error, Result};

/// Raw byte-level access to a file, block device, or virtual blob.
pub trait DataSource: Send + Sync {
  /// Read bytes starting at `offset` into `buf`.
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

  /// Return the total size of this source in bytes.
  fn size(&self) -> Result<u64>;

  /// Describe the backend's read behavior.
  fn capabilities(&self) -> DataSourceCapabilities {
    DataSourceCapabilities::default()
  }

  /// Return a stable label for tracing and diagnostics.
  fn telemetry_name(&self) -> &'static str {
    std::any::type_name::<Self>()
  }

  /// Return the backing host path when one exists.
  fn origin_path(&self) -> Option<&Path> {
    None
  }

  /// Materialize the full source into memory.
  fn read_all(&self) -> Result<Vec<u8>> {
    let size = usize::try_from(self.size()?).map_err(|_| {
      Error::InvalidRange("data source is too large to read into memory".to_string())
    })?;
    let mut buf = vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
      let read = self.read_at(offset as u64, &mut buf[offset..])?;
      if read == 0 {
        break;
      }
      offset += read;
    }
    buf.truncate(offset);
    Ok(buf)
  }
}

/// Whether the backing source can serve reads concurrently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSourceReadConcurrency {
  /// The backend has not declared its concurrency model.
  Unknown,
  /// Reads are effectively serialized by the backend.
  Serialized,
  /// Reads at different offsets can proceed concurrently.
  Concurrent,
}

/// Relative cost of moving between offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSourceSeekCost {
  /// The backend has not declared its seek characteristics.
  Unknown,
  /// Seeking is cheap enough to treat reads as random-access friendly.
  Cheap,
  /// Seeking is expensive and callers should prefer sequential access.
  Expensive,
}

/// Backend capabilities that inform concurrent readers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSourceCapabilities {
  /// Whether the backend can satisfy reads in parallel.
  pub read_concurrency: DataSourceReadConcurrency,
  /// Whether frequent offset changes are cheap.
  pub seek_cost: DataSourceSeekCost,
  /// Optional chunk-size hint for high-throughput callers.
  pub preferred_chunk_size: Option<usize>,
}

impl DataSourceCapabilities {
  /// Construct a capability descriptor.
  pub const fn new(
    read_concurrency: DataSourceReadConcurrency, seek_cost: DataSourceSeekCost,
  ) -> Self {
    Self {
      read_concurrency,
      seek_cost,
      preferred_chunk_size: None,
    }
  }

  /// Construct capabilities for a serialized backend.
  pub const fn serialized(seek_cost: DataSourceSeekCost) -> Self {
    Self::new(DataSourceReadConcurrency::Serialized, seek_cost)
  }

  /// Construct capabilities for a concurrent backend.
  pub const fn concurrent(seek_cost: DataSourceSeekCost) -> Self {
    Self::new(DataSourceReadConcurrency::Concurrent, seek_cost)
  }

  /// Attach an optional preferred chunk size.
  pub fn with_preferred_chunk_size(mut self, preferred_chunk_size: usize) -> Self {
    self.preferred_chunk_size = Some(preferred_chunk_size);
    self
  }
}

impl Default for DataSourceCapabilities {
  fn default() -> Self {
    Self::new(
      DataSourceReadConcurrency::Unknown,
      DataSourceSeekCost::Unknown,
    )
  }
}

/// Shared statistics handle for observed read activity.
#[derive(Debug, Clone, Default)]
pub struct DataSourceReadStats {
  inner: Arc<Mutex<DataSourceReadStatsState>>,
}

/// Immutable read statistics snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataSourceReadStatsSnapshot {
  /// Number of read requests issued.
  pub read_count: u64,
  /// Total bytes returned across all reads.
  pub read_bytes: u64,
  /// Average read size in bytes.
  pub average_read_size: u64,
  /// Sum of absolute gaps between consecutive read requests.
  pub request_offset_distance_bytes: u64,
  /// Average absolute gap between consecutive read requests.
  pub average_offset_distance_bytes: u64,
  /// Largest single read size seen.
  pub max_read_size: usize,
  /// Largest absolute gap between consecutive read requests.
  pub max_offset_distance_bytes: u64,
  /// Total time spent in reads, in microseconds.
  pub total_read_micros: u128,
  /// Average per-read time, in microseconds.
  pub average_read_micros: u128,
}

#[derive(Debug, Default)]
struct DataSourceReadStatsState {
  read_count: u64,
  read_bytes: u64,
  request_offset_distance_bytes: u64,
  max_read_size: usize,
  max_offset_distance_bytes: u64,
  total_read_micros: u128,
  last_offset: Option<u64>,
  last_len: usize,
}

impl DataSourceReadStats {
  fn record_read(&self, offset: u64, len: usize, started_at: Instant) {
    let mut state = self.inner.lock().unwrap();
    state.read_count = state.read_count.saturating_add(1);
    state.read_bytes = state.read_bytes.saturating_add(len as u64);
    state.max_read_size = state.max_read_size.max(len);
    state.total_read_micros = state
      .total_read_micros
      .saturating_add(started_at.elapsed().as_micros());

    if let Some(last_offset) = state.last_offset {
      let last_end = last_offset.saturating_add(state.last_len as u64);
      let distance = offset.abs_diff(last_end);
      state.request_offset_distance_bytes =
        state.request_offset_distance_bytes.saturating_add(distance);
      state.max_offset_distance_bytes = state.max_offset_distance_bytes.max(distance);
    }

    state.last_offset = Some(offset);
    state.last_len = len;
  }

  /// Capture the current statistics snapshot.
  pub fn snapshot(&self) -> DataSourceReadStatsSnapshot {
    let state = self.inner.lock().unwrap();
    let average_read_size = if state.read_count == 0 {
      0
    } else {
      state.read_bytes / state.read_count
    };
    let average_offset_distance_bytes = if state.read_count <= 1 {
      0
    } else {
      state.request_offset_distance_bytes / (state.read_count - 1)
    };
    let average_read_micros = if state.read_count == 0 {
      0
    } else {
      state.total_read_micros / u128::from(state.read_count)
    };

    DataSourceReadStatsSnapshot {
      read_count: state.read_count,
      read_bytes: state.read_bytes,
      average_read_size,
      request_offset_distance_bytes: state.request_offset_distance_bytes,
      average_offset_distance_bytes,
      max_read_size: state.max_read_size,
      max_offset_distance_bytes: state.max_offset_distance_bytes,
      total_read_micros: state.total_read_micros,
      average_read_micros,
    }
  }
}

/// Wrapper that records read statistics while delegating to another source.
pub struct ObservedDataSource {
  inner: Arc<dyn DataSource>,
  stats: DataSourceReadStats,
}

impl ObservedDataSource {
  /// Wrap a source with read-observation metrics.
  pub fn new(inner: Arc<dyn DataSource>) -> Self {
    Self {
      inner,
      stats: DataSourceReadStats::default(),
    }
  }

  /// Access the shared statistics handle.
  pub fn stats(&self) -> DataSourceReadStats {
    self.stats.clone()
  }
}

impl DataSource for ObservedDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let started_at = Instant::now();
    let read = self.inner.read_at(offset, buf)?;
    self.stats.record_read(offset, read, started_at);
    Ok(read)
  }

  fn size(&self) -> Result<u64> {
    self.inner.size()
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self.inner.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    self.inner.telemetry_name()
  }

  fn origin_path(&self) -> Option<&Path> {
    self.inner.origin_path()
  }
}

/// Thin wrapper that turns an `Arc<dyn DataSource>` back into a `DataSource`.
pub struct SharedDataSource {
  inner: Arc<dyn DataSource>,
}

impl SharedDataSource {
  /// Wrap a shared source for trait-object handoff.
  pub fn new(inner: Arc<dyn DataSource>) -> Self {
    Self { inner }
  }
}

impl DataSource for SharedDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    self.inner.read_at(offset, buf)
  }

  fn size(&self) -> Result<u64> {
    self.inner.size()
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self.inner.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    self.inner.telemetry_name()
  }

  fn origin_path(&self) -> Option<&Path> {
    self.inner.origin_path()
  }
}

/// Windowed view into a sub-range of another source.
pub struct SliceDataSource {
  inner: Arc<dyn DataSource>,
  base_offset: u64,
  size: u64,
}

impl SliceDataSource {
  /// Create a slice backed by `inner[base_offset..base_offset + size]`.
  pub fn new(inner: Arc<dyn DataSource>, base_offset: u64, size: u64) -> Self {
    Self {
      inner,
      base_offset,
      size,
    }
  }
}

impl DataSource for SliceDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.size || buf.is_empty() {
      return Ok(0);
    }

    let available = usize::try_from(self.size - offset)
      .unwrap_or(usize::MAX)
      .min(buf.len());
    let absolute_offset = self
      .base_offset
      .checked_add(offset)
      .ok_or_else(|| Error::InvalidRange("slice data source offset overflow".to_string()))?;
    self.inner.read_at(absolute_offset, &mut buf[..available])
  }

  fn size(&self) -> Result<u64> {
    Ok(self.size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self.inner.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    self.inner.telemetry_name()
  }

  fn origin_path(&self) -> Option<&Path> {
    self.inner.origin_path()
  }
}

const PROBE_CACHE_WINDOW_SIZE: usize = 4096;
const PROBE_CACHE_LIMIT: u64 = 64 * 1024;

/// Small-window cache for repeated probe reads near the start of a source.
pub struct ProbeCachedDataSource<'a> {
  inner: &'a dyn DataSource,
  windows: RwLock<HashMap<u64, Arc<[u8]>>>,
}

impl<'a> ProbeCachedDataSource<'a> {
  /// Wrap a source with a probe-oriented cache.
  pub fn new(inner: &'a dyn DataSource) -> Self {
    Self {
      inner,
      windows: RwLock::new(HashMap::new()),
    }
  }

  fn cacheable(offset: u64, len: usize) -> bool {
    if len == 0 {
      return false;
    }
    let Some(end) = offset.checked_add(len as u64) else {
      return false;
    };
    end <= PROBE_CACHE_LIMIT
  }

  fn read_window(&self, window_offset: u64) -> Result<Arc<[u8]>> {
    if let Some(window) = self.windows.read().unwrap().get(&window_offset).cloned() {
      return Ok(window);
    }

    let mut data = vec![0u8; PROBE_CACHE_WINDOW_SIZE];
    let read = self.inner.read_at(window_offset, &mut data)?;
    data.truncate(read);
    let window: Arc<[u8]> = data.into();

    let mut cache = self.windows.write().unwrap();
    let entry = cache.entry(window_offset).or_insert_with(|| window.clone());
    Ok(entry.clone())
  }
}

impl DataSource for ProbeCachedDataSource<'_> {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if !Self::cacheable(offset, buf.len()) {
      return self.inner.read_at(offset, buf);
    }

    let mut written = 0usize;
    while written < buf.len() {
      let absolute = offset
        .checked_add(written as u64)
        .ok_or_else(|| Error::InvalidRange("probe cache offset overflow".to_string()))?;
      let window_offset =
        (absolute / PROBE_CACHE_WINDOW_SIZE as u64) * PROBE_CACHE_WINDOW_SIZE as u64;
      let window = self.read_window(window_offset)?;
      let window_inner = (absolute - window_offset) as usize;
      if window_inner >= window.len() {
        break;
      }
      let available = (window.len() - window_inner).min(buf.len() - written);
      buf[written..written + available]
        .copy_from_slice(&window[window_inner..window_inner + available]);
      written += available;
      if window.len() < PROBE_CACHE_WINDOW_SIZE {
        break;
      }
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    self.inner.size()
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self.inner.capabilities()
  }

  fn telemetry_name(&self) -> &'static str {
    self.inner.telemetry_name()
  }

  fn origin_path(&self) -> Option<&Path> {
    self.inner.origin_path()
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};

  use super::*;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = offset as usize;
      if offset >= self.data.len() {
        return Ok(0);
      }
      let available = &self.data[offset..];
      let read = buf.len().min(available.len());
      buf[..read].copy_from_slice(&available[..read]);
      Ok(read)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.data.len() as u64)
    }

    fn capabilities(&self) -> DataSourceCapabilities {
      DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap).with_preferred_chunk_size(4096)
    }
  }

  #[test]
  fn read_all_materializes_the_source() {
    let source = MemDataSource {
      data: b"read-all".to_vec(),
    };

    assert_eq!(source.read_all().unwrap(), b"read-all");
  }

  #[test]
  fn observed_data_source_tracks_requested_read_patterns() {
    let source: Arc<dyn DataSource> = Arc::new(MemDataSource {
      data: b"abcdefghijklmnopqrstuvwxyz".to_vec(),
    });
    let observed = ObservedDataSource::new(source);
    let stats = observed.stats();

    let mut first = [0u8; 4];
    let mut second = [0u8; 2];
    let mut third = [0u8; 3];
    observed.read_at(0, &mut first).unwrap();
    observed.read_at(4, &mut second).unwrap();
    observed.read_at(10, &mut third).unwrap();

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.read_count, 3);
    assert_eq!(snapshot.read_bytes, 9);
    assert_eq!(snapshot.average_read_size, 3);
    assert_eq!(snapshot.request_offset_distance_bytes, 4);
    assert_eq!(snapshot.average_offset_distance_bytes, 2);
    assert_eq!(snapshot.max_read_size, 4);
    assert_eq!(snapshot.max_offset_distance_bytes, 4);
  }

  #[test]
  fn observed_data_source_forwards_capabilities() {
    let source: Arc<dyn DataSource> = Arc::new(MemDataSource {
      data: b"capabilities".to_vec(),
    });
    let observed = ObservedDataSource::new(source);

    assert_eq!(
      observed.capabilities(),
      DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap).with_preferred_chunk_size(4096)
    );
  }

  #[test]
  fn shared_data_source_forwards_reads() {
    let source: Arc<dyn DataSource> = Arc::new(MemDataSource {
      data: b"shared".to_vec(),
    });
    let shared = SharedDataSource::new(source);
    let mut buf = [0u8; 3];

    let read = shared.read_at(1, &mut buf).unwrap();
    assert_eq!(read, 3);
    assert_eq!(&buf, b"har");
  }

  #[test]
  fn slice_data_source_reads_from_the_requested_window() {
    let source: Arc<dyn DataSource> = Arc::new(MemDataSource {
      data: b"abcdefghijklmnopqrstuvwxyz".to_vec(),
    });
    let slice = SliceDataSource::new(source, 5, 7);

    let mut buf = [0u8; 8];
    let read = slice.read_at(0, &mut buf).unwrap();
    assert_eq!(read, 7);
    assert_eq!(&buf[..read], b"fghijkl");

    let read = slice.read_at(4, &mut buf).unwrap();
    assert_eq!(read, 3);
    assert_eq!(&buf[..read], b"jkl");
  }

  #[test]
  fn slice_data_source_forwards_capabilities() {
    let source: Arc<dyn DataSource> = Arc::new(MemDataSource {
      data: b"capabilities".to_vec(),
    });
    let slice = SliceDataSource::new(source, 2, 5);

    assert_eq!(
      slice.capabilities(),
      DataSourceCapabilities::concurrent(DataSourceSeekCost::Cheap).with_preferred_chunk_size(4096)
    );
  }

  #[test]
  fn probe_cached_data_source_reuses_small_probe_windows() {
    struct CountingDataSource {
      data: Vec<u8>,
      reads: Arc<AtomicUsize>,
    }

    impl DataSource for CountingDataSource {
      fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let offset = offset as usize;
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

    let reads = Arc::new(AtomicUsize::new(0));
    let source = CountingDataSource {
      data: (0..128u8).collect(),
      reads: reads.clone(),
    };
    let cached = ProbeCachedDataSource::new(&source);

    let mut first = [0u8; 16];
    let mut second = [0u8; 8];
    cached.read_at(0, &mut first).unwrap();
    cached.read_at(4, &mut second).unwrap();

    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(&first[..4], &[0, 1, 2, 3]);
    assert_eq!(&second[..4], &[4, 5, 6, 7]);
  }
}
