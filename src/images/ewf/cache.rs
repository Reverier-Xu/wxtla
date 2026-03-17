//! Small bounded cache for decompressed EWF chunks.

use std::{
  collections::{HashMap, VecDeque},
  sync::{Arc, Mutex},
};

use crate::Result;

/// Concurrent chunk cache with FIFO eviction.
#[derive(Debug)]
pub struct EwfChunkCache {
  capacity: usize,
  inner: Mutex<EwfChunkCacheState>,
}

#[derive(Debug, Default)]
struct EwfChunkCacheState {
  order: VecDeque<u32>,
  chunks: HashMap<u32, Arc<[u8]>>,
}

impl EwfChunkCache {
  /// Create a cache with a maximum number of resident chunks.
  pub fn new(capacity: usize) -> Self {
    Self {
      capacity,
      inner: Mutex::new(EwfChunkCacheState::default()),
    }
  }

  /// Retrieve a cached chunk or load it on demand.
  pub fn get_or_load<F>(&self, chunk_index: u32, load: F) -> Result<Arc<[u8]>>
  where
    F: FnOnce() -> Result<Arc<[u8]>>, {
    if let Some(chunk) = self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .chunks
      .get(&chunk_index)
      .cloned()
    {
      return Ok(chunk);
    }

    let loaded = load()?;

    let mut state = self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(chunk) = state.chunks.get(&chunk_index).cloned() {
      return Ok(chunk);
    }

    if self.capacity != 0
      && state.order.len() >= self.capacity
      && let Some(evicted) = state.order.pop_front()
    {
      state.chunks.remove(&evicted);
    }
    state.order.push_back(chunk_index);
    state.chunks.insert(chunk_index, loaded.clone());

    Ok(loaded)
  }
}
