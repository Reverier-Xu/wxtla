//! Small caches for QCOW metadata and clusters.

use std::{
  collections::{HashMap, VecDeque},
  sync::{Arc, Mutex},
};

use crate::Result;

/// Generic FIFO cache keyed by a `u64` index.
#[derive(Debug)]
pub struct QcowCache<T> {
  capacity: usize,
  inner: Mutex<QcowCacheState<T>>,
}

#[derive(Debug)]
struct QcowCacheState<T> {
  order: VecDeque<u64>,
  values: HashMap<u64, Arc<T>>,
}

impl<T> Default for QcowCacheState<T> {
  fn default() -> Self {
    Self {
      order: VecDeque::new(),
      values: HashMap::new(),
    }
  }
}

impl<T> QcowCache<T> {
  /// Create a cache with a maximum number of resident entries.
  pub fn new(capacity: usize) -> Self {
    Self {
      capacity,
      inner: Mutex::new(QcowCacheState::default()),
    }
  }

  /// Retrieve a cached value or load it on demand.
  pub fn get_or_load<F>(&self, key: u64, load: F) -> Result<Arc<T>>
  where
    F: FnOnce() -> Result<Arc<T>>, {
    if let Some(value) = self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .values
      .get(&key)
      .cloned()
    {
      return Ok(value);
    }

    let loaded = load()?;

    let mut state = self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(value) = state.values.get(&key).cloned() {
      return Ok(value);
    }

    if self.capacity != 0
      && state.order.len() >= self.capacity
      && let Some(evicted) = state.order.pop_front()
    {
      state.values.remove(&evicted);
    }
    state.order.push_back(key);
    state.values.insert(key, loaded.clone());

    Ok(loaded)
  }
}
