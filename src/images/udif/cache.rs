//! Small caches used by the UDIF reader.

use std::{
  collections::{HashMap, VecDeque},
  sync::{Arc, Mutex},
};

use crate::Result;

#[derive(Debug)]
pub struct UdifCache<T> {
  capacity: usize,
  inner: Mutex<UdifCacheState<T>>,
}

#[derive(Debug)]
struct UdifCacheState<T> {
  order: VecDeque<u64>,
  values: HashMap<u64, Arc<T>>,
}

impl<T> Default for UdifCacheState<T> {
  fn default() -> Self {
    Self {
      order: VecDeque::new(),
      values: HashMap::new(),
    }
  }
}

impl<T> UdifCache<T> {
  pub fn new(capacity: usize) -> Self {
    Self {
      capacity,
      inner: Mutex::new(UdifCacheState::default()),
    }
  }

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
