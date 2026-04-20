use std::{
  collections::{HashMap, VecDeque},
  hash::Hash,
  sync::{Arc, Mutex},
};

use crate::Result;

#[derive(Debug)]
pub struct FifoCache<K, T: ?Sized = ()> {
  capacity: usize,
  inner: Mutex<FifoCacheState<K, T>>,
}

#[derive(Debug)]
struct FifoCacheState<K, T: ?Sized> {
  order: VecDeque<K>,
  values: HashMap<K, Arc<T>>,
}

impl<K, T: ?Sized> Default for FifoCacheState<K, T> {
  fn default() -> Self {
    Self {
      order: VecDeque::new(),
      values: HashMap::new(),
    }
  }
}

impl<K, T: ?Sized> FifoCache<K, T>
where
  K: Clone + Eq + Hash,
{
  pub fn new(capacity: usize) -> Self {
    Self {
      capacity,
      inner: Mutex::new(FifoCacheState::default()),
    }
  }

  pub fn get_or_load<F>(&self, key: K, load: F) -> Result<Arc<T>>
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
    state.order.push_back(key.clone());
    state.values.insert(key, loaded.clone());

    Ok(loaded)
  }
}
