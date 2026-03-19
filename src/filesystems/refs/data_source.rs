//! ReFS non-resident data-source mapping.

use std::sync::Arc;

use super::parser::RefsDataRun;
use crate::{DataSource, DataSourceCapabilities, DataSourceHandle, Error, Result};

pub(crate) struct RefsDataRunsDataSource {
  pub(crate) source: DataSourceHandle,
  pub(crate) metadata_block_size: u64,
  pub(crate) data_size: u64,
  pub(crate) valid_data_size: u64,
  pub(crate) data_runs: Arc<[RefsDataRun]>,
}

impl DataSource for RefsDataRunsDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.data_size || buf.is_empty() {
      return Ok(0);
    }

    let limit = usize::try_from(self.data_size - offset)
      .unwrap_or(usize::MAX)
      .min(buf.len());
    let mut written = 0usize;

    while written < limit {
      let absolute = offset
        .checked_add(written as u64)
        .ok_or_else(|| Error::InvalidRange("refs read offset overflow".to_string()))?;
      let run = self
        .data_runs
        .iter()
        .find(|run| {
          let run_end = run
            .logical_offset
            .saturating_add(run.block_count * self.metadata_block_size);
          absolute >= run.logical_offset && absolute < run_end
        })
        .ok_or_else(|| {
          Error::InvalidFormat("refs data run is missing for the requested offset".to_string())
        })?;

      let run_length = run.block_count * self.metadata_block_size;
      let run_offset = absolute - run.logical_offset;
      let chunk = usize::try_from(run_length - run_offset)
        .unwrap_or(usize::MAX)
        .min(limit - written);
      let valid_chunk = if absolute >= self.valid_data_size {
        0
      } else {
        usize::try_from((self.valid_data_size - absolute).min(chunk as u64)).unwrap_or(chunk)
      };

      if valid_chunk != 0 {
        self.source.read_exact_at(
          run
            .physical_block_number
            .checked_mul(self.metadata_block_size)
            .and_then(|base| base.checked_add(run_offset))
            .ok_or_else(|| Error::InvalidRange("refs physical read offset overflow".to_string()))?,
          &mut buf[written..written + valid_chunk],
        )?;
      }
      if valid_chunk < chunk {
        buf[written + valid_chunk..written + chunk].fill(0);
      }
      written += chunk;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.data_size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self.source.capabilities()
  }
}
