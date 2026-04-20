//! ReFS non-resident data-source mapping.

use std::sync::Arc;

use super::parser::RefsDataRun;
use crate::{ByteSource, ByteSourceCapabilities, ByteSourceHandle, Error, Result};

pub(crate) struct RefsDataRunsDataSource {
  pub(crate) source: ByteSourceHandle,
  pub(crate) metadata_block_size: u64,
  pub(crate) data_size: u64,
  pub(crate) valid_data_size: u64,
  pub(crate) data_runs: Arc<[RefsDataRun]>,
}

impl RefsDataRunsDataSource {
  fn run_for_offset(&self, offset: u64) -> Option<&RefsDataRun> {
    let index = self
      .data_runs
      .partition_point(|run| run.logical_offset <= offset)
      .checked_sub(1)?;
    let run = self.data_runs.get(index)?;
    let run_end = run
      .logical_offset
      .checked_add(run.block_count.checked_mul(self.metadata_block_size)?)?;

    (offset < run_end).then_some(run)
  }
}

impl ByteSource for RefsDataRunsDataSource {
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
        .ok_or_else(|| Error::invalid_range("refs read offset overflow"))?;
      let run = self.run_for_offset(absolute).ok_or_else(|| {
        Error::invalid_format("refs data run is missing for the requested offset")
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
            .ok_or_else(|| Error::invalid_range("refs physical read offset overflow"))?,
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

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities()
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::BytesDataSource;

  #[test]
  fn refs_data_source_handles_fragmented_random_reads() {
    let mut backing = vec![0u8; 16 * 1024];
    backing[4096..8192].fill(0x33);
    backing[12 * 1024..16 * 1024].fill(0x44);
    let source = RefsDataRunsDataSource {
      source: Arc::new(BytesDataSource::new(backing)),
      metadata_block_size: 4096,
      data_size: 8192,
      valid_data_size: 8192,
      data_runs: Arc::from(
        vec![
          RefsDataRun {
            logical_offset: 0,
            block_count: 1,
            physical_block_number: 1,
          },
          RefsDataRun {
            logical_offset: 4096,
            block_count: 1,
            physical_block_number: 3,
          },
        ]
        .into_boxed_slice(),
      ),
    };
    let mut buf = [0u8; 1024];

    let read = source.read_at(5120, &mut buf).unwrap();

    assert_eq!(read, buf.len());
    assert!(buf.iter().all(|byte| *byte == 0x44));
  }
}
