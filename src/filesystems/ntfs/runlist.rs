//! NTFS non-resident runlist parsing and read mapping.

use std::sync::Arc;

use crate::{DataSource, DataSourceCapabilities, DataSourceHandle, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NtfsDataRun {
  pub logical_offset: u64,
  pub physical_offset: Option<u64>,
  pub length: u64,
}

pub(crate) fn parse_runlist(bytes: &[u8], cluster_size: u64) -> Result<Vec<NtfsDataRun>> {
  let mut runs = Vec::new();
  let mut cursor = 0usize;
  let mut logical_offset = 0u64;
  let mut current_cluster = 0i64;

  while cursor < bytes.len() {
    let header = bytes[cursor];
    cursor += 1;
    if header == 0 {
      break;
    }

    let cluster_count_size = usize::from(header & 0x0F);
    let cluster_delta_size = usize::from(header >> 4);
    if cluster_count_size == 0 {
      return Err(Error::InvalidFormat(
        "ntfs runlist element has a zero-sized cluster count".to_string(),
      ));
    }
    let element_size = cluster_count_size
      .checked_add(cluster_delta_size)
      .ok_or_else(|| Error::InvalidRange("ntfs runlist element size overflow".to_string()))?;
    if cursor
      .checked_add(element_size)
      .is_none_or(|end| end > bytes.len())
    {
      return Err(Error::InvalidFormat(
        "ntfs runlist element exceeds the encoded runlist".to_string(),
      ));
    }

    let cluster_count = decode_unsigned(&bytes[cursor..cursor + cluster_count_size]);
    if cluster_count == 0 {
      return Err(Error::InvalidFormat(
        "ntfs runlist element has a zero-length cluster span".to_string(),
      ));
    }
    cursor += cluster_count_size;

    let physical_offset = if cluster_delta_size == 0 {
      None
    } else {
      let delta = decode_signed(&bytes[cursor..cursor + cluster_delta_size])?;
      cursor += cluster_delta_size;
      current_cluster = current_cluster
        .checked_add(delta)
        .ok_or_else(|| Error::InvalidRange("ntfs runlist cluster delta overflow".to_string()))?;
      let cluster_number = u64::try_from(current_cluster).map_err(|_| {
        Error::InvalidFormat("ntfs runlist cluster number became negative".to_string())
      })?;
      Some(
        cluster_number
          .checked_mul(cluster_size)
          .ok_or_else(|| Error::InvalidRange("ntfs runlist offset overflow".to_string()))?,
      )
    };

    let length = cluster_count
      .checked_mul(cluster_size)
      .ok_or_else(|| Error::InvalidRange("ntfs runlist length overflow".to_string()))?;
    runs.push(NtfsDataRun {
      logical_offset,
      physical_offset,
      length,
    });
    logical_offset = logical_offset
      .checked_add(length)
      .ok_or_else(|| Error::InvalidRange("ntfs runlist logical offset overflow".to_string()))?;
  }

  Ok(runs)
}

pub(crate) struct NtfsNonResidentDataSource {
  source: DataSourceHandle,
  runs: Arc<[NtfsDataRun]>,
  size: u64,
  valid_size: u64,
}

impl NtfsNonResidentDataSource {
  pub fn new(
    source: DataSourceHandle, runs: Arc<[NtfsDataRun]>, size: u64, valid_size: u64,
  ) -> Self {
    Self {
      source,
      runs,
      size,
      valid_size,
    }
  }

  fn run_for_offset(&self, offset: u64) -> Option<&NtfsDataRun> {
    let index = self
      .runs
      .partition_point(|run| run.logical_offset <= offset)
      .checked_sub(1)?;
    let run = self.runs.get(index)?;
    let run_end = run.logical_offset.checked_add(run.length)?;

    (offset < run_end).then_some(run)
  }
}

impl DataSource for NtfsNonResidentDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.size || buf.is_empty() {
      return Ok(0);
    }

    let mut written = 0usize;
    let limit = usize::try_from(self.size - offset)
      .unwrap_or(usize::MAX)
      .min(buf.len());

    while written < limit {
      let absolute_offset = offset
        .checked_add(written as u64)
        .ok_or_else(|| Error::InvalidRange("ntfs non-resident read overflow".to_string()))?;
      let run = self.run_for_offset(absolute_offset).ok_or_else(|| {
        Error::InvalidFormat("ntfs runlist does not cover the requested offset".to_string())
      })?;
      let run_offset = absolute_offset - run.logical_offset;
      let chunk = usize::try_from(run.length - run_offset)
        .unwrap_or(usize::MAX)
        .min(limit - written);
      let valid_len = if absolute_offset >= self.valid_size {
        0
      } else {
        usize::try_from((self.valid_size - absolute_offset).min(chunk as u64)).unwrap_or(chunk)
      };

      if valid_len != 0 {
        if let Some(physical_offset) = run.physical_offset {
          self.source.read_exact_at(
            physical_offset
              .checked_add(run_offset)
              .ok_or_else(|| Error::InvalidRange("ntfs physical read overflow".to_string()))?,
            &mut buf[written..written + valid_len],
          )?;
        } else {
          buf[written..written + valid_len].fill(0);
        }
      }

      if valid_len < chunk {
        buf[written + valid_len..written + chunk].fill(0);
      }
      written += chunk;
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    self
      .source
      .capabilities()
      .with_preferred_chunk_size(usize::try_from(self.size.min(64 * 1024)).unwrap_or(64 * 1024))
  }

  fn telemetry_name(&self) -> &'static str {
    "filesystem.ntfs.nonresident_data_source"
  }
}

fn decode_unsigned(bytes: &[u8]) -> u64 {
  let mut value = 0u64;
  for (index, byte) in bytes.iter().enumerate() {
    value |= u64::from(*byte) << (index * 8);
  }
  value
}

fn decode_signed(bytes: &[u8]) -> Result<i64> {
  if bytes.is_empty() || bytes.len() > 8 {
    return Err(Error::InvalidFormat(
      "ntfs signed runlist values must be 1-8 bytes wide".to_string(),
    ));
  }

  let mut raw = [0u8; 8];
  raw[..bytes.len()].copy_from_slice(bytes);
  if bytes[bytes.len() - 1] & 0x80 != 0 {
    raw[bytes.len()..].fill(0xFF);
  }
  Ok(i64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::BytesDataSource;

  #[test]
  fn parses_sparse_runlists() {
    let runs = parse_runlist(&[0x11, 0x02, 0x04, 0x01, 0x02, 0x00], 4096).unwrap();

    assert_eq!(
      runs,
      vec![
        NtfsDataRun {
          logical_offset: 0,
          physical_offset: Some(16384),
          length: 8192,
        },
        NtfsDataRun {
          logical_offset: 8192,
          physical_offset: None,
          length: 8192,
        },
      ]
    );
  }

  #[test]
  fn nonresident_data_source_reads_sparse_regions_as_zeroes() {
    let data = BytesDataSource::new(Arc::<[u8]>::from(vec![0x41; 8192]));
    let source = NtfsNonResidentDataSource::new(
      Arc::new(data),
      Arc::from(
        vec![
          NtfsDataRun {
            logical_offset: 0,
            physical_offset: Some(0),
            length: 4096,
          },
          NtfsDataRun {
            logical_offset: 4096,
            physical_offset: None,
            length: 4096,
          },
        ]
        .into_boxed_slice(),
      ),
      8192,
      8192,
    );
    let mut buf = vec![0u8; 8192];

    let read = source.read_at(0, &mut buf).unwrap();
    assert_eq!(read, 8192);
    assert!(buf[..4096].iter().all(|byte| *byte == 0x41));
    assert!(buf[4096..].iter().all(|byte| *byte == 0));
  }

  #[test]
  fn nonresident_data_source_handles_fragmented_random_reads() {
    let mut backing = vec![0u8; 16 * 1024];
    backing[4096..8192].fill(0x11);
    backing[12 * 1024..16 * 1024].fill(0x22);
    let source = NtfsNonResidentDataSource::new(
      Arc::new(BytesDataSource::new(backing)),
      Arc::from(
        vec![
          NtfsDataRun {
            logical_offset: 0,
            physical_offset: Some(4096),
            length: 4096,
          },
          NtfsDataRun {
            logical_offset: 4096,
            physical_offset: Some(12 * 1024),
            length: 4096,
          },
        ]
        .into_boxed_slice(),
      ),
      8192,
      8192,
    );
    let mut buf = [0u8; 2048];

    let read = source.read_at(5120, &mut buf).unwrap();

    assert_eq!(read, buf.len());
    assert!(buf.iter().all(|byte| *byte == 0x22));
  }
}
