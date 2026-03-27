//! NTFS non-resident runlist parsing and read mapping.

use std::sync::Arc;

use crate::{ByteSource, ByteSourceCapabilities, ByteSourceHandle, Error, Result};

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
  source: ByteSourceHandle,
  runs: Arc<[NtfsDataRun]>,
  size: u64,
  valid_size: u64,
}

impl NtfsNonResidentDataSource {
  pub fn new(
    source: ByteSourceHandle, runs: Arc<[NtfsDataRun]>, size: u64, valid_size: u64,
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

impl ByteSource for NtfsNonResidentDataSource {
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

  fn capabilities(&self) -> ByteSourceCapabilities {
    self
      .source
      .capabilities()
      .with_preferred_chunk_size(usize::try_from(self.size.min(64 * 1024)).unwrap_or(64 * 1024))
  }

  fn telemetry_name(&self) -> &'static str {
    "filesystem.ntfs.nonresident_data_source"
  }
}

pub(crate) struct NtfsCompressedDataSource {
  source: ByteSourceHandle,
  runs: Arc<[NtfsDataRun]>,
  size: u64,
  valid_size: u64,
  cluster_size: u64,
  compression_unit_size: u64,
}

#[derive(Clone, Copy)]
struct NtfsUnitSegment {
  physical_offset: Option<u64>,
  length: u64,
}

impl NtfsCompressedDataSource {
  pub fn new(
    source: ByteSourceHandle, runs: Arc<[NtfsDataRun]>, size: u64, valid_size: u64,
    cluster_size: u64, compression_unit_size: u64,
  ) -> Self {
    Self {
      source,
      runs,
      size,
      valid_size,
      cluster_size,
      compression_unit_size,
    }
  }

  fn read_unit(&self, unit_index: u64) -> Result<Vec<u8>> {
    let unit_start = unit_index
      .checked_mul(self.compression_unit_size)
      .ok_or_else(|| Error::InvalidRange("ntfs compression-unit offset overflow".to_string()))?;
    let logical_size_u64 = (self.size - unit_start).min(self.compression_unit_size);
    if logical_size_u64 == 0 {
      return Ok(Vec::new());
    }

    let unit_end = unit_start
      .checked_add(self.compression_unit_size)
      .ok_or_else(|| Error::InvalidRange("ntfs compression-unit offset overflow".to_string()))?;
    let required_coverage_end = unit_start
      .checked_add(align_up(logical_size_u64, self.cluster_size)?)
      .ok_or_else(|| Error::InvalidRange("ntfs compression-unit range overflow".to_string()))?;
    let logical_size = usize::try_from(logical_size_u64)
      .map_err(|_| Error::InvalidRange("ntfs compressed unit is too large".to_string()))?;

    let (segments, covered_end) = self.collect_unit_segments(unit_start, unit_end)?;
    if covered_end < required_coverage_end {
      return Err(Error::InvalidFormat(
        "ntfs compressed runlist does not cover the requested compression unit".to_string(),
      ));
    }

    let has_sparse = segments
      .iter()
      .any(|segment| segment.physical_offset.is_none());
    let non_sparse_len = segments
      .iter()
      .filter(|segment| segment.physical_offset.is_some())
      .try_fold(0u64, |len, segment| {
        len
          .checked_add(segment.length)
          .ok_or_else(|| Error::InvalidRange("ntfs compressed unit length overflow".to_string()))
      })?;
    if non_sparse_len == 0 {
      return Ok(vec![0u8; logical_size]);
    }

    if has_sparse {
      if covered_end != unit_end {
        return Err(Error::InvalidFormat(
          "ntfs compressed unit does not cover the full compression range".to_string(),
        ));
      }

      let stored = self.read_segments(&segments, false)?;
      let mut unit = decompress_lznt1(&stored)?;
      if unit.len() < logical_size {
        return Err(Error::InvalidFormat(
          "ntfs compressed unit expanded shorter than the logical stream size".to_string(),
        ));
      }
      unit.truncate(logical_size);
      return Ok(unit);
    }

    if covered_end != unit_end && logical_size_u64 == self.compression_unit_size {
      return Err(Error::InvalidFormat(
        "ntfs uncompressed compression unit does not cover the full logical range".to_string(),
      ));
    }

    let mut unit = self.read_segments(&segments, true)?;
    if unit.len() < logical_size {
      return Err(Error::InvalidFormat(
        "ntfs compression-unit storage is shorter than the logical stream size".to_string(),
      ));
    }
    unit.truncate(logical_size);
    Ok(unit)
  }

  fn collect_unit_segments(
    &self, unit_start: u64, unit_end: u64,
  ) -> Result<(Vec<NtfsUnitSegment>, u64)> {
    let start_index = self
      .runs
      .partition_point(|run| run.logical_offset.saturating_add(run.length) <= unit_start);
    let mut segments = Vec::new();
    let mut cursor = unit_start;

    for run in &self.runs[start_index..] {
      if run.logical_offset >= unit_end {
        break;
      }

      let run_end = run
        .logical_offset
        .checked_add(run.length)
        .ok_or_else(|| Error::InvalidRange("ntfs run logical range overflow".to_string()))?;
      if run_end <= cursor {
        continue;
      }

      let overlap_start = cursor.max(run.logical_offset);
      if overlap_start > cursor {
        break;
      }

      let overlap_end = run_end.min(unit_end);
      let physical_offset = run.physical_offset.map(|offset| {
        offset
          .checked_add(overlap_start - run.logical_offset)
          .ok_or_else(|| Error::InvalidRange("ntfs compressed run offset overflow".to_string()))
      });
      segments.push(NtfsUnitSegment {
        physical_offset: physical_offset.transpose()?,
        length: overlap_end - overlap_start,
      });
      cursor = overlap_end;
      if cursor == unit_end {
        break;
      }
    }

    Ok((segments, cursor))
  }

  fn read_segments(&self, segments: &[NtfsUnitSegment], include_sparse: bool) -> Result<Vec<u8>> {
    let total_len = segments.iter().try_fold(0usize, |len, segment| {
      let segment_len = usize::try_from(segment.length).map_err(|_| {
        Error::InvalidRange("ntfs compressed unit segment is too large".to_string())
      })?;
      if segment.physical_offset.is_none() && !include_sparse {
        return Ok(len);
      }
      len
        .checked_add(segment_len)
        .ok_or_else(|| Error::InvalidRange("ntfs compressed unit buffer overflow".to_string()))
    })?;
    let mut bytes = Vec::with_capacity(total_len);

    for segment in segments {
      let segment_len = usize::try_from(segment.length).map_err(|_| {
        Error::InvalidRange("ntfs compressed unit segment is too large".to_string())
      })?;
      if let Some(physical_offset) = segment.physical_offset {
        let start = bytes.len();
        let end = start
          .checked_add(segment_len)
          .ok_or_else(|| Error::InvalidRange("ntfs compressed unit buffer overflow".to_string()))?;
        bytes.resize(end, 0);
        self
          .source
          .read_exact_at(physical_offset, &mut bytes[start..end])?;
      } else if include_sparse {
        let end = bytes
          .len()
          .checked_add(segment_len)
          .ok_or_else(|| Error::InvalidRange("ntfs compressed unit buffer overflow".to_string()))?;
        bytes.resize(end, 0);
      }
    }

    Ok(bytes)
  }
}

impl ByteSource for NtfsCompressedDataSource {
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
        .ok_or_else(|| Error::InvalidRange("ntfs compressed read overflow".to_string()))?;
      let unit_index = absolute_offset / self.compression_unit_size;
      let unit_start = unit_index
        .checked_mul(self.compression_unit_size)
        .ok_or_else(|| Error::InvalidRange("ntfs compression-unit offset overflow".to_string()))?;
      let unit = self.read_unit(unit_index)?;
      let within_unit = usize::try_from(absolute_offset - unit_start)
        .map_err(|_| Error::InvalidRange("ntfs compressed unit offset is too large".to_string()))?;
      if within_unit >= unit.len() {
        return Err(Error::InvalidFormat(
          "ntfs compressed unit does not cover the requested offset".to_string(),
        ));
      }

      let chunk = (unit.len() - within_unit).min(limit - written);
      let valid_len = if absolute_offset >= self.valid_size {
        0
      } else {
        usize::try_from((self.valid_size - absolute_offset).min(chunk as u64)).unwrap_or(chunk)
      };
      if valid_len != 0 {
        buf[written..written + valid_len]
          .copy_from_slice(&unit[within_unit..within_unit + valid_len]);
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

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities().with_preferred_chunk_size(
      usize::try_from(self.compression_unit_size.min(64 * 1024)).unwrap_or(64 * 1024),
    )
  }

  fn telemetry_name(&self) -> &'static str {
    "filesystem.ntfs.compressed_data_source"
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

fn align_up(value: u64, alignment: u64) -> Result<u64> {
  if value == 0 {
    return Ok(0);
  }

  let remainder = value % alignment;
  if remainder == 0 {
    Ok(value)
  } else {
    value
      .checked_add(alignment - remainder)
      .ok_or_else(|| Error::InvalidRange("ntfs alignment overflow".to_string()))
  }
}

fn decompress_lznt1(bytes: &[u8]) -> Result<Vec<u8>> {
  let mut cursor = 0usize;
  let mut output = Vec::new();

  while cursor + 2 <= bytes.len() {
    let chunk_output_start = output.len();
    let chunk_start = cursor;
    let header = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
    if header == 0 {
      break;
    }
    cursor += 2;

    let payload_size = usize::from(header & 0x0FFF);
    let chunk_end = chunk_start
      .checked_add(payload_size)
      .and_then(|offset| offset.checked_add(3))
      .ok_or_else(|| Error::InvalidRange("ntfs lznt1 block range overflow".to_string()))?;
    if chunk_end > bytes.len() {
      return Err(Error::InvalidFormat(
        "ntfs lznt1 block exceeds the available compressed bytes".to_string(),
      ));
    }

    if header & 0x8000 != 0 {
      while cursor < chunk_end {
        let mut tag = bytes[cursor];
        cursor += 1;

        for _ in 0..8 {
          if cursor >= chunk_end {
            break;
          }

          if tag & 1 == 0 {
            output.push(bytes[cursor]);
            cursor += 1;
          } else {
            if cursor + 2 > chunk_end {
              return Err(Error::InvalidFormat(
                "ntfs lznt1 back-reference is truncated".to_string(),
              ));
            }

            let pointer = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
            cursor += 2;
            let relative_output_offset = output
              .len()
              .checked_sub(chunk_output_start)
              .and_then(|offset| offset.checked_sub(1))
              .ok_or_else(|| {
                Error::InvalidFormat(
                  "ntfs lznt1 back-reference appears before any literal data".to_string(),
                )
              })?;
            let displacement = lznt1_displacement(relative_output_offset);
            let symbol_offset = usize::from(pointer >> (12 - u32::from(displacement))) + 1;
            let symbol_length = usize::from(pointer & (0x0FFFu16 >> displacement)) + 3;
            let start_offset = output.len().checked_sub(symbol_offset).ok_or_else(|| {
              Error::InvalidFormat(
                "ntfs lznt1 back-reference exceeds the decompressed output".to_string(),
              )
            })?;

            for copy_index in 0..symbol_length {
              let source_index = start_offset.checked_add(copy_index).ok_or_else(|| {
                Error::InvalidRange("ntfs lznt1 back-reference overflow".to_string())
              })?;
              let byte = *output.get(source_index).ok_or_else(|| {
                Error::InvalidFormat(
                  "ntfs lznt1 back-reference exceeds the decompressed output".to_string(),
                )
              })?;
              output.push(byte);
            }
          }

          tag >>= 1;
        }
      }
    } else {
      output.extend_from_slice(&bytes[cursor..chunk_end]);
      cursor = chunk_end;
    }
  }

  Ok(output)
}

fn lznt1_displacement(offset: usize) -> u8 {
  let mut result = 0u8;
  let mut offset = offset;
  while offset >= 0x10 {
    offset >>= 1;
    result = result.saturating_add(1);
  }
  result
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

  #[test]
  fn decompresses_lznt1_back_references() {
    let compressed = [0x05, 0xB0, 0x08, b'A', b'B', b'C', 0x06, 0x20];

    let decompressed = decompress_lznt1(&compressed).unwrap();

    assert_eq!(decompressed, b"ABCABCABCABC");
  }

  #[test]
  fn compressed_data_source_reads_lznt1_units() {
    let mut backing = vec![0u8; 2 * 4096];
    backing[4096..4104].copy_from_slice(&[0x05, 0xB0, 0x08, b'A', b'B', b'C', 0x06, 0x20]);
    let source = NtfsCompressedDataSource::new(
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
            physical_offset: None,
            length: 15 * 4096,
          },
        ]
        .into_boxed_slice(),
      ),
      12,
      12,
      4096,
      16 * 4096,
    );

    assert_eq!(source.read_all().unwrap(), b"ABCABCABCABC");
  }
}
