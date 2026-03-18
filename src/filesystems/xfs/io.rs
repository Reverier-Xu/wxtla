use crate::{DataSource, Error, Result};

pub(crate) fn read_exact_at(source: &dyn DataSource, offset: u64, size: usize) -> Result<Vec<u8>> {
  let mut buf = vec![0u8; size];
  source.read_exact_at(offset, &mut buf)?;
  Ok(buf)
}

pub(crate) fn read_slice(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
  data
    .get(offset..offset + size)
    .ok_or_else(|| Error::InvalidFormat("xfs slice out of bounds".to_string()))
}

pub(crate) fn be_u16(data: &[u8]) -> u16 {
  u16::from_be_bytes([data[0], data[1]])
}

pub(crate) fn be_u32(data: &[u8]) -> u32 {
  u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

pub(crate) fn be_u64(data: &[u8]) -> u64 {
  u64::from_be_bytes([
    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
  ])
}
