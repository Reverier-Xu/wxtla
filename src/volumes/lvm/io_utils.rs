use crate::{ByteSource, Error, Result};

pub(super) fn read_fully_at(source: &dyn ByteSource, offset: u64, buf: &mut [u8]) -> Result<()> {
  source.read_exact_at(offset, buf)
}

pub(super) fn ascii_trim_end(data: &[u8]) -> String {
  let end = data
    .iter()
    .rposition(|byte| *byte != 0 && !byte.is_ascii_whitespace())
    .map(|index| index + 1)
    .unwrap_or(0);
  String::from_utf8_lossy(&data[..end]).to_string()
}

pub(super) fn le_u32(data: &[u8]) -> u32 {
  let mut buf = [0u8; 4];
  buf.copy_from_slice(&data[..4]);
  u32::from_le_bytes(buf)
}

pub(super) fn le_u64(data: &[u8]) -> u64 {
  let mut buf = [0u8; 8];
  buf.copy_from_slice(&data[..8]);
  u64::from_le_bytes(buf)
}

pub(super) fn unsupported(message: impl Into<String>) -> Error {
  Error::invalid_format(message.into())
}
