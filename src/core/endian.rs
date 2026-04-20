pub(crate) fn le_u16(data: &[u8]) -> u16 {
  let mut buf = [0u8; 2];
  buf.copy_from_slice(&data[..2]);
  u16::from_le_bytes(buf)
}

pub(crate) fn le_u32(data: &[u8]) -> u32 {
  let mut buf = [0u8; 4];
  buf.copy_from_slice(&data[..4]);
  u32::from_le_bytes(buf)
}

pub(crate) fn le_u64(data: &[u8]) -> u64 {
  let mut buf = [0u8; 8];
  buf.copy_from_slice(&data[..8]);
  u64::from_le_bytes(buf)
}

pub(crate) fn be_u16(data: &[u8]) -> u16 {
  let mut buf = [0u8; 2];
  buf.copy_from_slice(&data[..2]);
  u16::from_be_bytes(buf)
}

pub(crate) fn be_u32(data: &[u8]) -> u32 {
  let mut buf = [0u8; 4];
  buf.copy_from_slice(&data[..4]);
  u32::from_be_bytes(buf)
}

pub(crate) fn be_u64(data: &[u8]) -> u64 {
  let mut buf = [0u8; 8];
  buf.copy_from_slice(&data[..8]);
  u64::from_be_bytes(buf)
}

pub(crate) fn decode_utf16_le_string(data: &[u8]) -> Result<String, crate::Error> {
  let units = data
    .chunks_exact(2)
    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  String::from_utf16(&units)
    .map_err(|_| crate::Error::InvalidFormat("invalid UTF-16LE string".to_string()))
}

pub(crate) fn decode_utf16_be_string(data: &[u8]) -> Result<String, crate::Error> {
  let units = data
    .chunks_exact(2)
    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  String::from_utf16(&units)
    .map_err(|_| crate::Error::InvalidFormat("invalid UTF-16BE string".to_string()))
}
