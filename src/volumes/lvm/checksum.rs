pub(super) fn weak_crc32(data: &[u8], initial: u32) -> u32 {
  let table = crc32_table();
  let mut checksum = initial;
  for byte in data {
    let table_index = ((checksum ^ (*byte as u32)) & 0xFF) as usize;
    checksum = table[table_index] ^ (checksum >> 8);
  }
  checksum
}

fn crc32_table() -> [u32; 256] {
  let mut table = [0u32; 256];
  for i in 0..256u32 {
    let mut value = i;
    for _ in 0..8 {
      if value & 1 != 0 {
        value = 0xEDB8_8320 ^ (value >> 1);
      } else {
        value >>= 1;
      }
    }
    table[i as usize] = value;
  }
  table
}
