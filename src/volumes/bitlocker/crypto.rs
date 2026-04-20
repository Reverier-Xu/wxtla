//! BitLocker key derivation and sector cryptography.

use aes::{
  Aes128, Aes256,
  cipher::{
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, consts::U16 as BlockU16,
    generic_array::GenericArray,
  },
};
use ccm::{
  Ccm,
  aead::{
    AeadInPlace,
    consts::{U12, U16},
  },
};
use sha2::{Digest, Sha256};
use xts_mode::{Xts128, get_tweak_default};

use super::metadata::BitlockerEncryptionMethod;
use crate::{Error, Result};

type Aes256Ccm = Ccm<Aes256, U16, U12>;

pub(super) fn password_hash(password: &str) -> [u8; 32] {
  let utf16le = password
    .encode_utf16()
    .chain(std::iter::once(0))
    .flat_map(u16::to_le_bytes)
    .collect::<Vec<_>>();
  let first = Sha256::digest(&utf16le);
  let second = Sha256::digest(first);
  second.into()
}

pub(super) fn recovery_password_hash(recovery_password: &str) -> Result<[u8; 32]> {
  let segments = recovery_password.split('-').collect::<Vec<_>>();
  if segments.len() != 8 {
    return Err(Error::invalid_source_reference(
      "bitlocker recovery passwords must contain 8 numeric groups".to_string(),
    ));
  }

  let mut binary = [0u8; 16];
  for (index, segment) in segments.iter().enumerate() {
    let value = segment.parse::<u64>().map_err(|_| {
      Error::invalid_source_reference(
        "bitlocker recovery passwords must be decimal numbers".to_string(),
      )
    })?;
    if value % 11 != 0 {
      return Err(Error::invalid_source_reference(
        "bitlocker recovery password groups must be divisible by 11".to_string(),
      ));
    }
    let decoded = value / 11;
    let decoded = u16::try_from(decoded).map_err(|_| {
      Error::invalid_source_reference(
        "bitlocker recovery password groups are out of range".to_string(),
      )
    })?;
    binary[index * 2..index * 2 + 2].copy_from_slice(&decoded.to_le_bytes());
  }

  Ok(Sha256::digest(binary).into())
}

pub(super) fn password_aes_ccm_key(password_hash: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
  let mut last_hash = [0u8; 32];
  for iteration_count in 0..0x0FFFFFu64 {
    let mut state = [0u8; 88];
    state[0..32].copy_from_slice(&last_hash);
    state[32..64].copy_from_slice(password_hash);
    state[64..80].copy_from_slice(salt);
    state[80..88].copy_from_slice(&iteration_count.to_le_bytes());
    last_hash.copy_from_slice(&Sha256::digest(state));
  }

  let mut state = [0u8; 88];
  state[0..32].copy_from_slice(&last_hash);
  state[32..64].copy_from_slice(password_hash);
  state[64..80].copy_from_slice(salt);
  state[80..88].copy_from_slice(&(0x0FFFFFu64).to_le_bytes());
  Sha256::digest(state).into()
}

pub(super) fn decrypt_aes_ccm_key_blob(
  aes_ccm_key: &[u8; 32], nonce: &[u8; 12], encrypted: &[u8],
) -> Result<Vec<u8>> {
  if encrypted.len() < 16 {
    return Err(Error::invalid_format(
      "bitlocker AES-CCM key blobs must include a 16-byte authentication tag".to_string(),
    ));
  }

  let cipher = Aes256Ccm::new_from_slice(aes_ccm_key)
    .map_err(|_| Error::invalid_format("bitlocker AES-CCM key size is invalid"))?;
  let tag = &encrypted[..16];
  let mut ciphertext = encrypted[16..].to_vec();
  let tag = GenericArray::from_slice(tag);
  cipher
    .decrypt_in_place_detached(nonce.into(), b"", &mut ciphertext, tag)
    .map_err(|_| Error::invalid_source_reference("bitlocker key decryption failed"))?;

  let mut output = Vec::with_capacity(encrypted.len());
  output.extend_from_slice(&encrypted[..16]);
  output.extend_from_slice(&ciphertext);
  Ok(output)
}

pub(super) fn decrypt_sector(
  method: BitlockerEncryptionMethod, fvek: &[u8], tweak_key: Option<&[u8]>, block_key: u64,
  data: &mut [u8],
) -> Result<()> {
  match method {
    BitlockerEncryptionMethod::None => Ok(()),
    BitlockerEncryptionMethod::Aes128Cbc => aes_cbc_crypt::<Aes128>(false, fvek, block_key, data),
    BitlockerEncryptionMethod::Aes256Cbc => aes_cbc_crypt::<Aes256>(false, fvek, block_key, data),
    BitlockerEncryptionMethod::Aes128CbcDiffuser => {
      aes_cbc_crypt::<Aes128>(false, fvek, block_key, data)?;
      let tweak = tweak_key.ok_or_else(|| {
        Error::invalid_format("bitlocker diffuser encryption requires a tweak key")
      })?;
      diffuser_apply::<Aes128>(false, tweak, block_key, data)
    }
    BitlockerEncryptionMethod::Aes256CbcDiffuser => {
      aes_cbc_crypt::<Aes256>(false, fvek, block_key, data)?;
      let tweak = tweak_key.ok_or_else(|| {
        Error::invalid_format("bitlocker diffuser encryption requires a tweak key")
      })?;
      diffuser_apply::<Aes256>(false, tweak, block_key, data)
    }
    BitlockerEncryptionMethod::Aes128Xts => xts_crypt::<Aes128>(false, fvek, block_key, data),
    BitlockerEncryptionMethod::Aes256Xts => xts_crypt::<Aes256>(false, fvek, block_key, data),
  }
}

#[cfg(test)]
pub(super) fn encrypt_sector(
  method: BitlockerEncryptionMethod, fvek: &[u8], tweak_key: Option<&[u8]>, block_key: u64,
  data: &mut [u8],
) -> Result<()> {
  match method {
    BitlockerEncryptionMethod::None => Ok(()),
    BitlockerEncryptionMethod::Aes128Cbc => aes_cbc_crypt::<Aes128>(true, fvek, block_key, data),
    BitlockerEncryptionMethod::Aes256Cbc => aes_cbc_crypt::<Aes256>(true, fvek, block_key, data),
    BitlockerEncryptionMethod::Aes128CbcDiffuser => {
      let tweak = tweak_key.ok_or_else(|| {
        Error::invalid_format("bitlocker diffuser encryption requires a tweak key")
      })?;
      diffuser_apply::<Aes128>(true, tweak, block_key, data)?;
      aes_cbc_crypt::<Aes128>(true, fvek, block_key, data)
    }
    BitlockerEncryptionMethod::Aes256CbcDiffuser => {
      let tweak = tweak_key.ok_or_else(|| {
        Error::invalid_format("bitlocker diffuser encryption requires a tweak key")
      })?;
      diffuser_apply::<Aes256>(true, tweak, block_key, data)?;
      aes_cbc_crypt::<Aes256>(true, fvek, block_key, data)
    }
    BitlockerEncryptionMethod::Aes128Xts => xts_crypt::<Aes128>(true, fvek, block_key, data),
    BitlockerEncryptionMethod::Aes256Xts => xts_crypt::<Aes256>(true, fvek, block_key, data),
  }
}

fn aes_cbc_crypt<C>(encrypt: bool, key: &[u8], block_key: u64, data: &mut [u8]) -> Result<()>
where
  C: BlockEncrypt + BlockDecrypt + KeyInit + BlockSizeUser<BlockSize = BlockU16>, {
  if !data.len().is_multiple_of(16) {
    return Err(Error::invalid_format(
      "bitlocker AES-CBC sectors must be aligned to 16-byte blocks".to_string(),
    ));
  }
  let cipher = C::new_from_slice(key)
    .map_err(|_| Error::invalid_format("bitlocker FVEK length does not match the AES mode"))?;
  let mut iv_block = [0u8; 16];
  iv_block[..8].copy_from_slice(&block_key.to_le_bytes());
  let iv = encrypt_block_ecb(&cipher, iv_block);
  let mut prev = iv;

  for block in data.chunks_exact_mut(16) {
    let mut array = GenericArray::clone_from_slice(block);
    if encrypt {
      xor_in_place(block, &prev);
      array.copy_from_slice(block);
      cipher.encrypt_block(&mut array);
      block.copy_from_slice(&array);
      prev.copy_from_slice(block);
    } else {
      let mut current_ciphertext = [0u8; 16];
      current_ciphertext.copy_from_slice(block);
      cipher.decrypt_block(&mut array);
      let mut plaintext = [0u8; 16];
      plaintext.copy_from_slice(&array);
      xor_in_place(&mut plaintext, &prev);
      block.copy_from_slice(&plaintext);
      prev = current_ciphertext;
    }
  }

  Ok(())
}

fn xts_crypt<C>(encrypt: bool, key: &[u8], sector_index: u64, data: &mut [u8]) -> Result<()>
where
  C: BlockEncrypt
    + BlockDecrypt
    + BlockCipher
    + KeyInit
    + Clone
    + BlockSizeUser<BlockSize = BlockU16>, {
  let half = key.len() / 2;
  let cipher_1 = C::new_from_slice(&key[..half])
    .map_err(|_| Error::invalid_format("bitlocker XTS key length does not match the AES mode"))?;
  let cipher_2 = C::new_from_slice(&key[half..])
    .map_err(|_| Error::invalid_format("bitlocker XTS key length does not match the AES mode"))?;
  let xts = Xts128::<C>::new(cipher_1, cipher_2);
  if encrypt {
    xts.encrypt_sector(data, get_tweak_default(u128::from(sector_index)));
  } else {
    xts.decrypt_sector(data, get_tweak_default(u128::from(sector_index)));
  }
  Ok(())
}

fn diffuser_apply<C>(
  encrypt: bool, tweak_key: &[u8], block_key: u64, data: &mut [u8],
) -> Result<()>
where
  C: BlockEncrypt + KeyInit + BlockSizeUser<BlockSize = BlockU16>, {
  if !data.len().is_multiple_of(4) || data.len() < 32 {
    return Err(Error::invalid_format(
      "bitlocker diffuser blocks must be at least 32 bytes and 4-byte aligned".to_string(),
    ));
  }

  let cipher = C::new_from_slice(tweak_key)
    .map_err(|_| Error::invalid_format("bitlocker tweak key length does not match the AES mode"))?;
  let mut first_input = [0u8; 16];
  first_input[..8].copy_from_slice(&block_key.to_le_bytes());
  let first = encrypt_block_ecb(&cipher, first_input);
  let mut second_input = first_input;
  second_input[15] = 0x80;
  let second = encrypt_block_ecb(&cipher, second_input);
  let mut sector_key = [0u8; 32];
  sector_key[..16].copy_from_slice(&first);
  sector_key[16..].copy_from_slice(&second);

  if encrypt {
    xor_repeat(data, &sector_key);
    diffuser_encrypt(data);
  } else {
    diffuser_decrypt(data);
    xor_repeat(data, &sector_key);
  }

  Ok(())
}

fn encrypt_block_ecb<C>(cipher: &C, input: [u8; 16]) -> [u8; 16]
where
  C: BlockEncrypt + BlockSizeUser<BlockSize = BlockU16>, {
  let mut block = GenericArray::clone_from_slice(&input);
  cipher.encrypt_block(&mut block);
  let mut output = [0u8; 16];
  output.copy_from_slice(&block);
  output
}

fn xor_repeat(data: &mut [u8], key: &[u8; 32]) {
  for (index, byte) in data.iter_mut().enumerate() {
    *byte ^= key[index % 32];
  }
}

fn xor_in_place(left: &mut [u8], right: &[u8]) {
  for (l, r) in left.iter_mut().zip(right.iter()) {
    *l ^= *r;
  }
}

fn diffuser_decrypt(data: &mut [u8]) {
  let mut values = data
    .chunks_exact(4)
    .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
    .collect::<Vec<_>>();
  diffuser_b_decrypt(&mut values);
  diffuser_a_decrypt(&mut values);
  for (chunk, value) in data.chunks_exact_mut(4).zip(values) {
    chunk.copy_from_slice(&value.to_le_bytes());
  }
}

fn diffuser_encrypt(data: &mut [u8]) {
  let mut values = data
    .chunks_exact(4)
    .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
    .collect::<Vec<_>>();
  diffuser_a_encrypt(&mut values);
  diffuser_b_encrypt(&mut values);
  for (chunk, value) in data.chunks_exact_mut(4).zip(values) {
    chunk.copy_from_slice(&value.to_le_bytes());
  }
}

fn diffuser_a_decrypt(values: &mut [u32]) {
  let n = values.len();
  for _ in 0..5 {
    let mut i1 = 0usize;
    let mut i2 = n - 2;
    let mut i3 = n - 5;
    while i1 < n - 1 {
      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3].rotate_left(9));
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;

      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3]);
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;

      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3].rotate_left(13));
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;

      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3]);
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;
    }
  }
}

fn diffuser_b_decrypt(values: &mut [u32]) {
  let n = values.len();
  for _ in 0..3 {
    let mut i1 = 0usize;
    let mut i2 = n - 2;
    let mut i3 = n - 3;
    while i1 < n - 1 {
      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3].rotate_left(13));
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;

      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3]);
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;

      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3].rotate_left(10));
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;

      values[i1] = values[i1].wrapping_add(values[i2] ^ values[i3]);
      i1 += 1;
      i2 = (i2 + 1) % n;
      i3 = (i3 + 1) % n;
    }
  }
}

fn diffuser_a_encrypt(values: &mut [u32]) {
  let n = values.len();
  for _ in 0..5 {
    let mut i1 = n - 1;
    let mut i2 = n - 2;
    let mut i3 = n - 5;
    while i1 > 0 {
      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3]);
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);

      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3].rotate_left(13));
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);

      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3]);
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);

      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3].rotate_left(9));
      if i1 == 0 {
        break;
      }
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);
    }
  }
}

fn diffuser_b_encrypt(values: &mut [u32]) {
  let n = values.len();
  for _ in 0..3 {
    let mut i1 = n - 1;
    let mut i2 = n - 2;
    let mut i3 = n - 3;
    while i1 > 0 {
      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3]);
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);

      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3].rotate_left(10));
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);

      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3]);
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);

      values[i1] = values[i1].wrapping_sub(values[i2] ^ values[i3].rotate_left(13));
      if i1 == 0 {
        break;
      }
      i1 -= 1;
      i2 = dec_index(i2, n);
      i3 = dec_index(i3, n);
    }
  }
}

fn dec_index(index: usize, len: usize) -> usize {
  if index == 0 { len - 1 } else { index - 1 }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn to_hex(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
      use std::fmt::Write as _;
      let _ = write!(&mut output, "{byte:02x}");
    }
    output
  }

  #[test]
  fn derives_password_hash_like_libbde() {
    assert_eq!(
      to_hex(&password_hash("TeSt")),
      "f8559b5acf ab5409c126e8ac8a5939bffaa893f62ae8373b689ceea64bd47569".replace(' ', "")
    );
  }

  #[test]
  fn derives_recovery_password_hash() {
    let hash =
      recovery_password_hash("471207-278498-422125-177177-561902-537405-468006-693451").unwrap();
    assert_eq!(
      to_hex(&hash),
      "a4c9244478110805015c94d1b001a933ada2ab0b716bac342bb86c844b63491f"
    );
  }

  #[test]
  fn derives_password_aes_ccm_key() {
    let password_hash = password_hash("TeSt");
    let salt: [u8; 16] = [
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
      0xFF,
    ];
    let key = password_aes_ccm_key(&password_hash, &salt);
    assert_eq!(
      to_hex(&key),
      "241eddbf84a8f855da22ef18995a8e841c93ae93e4e5f3f90ace59b19c698188"
    );
  }
}
