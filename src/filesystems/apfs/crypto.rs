//! APFS encryption helpers.

use std::sync::Arc;

use aes::{
  Aes128, Aes256,
  cipher::{
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, consts::U16 as BlockU16,
    generic_array::GenericArray,
  },
};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha2::{Digest, Sha256};
use xts_mode::{Xts128, get_tweak_default};

use crate::{Error, Result};

const APFS_CRYPTO_SECTOR_SIZE: usize = 512;
const RFC3394_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;
const KEYBAG_HMAC_PREFIX: [u8; 6] = [0x01, 0x16, 0x20, 0x17, 0x15, 0x05];

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub(crate) struct ApfsXtsCipher {
  key: Arc<[u8]>,
}

impl ApfsXtsCipher {
  pub(crate) fn new(key: impl Into<Arc<[u8]>>) -> Result<Self> {
    let key = key.into();
    match key.len() {
      32 | 64 => Ok(Self { key }),
      length => Err(Error::invalid_format(format!(
        "apfs xts key length must be 32 or 64 bytes, got {length}"
      ))),
    }
  }

  pub(crate) fn decrypt(&self, sector_index: u64, data: &mut [u8]) -> Result<()> {
    if !data.len().is_multiple_of(APFS_CRYPTO_SECTOR_SIZE) {
      return Err(Error::invalid_format(
        "apfs encrypted data must be 512-byte aligned".to_string(),
      ));
    }

    match self.key.len() {
      32 => xts_decrypt::<Aes128>(&self.key, sector_index, data),
      64 => xts_decrypt::<Aes256>(&self.key, sector_index, data),
      _ => Err(Error::invalid_format(
        "apfs xts key length is invalid".to_string(),
      )),
    }
  }
}

pub(crate) fn verify_keybag_hmac(blob_der: &[u8], salt: &[u8], expected: &[u8]) -> Result<bool> {
  let mut digest = Sha256::new();
  digest.update(KEYBAG_HMAC_PREFIX);
  digest.update(salt);
  let key = digest.finalize();
  let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)
    .map_err(|_| Error::invalid_format("invalid apfs keybag hmac key"))?;
  mac.update(blob_der);
  Ok(mac.verify_slice(expected).is_ok())
}

pub(crate) fn derive_password_key(
  password: &str, salt: &[u8], iterations: u64,
) -> Result<[u8; 32]> {
  let iterations = u32::try_from(iterations)
    .map_err(|_| Error::invalid_range("apfs keybag iteration count exceeds u32"))?;
  Ok(pbkdf2_hmac_array::<Sha256, 32>(
    password.as_bytes(),
    salt,
    iterations,
  ))
}

pub(crate) fn aes_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
  if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) {
    return Err(Error::invalid_format(
      "apfs wrapped key length is invalid".to_string(),
    ));
  }

  match kek.len() {
    16 => aes_unwrap_inner::<Aes128>(kek, wrapped),
    32 => aes_unwrap_inner::<Aes256>(kek, wrapped),
    length => Err(Error::invalid_format(format!(
      "apfs KEK length must be 16 or 32 bytes, got {length}"
    ))),
  }
}

pub(crate) fn sha256_prefix(data: &[u8], prefix_len: usize) -> Result<Vec<u8>> {
  if prefix_len > 32 {
    return Err(Error::invalid_range(
      "apfs sha256 prefix length exceeds digest size".to_string(),
    ));
  }
  Ok(Sha256::digest(data)[..prefix_len].to_vec())
}

fn xts_decrypt<C>(key: &[u8], sector_index: u64, data: &mut [u8]) -> Result<()>
where
  C: BlockEncrypt
    + BlockDecrypt
    + BlockCipher
    + KeyInit
    + Clone
    + BlockSizeUser<BlockSize = BlockU16>, {
  let half = key.len() / 2;
  let cipher_1 = C::new_from_slice(&key[..half])
    .map_err(|_| Error::invalid_format("apfs xts key length does not match the AES mode"))?;
  let cipher_2 = C::new_from_slice(&key[half..])
    .map_err(|_| Error::invalid_format("apfs xts key length does not match the AES mode"))?;
  let xts = Xts128::<C>::new(cipher_1, cipher_2);

  for (index, sector) in data.chunks_exact_mut(APFS_CRYPTO_SECTOR_SIZE).enumerate() {
    let tweak = get_tweak_default(u128::from(
      sector_index
        .checked_add(index as u64)
        .ok_or_else(|| Error::invalid_range("apfs sector index overflow"))?,
    ));
    xts.decrypt_sector(sector, tweak);
  }

  Ok(())
}

fn aes_unwrap_inner<C>(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>>
where
  C: BlockDecrypt + KeyInit, {
  let cipher = C::new_from_slice(kek)
    .map_err(|_| Error::invalid_format("apfs KEK length does not match AES mode"))?;

  let n = wrapped.len() / 8 - 1;
  let mut registers = Vec::with_capacity(n + 1);
  registers.push([0u8; 8]);
  for index in 0..n {
    let mut value = [0u8; 8];
    value.copy_from_slice(&wrapped[(index + 1) * 8..(index + 2) * 8]);
    registers.push(value);
  }

  let mut a = [0u8; 8];
  a.copy_from_slice(&wrapped[..8]);

  for j in (0..=5).rev() {
    for i in (1..=n).rev() {
      let t = (n * j + i) as u64;
      let mut block = [0u8; 16];
      let a_xor = u64::from_be_bytes(a) ^ t;
      block[..8].copy_from_slice(&a_xor.to_be_bytes());
      block[8..].copy_from_slice(&registers[i]);

      let mut block_array = GenericArray::clone_from_slice(&block);
      cipher.decrypt_block(&mut block_array);
      block.copy_from_slice(&block_array);
      a.copy_from_slice(&block[..8]);
      registers[i].copy_from_slice(&block[8..]);
    }
  }

  if u64::from_be_bytes(a) != RFC3394_IV {
    return Err(Error::invalid_source_reference(
      "apfs wrapped key integrity verification failed".to_string(),
    ));
  }

  let mut result = Vec::with_capacity(n * 8);
  for register in registers.into_iter().skip(1) {
    result.extend_from_slice(&register);
  }
  Ok(result)
}
