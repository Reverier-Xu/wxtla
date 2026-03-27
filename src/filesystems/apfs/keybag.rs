//! APFS keybag parsing and software-unlock helpers.

use std::{collections::HashMap, sync::Arc};

use super::{
  container::read_blocks,
  crypto::{ApfsXtsCipher, aes_unwrap, derive_password_key, sha256_prefix, verify_keybag_hmac},
  ondisk::{
    APFS_FS_ONEKEY, APFS_FS_PFK, APFS_FS_UNENCRYPTED, APFS_OBJECT_TYPE_CONTAINER_KEYBAG,
    APFS_OBJECT_TYPE_VOLUME_KEYBAG, ApfsObjectHeader, ApfsPrange, read_u16_le, read_u32_le,
  },
};
use crate::{ByteSource, ByteSourceHandle, Credential, Error, Result};

const KEYBAG_ENTRY_HEADER_SIZE: usize = 24;
const KEYBAG_VERSION: u16 = 2;

const KB_TAG_VOLUME_KEY: u16 = 2;
const KB_TAG_VOLUME_UNLOCK_RECORDS: u16 = 3;
const KB_TAG_VOLUME_PASSPHRASE_HINT: u16 = 4;

const KEK_FLAG_CORESTORAGE_COMPAT: u32 = 0x0000_0002;

#[derive(Clone)]
pub(crate) struct ApfsUnlockState {
  pub cipher: Arc<ApfsXtsCipher>,
  pub password_hint: Option<String>,
}

#[derive(Debug, Clone)]
struct ApfsKeybagEntry {
  uuid: [u8; 16],
  tag: u16,
  data: Arc<[u8]>,
}

#[derive(Debug, Clone)]
struct ApfsContainerKeybag {
  entries: HashMap<([u8; 16], u16), ApfsKeybagEntry>,
}

#[derive(Debug, Clone)]
struct ApfsVolumeKeybag {
  entries: Vec<ApfsKeybagEntry>,
}

#[derive(Debug, Clone)]
struct ApfsKek {
  blob_der: Arc<[u8]>,
  hmac: Arc<[u8]>,
  salt: Arc<[u8]>,
  flags: u32,
  wrapped: Arc<[u8]>,
  iterations: u64,
  wrapped_salt: Arc<[u8]>,
}

#[derive(Debug, Clone)]
struct ApfsVek {
  blob_der: Arc<[u8]>,
  hmac: Arc<[u8]>,
  salt: Arc<[u8]>,
  uuid: [u8; 16],
  flags: u32,
  wrapped: Arc<[u8]>,
}

#[derive(Debug, Clone, Copy)]
struct DerTag {
  class: u8,
  constructed: bool,
  number: u8,
}

#[derive(Debug, Clone, Copy)]
struct DerTlv<'a> {
  tag: DerTag,
  value: &'a [u8],
  full: &'a [u8],
}

pub(crate) fn unlock_volume(
  source: ByteSourceHandle, block_size: u32, container_uuid: [u8; 16],
  container_keybag_prange: Option<ApfsPrange>, volume_uuid: [u8; 16], volume_flags: u64,
  credentials: &[Credential<'_>],
) -> Result<ApfsUnlockState> {
  if (volume_flags & APFS_FS_UNENCRYPTED) != 0 || (volume_flags & APFS_FS_PFK) != 0 {
    return Err(Error::InvalidSourceReference(
      "apfs volume does not require software password unlock".to_string(),
    ));
  }
  if (volume_flags & APFS_FS_ONEKEY) == 0 {
    return Err(Error::Unsupported(
      "apfs multi-key software encryption is not implemented yet".to_string(),
    ));
  }

  let container_keybag_prange = container_keybag_prange.ok_or_else(|| {
    Error::InvalidSourceReference("apfs container does not expose a software keybag".to_string())
  })?;

  if let Some(key) = credential_keys(credentials).next() {
    return Ok(ApfsUnlockState {
      cipher: Arc::new(ApfsXtsCipher::new(Arc::<[u8]>::from(
        key.to_vec().into_boxed_slice(),
      ))?),
      password_hint: None,
    });
  }

  let container_keybag_cipher = ApfsXtsCipher::new(Arc::<[u8]>::from(
    container_uuid
      .iter()
      .copied()
      .chain(container_uuid)
      .collect::<Vec<_>>()
      .into_boxed_slice(),
  ))?;
  let container_keybag = read_container_keybag(
    source.as_ref(),
    block_size,
    container_keybag_prange,
    &container_keybag_cipher,
  )?;
  let vek = container_keybag.vek(volume_uuid)?.ok_or_else(|| {
    Error::InvalidSourceReference("apfs volume encryption key is missing".to_string())
  })?;
  vek.verify()?;

  let volume_keybag_prange = container_keybag
    .volume_keybag_prange(volume_uuid)?
    .ok_or_else(|| {
      Error::InvalidSourceReference("apfs volume keybag extent is missing".to_string())
    })?;
  let volume_keybag_cipher = ApfsXtsCipher::new(Arc::<[u8]>::from(
    volume_uuid
      .iter()
      .copied()
      .chain(volume_uuid)
      .collect::<Vec<_>>()
      .into_boxed_slice(),
  ))?;
  let volume_keybag = read_volume_keybag(
    source.as_ref(),
    block_size,
    volume_keybag_prange,
    &volume_keybag_cipher,
  )?;
  let password_hint = volume_keybag.password_hint(volume_uuid)?;

  for secret in credential_passwords(credentials) {
    for kek in volume_keybag.keks() {
      let Ok(kek) = kek else {
        continue;
      };
      if kek.verify()? {
        let Ok(unwrapped_kek) = kek.unwrap(secret) else {
          continue;
        };
        let Ok(vek_bytes) = vek.unwrap(&unwrapped_kek) else {
          continue;
        };
        return Ok(ApfsUnlockState {
          cipher: Arc::new(ApfsXtsCipher::new(Arc::<[u8]>::from(
            vek_bytes.into_boxed_slice(),
          ))?),
          password_hint,
        });
      }
    }
  }

  Err(Error::InvalidSourceReference(
    "failed to unlock apfs volume with the provided credentials".to_string(),
  ))
}

fn read_container_keybag(
  source: &dyn ByteSource, block_size: u32, prange: ApfsPrange, decryptor: &ApfsXtsCipher,
) -> Result<ApfsContainerKeybag> {
  let bytes = read_keybag_object(
    source,
    block_size,
    prange.start_paddr,
    prange.block_count,
    decryptor,
    APFS_OBJECT_TYPE_CONTAINER_KEYBAG,
  )?;
  ApfsContainerKeybag::parse(&bytes)
}

fn read_volume_keybag(
  source: &dyn ByteSource, block_size: u32, prange: ApfsPrange, decryptor: &ApfsXtsCipher,
) -> Result<ApfsVolumeKeybag> {
  let bytes = read_keybag_object(
    source,
    block_size,
    prange.start_paddr,
    prange.block_count,
    decryptor,
    APFS_OBJECT_TYPE_VOLUME_KEYBAG,
  )?;
  ApfsVolumeKeybag::parse(&bytes)
}

fn read_keybag_object(
  source: &dyn ByteSource, block_size: u32, address: u64, block_count: u64,
  decryptor: &ApfsXtsCipher, expected_type: u32,
) -> Result<Vec<u8>> {
  let encrypted = read_blocks(source, block_size, address, block_count)?;
  if keybag_object_matches(&encrypted, expected_type) {
    return Ok(encrypted);
  }

  let mut decrypted = encrypted.clone();
  let sectors_per_block = u64::from(block_size / 512);
  decryptor.decrypt(
    address
      .checked_mul(sectors_per_block)
      .ok_or_else(|| Error::InvalidRange("apfs keybag sector index overflow".to_string()))?,
    &mut decrypted,
  )?;
  if !keybag_object_matches(&decrypted, expected_type) {
    return Err(Error::InvalidFormat(
      "apfs decrypted keybag does not match the expected object type".to_string(),
    ));
  }
  Ok(decrypted)
}

fn keybag_object_matches(bytes: &[u8], expected_type: u32) -> bool {
  let Ok(header) = ApfsObjectHeader::parse(bytes) else {
    return false;
  };
  (header.object_type == expected_type || header.type_code() == expected_type)
    && header.validate_checksum(bytes)
}

impl ApfsContainerKeybag {
  fn parse(bytes: &[u8]) -> Result<Self> {
    let entries = parse_keybag_entries(bytes)?
      .into_iter()
      .map(|entry| ((entry.uuid, entry.tag), entry))
      .collect();
    Ok(Self { entries })
  }

  fn volume_keybag_prange(&self, volume_uuid: [u8; 16]) -> Result<Option<ApfsPrange>> {
    let Some(entry) = self
      .entries
      .get(&(volume_uuid, KB_TAG_VOLUME_UNLOCK_RECORDS))
    else {
      return Ok(None);
    };
    Ok(Some(ApfsPrange::parse(&entry.data)?))
  }

  fn vek(&self, volume_uuid: [u8; 16]) -> Result<Option<ApfsVek>> {
    let Some(entry) = self.entries.get(&(volume_uuid, KB_TAG_VOLUME_KEY)) else {
      return Ok(None);
    };
    Ok(Some(ApfsVek::parse(&entry.data)?))
  }
}

impl ApfsVolumeKeybag {
  fn parse(bytes: &[u8]) -> Result<Self> {
    Ok(Self {
      entries: parse_keybag_entries(bytes)?,
    })
  }

  fn password_hint(&self, volume_uuid: [u8; 16]) -> Result<Option<String>> {
    let Some(entry) = self
      .entries
      .iter()
      .find(|entry| entry.uuid == volume_uuid && entry.tag == KB_TAG_VOLUME_PASSPHRASE_HINT)
    else {
      return Ok(None);
    };
    Ok(Some(String::from_utf8_lossy(&entry.data).to_string()))
  }

  fn keks(&self) -> impl Iterator<Item = Result<ApfsKek>> + '_ {
    self
      .entries
      .iter()
      .filter(|entry| entry.tag == KB_TAG_VOLUME_UNLOCK_RECORDS)
      .map(|entry| ApfsKek::parse(&entry.data))
  }
}

impl ApfsKek {
  fn parse(bytes: &[u8]) -> Result<Self> {
    let outer = parse_sequence(bytes)?;
    let hmac = context_child(&outer, 1)?.value;
    let salt = context_child(&outer, 2)?.value;
    let blob = context_child(&outer, 3)?;
    let inner = parse_sequence_contents(blob.value)?;

    Ok(Self {
      blob_der: Arc::from(blob.full.to_vec().into_boxed_slice()),
      hmac: Arc::from(hmac.to_vec().into_boxed_slice()),
      salt: Arc::from(salt.to_vec().into_boxed_slice()),
      flags: read_u32_le(context_child(&inner, 2)?.value, 0).unwrap_or(0),
      wrapped: Arc::from(context_child(&inner, 3)?.value.to_vec().into_boxed_slice()),
      iterations: parse_der_integer(context_child(&inner, 4)?.value)?,
      wrapped_salt: Arc::from(context_child(&inner, 5)?.value.to_vec().into_boxed_slice()),
    })
  }

  fn verify(&self) -> Result<bool> {
    verify_keybag_hmac(&self.blob_der, &self.salt, &self.hmac)
  }

  fn unwrap(&self, password: &str) -> Result<Vec<u8>> {
    let key = derive_password_key(password, &self.wrapped_salt, self.iterations)?;
    let (key, wrapped) = if (self.flags & KEK_FLAG_CORESTORAGE_COMPAT) != 0 {
      (key[..16].to_vec(), self.wrapped[..24].to_vec())
    } else {
      (key.to_vec(), self.wrapped.to_vec())
    };
    aes_unwrap(&key, &wrapped)
  }
}

impl ApfsVek {
  fn parse(bytes: &[u8]) -> Result<Self> {
    let outer = parse_sequence(bytes)?;
    let hmac = context_child(&outer, 1)?.value;
    let salt = context_child(&outer, 2)?.value;
    let blob = context_child(&outer, 3)?;
    let inner = parse_sequence_contents(blob.value)?;

    Ok(Self {
      blob_der: Arc::from(blob.full.to_vec().into_boxed_slice()),
      hmac: Arc::from(hmac.to_vec().into_boxed_slice()),
      salt: Arc::from(salt.to_vec().into_boxed_slice()),
      uuid: read_uuid(context_child(&inner, 1)?.value)?,
      flags: read_u32_le(context_child(&inner, 2)?.value, 0).unwrap_or(0),
      wrapped: Arc::from(context_child(&inner, 3)?.value.to_vec().into_boxed_slice()),
    })
  }

  fn verify(&self) -> Result<bool> {
    verify_keybag_hmac(&self.blob_der, &self.salt, &self.hmac)
  }

  fn unwrap(&self, key: &[u8]) -> Result<Vec<u8>> {
    let mut base_key = key.to_vec();
    let mut wrapped = self.wrapped.to_vec();
    if (self.flags & KEK_FLAG_CORESTORAGE_COMPAT) != 0 {
      base_key.truncate(16);
      wrapped.truncate(24);
    }

    let mut unwrapped = aes_unwrap(&base_key, &wrapped)?;
    if (self.flags & KEK_FLAG_CORESTORAGE_COMPAT) != 0 {
      let mut digest_input = unwrapped.clone();
      digest_input.extend_from_slice(&self.uuid);
      unwrapped.extend_from_slice(&sha256_prefix(&digest_input, 16)?);
    }
    Ok(unwrapped)
  }
}

fn parse_keybag_entries(bytes: &[u8]) -> Result<Vec<ApfsKeybagEntry>> {
  if bytes.len() < 48 {
    return Err(Error::InvalidFormat(
      "apfs keybag object is too short".to_string(),
    ));
  }
  let version = read_u16_le(bytes, 32)?;
  if version != KEYBAG_VERSION {
    return Err(Error::Unsupported(format!(
      "unsupported apfs keybag version: {version}"
    )));
  }

  let entry_count = usize::from(read_u16_le(bytes, 34)?);
  let mut offset = 48usize;
  let mut entries = Vec::with_capacity(entry_count);
  for _ in 0..entry_count {
    let uuid = read_array_16(bytes, offset)?;
    let tag = read_u16_le(bytes, offset + 16)?;
    let key_length = usize::from(read_u16_le(bytes, offset + 18)?);
    let data = bytes
      .get(offset + KEYBAG_ENTRY_HEADER_SIZE..offset + KEYBAG_ENTRY_HEADER_SIZE + key_length)
      .ok_or_else(|| Error::InvalidFormat("apfs keybag entry data is truncated".to_string()))?;
    entries.push(ApfsKeybagEntry {
      uuid,
      tag,
      data: Arc::from(data.to_vec().into_boxed_slice()),
    });
    offset = align_16(
      offset
        .checked_add(KEYBAG_ENTRY_HEADER_SIZE + key_length)
        .ok_or_else(|| Error::InvalidRange("apfs keybag entry offset overflow".to_string()))?,
    );
  }

  Ok(entries)
}

fn credential_passwords<'a>(
  credentials: &'a [Credential<'a>],
) -> impl Iterator<Item = &'a str> + 'a {
  credentials
    .iter()
    .filter_map(|credential| match credential {
      Credential::Password(password) | Credential::RecoveryPassword(password) => Some(*password),
      Credential::KeyData(_) | Credential::NamedKey(..) => None,
    })
}

fn credential_keys<'a>(credentials: &'a [Credential<'a>]) -> impl Iterator<Item = &'a [u8]> + 'a {
  credentials
    .iter()
    .filter_map(|credential| match credential {
      Credential::KeyData(key) => Some(*key),
      Credential::NamedKey(name, key) if *name == "apfs-vek" || *name == "vek" => Some(*key),
      _ => None,
    })
}

fn parse_sequence(bytes: &[u8]) -> Result<Vec<DerTlv<'_>>> {
  let tlv = parse_tlv(bytes)?;
  if tlv.tag.class != 0 || !tlv.tag.constructed || tlv.tag.number != 16 {
    return Err(Error::InvalidFormat(
      "apfs keybag packed object is not a DER sequence".to_string(),
    ));
  }
  parse_sequence_contents(tlv.value)
}

fn parse_sequence_contents(mut bytes: &[u8]) -> Result<Vec<DerTlv<'_>>> {
  let mut values = Vec::new();
  while !bytes.is_empty() {
    let tlv = parse_tlv(bytes)?;
    let used = tlv.full.len();
    values.push(tlv);
    bytes = &bytes[used..];
  }
  Ok(values)
}

fn context_child<'a>(values: &'a [DerTlv<'a>], tag_number: u8) -> Result<&'a DerTlv<'a>> {
  values
    .iter()
    .find(|value| value.tag.class == 2 && value.tag.number == tag_number)
    .ok_or_else(|| {
      Error::InvalidFormat(format!(
        "apfs keybag packed object is missing context tag {tag_number}"
      ))
    })
}

fn parse_der_tlv_length(bytes: &[u8], offset: &mut usize) -> Result<usize> {
  let Some(first) = bytes.get(*offset).copied() else {
    return Err(Error::InvalidFormat(
      "apfs DER length is truncated".to_string(),
    ));
  };
  *offset += 1;
  if (first & 0x80) == 0 {
    return Ok(usize::from(first));
  }

  let count = usize::from(first & 0x7F);
  if count == 0 || count > 8 {
    return Err(Error::InvalidFormat(
      "apfs DER long-form length is invalid".to_string(),
    ));
  }
  let end = offset
    .checked_add(count)
    .ok_or_else(|| Error::InvalidRange("apfs DER length overflow".to_string()))?;
  let encoded = bytes
    .get(*offset..end)
    .ok_or_else(|| Error::InvalidFormat("apfs DER long-form length is truncated".to_string()))?;
  *offset = end;
  Ok(
    encoded
      .iter()
      .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte)),
  )
}

fn parse_tlv(bytes: &[u8]) -> Result<DerTlv<'_>> {
  if bytes.len() < 2 {
    return Err(Error::InvalidFormat(
      "apfs DER value is truncated".to_string(),
    ));
  }

  let tag_byte = bytes[0];
  if (tag_byte & 0x1F) == 0x1F {
    return Err(Error::Unsupported(
      "apfs keybag DER high-tag-number form is not supported".to_string(),
    ));
  }

  let mut offset = 1usize;
  let length = parse_der_tlv_length(bytes, &mut offset)?;
  let end = offset
    .checked_add(length)
    .ok_or_else(|| Error::InvalidRange("apfs DER value length overflow".to_string()))?;
  let value = bytes
    .get(offset..end)
    .ok_or_else(|| Error::InvalidFormat("apfs DER value extends beyond the input".to_string()))?;

  Ok(DerTlv {
    tag: DerTag {
      class: tag_byte >> 6,
      constructed: (tag_byte & 0x20) != 0,
      number: tag_byte & 0x1F,
    },
    value,
    full: &bytes[..end],
  })
}

fn parse_der_integer(bytes: &[u8]) -> Result<u64> {
  if bytes.is_empty() {
    return Err(Error::InvalidFormat(
      "apfs DER integer is empty".to_string(),
    ));
  }
  Ok(
    bytes
      .iter()
      .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
  )
}

fn read_uuid(bytes: &[u8]) -> Result<[u8; 16]> {
  bytes
    .try_into()
    .map_err(|_| Error::InvalidFormat("apfs keybag uuid must be 16 bytes".to_string()))
}

fn read_array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16]> {
  bytes
    .get(offset..offset + 16)
    .ok_or_else(|| Error::InvalidFormat("apfs keybag uuid is truncated".to_string()))?
    .try_into()
    .map_err(|_| Error::InvalidFormat("apfs keybag uuid is truncated".to_string()))
}

fn align_16(value: usize) -> usize {
  (value + 15) & !15
}
