//! BitLocker metadata block parsing.

use crate::{Error, Result};

pub(super) const BLOCK_SIGNATURE: &[u8; 8] = b"-FVE-FS-";
pub(super) const ENTRY_TYPE_VOLUME_MASTER_KEY: u16 = 0x0002;
pub(super) const ENTRY_TYPE_FULL_VOLUME_ENCRYPTION_KEY: u16 = 0x0003;
pub(super) const ENTRY_TYPE_STARTUP_KEY: u16 = 0x0006;
pub(super) const ENTRY_TYPE_DESCRIPTION: u16 = 0x0007;
pub(super) const ENTRY_TYPE_VOLUME_HEADER_BLOCK: u16 = 0x000F;

pub(super) const VALUE_TYPE_KEY: u16 = 0x0001;
pub(super) const VALUE_TYPE_UNICODE_STRING: u16 = 0x0002;
pub(super) const VALUE_TYPE_STRETCH_KEY: u16 = 0x0003;
pub(super) const VALUE_TYPE_AES_CCM_ENCRYPTED_KEY: u16 = 0x0005;
pub(super) const VALUE_TYPE_VOLUME_MASTER_KEY: u16 = 0x0008;
pub(super) const VALUE_TYPE_EXTERNAL_KEY: u16 = 0x0009;
pub(super) const VALUE_TYPE_OFFSET_AND_SIZE: u16 = 0x000F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitlockerEncryptionMethod {
  None,
  Aes128CbcDiffuser,
  Aes256CbcDiffuser,
  Aes128Cbc,
  Aes256Cbc,
  Aes128Xts,
  Aes256Xts,
}

impl BitlockerEncryptionMethod {
  pub fn from_raw(value: u32) -> Result<Self> {
    match value {
      0x0000 => Ok(Self::None),
      0x8000 => Ok(Self::Aes128CbcDiffuser),
      0x8001 => Ok(Self::Aes256CbcDiffuser),
      0x8002 => Ok(Self::Aes128Cbc),
      0x8003 => Ok(Self::Aes256Cbc),
      0x8004 => Ok(Self::Aes128Xts),
      0x8005 => Ok(Self::Aes256Xts),
      other => Err(Error::InvalidFormat(format!(
        "unsupported bitlocker encryption method: 0x{other:04x}"
      ))),
    }
  }

  pub fn fvek_length(self) -> usize {
    match self {
      Self::None => 0,
      Self::Aes128Cbc | Self::Aes128CbcDiffuser => 16,
      Self::Aes256Cbc | Self::Aes256CbcDiffuser | Self::Aes128Xts => 32,
      Self::Aes256Xts => 64,
    }
  }

  pub fn tweak_key_length(self) -> usize {
    match self {
      Self::Aes128CbcDiffuser | Self::Aes256CbcDiffuser => 32,
      Self::None | Self::Aes128Cbc | Self::Aes256Cbc | Self::Aes128Xts | Self::Aes256Xts => 0,
    }
  }

  pub fn uses_xts(self) -> bool {
    matches!(self, Self::Aes128Xts | Self::Aes256Xts)
  }

  pub fn raw(self) -> u16 {
    match self {
      Self::None => 0x0000,
      Self::Aes128CbcDiffuser => 0x8000,
      Self::Aes256CbcDiffuser => 0x8001,
      Self::Aes128Cbc => 0x8002,
      Self::Aes256Cbc => 0x8003,
      Self::Aes128Xts => 0x8004,
      Self::Aes256Xts => 0x8005,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitlockerKeyProtectorKind {
  ClearKey,
  Tpm,
  StartupKey,
  TpmAndPin,
  RecoveryPassword,
  Password,
  Unknown(u16),
}

impl BitlockerKeyProtectorKind {
  fn from_raw(value: u16) -> Self {
    match value {
      0x0000 => Self::ClearKey,
      0x0100 => Self::Tpm,
      0x0200 => Self::StartupKey,
      0x0500 => Self::TpmAndPin,
      0x0800 => Self::RecoveryPassword,
      0x2000 => Self::Password,
      other => Self::Unknown(other),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerMetadataBlockHeader {
  pub version: u16,
  pub encrypted_volume_size: u64,
  pub volume_header_sector_count: u32,
  pub metadata_offsets: [u64; 3],
  pub volume_header_offset: u64,
  pub mft_mirror_cluster_block_number: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerMetadataHeader {
  pub metadata_size: u32,
  pub version: u32,
  pub header_size: u32,
  pub metadata_size_copy: u32,
  pub volume_identifier: [u8; 16],
  pub next_nonce_counter: u32,
  pub encryption_method: BitlockerEncryptionMethod,
  pub creation_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerKeyBlob {
  pub encryption_method: BitlockerEncryptionMethod,
  pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerStretchKey {
  pub encryption_method: BitlockerEncryptionMethod,
  pub salt: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerAesCcmEncryptedKey {
  pub nonce: [u8; 12],
  pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerVolumeMasterKey {
  pub identifier: [u8; 16],
  pub protection_type: BitlockerKeyProtectorKind,
  pub key: Option<BitlockerKeyBlob>,
  pub stretch_key: Option<BitlockerStretchKey>,
  pub aes_ccm_encrypted_key: Option<BitlockerAesCcmEncryptedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerExternalKey {
  pub identifier: [u8; 16],
  pub key: Option<BitlockerKeyBlob>,
  pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerMetadata {
  pub block_header: BitlockerMetadataBlockHeader,
  pub header: BitlockerMetadataHeader,
  pub description: Option<String>,
  pub volume_header_size: u64,
  pub volume_master_keys: Vec<BitlockerVolumeMasterKey>,
  pub startup_key_external_key: Option<BitlockerExternalKey>,
  pub full_volume_encryption_key: Option<BitlockerAesCcmEncryptedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MetadataEntry {
  entry_type: u16,
  value_type: u16,
  version: u16,
  value_data: Vec<u8>,
}

impl BitlockerMetadataBlockHeader {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < 64 {
      return Err(Error::InvalidFormat(
        "bitlocker metadata block header must be 64 bytes".to_string(),
      ));
    }
    if &data[0..8] != BLOCK_SIGNATURE {
      return Err(Error::InvalidFormat(
        "bitlocker metadata block signature is missing".to_string(),
      ));
    }

    let version = u16::from_le_bytes([data[10], data[11]]);
    match version {
      1 => Ok(Self {
        version,
        encrypted_volume_size: 0,
        volume_header_sector_count: 0,
        metadata_offsets: [
          le_u64(&data[32..40])?,
          le_u64(&data[40..48])?,
          le_u64(&data[48..56])?,
        ],
        volume_header_offset: 0,
        mft_mirror_cluster_block_number: Some(le_u64(&data[56..64])?),
      }),
      2 => Ok(Self {
        version,
        encrypted_volume_size: le_u64(&data[16..24])?,
        volume_header_sector_count: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
        metadata_offsets: [
          le_u64(&data[32..40])?,
          le_u64(&data[40..48])?,
          le_u64(&data[48..56])?,
        ],
        volume_header_offset: le_u64(&data[56..64])?,
        mft_mirror_cluster_block_number: None,
      }),
      other => Err(Error::InvalidFormat(format!(
        "unsupported bitlocker metadata block version: {other}"
      ))),
    }
  }
}

impl BitlockerMetadataHeader {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < 48 {
      return Err(Error::InvalidFormat(
        "bitlocker metadata header must be 48 bytes".to_string(),
      ));
    }

    let metadata_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let header_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if metadata_size < 48 || header_size != 48 {
      return Err(Error::InvalidFormat(
        "unsupported bitlocker metadata header layout".to_string(),
      ));
    }

    Ok(Self {
      metadata_size,
      version: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
      header_size,
      metadata_size_copy: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
      volume_identifier: data[16..32].try_into().map_err(|_| {
        Error::InvalidFormat("bitlocker metadata identifier length mismatch".to_string())
      })?,
      next_nonce_counter: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
      encryption_method: BitlockerEncryptionMethod::from_raw(u32::from(u16::from_le_bytes([
        data[36], data[37],
      ])))?,
      creation_time: le_u64(&data[40..48])?,
    })
  }
}

impl BitlockerMetadata {
  pub fn read_block(source: &dyn crate::DataSource, offset: u64) -> Result<Self> {
    let block_header =
      BitlockerMetadataBlockHeader::from_bytes(&source.read_bytes_at(offset, 64)?)?;
    let header = BitlockerMetadataHeader::from_bytes(&source.read_bytes_at(offset + 64, 48)?)?;
    let entry_size = usize::try_from(header.metadata_size.saturating_sub(header.header_size))
      .map_err(|_| Error::InvalidRange("bitlocker metadata entry size is too large".to_string()))?;
    let entries = parse_entries(
      &source.read_bytes_at(offset + 64 + u64::from(header.header_size), entry_size)?,
    )?;
    Self::from_parts(block_header, header, &entries)
  }

  pub fn read_startup_key_file(source: &dyn crate::DataSource) -> Result<BitlockerExternalKey> {
    let header = BitlockerMetadataHeader::from_bytes(&source.read_bytes_at(0, 48)?)?;
    let entry_size = usize::try_from(header.metadata_size.saturating_sub(header.header_size))
      .map_err(|_| {
        Error::InvalidRange("bitlocker startup key entry size is too large".to_string())
      })?;
    let entries = parse_entries(&source.read_bytes_at(u64::from(header.header_size), entry_size)?)?;
    let startup = entries
      .iter()
      .find(|entry| entry.entry_type == ENTRY_TYPE_STARTUP_KEY)
      .ok_or_else(|| {
        Error::InvalidFormat(
          "bitlocker startup key file is missing an external key entry".to_string(),
        )
      })?;
    parse_external_key(startup)
  }

  pub fn clear_key_vmk(&self) -> Option<&BitlockerVolumeMasterKey> {
    self
      .volume_master_keys
      .iter()
      .find(|vmk| vmk.protection_type == BitlockerKeyProtectorKind::ClearKey)
  }

  pub fn password_vmk(&self) -> Option<&BitlockerVolumeMasterKey> {
    self
      .volume_master_keys
      .iter()
      .find(|vmk| vmk.protection_type == BitlockerKeyProtectorKind::Password)
  }

  pub fn recovery_password_vmk(&self) -> Option<&BitlockerVolumeMasterKey> {
    self
      .volume_master_keys
      .iter()
      .find(|vmk| vmk.protection_type == BitlockerKeyProtectorKind::RecoveryPassword)
  }

  pub fn startup_key_vmk(
    &self, startup_identifier: Option<&[u8; 16]>,
  ) -> Option<&BitlockerVolumeMasterKey> {
    self.volume_master_keys.iter().find(|vmk| {
      vmk.protection_type == BitlockerKeyProtectorKind::StartupKey
        && startup_identifier
          .map(|identifier| identifier == &vmk.identifier)
          .unwrap_or(true)
    })
  }

  pub(super) fn from_parts(
    block_header: BitlockerMetadataBlockHeader, header: BitlockerMetadataHeader,
    entries: &[MetadataEntry],
  ) -> Result<Self> {
    let mut description = None;
    let mut volume_header_size = 0u64;
    let mut volume_master_keys = Vec::new();
    let mut startup_key_external_key = None;
    let mut full_volume_encryption_key = None;

    for entry in entries {
      match entry.entry_type {
        ENTRY_TYPE_VOLUME_MASTER_KEY => {
          volume_master_keys.push(parse_volume_master_key(entry)?);
        }
        ENTRY_TYPE_FULL_VOLUME_ENCRYPTION_KEY | 0x000B if full_volume_encryption_key.is_none() => {
          full_volume_encryption_key = Some(parse_aes_ccm_encrypted_key(entry)?);
        }
        ENTRY_TYPE_STARTUP_KEY if startup_key_external_key.is_none() => {
          startup_key_external_key = Some(parse_external_key(entry)?);
        }
        ENTRY_TYPE_DESCRIPTION
          if description.is_none() && entry.value_type == VALUE_TYPE_UNICODE_STRING =>
        {
          description = Some(parse_utf16le_string(&entry.value_data)?);
        }
        ENTRY_TYPE_VOLUME_HEADER_BLOCK
          if entry.value_type == VALUE_TYPE_OFFSET_AND_SIZE && entry.value_data.len() >= 16 =>
        {
          let offset = le_u64(&entry.value_data[0..8])?;
          if offset != block_header.volume_header_offset {
            return Err(Error::InvalidFormat(
              "bitlocker metadata volume header offset does not match the metadata block header"
                .to_string(),
            ));
          }
          volume_header_size = le_u64(&entry.value_data[8..16])?;
        }
        _ => {}
      }
    }

    Ok(Self {
      block_header,
      header,
      description,
      volume_header_size,
      volume_master_keys,
      startup_key_external_key,
      full_volume_encryption_key,
    })
  }
}

pub(super) fn parse_entries(data: &[u8]) -> Result<Vec<MetadataEntry>> {
  let mut offset = 0usize;
  let mut entries = Vec::new();
  while offset + 8 <= data.len() {
    if data[offset..offset + 8].iter().all(|byte| *byte == 0) {
      break;
    }
    let size = usize::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
    let entry_type = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
    let value_type = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
    let version = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
    if !matches!(version, 1 | 3) || size < 8 || offset + size > data.len() {
      return Err(Error::InvalidFormat(
        "bitlocker metadata entry size is invalid".to_string(),
      ));
    }
    entries.push(MetadataEntry {
      entry_type,
      value_type,
      version,
      value_data: data[offset + 8..offset + size].to_vec(),
    });
    offset += size;
  }
  Ok(entries)
}

fn parse_volume_master_key(entry: &MetadataEntry) -> Result<BitlockerVolumeMasterKey> {
  if entry.value_type != VALUE_TYPE_VOLUME_MASTER_KEY || entry.value_data.len() < 28 {
    return Err(Error::InvalidFormat(
      "bitlocker VMK metadata entry is malformed".to_string(),
    ));
  }
  let properties = parse_entries(&entry.value_data[28..])?;
  let mut key = None;
  let mut stretch_key = None;
  let mut aes_ccm_encrypted_key = None;
  for property in &properties {
    match property.value_type {
      VALUE_TYPE_KEY => key = Some(parse_key_blob(property)?),
      VALUE_TYPE_STRETCH_KEY => stretch_key = Some(parse_stretch_key(property)?),
      VALUE_TYPE_AES_CCM_ENCRYPTED_KEY => {
        aes_ccm_encrypted_key = Some(parse_aes_ccm_encrypted_key(property)?)
      }
      _ => {}
    }
  }

  Ok(BitlockerVolumeMasterKey {
    identifier: entry.value_data[0..16]
      .try_into()
      .map_err(|_| Error::InvalidFormat("bitlocker VMK identifier length mismatch".to_string()))?,
    protection_type: BitlockerKeyProtectorKind::from_raw(u16::from_le_bytes([
      entry.value_data[26],
      entry.value_data[27],
    ])),
    key,
    stretch_key,
    aes_ccm_encrypted_key,
  })
}

fn parse_external_key(entry: &MetadataEntry) -> Result<BitlockerExternalKey> {
  if entry.value_type != VALUE_TYPE_EXTERNAL_KEY || entry.value_data.len() < 24 {
    return Err(Error::InvalidFormat(
      "bitlocker external key metadata entry is malformed".to_string(),
    ));
  }

  let properties = parse_entries(&entry.value_data[24..])?;
  let mut key = None;
  let mut description = None;
  for property in &properties {
    match property.value_type {
      VALUE_TYPE_KEY => key = Some(parse_key_blob(property)?),
      VALUE_TYPE_UNICODE_STRING => description = Some(parse_utf16le_string(&property.value_data)?),
      _ => {}
    }
  }

  Ok(BitlockerExternalKey {
    identifier: entry.value_data[0..16].try_into().map_err(|_| {
      Error::InvalidFormat("bitlocker external key identifier length mismatch".to_string())
    })?,
    key,
    description,
  })
}

fn parse_key_blob(entry: &MetadataEntry) -> Result<BitlockerKeyBlob> {
  if entry.value_type != VALUE_TYPE_KEY || entry.value_data.len() < 4 {
    return Err(Error::InvalidFormat(
      "bitlocker key entry is malformed".to_string(),
    ));
  }
  Ok(BitlockerKeyBlob {
    encryption_method: BitlockerEncryptionMethod::from_raw(le_u32(&entry.value_data[0..4])?)?,
    data: entry.value_data[4..].to_vec(),
  })
}

fn parse_stretch_key(entry: &MetadataEntry) -> Result<BitlockerStretchKey> {
  if entry.value_type != VALUE_TYPE_STRETCH_KEY || entry.value_data.len() < 20 {
    return Err(Error::InvalidFormat(
      "bitlocker stretch key entry is malformed".to_string(),
    ));
  }
  Ok(BitlockerStretchKey {
    encryption_method: BitlockerEncryptionMethod::from_raw(le_u32(&entry.value_data[0..4])?)?,
    salt: entry.value_data[4..20].try_into().map_err(|_| {
      Error::InvalidFormat("bitlocker stretch key salt length mismatch".to_string())
    })?,
  })
}

fn parse_aes_ccm_encrypted_key(entry: &MetadataEntry) -> Result<BitlockerAesCcmEncryptedKey> {
  if entry.value_type != VALUE_TYPE_AES_CCM_ENCRYPTED_KEY || entry.value_data.len() < 12 {
    return Err(Error::InvalidFormat(
      "bitlocker AES-CCM key entry is malformed".to_string(),
    ));
  }
  Ok(BitlockerAesCcmEncryptedKey {
    nonce: entry.value_data[0..12]
      .try_into()
      .map_err(|_| Error::InvalidFormat("bitlocker nonce length mismatch".to_string()))?,
    data: entry.value_data[12..].to_vec(),
  })
}

fn parse_utf16le_string(data: &[u8]) -> Result<String> {
  if !data.len().is_multiple_of(2) {
    return Err(Error::InvalidFormat(
      "bitlocker UTF-16 string length must be even".to_string(),
    ));
  }
  let mut units = data
    .chunks_exact(2)
    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
    .collect::<Vec<_>>();
  while matches!(units.last(), Some(0)) {
    units.pop();
  }
  String::from_utf16(&units)
    .map_err(|_| Error::InvalidFormat("bitlocker UTF-16 string is invalid".to_string()))
}

fn le_u32(data: &[u8]) -> Result<u32> {
  Ok(u32::from_le_bytes(data.try_into().map_err(|_| {
    Error::InvalidFormat("bitlocker integer length mismatch".to_string())
  })?))
}

fn le_u64(data: &[u8]) -> Result<u64> {
  Ok(u64::from_le_bytes(data.try_into().map_err(|_| {
    Error::InvalidFormat("bitlocker integer length mismatch".to_string())
  })?))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_metadata_block_header_sample() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/bitlocker/metadata_block_header.1"
    ))
    .unwrap();
    let header = BitlockerMetadataBlockHeader::from_bytes(&bytes).unwrap();

    assert_eq!(header.version, 2);
    assert_eq!(header.encrypted_volume_size, 262_144_000);
    assert_eq!(header.volume_header_sector_count, 10_480);
  }

  #[test]
  fn parses_metadata_header_sample() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/bitlocker/metadata_header.1"
    ))
    .unwrap();
    let header = BitlockerMetadataHeader::from_bytes(&bytes).unwrap();

    assert_eq!(header.version, 1);
    assert_eq!(header.header_size, 48);
    assert_eq!(
      header.encryption_method,
      BitlockerEncryptionMethod::Aes128CbcDiffuser
    );
  }

  #[test]
  fn parses_utf16le_description_values() {
    let data = b"b\0i\0t\0l\0o\0c\0k\0e\0r\0\0\0";
    assert_eq!(parse_utf16le_string(data).unwrap(), "bitlocker");
  }
}
