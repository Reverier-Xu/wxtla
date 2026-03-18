//! Open BitLocker volume-system state.

use std::sync::Arc;

use super::{
  DESCRIPTOR,
  crypto::{
    decrypt_aes_ccm_key_blob, decrypt_sector, password_aes_ccm_key, password_hash,
    recovery_password_hash,
  },
  header::{BitlockerHeaderFlavor, BitlockerVolumeHeader},
  metadata::{BitlockerEncryptionMethod, BitlockerMetadata, BitlockerVolumeMasterKey},
};
use crate::{
  DataSource, DataSourceCapabilities, DataSourceHandle, DataSourceSeekCost, Error, Result,
  SourceHints,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan, VolumeSystem},
};

pub struct BitlockerVolumeSystem {
  source: DataSourceHandle,
  header: BitlockerVolumeHeader,
  metadata: BitlockerMetadata,
  decrypted_volume: Option<DataSourceHandle>,
  volumes: Vec<VolumeRecord>,
}

#[derive(Clone)]
struct BitlockerDecryptedVolume {
  source: DataSourceHandle,
  bytes_per_sector: u16,
  flavor: BitlockerHeaderFlavor,
  metadata_offsets: [u64; 3],
  metadata_size: u64,
  volume_header_offset: u64,
  volume_header_size: u64,
  encrypted_volume_size: u64,
  encryption_method: BitlockerEncryptionMethod,
  full_volume_encryption_key: Vec<u8>,
  tweak_key: Option<Vec<u8>>,
  media_size: u64,
}

impl BitlockerVolumeSystem {
  pub fn open(source: DataSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: DataSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let header = BitlockerVolumeHeader::from_bytes(&source.read_bytes_at(0, 512)?)?;
    let metadata = header
      .metadata_offsets
      .iter()
      .copied()
      .filter(|offset| *offset != 0)
      .find_map(|offset| BitlockerMetadata::read_block(source.as_ref(), offset).ok())
      .ok_or_else(|| {
        Error::InvalidFormat("unable to parse any bitlocker metadata block".to_string())
      })?;
    let media_size = source.size()?;
    let mut system = Self {
      source,
      header,
      metadata,
      decrypted_volume: None,
      volumes: vec![
        VolumeRecord::new(0, VolumeSpan::new(0, media_size), VolumeRole::Primary)
          .with_name("bitlocker"),
      ],
    };

    if system.metadata.header.encryption_method == BitlockerEncryptionMethod::None {
      system.configure_unlocked_volume(Vec::new(), None)?;
    }

    Ok(system)
  }

  pub fn header(&self) -> &BitlockerVolumeHeader {
    &self.header
  }

  pub fn metadata(&self) -> &BitlockerMetadata {
    &self.metadata
  }

  pub fn is_locked(&self) -> bool {
    self.decrypted_volume.is_none()
  }

  pub fn unlock_with_clear_key(&mut self) -> Result<bool> {
    let Some(vmk) = self.metadata.clear_key_vmk() else {
      return Ok(false);
    };
    let volume_master_key = decrypt_volume_master_key_with_clear_key(vmk)?;
    self.unlock_with_volume_master_key(&volume_master_key)?;
    Ok(true)
  }

  pub fn unlock_with_password(&mut self, password: &str) -> Result<bool> {
    let Some(vmk) = self.metadata.password_vmk() else {
      return Ok(false);
    };
    let stretch_key = vmk.stretch_key.as_ref().ok_or_else(|| {
      Error::InvalidFormat("bitlocker password protector is missing a stretch key".to_string())
    })?;
    let password_hash = password_hash(password);
    let aes_ccm_key = password_aes_ccm_key(&password_hash, &stretch_key.salt);
    let volume_master_key = decrypt_volume_master_key(vmk, &aes_ccm_key)?;
    self.unlock_with_volume_master_key(&volume_master_key)?;
    Ok(true)
  }

  pub fn unlock_with_recovery_password(&mut self, recovery_password: &str) -> Result<bool> {
    let Some(vmk) = self.metadata.recovery_password_vmk() else {
      return Ok(false);
    };
    let stretch_key = vmk.stretch_key.as_ref().ok_or_else(|| {
      Error::InvalidFormat("bitlocker recovery protector is missing a stretch key".to_string())
    })?;
    let recovery_hash = recovery_password_hash(recovery_password)?;
    let aes_ccm_key = password_aes_ccm_key(&recovery_hash, &stretch_key.salt);
    let volume_master_key = decrypt_volume_master_key(vmk, &aes_ccm_key)?;
    self.unlock_with_volume_master_key(&volume_master_key)?;
    Ok(true)
  }

  pub fn unlock_with_startup_key_source(
    &mut self, startup_key_source: DataSourceHandle,
  ) -> Result<bool> {
    let external_key = BitlockerMetadata::read_startup_key_file(startup_key_source.as_ref())?;
    let Some(startup_key) = external_key.key.as_ref() else {
      return Err(Error::InvalidFormat(
        "bitlocker startup key file does not contain a key blob".to_string(),
      ));
    };
    let Some(vmk) = self
      .metadata
      .startup_key_vmk(Some(&external_key.identifier))
    else {
      return Ok(false);
    };
    let startup_key_bytes: [u8; 32] = startup_key.data.as_slice().try_into().map_err(|_| {
      Error::InvalidFormat("bitlocker startup key blobs must be 32 bytes".to_string())
    })?;
    let volume_master_key = decrypt_volume_master_key(vmk, &startup_key_bytes)?;
    self.unlock_with_volume_master_key(&volume_master_key)?;
    Ok(true)
  }

  pub fn set_keys(
    &mut self, full_volume_encryption_key: &[u8], tweak_key: Option<&[u8]>,
  ) -> Result<()> {
    self.configure_unlocked_volume(
      full_volume_encryption_key.to_vec(),
      tweak_key.map(ToOwned::to_owned),
    )
  }

  fn unlock_with_volume_master_key(&mut self, volume_master_key: &[u8; 32]) -> Result<()> {
    let (fvek, tweak) = decrypt_full_volume_encryption_key(&self.metadata, volume_master_key)?;
    self.configure_unlocked_volume(fvek, tweak)
  }

  fn configure_unlocked_volume(
    &mut self, full_volume_encryption_key: Vec<u8>, tweak_key: Option<Vec<u8>>,
  ) -> Result<()> {
    self.decrypted_volume = Some(Arc::new(BitlockerDecryptedVolume {
      source: self.source.clone(),
      bytes_per_sector: self.header.bytes_per_sector,
      flavor: self.header.flavor,
      metadata_offsets: self.header.metadata_offsets,
      metadata_size: self.header.metadata_size,
      volume_header_offset: self.metadata.block_header.volume_header_offset,
      volume_header_size: self.metadata.volume_header_size,
      encrypted_volume_size: if self.metadata.block_header.encrypted_volume_size != 0 {
        self.metadata.block_header.encrypted_volume_size
      } else {
        self.header.volume_size
      },
      encryption_method: self.metadata.header.encryption_method,
      full_volume_encryption_key,
      tweak_key,
      media_size: self.header.volume_size,
    }) as DataSourceHandle);
    Ok(())
  }
}

impl VolumeSystem for BitlockerVolumeSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn block_size(&self) -> u32 {
    u32::from(self.header.bytes_per_sector)
  }

  fn volumes(&self) -> &[VolumeRecord] {
    &self.volumes
  }

  fn open_volume(&self, index: usize) -> Result<DataSourceHandle> {
    let _ = self
      .volumes
      .get(index)
      .ok_or_else(|| Error::NotFound(format!("bitlocker volume index {index} is out of bounds")))?;
    self.decrypted_volume.clone().ok_or_else(|| {
      Error::InvalidSourceReference(
        "bitlocker volume is locked; unlock it before opening".to_string(),
      )
    })
  }
}

impl DataSource for BitlockerDecryptedVolume {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let sector_size = u64::from(self.bytes_per_sector);
    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::InvalidRange("bitlocker read offset overflow".to_string()))?;
      if absolute_offset >= self.media_size {
        break;
      }

      let sector_offset = (absolute_offset / sector_size) * sector_size;
      let within_sector = usize::try_from(absolute_offset - sector_offset)
        .map_err(|_| Error::InvalidRange("bitlocker sector offset is too large".to_string()))?;
      let mut sector = vec![0u8; usize::from(self.bytes_per_sector)];
      self.read_sector(sector_offset, &mut sector)?;
      let available = sector
        .len()
        .saturating_sub(within_sector)
        .min(buf.len() - copied)
        .min(usize::try_from(self.media_size - absolute_offset).unwrap_or(usize::MAX));
      buf[copied..copied + available]
        .copy_from_slice(&sector[within_sector..within_sector + available]);
      copied += available;
    }

    Ok(copied)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.media_size)
  }

  fn capabilities(&self) -> DataSourceCapabilities {
    DataSourceCapabilities::concurrent(DataSourceSeekCost::Expensive)
      .with_preferred_chunk_size(usize::from(self.bytes_per_sector))
  }

  fn telemetry_name(&self) -> &'static str {
    "volume.bitlocker.decrypted"
  }
}

impl BitlockerDecryptedVolume {
  fn read_sector(&self, logical_sector_offset: u64, sector: &mut [u8]) -> Result<()> {
    if self.is_zeroed_region(logical_sector_offset) {
      sector.fill(0);
      return Ok(());
    }

    let physical_offset = if matches!(
      self.flavor,
      BitlockerHeaderFlavor::Fixed | BitlockerHeaderFlavor::ToGo
    ) && logical_sector_offset < self.volume_header_size
      && self.volume_header_offset != 0
    {
      self.volume_header_offset + logical_sector_offset
    } else {
      logical_sector_offset
    };

    self.source.read_exact_at(physical_offset, sector)?;

    if self.encryption_method != BitlockerEncryptionMethod::None
      && physical_offset < self.encrypted_volume_size
    {
      let block_key = if self.encryption_method.uses_xts() {
        physical_offset / u64::from(self.bytes_per_sector)
      } else {
        physical_offset
      };
      decrypt_sector(
        self.encryption_method,
        &self.full_volume_encryption_key,
        self.tweak_key.as_deref(),
        block_key,
        sector,
      )?;
    }

    Ok(())
  }

  fn is_zeroed_region(&self, logical_offset: u64) -> bool {
    self.metadata_offsets.iter().any(|metadata_offset| {
      *metadata_offset != 0
        && logical_offset >= *metadata_offset
        && logical_offset < metadata_offset.saturating_add(self.metadata_size)
    }) || (self.volume_header_offset != 0
      && logical_offset >= self.volume_header_offset
      && logical_offset
        < self
          .volume_header_offset
          .saturating_add(self.volume_header_size))
  }
}

fn decrypt_volume_master_key_with_clear_key(vmk: &BitlockerVolumeMasterKey) -> Result<[u8; 32]> {
  let key = vmk.key.as_ref().ok_or_else(|| {
    Error::InvalidFormat("bitlocker clear-key protector is missing its key material".to_string())
  })?;
  let clear_key: [u8; 32] =
    key.data.as_slice().try_into().map_err(|_| {
      Error::InvalidFormat("bitlocker clear-key blobs must be 32 bytes".to_string())
    })?;
  decrypt_volume_master_key(vmk, &clear_key)
}

fn decrypt_volume_master_key(
  vmk: &BitlockerVolumeMasterKey, aes_ccm_key: &[u8; 32],
) -> Result<[u8; 32]> {
  let encrypted = vmk.aes_ccm_encrypted_key.as_ref().ok_or_else(|| {
    Error::InvalidFormat("bitlocker VMK protector is missing its AES-CCM payload".to_string())
  })?;
  let decrypted = decrypt_aes_ccm_key_blob(aes_ccm_key, &encrypted.nonce, &encrypted.data)?;
  if decrypted.len() < 60 {
    return Err(Error::InvalidFormat(
      "bitlocker decrypted VMK payload is too small".to_string(),
    ));
  }
  let data_size = u16::from_le_bytes([decrypted[16], decrypted[17]]);
  let version = u16::from_le_bytes([decrypted[20], decrypted[21]]);
  if version != 1 || data_size != 0x2C {
    return Err(Error::InvalidFormat(
      "unsupported bitlocker VMK payload layout".to_string(),
    ));
  }
  decrypted[28..60]
    .try_into()
    .map_err(|_| Error::InvalidFormat("bitlocker VMK length mismatch".to_string()))
}

fn decrypt_full_volume_encryption_key(
  metadata: &BitlockerMetadata, volume_master_key: &[u8; 32],
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
  let encrypted = metadata
    .full_volume_encryption_key
    .as_ref()
    .ok_or_else(|| {
      Error::InvalidFormat(
        "bitlocker metadata is missing the full volume encryption key".to_string(),
      )
    })?;
  let decrypted = decrypt_aes_ccm_key_blob(volume_master_key, &encrypted.nonce, &encrypted.data)?;
  let data_size = usize::from(u16::from_le_bytes([decrypted[16], decrypted[17]]));
  let version = u16::from_le_bytes([decrypted[20], decrypted[21]]);
  if version != 1 {
    return Err(Error::InvalidFormat(
      "unsupported bitlocker FVEK payload version".to_string(),
    ));
  }

  let method = metadata.header.encryption_method;
  let fvek_length = method.fvek_length();
  let tweak_length = method.tweak_key_length();
  let expected_data_size = match method {
    BitlockerEncryptionMethod::Aes128Cbc => 0x1C,
    BitlockerEncryptionMethod::Aes256Cbc | BitlockerEncryptionMethod::Aes128Xts => 0x2C,
    BitlockerEncryptionMethod::Aes128CbcDiffuser
    | BitlockerEncryptionMethod::Aes256CbcDiffuser
    | BitlockerEncryptionMethod::Aes256Xts => 0x4C,
    BitlockerEncryptionMethod::None => 0,
  };
  if method != BitlockerEncryptionMethod::None && data_size != expected_data_size {
    return Err(Error::InvalidFormat(
      "unsupported bitlocker FVEK payload size for the encryption method".to_string(),
    ));
  }

  let key_start = 28usize;
  let key_end = key_start + fvek_length;
  if decrypted.len() < key_end {
    return Err(Error::InvalidFormat(
      "bitlocker decrypted FVEK payload is truncated".to_string(),
    ));
  }
  let fvek = decrypted[key_start..key_end].to_vec();
  let tweak = if tweak_length != 0 {
    let tweak_start = 60usize;
    let tweak_end = tweak_start + tweak_length;
    if decrypted.len() < tweak_end {
      return Err(Error::InvalidFormat(
        "bitlocker decrypted tweak key payload is truncated".to_string(),
      ));
    }
    Some(decrypted[tweak_start..tweak_end].to_vec())
  } else {
    None
  };

  Ok((fvek, tweak))
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use aes::Aes256;
  use ccm::{
    Ccm,
    aead::{
      AeadInPlace, KeyInit,
      consts::{U12, U16},
    },
  };

  use super::{
    super::{
      crypto::{encrypt_sector, password_aes_ccm_key, password_hash, recovery_password_hash},
      metadata::{
        BLOCK_SIGNATURE, BitlockerMetadataBlockHeader, BitlockerMetadataHeader,
        ENTRY_TYPE_FULL_VOLUME_ENCRYPTION_KEY, ENTRY_TYPE_STARTUP_KEY,
        ENTRY_TYPE_VOLUME_HEADER_BLOCK, ENTRY_TYPE_VOLUME_MASTER_KEY,
        VALUE_TYPE_AES_CCM_ENCRYPTED_KEY, VALUE_TYPE_EXTERNAL_KEY, VALUE_TYPE_KEY,
        VALUE_TYPE_OFFSET_AND_SIZE, VALUE_TYPE_STRETCH_KEY, VALUE_TYPE_VOLUME_MASTER_KEY,
        parse_entries,
      },
    },
    *,
  };
  use crate::{
    DataSource, DataSourceHandle, FileDataSource,
    images::ewf::EwfImage,
    volumes::{bitlocker::BitlockerKeyProtectorKind, mbr::MbrDriver},
  };

  type Aes256Ccm = Ccm<Aes256, U16, U12>;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = usize::try_from(offset)
        .map_err(|_| Error::InvalidRange("test read offset is too large".to_string()))?;
      if offset >= self.data.len() {
        return Ok(0);
      }
      let read = buf.len().min(self.data.len() - offset);
      buf[..read].copy_from_slice(&self.data[offset..offset + read]);
      Ok(read)
    }

    fn size(&self) -> Result<u64> {
      Ok(self.data.len() as u64)
    }
  }

  fn fixture_path(relative_path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join(relative_path)
  }

  fn open_bitlocker_fixture() -> BitlockerVolumeSystem {
    let ewf_source: DataSourceHandle =
      Arc::new(FileDataSource::open(fixture_path("bitlocker/bitlocker.E01")).unwrap());
    let image: DataSourceHandle = Arc::new(EwfImage::open(ewf_source).unwrap());
    let mbr = MbrDriver::open(image).unwrap();
    BitlockerVolumeSystem::open(mbr.open_volume(0).unwrap()).unwrap()
  }

  fn metadata_entry(entry_type: u16, value_type: u16, value: &[u8]) -> Vec<u8> {
    let size = u16::try_from(8 + value.len()).unwrap();
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&entry_type.to_le_bytes());
    out.extend_from_slice(&value_type.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(value);
    out
  }

  fn key_property(method: BitlockerEncryptionMethod, key: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + key.len());
    value.extend_from_slice(&u32::from(method.raw()).to_le_bytes());
    value.extend_from_slice(key);
    metadata_entry(0, VALUE_TYPE_KEY, &value)
  }

  fn stretch_key_property(method: u32, salt: &[u8; 16]) -> Vec<u8> {
    let mut value = Vec::with_capacity(20);
    value.extend_from_slice(&method.to_le_bytes());
    value.extend_from_slice(salt);
    metadata_entry(0, VALUE_TYPE_STRETCH_KEY, &value)
  }

  fn aes_ccm_property(nonce: [u8; 12], plaintext_tail: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Ccm::new_from_slice(key).unwrap();
    let mut plaintext = plaintext_tail.to_vec();
    let tag = cipher
      .encrypt_in_place_detached((&nonce).into(), b"", &mut plaintext)
      .unwrap();
    let mut value = Vec::with_capacity(12 + 16 + plaintext.len());
    value.extend_from_slice(&nonce);
    value.extend_from_slice(tag.as_slice());
    value.extend_from_slice(&plaintext);
    metadata_entry(0, VALUE_TYPE_AES_CCM_ENCRYPTED_KEY, &value)
  }

  fn vmk_entry(
    protector: BitlockerKeyProtectorKind, key_property_bytes: Option<Vec<u8>>,
    stretch_key: Option<Vec<u8>>, aes_ccm: Vec<u8>,
  ) -> Vec<u8> {
    let mut value = vec![0u8; 28];
    value[26..28].copy_from_slice(&protector_raw(protector).to_le_bytes());
    if let Some(key_property_bytes) = key_property_bytes {
      value.extend_from_slice(&key_property_bytes);
    }
    if let Some(stretch_key) = stretch_key {
      value.extend_from_slice(&stretch_key);
    }
    value.extend_from_slice(&aes_ccm);
    metadata_entry(
      ENTRY_TYPE_VOLUME_MASTER_KEY,
      VALUE_TYPE_VOLUME_MASTER_KEY,
      &value,
    )
  }

  fn fvek_entry(
    method: BitlockerEncryptionMethod, vmk: &[u8; 32], fvek: &[u8], tweak: Option<&[u8]>,
  ) -> Vec<u8> {
    let mut plaintext = vec![
      0u8;
      16 + match method {
        BitlockerEncryptionMethod::Aes128Cbc => 0x1C,
        BitlockerEncryptionMethod::Aes256Cbc | BitlockerEncryptionMethod::Aes128Xts => 0x2C,
        BitlockerEncryptionMethod::Aes128CbcDiffuser
        | BitlockerEncryptionMethod::Aes256CbcDiffuser
        | BitlockerEncryptionMethod::Aes256Xts => 0x4C,
        BitlockerEncryptionMethod::None => 0,
      }
    ];
    let data_size = u16::try_from(plaintext.len() - 16).unwrap();
    plaintext[16..18].copy_from_slice(&data_size.to_le_bytes());
    plaintext[20..22].copy_from_slice(&1u16.to_le_bytes());
    plaintext[28..28 + fvek.len()].copy_from_slice(fvek);
    if let Some(tweak) = tweak {
      plaintext[60..60 + tweak.len()].copy_from_slice(tweak);
    }
    let property = aes_ccm_property([9; 12], plaintext[16..].as_ref(), vmk);
    metadata_entry(
      ENTRY_TYPE_FULL_VOLUME_ENCRYPTION_KEY,
      VALUE_TYPE_AES_CCM_ENCRYPTED_KEY,
      &property[8..],
    )
  }

  fn protector_raw(kind: BitlockerKeyProtectorKind) -> u16 {
    match kind {
      BitlockerKeyProtectorKind::ClearKey => 0x0000,
      BitlockerKeyProtectorKind::StartupKey => 0x0200,
      BitlockerKeyProtectorKind::RecoveryPassword => 0x0800,
      BitlockerKeyProtectorKind::Password => 0x2000,
      BitlockerKeyProtectorKind::Tpm => 0x0100,
      BitlockerKeyProtectorKind::TpmAndPin => 0x0500,
      BitlockerKeyProtectorKind::Unknown(value) => value,
    }
  }

  fn build_synthetic_metadata(
    method: BitlockerEncryptionMethod,
  ) -> (BitlockerMetadata, [u8; 32], Vec<u8>, Option<Vec<u8>>) {
    let clear_key = [0x33; 32];
    let vmk = [0x44; 32];
    let fvek = vec![0x55; method.fvek_length()];
    let tweak = (method.tweak_key_length() != 0).then(|| vec![0x66; method.tweak_key_length()]);

    let mut vmk_plain = vec![0u8; 44];
    vmk_plain[0..2].copy_from_slice(&0x2Cu16.to_le_bytes());
    vmk_plain[4..6].copy_from_slice(&1u16.to_le_bytes());
    vmk_plain[12..44].copy_from_slice(&vmk);

    let entries = [
      vmk_entry(
        BitlockerKeyProtectorKind::ClearKey,
        Some(key_property(BitlockerEncryptionMethod::None, &clear_key)),
        None,
        aes_ccm_property([7; 12], &vmk_plain, &clear_key),
      ),
      fvek_entry(method, &vmk, &fvek, tweak.as_deref()),
      metadata_entry(
        ENTRY_TYPE_VOLUME_HEADER_BLOCK,
        VALUE_TYPE_OFFSET_AND_SIZE,
        &[
          0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00,
        ],
      ),
    ];
    let mut entry_bytes = entries.concat();
    entry_bytes.extend_from_slice(&[0u8; 8]);
    let metadata_size = 48 + entry_bytes.len() as u32;
    let mut header = vec![0u8; 48];
    header[0..4].copy_from_slice(&metadata_size.to_le_bytes());
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    header[8..12].copy_from_slice(&48u32.to_le_bytes());
    header[12..16].copy_from_slice(&metadata_size.to_le_bytes());
    header[36..38].copy_from_slice(&method.raw().to_le_bytes());

    let mut block_header = vec![0u8; 64];
    block_header[0..8].copy_from_slice(BLOCK_SIGNATURE);
    block_header[8..10].copy_from_slice(&64u16.to_le_bytes());
    block_header[10..12].copy_from_slice(&2u16.to_le_bytes());
    block_header[16..24].copy_from_slice(&0x4000u64.to_le_bytes());
    block_header[28..32].copy_from_slice(&16u32.to_le_bytes());
    block_header[32..40].copy_from_slice(&0x1000u64.to_le_bytes());
    block_header[40..48].copy_from_slice(&0x1800u64.to_le_bytes());
    block_header[48..56].copy_from_slice(&0x2000u64.to_le_bytes());
    block_header[56..64].copy_from_slice(&0x2000u64.to_le_bytes());

    let metadata = BitlockerMetadata::from_parts(
      BitlockerMetadataBlockHeader::from_bytes(&block_header).unwrap(),
      BitlockerMetadataHeader::from_bytes(&header).unwrap(),
      &parse_entries(&entry_bytes).unwrap(),
    )
    .unwrap();

    (metadata, vmk, fvek, tweak)
  }

  fn build_volume_header(
    metadata_offsets: [u64; 3], metadata_size: u64, volume_size: u64,
  ) -> [u8; 512] {
    let mut data = [0u8; 512];
    let total_sectors = volume_size / 512;
    data[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    data[3..11].copy_from_slice(b"-FVE-FS-");
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[13] = 8;
    data[32..36].copy_from_slice(&(u32::try_from(total_sectors).unwrap()).to_le_bytes());
    data[112..120].copy_from_slice(&metadata_size.to_le_bytes());
    data[120..128].copy_from_slice(&volume_size.to_le_bytes());
    for (index, offset) in metadata_offsets.iter().enumerate() {
      let start = 176 + index * 8;
      data[start..start + 8].copy_from_slice(&offset.to_le_bytes());
    }
    data[510..512].copy_from_slice(&[0x55, 0xAA]);
    data
  }

  fn build_metadata_block(
    entries: &[Vec<u8>], method: BitlockerEncryptionMethod, encrypted_volume_size: u64,
    volume_header_offset: u64, metadata_offsets: [u64; 3],
  ) -> Vec<u8> {
    let mut entry_bytes = entries.concat();
    entry_bytes.extend_from_slice(&[0u8; 8]);
    let metadata_size = 48 + u32::try_from(entry_bytes.len()).unwrap();

    let mut header = vec![0u8; 48];
    header[0..4].copy_from_slice(&metadata_size.to_le_bytes());
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    header[8..12].copy_from_slice(&48u32.to_le_bytes());
    header[12..16].copy_from_slice(&metadata_size.to_le_bytes());
    header[36..38].copy_from_slice(&method.raw().to_le_bytes());

    let mut block_header = vec![0u8; 64];
    block_header[0..8].copy_from_slice(BLOCK_SIGNATURE);
    block_header[8..10].copy_from_slice(&64u16.to_le_bytes());
    block_header[10..12].copy_from_slice(&2u16.to_le_bytes());
    block_header[16..24].copy_from_slice(&encrypted_volume_size.to_le_bytes());
    block_header[28..32].copy_from_slice(&16u32.to_le_bytes());
    for (index, offset) in metadata_offsets.iter().enumerate() {
      let start = 32 + index * 8;
      block_header[start..start + 8].copy_from_slice(&offset.to_le_bytes());
    }
    block_header[56..64].copy_from_slice(&volume_header_offset.to_le_bytes());

    [block_header, header, entry_bytes].concat()
  }

  fn build_synthetic_volume(
    method: BitlockerEncryptionMethod, entries: Vec<Vec<u8>>, fvek: &[u8], tweak: Option<&[u8]>,
    header_plaintext: &[u8; 512],
  ) -> Vec<u8> {
    let metadata_offsets = [0x1000u64, 0x1800u64, 0x2000u64];
    let volume_header_offset = 0x4000u64;
    let volume_size = 0x6000u64;
    let metadata_block = build_metadata_block(
      &entries,
      method,
      volume_size,
      volume_header_offset,
      metadata_offsets,
    );
    let metadata_size = 0x800u64;
    let mut image = vec![0u8; volume_size as usize];
    image[..512].copy_from_slice(&build_volume_header(
      metadata_offsets,
      metadata_size,
      volume_size,
    ));
    for offset in metadata_offsets {
      image[offset as usize..offset as usize + metadata_block.len()]
        .copy_from_slice(&metadata_block);
    }

    let mut encrypted_header = *header_plaintext;
    encrypt_sector(
      method,
      fvek,
      tweak,
      volume_header_offset,
      &mut encrypted_header,
    )
    .unwrap();
    image[volume_header_offset as usize..volume_header_offset as usize + 512]
      .copy_from_slice(&encrypted_header);
    image
  }

  #[test]
  fn parses_metadata_from_fixture_headers() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/bitlocker/metadata_block_header.1"
    ))
    .unwrap();
    let header = BitlockerMetadataBlockHeader::from_bytes(&bytes).unwrap();
    assert_eq!(header.version, 2);
  }

  #[test]
  fn decrypts_clear_key_vmk_and_fvek() {
    let (metadata, vmk, fvek, tweak) =
      build_synthetic_metadata(BitlockerEncryptionMethod::Aes256Cbc);
    let decrypted_vmk =
      decrypt_volume_master_key_with_clear_key(metadata.clear_key_vmk().unwrap()).unwrap();
    assert_eq!(decrypted_vmk, vmk);
    let (decrypted_fvek, decrypted_tweak) =
      decrypt_full_volume_encryption_key(&metadata, &vmk).unwrap();
    assert_eq!(decrypted_fvek, fvek);
    assert_eq!(decrypted_tweak, tweak);
  }

  #[test]
  fn unlocks_and_decrypts_with_a_clear_key() {
    let method = BitlockerEncryptionMethod::Aes128Cbc;
    let clear_key = [0x33; 32];
    let vmk = [0x44; 32];
    let fvek = vec![0x55; method.fvek_length()];
    let mut vmk_plain = vec![0u8; 44];
    vmk_plain[0..2].copy_from_slice(&0x2Cu16.to_le_bytes());
    vmk_plain[4..6].copy_from_slice(&1u16.to_le_bytes());
    vmk_plain[12..44].copy_from_slice(&vmk);
    let entries = vec![
      vmk_entry(
        BitlockerKeyProtectorKind::ClearKey,
        Some(key_property(BitlockerEncryptionMethod::None, &clear_key)),
        None,
        aes_ccm_property([7; 12], &vmk_plain, &clear_key),
      ),
      fvek_entry(method, &vmk, &fvek, None),
      metadata_entry(
        ENTRY_TYPE_VOLUME_HEADER_BLOCK,
        VALUE_TYPE_OFFSET_AND_SIZE,
        &[
          0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00,
        ],
      ),
    ];
    let mut plaintext_header = [0u8; 512];
    plaintext_header[..8].copy_from_slice(b"TESTNTFS");
    let source = Arc::new(MemDataSource {
      data: build_synthetic_volume(method, entries, &fvek, None, &plaintext_header),
    }) as DataSourceHandle;

    let mut system = BitlockerVolumeSystem::open(source).unwrap();
    assert!(system.is_locked());
    assert!(system.unlock_with_clear_key().unwrap());
    let volume = system.open_volume(0).unwrap();
    let header = volume.read_bytes_at(0, 8).unwrap();
    assert_eq!(&header, b"TESTNTFS");
  }

  #[test]
  fn unlocks_with_password_and_recovery_password() {
    let method = BitlockerEncryptionMethod::Aes128Cbc;
    let password = "TeSt";
    let recovery = "471207-278498-422125-177177-561902-537405-468006-693451";
    let salt = [0x11; 16];
    let vmk = [0x44; 32];
    let fvek = vec![0x55; method.fvek_length()];
    let mut vmk_plain = vec![0u8; 44];
    vmk_plain[0..2].copy_from_slice(&0x2Cu16.to_le_bytes());
    vmk_plain[4..6].copy_from_slice(&1u16.to_le_bytes());
    vmk_plain[12..44].copy_from_slice(&vmk);
    let password_key = password_aes_ccm_key(&password_hash(password), &salt);
    let recovery_key = password_aes_ccm_key(&recovery_password_hash(recovery).unwrap(), &salt);
    let mut plaintext_header = [0u8; 512];
    plaintext_header[..4].copy_from_slice(b"PASS");

    let password_entries = vec![
      vmk_entry(
        BitlockerKeyProtectorKind::Password,
        None,
        Some(stretch_key_property(0x1001, &salt)),
        aes_ccm_property([1; 12], &vmk_plain, &password_key),
      ),
      fvek_entry(method, &vmk, &fvek, None),
      metadata_entry(
        ENTRY_TYPE_VOLUME_HEADER_BLOCK,
        VALUE_TYPE_OFFSET_AND_SIZE,
        &[
          0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00,
        ],
      ),
    ];
    let mut password_system = BitlockerVolumeSystem::open(Arc::new(MemDataSource {
      data: build_synthetic_volume(method, password_entries, &fvek, None, &plaintext_header),
    }) as DataSourceHandle)
    .unwrap();
    assert!(password_system.unlock_with_password(password).unwrap());
    assert_eq!(
      &password_system
        .open_volume(0)
        .unwrap()
        .read_bytes_at(0, 4)
        .unwrap(),
      b"PASS"
    );

    let recovery_entries = vec![
      vmk_entry(
        BitlockerKeyProtectorKind::RecoveryPassword,
        None,
        Some(stretch_key_property(0x1000, &salt)),
        aes_ccm_property([2; 12], &vmk_plain, &recovery_key),
      ),
      fvek_entry(method, &vmk, &fvek, None),
      metadata_entry(
        ENTRY_TYPE_VOLUME_HEADER_BLOCK,
        VALUE_TYPE_OFFSET_AND_SIZE,
        &[
          0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00,
        ],
      ),
    ];
    let mut recovery_system = BitlockerVolumeSystem::open(Arc::new(MemDataSource {
      data: build_synthetic_volume(method, recovery_entries, &fvek, None, &plaintext_header),
    }) as DataSourceHandle)
    .unwrap();
    assert!(
      recovery_system
        .unlock_with_recovery_password(recovery)
        .unwrap()
    );
    assert_eq!(
      &recovery_system
        .open_volume(0)
        .unwrap()
        .read_bytes_at(0, 4)
        .unwrap(),
      b"PASS"
    );
  }

  #[test]
  fn unlocks_with_a_startup_key_file() {
    let method = BitlockerEncryptionMethod::Aes128Cbc;
    let startup_key = [0x99; 32];
    let identifier = [0xAB; 16];
    let vmk = [0x44; 32];
    let fvek = vec![0x55; method.fvek_length()];
    let mut vmk_plain = vec![0u8; 44];
    vmk_plain[0..2].copy_from_slice(&0x2Cu16.to_le_bytes());
    vmk_plain[4..6].copy_from_slice(&1u16.to_le_bytes());
    vmk_plain[12..44].copy_from_slice(&vmk);
    let mut startup_vmk = vmk_entry(
      BitlockerKeyProtectorKind::StartupKey,
      None,
      None,
      aes_ccm_property([3; 12], &vmk_plain, &startup_key),
    );
    startup_vmk[8..24].copy_from_slice(&identifier);
    let entries = vec![
      startup_vmk,
      fvek_entry(method, &vmk, &fvek, None),
      metadata_entry(
        ENTRY_TYPE_VOLUME_HEADER_BLOCK,
        VALUE_TYPE_OFFSET_AND_SIZE,
        &[
          0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00,
        ],
      ),
    ];
    let mut plaintext_header = [0u8; 512];
    plaintext_header[..4].copy_from_slice(b"BEK!");
    let mut system = BitlockerVolumeSystem::open(Arc::new(MemDataSource {
      data: build_synthetic_volume(method, entries, &fvek, None, &plaintext_header),
    }) as DataSourceHandle)
    .unwrap();

    let mut startup_value = vec![0u8; 24];
    startup_value[0..16].copy_from_slice(&identifier);
    startup_value.extend_from_slice(&key_property(BitlockerEncryptionMethod::None, &startup_key));
    let startup_entry = metadata_entry(
      ENTRY_TYPE_STARTUP_KEY,
      VALUE_TYPE_EXTERNAL_KEY,
      &startup_value,
    );
    let metadata_size = 48 + u32::try_from(startup_entry.len()).unwrap();
    let mut bek_header = vec![0u8; 48];
    bek_header[0..4].copy_from_slice(&metadata_size.to_le_bytes());
    bek_header[4..8].copy_from_slice(&1u32.to_le_bytes());
    bek_header[8..12].copy_from_slice(&48u32.to_le_bytes());
    bek_header[12..16].copy_from_slice(&metadata_size.to_le_bytes());
    let startup_source = Arc::new(MemDataSource {
      data: [bek_header, startup_entry].concat(),
    }) as DataSourceHandle;

    assert!(
      system
        .unlock_with_startup_key_source(startup_source)
        .unwrap()
    );
    assert_eq!(
      &system.open_volume(0).unwrap().read_bytes_at(0, 4).unwrap(),
      b"BEK!"
    );
  }

  #[test]
  fn parses_startup_key_files() {
    let mut external_value = vec![0u8; 24];
    external_value[0..16].copy_from_slice(&[0xAA; 16]);
    external_value.extend_from_slice(&key_property(BitlockerEncryptionMethod::None, &[0xBB; 32]));
    let entry = metadata_entry(
      ENTRY_TYPE_STARTUP_KEY,
      VALUE_TYPE_EXTERNAL_KEY,
      &external_value,
    );
    let metadata_size = 48 + u32::try_from(entry.len()).unwrap();
    let mut header = vec![0u8; 48];
    header[0..4].copy_from_slice(&metadata_size.to_le_bytes());
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    header[8..12].copy_from_slice(&48u32.to_le_bytes());
    header[12..16].copy_from_slice(&metadata_size.to_le_bytes());
    let source = MemDataSource {
      data: [header, entry].concat(),
    };

    let external = BitlockerMetadata::read_startup_key_file(&source).unwrap();
    assert_eq!(external.identifier, [0xAA; 16]);
    assert_eq!(external.key.unwrap().data, vec![0xBB; 32]);
  }

  #[test]
  fn opens_fixture_metadata_through_ewf_and_mbr() {
    let system = open_bitlocker_fixture();

    assert!(system.is_locked());
    assert_eq!(system.header().bytes_per_sector, 512);
    assert_eq!(system.header().hidden_sector_count, 2048);
    assert_eq!(
      system.header().metadata_offsets,
      [34_603_008, 253_059_072, 471_511_040]
    );
    assert_eq!(
      system.metadata().block_header.volume_header_offset,
      34_668_544
    );
    assert_eq!(system.metadata().volume_header_size, 8192);
    assert_eq!(system.metadata().header.raw_encryption_method, 0x8002_8002);
    assert_eq!(
      system.metadata().header.encryption_method,
      BitlockerEncryptionMethod::Aes128Cbc
    );
    assert_eq!(
      system.metadata().description.as_deref(),
      Some("ARK G: 2026/3/18")
    );
    assert_eq!(system.metadata().volume_master_keys.len(), 2);
    assert!(system.metadata().password_vmk().is_some());
    assert!(system.metadata().recovery_password_vmk().is_some());
  }

  #[test]
  fn unlocks_fixture_with_recovery_password_and_reads_known_plaintext() {
    const FIXTURE_RECOVERY_PASSWORD: &str =
      "447854-362307-188650-128513-644006-423984-040843-662508";
    const FIXTURE_FLAG_OFFSET: u64 = 3_862_528;

    let expected_flag = std::fs::read(fixture_path("bitlocker/flag.txt")).unwrap();
    let mut system = open_bitlocker_fixture();

    assert!(
      system
        .unlock_with_recovery_password(FIXTURE_RECOVERY_PASSWORD)
        .unwrap()
    );
    let volume = system.open_volume(0).unwrap();
    let boot_sector = volume.read_bytes_at(0, 90).unwrap();

    assert_eq!(&boot_sector[3..11], b"MSDOS5.0");
    assert_eq!(&boot_sector[82..90], b"FAT32   ");
    assert_eq!(
      volume
        .read_bytes_at(FIXTURE_FLAG_OFFSET, expected_flag.len())
        .unwrap(),
      expected_flag
    );
  }
}
