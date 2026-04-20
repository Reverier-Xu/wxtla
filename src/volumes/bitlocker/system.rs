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
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceSeekCost, Error, Result,
  SourceHints,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan, VolumeSystem},
};

pub struct BitlockerVolumeSystem {
  source: ByteSourceHandle,
  header: BitlockerVolumeHeader,
  metadata: BitlockerMetadata,
  decrypted_volume: Option<ByteSourceHandle>,
  volumes: Vec<VolumeRecord>,
}

#[derive(Clone)]
struct BitlockerDecryptedVolume {
  source: ByteSourceHandle,
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
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Self::open_with_hints(source, SourceHints::new())
  }

  pub fn open_with_hints(source: ByteSourceHandle, _hints: SourceHints<'_>) -> Result<Self> {
    let mut header = BitlockerVolumeHeader::from_bytes(&source.read_bytes_at(0, 512)?)?;
    let metadata = header
      .metadata_offsets
      .iter()
      .copied()
      .filter(|offset| *offset != 0)
      .find_map(|offset| BitlockerMetadata::read_block(source.as_ref(), offset).ok())
      .ok_or_else(|| Error::invalid_format("unable to parse any bitlocker metadata block"))?;
    header.metadata_offsets = merge_metadata_offsets(
      header.metadata_offsets,
      metadata.block_header.metadata_offsets,
    );
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

  pub fn block_size(&self) -> u32 {
    u32::from(self.header.bytes_per_sector)
  }

  pub fn volumes(&self) -> &[VolumeRecord] {
    &self.volumes
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
      Error::invalid_format("bitlocker password protector is missing a stretch key")
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
      Error::invalid_format("bitlocker recovery protector is missing a stretch key")
    })?;
    let recovery_hash = recovery_password_hash(recovery_password)?;
    let aes_ccm_key = password_aes_ccm_key(&recovery_hash, &stretch_key.salt);
    let volume_master_key = decrypt_volume_master_key(vmk, &aes_ccm_key)?;
    self.unlock_with_volume_master_key(&volume_master_key)?;
    Ok(true)
  }

  pub fn unlock_with_startup_key_source(
    &mut self, startup_key_source: ByteSourceHandle,
  ) -> Result<bool> {
    let external_key = BitlockerMetadata::read_startup_key_file(startup_key_source.as_ref())?;
    let Some(startup_key) = external_key.key.as_ref() else {
      return Err(Error::invalid_format(
        "bitlocker startup key file does not contain a key blob".to_string(),
      ));
    };
    let Some(vmk) = self
      .metadata
      .startup_key_vmk(Some(&external_key.identifier))
    else {
      return Ok(false);
    };
    let startup_key_bytes: [u8; 32] = startup_key
      .data
      .as_slice()
      .try_into()
      .map_err(|_| Error::invalid_format("bitlocker startup key blobs must be 32 bytes"))?;
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
      volume_header_size: self.metadata.volume_header_size.max(
        u64::from(self.metadata.block_header.volume_header_sector_count)
          .checked_mul(u64::from(self.header.bytes_per_sector))
          .ok_or_else(|| Error::invalid_range("bitlocker volume header size overflow"))?,
      ),
      encrypted_volume_size: if self.metadata.block_header.encrypted_volume_size != 0 {
        self.metadata.block_header.encrypted_volume_size
      } else {
        self.header.volume_size
      },
      encryption_method: self.metadata.header.encryption_method,
      full_volume_encryption_key,
      tweak_key,
      media_size: self.header.volume_size,
    }) as ByteSourceHandle);
    Ok(())
  }

  pub fn open_volume(&self, index: usize) -> Result<ByteSourceHandle> {
    let _ = self.volumes.get(index).ok_or_else(|| {
      Error::not_found(format!("bitlocker volume index {index} is out of bounds"))
    })?;
    self.decrypted_volume.clone().ok_or_else(|| {
      Error::invalid_source_reference(
        "bitlocker volume is locked; unlock it before opening".to_string(),
      )
    })
  }
}

impl VolumeSystem for BitlockerVolumeSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn block_size(&self) -> u32 {
    self.block_size()
  }

  fn volumes(&self) -> &[VolumeRecord] {
    self.volumes()
  }

  fn open_volume(&self, index: usize) -> Result<ByteSourceHandle> {
    self.open_volume(index)
  }
}

impl ByteSource for BitlockerDecryptedVolume {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.media_size || buf.is_empty() {
      return Ok(0);
    }

    let sector_size = u64::from(self.bytes_per_sector);
    let mut copied = 0usize;
    while copied < buf.len() {
      let absolute_offset = offset
        .checked_add(copied as u64)
        .ok_or_else(|| Error::invalid_range("bitlocker read offset overflow"))?;
      if absolute_offset >= self.media_size {
        break;
      }

      let sector_offset = (absolute_offset / sector_size) * sector_size;
      let within_sector = usize::try_from(absolute_offset - sector_offset)
        .map_err(|_| Error::invalid_range("bitlocker sector offset is too large"))?;
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

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::concurrent(ByteSourceSeekCost::Expensive)
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
    Error::invalid_format("bitlocker clear-key protector is missing its key material")
  })?;
  let clear_key: [u8; 32] = key
    .data
    .as_slice()
    .try_into()
    .map_err(|_| Error::invalid_format("bitlocker clear-key blobs must be 32 bytes"))?;
  decrypt_volume_master_key(vmk, &clear_key)
}

fn decrypt_volume_master_key(
  vmk: &BitlockerVolumeMasterKey, aes_ccm_key: &[u8; 32],
) -> Result<[u8; 32]> {
  let encrypted = vmk.aes_ccm_encrypted_key.as_ref().ok_or_else(|| {
    Error::invalid_format("bitlocker VMK protector is missing its AES-CCM payload")
  })?;
  let decrypted = decrypt_aes_ccm_key_blob(aes_ccm_key, &encrypted.nonce, &encrypted.data)?;
  if decrypted.len() < 28 {
    return Err(Error::invalid_format(
      "bitlocker decrypted VMK payload is too small".to_string(),
    ));
  }
  let data_size = u16::from_le_bytes([decrypted[16], decrypted[17]]);
  let payload_end = 16usize
    .checked_add(usize::from(data_size))
    .ok_or_else(|| Error::invalid_range("bitlocker VMK payload size overflow"))?;
  if payload_end > decrypted.len() || data_size < 0x2C {
    return Err(Error::invalid_format(
      "unsupported bitlocker VMK payload layout".to_string(),
    ));
  }
  decrypted[28..60]
    .try_into()
    .map_err(|_| Error::invalid_format("bitlocker VMK length mismatch"))
}

fn decrypt_full_volume_encryption_key(
  metadata: &BitlockerMetadata, volume_master_key: &[u8; 32],
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
  let encrypted = metadata
    .full_volume_encryption_key
    .as_ref()
    .ok_or_else(|| {
      Error::invalid_format(
        "bitlocker metadata is missing the full volume encryption key".to_string(),
      )
    })?;
  let decrypted = decrypt_aes_ccm_key_blob(volume_master_key, &encrypted.nonce, &encrypted.data)?;
  let data_size = usize::from(u16::from_le_bytes([decrypted[16], decrypted[17]]));
  let payload_end = 16usize
    .checked_add(data_size)
    .ok_or_else(|| Error::invalid_range("bitlocker FVEK payload size overflow"))?;
  if decrypted.len() < payload_end {
    return Err(Error::invalid_format(
      "bitlocker decrypted FVEK payload is truncated".to_string(),
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
  if method != BitlockerEncryptionMethod::None && data_size < expected_data_size {
    return Err(Error::invalid_format(
      "unsupported bitlocker FVEK payload size for the encryption method".to_string(),
    ));
  }

  let key_start = 28usize;
  let key_end = key_start + fvek_length;
  if decrypted.len() < key_end {
    return Err(Error::invalid_format(
      "bitlocker decrypted FVEK payload is truncated".to_string(),
    ));
  }
  let fvek = decrypted[key_start..key_end].to_vec();
  let tweak = if tweak_length != 0 {
    let tweak_start = 60usize;
    let tweak_end = tweak_start + tweak_length;
    if decrypted.len() < tweak_end {
      return Err(Error::invalid_format(
        "bitlocker decrypted tweak key payload is truncated".to_string(),
      ));
    }
    Some(decrypted[tweak_start..tweak_end].to_vec())
  } else {
    None
  };

  Ok((fvek, tweak))
}

fn merge_metadata_offsets(header_offsets: [u64; 3], metadata_offsets: [u64; 3]) -> [u64; 3] {
  let mut merged = [0u64; 3];
  let mut index = 0usize;

  for offset in metadata_offsets.into_iter().chain(header_offsets) {
    if offset == 0 || merged[..index].contains(&offset) {
      continue;
    }
    merged[index] = offset;
    index += 1;
    if index == merged.len() {
      break;
    }
  }

  merged
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

crate::volumes::driver::impl_volume_system_data_source!(BitlockerVolumeSystem);
