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
  ByteSource, ByteSourceHandle, FileDataSource,
  images::ewf::EwfImage,
  volumes::{bitlocker::BitlockerKeyProtectorKind, mbr::MbrDriver},
};

type Aes256Ccm = Ccm<Aes256, U16, U12>;

struct MemDataSource {
  data: Vec<u8>,
}

impl ByteSource for MemDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let offset =
      usize::try_from(offset).map_err(|_| Error::invalid_range("test read offset is too large"))?;
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
  let ewf_source: ByteSourceHandle =
    Arc::new(FileDataSource::open(fixture_path("bitlocker/bitlocker.E01")).unwrap());
  let image: ByteSourceHandle = Arc::new(EwfImage::open(ewf_source).unwrap());
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

fn build_vista_volume_header(first_metadata_lcn: u64, volume_size: u64) -> [u8; 512] {
  let mut data = [0u8; 512];
  let total_sectors = volume_size / 512;
  data[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
  data[3..11].copy_from_slice(b"-FVE-FS-");
  data[11..13].copy_from_slice(&512u16.to_le_bytes());
  data[13] = 8;
  data[40..48].copy_from_slice(&total_sectors.to_le_bytes());
  data[56..64].copy_from_slice(&first_metadata_lcn.to_le_bytes());
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

fn build_vista_metadata_block(entries: &[Vec<u8>], metadata_offsets: [u64; 3]) -> Vec<u8> {
  let mut entry_bytes = entries.concat();
  entry_bytes.extend_from_slice(&[0u8; 8]);
  let metadata_size = 48 + u32::try_from(entry_bytes.len()).unwrap();

  let mut header = vec![0u8; 48];
  header[0..4].copy_from_slice(&metadata_size.to_le_bytes());
  header[4..8].copy_from_slice(&1u32.to_le_bytes());
  header[8..12].copy_from_slice(&48u32.to_le_bytes());
  header[12..16].copy_from_slice(&metadata_size.to_le_bytes());

  let mut block_header = vec![0u8; 64];
  block_header[0..8].copy_from_slice(BLOCK_SIGNATURE);
  block_header[8..10].copy_from_slice(&64u16.to_le_bytes());
  block_header[10..12].copy_from_slice(&1u16.to_le_bytes());
  for (index, offset) in metadata_offsets.iter().enumerate() {
    let start = 32 + index * 8;
    block_header[start..start + 8].copy_from_slice(&offset.to_le_bytes());
  }

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
    image[offset as usize..offset as usize + metadata_block.len()].copy_from_slice(&metadata_block);
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
  let (metadata, vmk, fvek, tweak) = build_synthetic_metadata(BitlockerEncryptionMethod::Aes256Cbc);
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
  }) as ByteSourceHandle;

  let mut system = BitlockerVolumeSystem::open(source).unwrap();
  assert!(system.is_locked());
  assert!(system.unlock_with_clear_key().unwrap());
  let volume = system.open_volume(0).unwrap();
  let header = volume.read_bytes_at(0, 8).unwrap();
  assert_eq!(&header, b"TESTNTFS");
}

#[test]
fn opens_vista_style_headers_via_metadata_lcn_fallback() {
  let metadata_offsets = [0x1000u64, 0x1800u64, 0x2000u64];
  let volume_size = 0x6000u64;
  let metadata_block = build_vista_metadata_block(&[], metadata_offsets);
  let mut image = vec![0u8; volume_size as usize];
  image[..512].copy_from_slice(&build_vista_volume_header(1, volume_size));
  for offset in metadata_offsets {
    image[offset as usize..offset as usize + metadata_block.len()].copy_from_slice(&metadata_block);
  }

  let system = BitlockerVolumeSystem::open(Arc::new(MemDataSource { data: image })).unwrap();

  assert!(!system.is_locked());
  assert_eq!(system.header().version, 6);
  assert_eq!(system.header().metadata_offsets, metadata_offsets);
  assert_eq!(system.open_volume(0).unwrap().size().unwrap(), volume_size);
}

#[test]
fn unlocks_without_a_volume_header_metadata_entry() {
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
  ];
  let mut plaintext_header = [0u8; 512];
  plaintext_header[..8].copy_from_slice(b"TESTNTFS");
  let source = Arc::new(MemDataSource {
    data: build_synthetic_volume(method, entries, &fvek, None, &plaintext_header),
  }) as ByteSourceHandle;

  let mut system = BitlockerVolumeSystem::open(source).unwrap();

  assert!(system.unlock_with_clear_key().unwrap());
  assert_eq!(
    &system.open_volume(0).unwrap().read_bytes_at(0, 8).unwrap(),
    b"TESTNTFS"
  );
}

#[test]
fn unlocks_with_nonstandard_key_payload_headers() {
  let method = BitlockerEncryptionMethod::Aes128Cbc;
  let clear_key = [0x23; 32];
  let vmk = [0x34; 32];
  let fvek = vec![0x45; method.fvek_length()];
  let mut vmk_plain = vec![0u8; 48];
  vmk_plain[0..2].copy_from_slice(&48u16.to_le_bytes());
  vmk_plain[4..6].copy_from_slice(&2u16.to_le_bytes());
  vmk_plain[12..44].copy_from_slice(&vmk);
  let mut fvek_plain = [0u8; 16 + 0x1C + 4];
  let fvek_data_size = u16::try_from(fvek_plain.len() - 16).unwrap();
  fvek_plain[16..18].copy_from_slice(&fvek_data_size.to_le_bytes());
  fvek_plain[20..22].copy_from_slice(&2u16.to_le_bytes());
  fvek_plain[28..28 + fvek.len()].copy_from_slice(&fvek);
  let entries = vec![
    vmk_entry(
      BitlockerKeyProtectorKind::ClearKey,
      Some(key_property(BitlockerEncryptionMethod::None, &clear_key)),
      None,
      aes_ccm_property([7; 12], &vmk_plain, &clear_key),
    ),
    metadata_entry(
      ENTRY_TYPE_FULL_VOLUME_ENCRYPTION_KEY,
      VALUE_TYPE_AES_CCM_ENCRYPTED_KEY,
      &aes_ccm_property([9; 12], &fvek_plain[16..], &vmk)[8..],
    ),
  ];
  let mut plaintext_header = [0u8; 512];
  plaintext_header[..8].copy_from_slice(b"TESTNTFS");
  let source = Arc::new(MemDataSource {
    data: build_synthetic_volume(method, entries, &fvek, None, &plaintext_header),
  }) as ByteSourceHandle;

  let mut system = BitlockerVolumeSystem::open(source).unwrap();

  assert!(system.unlock_with_clear_key().unwrap());
  assert_eq!(
    &system.open_volume(0).unwrap().read_bytes_at(0, 8).unwrap(),
    b"TESTNTFS"
  );
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
  }) as ByteSourceHandle)
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
  }) as ByteSourceHandle)
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
  }) as ByteSourceHandle)
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
  }) as ByteSourceHandle;

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
  const FIXTURE_RECOVERY_PASSWORD: &str = "447854-362307-188650-128513-644006-423984-040843-662508";
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
