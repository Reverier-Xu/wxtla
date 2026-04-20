use std::path::Path;

use super::*;

fn fixture_bytes(name: &str) -> Vec<u8> {
  std::fs::read(
    Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("formats")
      .join("apfs")
      .join("libfsapfs")
      .join(name),
  )
  .expect("fixture bytes")
}

#[test]
fn fletcher64_matches_container_superblock_fixture() {
  let fixture = fixture_bytes("container_superblock.1");
  let header = ApfsObjectHeader::parse(&fixture).unwrap();

  assert_eq!(fletcher64(&fixture[8..]), header.checksum);
}

#[test]
fn parses_container_superblock_fixture() {
  let fixture = fixture_bytes("container_superblock.1");
  let superblock = ApfsContainerSuperblock::parse(&fixture).unwrap();

  superblock.validate(&fixture, 1).unwrap();
  assert_eq!(superblock.block_size, 4096);
  assert_eq!(superblock.block_count, 246);
  assert_eq!(superblock.incompatible_features, 2);
  assert_eq!(superblock.checkpoint_descriptor_blocks, 8);
  assert_eq!(superblock.checkpoint_data_blocks, 52);
  assert_eq!(superblock.checkpoint_descriptor_base, 1);
  assert_eq!(superblock.checkpoint_data_base, 9);
  assert_eq!(superblock.omap_oid, 90);
  assert_eq!(superblock.file_system_oids, vec![1026]);
  assert_eq!(superblock.blocked_out_prange, None);
  assert_eq!(superblock.fusion_middle_tree_oid, 0);
  assert_eq!(superblock.media_keybag_prange, None);
}

#[test]
fn parses_object_map_fixture() {
  let fixture = fixture_bytes("container_object_map.1");
  let omap = ApfsObjectMap::parse(&fixture).unwrap();

  omap.validate(&fixture, 83).unwrap();
  assert_eq!(omap.flags, 1);
  assert_eq!(omap.tree_type, OBJ_PHYSICAL | OBJECT_TYPE_BTREE);
  assert_eq!(omap.tree_oid, 84);
}

#[test]
fn parses_checkpoint_map_fixture() {
  let fixture = fixture_bytes("checkpoint_map.1");
  let map = ApfsCheckpointMap::parse(&fixture).unwrap();

  map.validate(&fixture).unwrap();
  assert!(map.is_last());
  assert_eq!(map.entry_count, 2);
  assert_eq!(map.entries[0].object_type, 0x8000_0005);
  assert_eq!(map.entries[0].object_type_name(), "spaceman");
  assert_eq!(map.entries[0].object_storage_kind_name(), "ephemeral");
  assert_eq!(map.entries[0].object_flag_names(), Vec::<&str>::new());
  assert_eq!(map.entries[0].size, 0x1000);
  assert_eq!(map.entries[0].object_id, 1024);
  assert_eq!(map.entries[0].physical_address, 9);
  assert_eq!(map.entries[1].object_type, 0x8000_0011);
  assert_eq!(map.entries[1].object_type_name(), "nx_reaper");
  assert_eq!(map.entries[1].object_storage_kind_name(), "ephemeral");
  assert_eq!(map.entries[1].physical_address, 10);
}

#[test]
fn parses_checkpoint_map_entry_fixture() {
  let entry = ApfsCheckpointMapping::parse(&fixture_bytes("checkpoint_map_entry.1")).unwrap();

  assert_eq!(entry.object_type, 0x8000_0005);
  assert_eq!(entry.object_subtype, 0);
  assert_eq!(entry.size, 0x1000);
  assert_eq!(entry.file_system_object_id, 0);
  assert_eq!(entry.object_id, 1024);
  assert_eq!(entry.physical_address, 9);
}

#[test]
fn parses_volume_superblock_fixture() {
  let fixture = fixture_bytes("volume_superblock.1");
  let superblock = ApfsVolumeSuperblock::parse(&fixture).unwrap();

  superblock.validate(&fixture).unwrap();
  assert_eq!(superblock.fs_index, 0);
  assert_eq!(superblock.omap_oid, 105);
  assert_eq!(superblock.root_tree_oid, 1028);
  assert_eq!(superblock.snap_meta_tree_oid, 88);
  assert_eq!(superblock.role, 0);
  assert_eq!(superblock.volume_name, "TestVolume");
  assert_eq!(superblock.doc_id_tree_oid, 0);
  assert_eq!(superblock.secondary_root_tree_oid, 0);
}

#[test]
fn parses_btree_header_and_footer_fixtures() {
  let header = ApfsBtreeNodeHeader::parse(&fixture_bytes("btree_header.1")).unwrap();
  let footer = ApfsBtreeInfo::parse(&fixture_bytes("btree_footer.1")).unwrap();

  assert_eq!(
    header.flags,
    BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE
  );
  assert_eq!(header.key_count, 1);
  assert_eq!(footer.flags, BTREE_PHYSICAL | 0x0000_0002);
  assert_eq!(footer.node_size, 4096);
  assert_eq!(footer.key_size, 16);
  assert_eq!(footer.value_size, 16);
}

#[test]
fn parses_integrity_metadata_blocks() {
  let mut block = vec![0u8; 128];
  block[24..28].copy_from_slice(&OBJECT_TYPE_INTEGRITY_META.to_le_bytes());
  block[32..36].copy_from_slice(&2u32.to_le_bytes());
  block[36..40].copy_from_slice(&APFS_SEAL_BROKEN.to_le_bytes());
  block[40..44].copy_from_slice(&APFS_HASH_SHA256.to_le_bytes());
  block[44..48].copy_from_slice(&96u32.to_le_bytes());
  block[48..56].copy_from_slice(&123u64.to_le_bytes());
  block[96..128].copy_from_slice(&[0xAB; 32]);
  let checksum = fletcher64(&block[8..]);
  block[0..8].copy_from_slice(&checksum.to_le_bytes());

  let metadata = ApfsIntegrityMetadata::parse(&block).unwrap();

  assert_eq!(metadata.version, 2);
  assert!(metadata.seal_broken());
  assert_eq!(metadata.hash_type, APFS_HASH_SHA256);
  assert_eq!(metadata.broken_xid, 123);
  assert_eq!(metadata.root_hash.as_ref(), &[0xAB; 32]);
}

#[test]
fn parses_modern_volume_superblock_tail_fields() {
  let mut block = fixture_bytes("volume_superblock.1");
  let features = APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE.to_le_bytes();
  block[40..48].copy_from_slice(&features);
  let incompat = (APFS_INCOMPAT_CASE_INSENSITIVE
    | APFS_INCOMPAT_DATALESS_SNAPS
    | APFS_INCOMPAT_SECONDARY_FSROOT)
    .to_le_bytes();
  block[56..64].copy_from_slice(&incompat);
  block[96..98].copy_from_slice(&1u16.to_le_bytes());
  block[98..100].copy_from_slice(&2u16.to_le_bytes());
  block[100..104].copy_from_slice(&3u32.to_le_bytes());
  block[104..108].copy_from_slice(&4u32.to_le_bytes());
  block[108..112].copy_from_slice(&5u32.to_le_bytes());
  block[112..114].copy_from_slice(&6u16.to_le_bytes());
  block[116..120].copy_from_slice(&2u32.to_le_bytes());
  block[120..124].copy_from_slice(&3u32.to_le_bytes());
  block[124..128].copy_from_slice(&4u32.to_le_bytes());
  block[1056..1064].copy_from_slice(&55u64.to_le_bytes());
  block[1064..1068].copy_from_slice(&7u32.to_le_bytes());
  block[1068..1072].copy_from_slice(&9u32.to_le_bytes());
  block[1072..1080].copy_from_slice(&100u64.to_le_bytes());
  block[1080..1088].copy_from_slice(&101u64.to_le_bytes());
  block[1088..1096].copy_from_slice(&102u64.to_le_bytes());
  block[1096..1104].copy_from_slice(&103u64.to_le_bytes());
  block[1104..1108].copy_from_slice(&11u32.to_le_bytes());
  block[1044..1048].copy_from_slice(&13u32.to_le_bytes());
  block[1048..1056].copy_from_slice(&104u64.to_le_bytes());
  block[1108..1112].copy_from_slice(&17u32.to_le_bytes());
  let checksum = fletcher64(&block[8..]);
  block[0..8].copy_from_slice(&checksum.to_le_bytes());

  let superblock = ApfsVolumeSuperblock::parse(&block).unwrap();
  superblock.validate(&block).unwrap();

  assert!(superblock.has_dataless_snapshots());
  assert!(superblock.has_secondary_fs_root());
  assert!(superblock.uses_volume_group_system_inode_space());
  assert_eq!(superblock.meta_crypto.major_version, 1);
  assert_eq!(superblock.meta_crypto.minor_version, 2);
  assert_eq!(superblock.meta_crypto.flags, 3);
  assert_eq!(superblock.meta_crypto.persistent_class, 4);
  assert_eq!(superblock.meta_crypto.key_os_version, 5);
  assert_eq!(superblock.meta_crypto.key_revision, 6);
  assert_eq!(superblock.pfkur_tree_type, 13);
  assert_eq!(superblock.pfkur_tree_oid, 104);
  assert_eq!(superblock.doc_id_index_xid, 55);
  assert_eq!(superblock.doc_id_index_flags, 7);
  assert_eq!(superblock.doc_id_tree_type, 9);
  assert_eq!(superblock.doc_id_tree_oid, 100);
  assert_eq!(superblock.prev_doc_id_tree_oid, 101);
  assert_eq!(superblock.doc_id_fixup_cursor, 102);
  assert_eq!(superblock.secondary_root_tree_oid, 103);
  assert_eq!(superblock.secondary_root_tree_type, 11);
  assert_eq!(superblock.clone_group_tree_flags, 17);
}

#[test]
fn parses_volume_change_history_and_counters() {
  let mut block = fixture_bytes("volume_superblock.1");
  block[60..68].copy_from_slice(&7u64.to_le_bytes());
  block[68..76].copy_from_slice(&11u64.to_le_bytes());
  block[76..84].copy_from_slice(&13u64.to_le_bytes());
  block[84..92].copy_from_slice(&17u64.to_le_bytes());
  block[116..120].copy_from_slice(&2u32.to_le_bytes());
  block[120..124].copy_from_slice(&3u32.to_le_bytes());
  block[124..128].copy_from_slice(&4u32.to_le_bytes());
  block[160..168].copy_from_slice(&19u64.to_le_bytes());
  block[168..176].copy_from_slice(&23u64.to_le_bytes());
  block[184..192].copy_from_slice(&29u64.to_le_bytes());
  block[192..200].copy_from_slice(&31u64.to_le_bytes());
  block[200..208].copy_from_slice(&37u64.to_le_bytes());
  block[208..216].copy_from_slice(&41u64.to_le_bytes());
  block[224..232].copy_from_slice(&43u64.to_le_bytes());
  block[232..240].copy_from_slice(&47u64.to_le_bytes());
  let mut formatted_id = [0u8; 32];
  formatted_id[..13].copy_from_slice(b"mkfs.apfs 123");
  block[272..304].copy_from_slice(&formatted_id);
  block[304..312].copy_from_slice(&53u64.to_le_bytes());
  block[312..320].copy_from_slice(&59u64.to_le_bytes());
  let mut modified_id = [0u8; 32];
  modified_id[..15].copy_from_slice(b"diskmanagementd");
  block[320..352].copy_from_slice(&modified_id);
  block[352..360].copy_from_slice(&61u64.to_le_bytes());
  block[360..368].copy_from_slice(&67u64.to_le_bytes());
  let checksum = fletcher64(&block[8..]);
  block[0..8].copy_from_slice(&checksum.to_le_bytes());

  let superblock = ApfsVolumeSuperblock::parse(&block).unwrap();
  superblock.validate(&block).unwrap();

  assert_eq!(superblock.unmount_time, 7);
  assert_eq!(superblock.reserve_block_count, 11);
  assert_eq!(superblock.quota_block_count, 13);
  assert_eq!(superblock.alloc_block_count, 17);
  assert_eq!(superblock.root_tree_type, 2);
  assert_eq!(superblock.extentref_tree_type, 3);
  assert_eq!(superblock.snap_meta_tree_type, 4);
  assert_eq!(superblock.revert_to_xid, 19);
  assert_eq!(superblock.revert_to_sblock_oid, 23);
  assert_eq!(superblock.number_of_files, 29);
  assert_eq!(superblock.number_of_directories, 31);
  assert_eq!(superblock.number_of_symlinks, 37);
  assert_eq!(superblock.number_of_other_fsobjects, 41);
  assert_eq!(superblock.total_blocks_allocated, 43);
  assert_eq!(superblock.total_blocks_freed, 47);
  assert_eq!(superblock.formatted_by.application_id, "mkfs.apfs 123");
  assert_eq!(superblock.formatted_by.timestamp, 53);
  assert_eq!(superblock.formatted_by.last_xid, 59);
  assert_eq!(superblock.modified_by[0].application_id, "diskmanagementd");
  assert_eq!(superblock.modified_by[0].timestamp, 61);
  assert_eq!(superblock.modified_by[0].last_xid, 67);
  assert!(superblock.modified_by[1].is_empty());
}

#[test]
fn parses_container_fusion_and_auxiliary_metadata() {
  let mut block = fixture_bytes("container_superblock.1");
  let incompat = (APFS_INCOMPAT_CASE_INSENSITIVE | NX_INCOMPAT_FUSION).to_le_bytes();
  block[64..72].copy_from_slice(&incompat);
  block[176..180].copy_from_slice(&67u32.to_le_bytes());
  block[984..992].copy_from_slice(&71u64.to_le_bytes());
  block[992..1000].copy_from_slice(&73u64.to_le_bytes());
  block[1240..1248].copy_from_slice(&71u64.to_le_bytes());
  block[1248..1256].copy_from_slice(&73u64.to_le_bytes());
  block[1256..1264].copy_from_slice(&79u64.to_le_bytes());
  block[1264..1272].copy_from_slice(&NX_CRYPTO_SW.to_le_bytes());
  block[1272..1280].copy_from_slice(&83u64.to_le_bytes());
  block[1280..1296].copy_from_slice(&[0x55; 16]);
  block[1296..1304].copy_from_slice(&89u64.to_le_bytes());
  block[1304..1312].copy_from_slice(&97u64.to_le_bytes());
  block[1312..1320].copy_from_slice(&101u64.to_le_bytes());
  block[1320..1328].copy_from_slice(&103u64.to_le_bytes());
  block[1328..1336].copy_from_slice(&107u64.to_le_bytes());
  block[1336..1344].copy_from_slice(&109u64.to_le_bytes());
  block[1344..1352].copy_from_slice(&113u64.to_le_bytes());
  block[1352..1360].copy_from_slice(&127u64.to_le_bytes());
  block[1360..1368].copy_from_slice(&131u64.to_le_bytes());
  block[1368..1376].copy_from_slice(&137u64.to_le_bytes());
  block[1376..1384].copy_from_slice(&139u64.to_le_bytes());
  block[1384..1392].copy_from_slice(&149u64.to_le_bytes());
  block[1392..1400].copy_from_slice(&151u64.to_le_bytes());
  block[1400..1408].copy_from_slice(&157u64.to_le_bytes());
  let checksum = fletcher64(&block[8..]);
  block[0..8].copy_from_slice(&checksum.to_le_bytes());

  let superblock = ApfsContainerSuperblock::parse(&block).unwrap();
  superblock.validate(&block, 1).unwrap();

  assert!(superblock.is_fusion());
  assert!(superblock.uses_software_crypto());
  assert_eq!(superblock.test_type, 67);
  assert_eq!(superblock.counters[0], 71);
  assert_eq!(superblock.counters[1], 73);
  assert_eq!(superblock.blocked_out_prange.unwrap().start_paddr, 71);
  assert_eq!(superblock.blocked_out_prange.unwrap().block_count, 73);
  assert_eq!(superblock.evict_mapping_tree_oid, 79);
  assert_eq!(superblock.efi_jumpstart_oid, 83);
  assert_eq!(superblock.fusion_uuid, [0x55; 16]);
  assert_eq!(superblock.container_keybag_prange.unwrap().start_paddr, 89);
  assert_eq!(superblock.container_keybag_prange.unwrap().block_count, 97);
  assert_eq!(superblock.ephemeral_info, [101, 103, 107, 109]);
  assert_eq!(superblock.test_oid, 113);
  assert_eq!(superblock.fusion_middle_tree_oid, 127);
  assert_eq!(superblock.fusion_wbc_oid, 131);
  assert_eq!(superblock.fusion_wbc_prange.unwrap().start_paddr, 137);
  assert_eq!(superblock.fusion_wbc_prange.unwrap().block_count, 139);
  assert_eq!(superblock.newest_mounted_version, 149);
  assert_eq!(superblock.media_keybag_prange.unwrap().start_paddr, 151);
  assert_eq!(superblock.media_keybag_prange.unwrap().block_count, 157);
}
