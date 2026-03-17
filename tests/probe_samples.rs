mod support;

use support::{FileDataSource, fixture_path};
use wxtla::{FormatDescriptor, formats};

#[test]
fn builtin_probes_match_sample_formats() {
  let registry = formats::builtin_probe_registry();
  let cases: [(&str, FormatDescriptor); 15] = [
    ("ewf/ext2.E01", formats::EWF_IMAGE),
    ("qcow/ext2.qcow2", formats::QCOW_IMAGE),
    ("vhd/ext2.vhd", formats::VHD_IMAGE),
    ("vhdx/ext2.vhdx", formats::VHDX_IMAGE),
    ("vmdk/ext2.vmdk", formats::VMDK_IMAGE),
    ("sparseimage/hfsplus.sparseimage", formats::SPARSE_IMAGE),
    ("udif/hfsplus_zlib.dmg", formats::UDIF_IMAGE),
    ("apm/apm.dmg", formats::APM_VOLUME_SYSTEM),
    ("gpt/gpt.raw", formats::GPT_VOLUME_SYSTEM),
    ("mbr/mbr.raw", formats::MBR_VOLUME_SYSTEM),
    ("fat/fat12.raw", formats::FAT_FILESYSTEM),
    ("ntfs/ntfs.raw", formats::NTFS_FILESYSTEM),
    ("ext/ext2.raw", formats::EXT_FILESYSTEM),
    ("hfs/hfs.raw", formats::HFS_FILESYSTEM),
    ("hfs/hfsplus.raw", formats::HFS_PLUS_FILESYSTEM),
  ];

  for (relative_path, expected) in cases {
    let source = FileDataSource::open(fixture_path(relative_path)).unwrap();
    let probe_match = registry.probe_best(&source).unwrap().unwrap();
    assert_eq!(probe_match.format, expected, "fixture: {relative_path}");
  }
}

#[test]
fn builtin_probes_reject_plain_directory_fixture_file() {
  let registry = formats::builtin_probe_registry();
  let source = FileDataSource::open(fixture_path("directory/file.txt")).unwrap();

  assert!(registry.probe_best(&source).unwrap().is_none());
}

#[test]
fn builtin_probes_report_secondary_matches_for_overlapping_signatures() {
  let registry = formats::builtin_probe_registry();
  let source = FileDataSource::open(fixture_path("gpt/gpt.raw")).unwrap();
  let report = registry.probe_all(&source).unwrap();

  assert_eq!(
    report.best_match().unwrap().format,
    formats::GPT_VOLUME_SYSTEM
  );
  assert!(
    report
      .matches()
      .iter()
      .any(|probe_match| probe_match.format == formats::MBR_VOLUME_SYSTEM)
  );
}
