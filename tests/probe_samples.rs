mod support;

use support::{FileDataSource, fixture_path};
use wxtla::{FormatDescriptor, formats};

#[test]
fn builtin_probes_match_sample_formats() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let cases: [(&str, FormatDescriptor); 15] = [
    ("ewf/ext2.E01", formats::ewf::DESCRIPTOR),
    ("qcow/ext2.qcow2", formats::qcow::DESCRIPTOR),
    ("vhd/ext2.vhd", formats::vhd::DESCRIPTOR),
    ("vhdx/ext2.vhdx", formats::vhdx::DESCRIPTOR),
    ("vmdk/ext2.vmdk", formats::vmdk::DESCRIPTOR),
    (
      "sparseimage/hfsplus.sparseimage",
      formats::sparseimage::DESCRIPTOR,
    ),
    ("udif/hfsplus_zlib.dmg", formats::udif::DESCRIPTOR),
    ("apm/apm.dmg", formats::apm::DESCRIPTOR),
    ("gpt/gpt.raw", formats::gpt::DESCRIPTOR),
    ("mbr/mbr.raw", formats::mbr::DESCRIPTOR),
    ("fat/fat12.raw", formats::fat::DESCRIPTOR),
    ("ntfs/ntfs.raw", formats::ntfs::DESCRIPTOR),
    ("ext/ext2.raw", formats::ext::DESCRIPTOR),
    ("hfs/hfs.raw", formats::hfs::DESCRIPTOR),
    ("hfs/hfsplus.raw", formats::hfs::PLUS_DESCRIPTOR),
  ];

  for (relative_path, expected) in cases {
    let source = FileDataSource::open(fixture_path(relative_path)).unwrap();
    let probe_match = registry.probe_best(&source).unwrap().unwrap();
    assert_eq!(probe_match.format, expected, "fixture: {relative_path}");
  }
}

#[test]
fn builtin_probes_reject_plain_directory_fixture_file() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let source = FileDataSource::open(fixture_path("directory/file.txt")).unwrap();

  assert!(registry.probe_best(&source).unwrap().is_none());
}

#[test]
fn builtin_probes_report_secondary_matches_for_overlapping_signatures() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let source = FileDataSource::open(fixture_path("gpt/gpt.raw")).unwrap();
  let report = registry.probe_all(&source).unwrap();

  assert_eq!(
    report.best_match().unwrap().format,
    formats::gpt::DESCRIPTOR
  );
  assert!(
    report
      .matches()
      .iter()
      .any(|probe_match| probe_match.format == formats::mbr::DESCRIPTOR)
  );
}
