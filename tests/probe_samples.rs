mod support;

use support::{FileDataSource, FixtureResolver, fixture_identity, fixture_path};
use wxtla::{
  FormatDescriptor, FormatKind, ProbeConfidence, ProbeOptions, archives, filesystems, formats,
  images, volumes,
};

#[test]
fn builtin_probes_match_sample_formats() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let cases: [(&str, FormatDescriptor); 22] = [
    ("adf/text-and-pictures.ad1", archives::adf::DESCRIPTOR),
    ("tar/sample.tar", archives::tar::DESCRIPTOR),
    ("zip/sample.zip", archives::zip::DESCRIPTOR),
    ("ewf/ext2.E01", images::ewf::DESCRIPTOR),
    ("qcow/ext2.qcow2", images::qcow::DESCRIPTOR),
    ("vhd/ext2.vhd", images::vhd::DESCRIPTOR),
    ("vhdx/ext2.vhdx", images::vhdx::DESCRIPTOR),
    ("vmdk/ext2.vmdk", images::vmdk::DESCRIPTOR),
    ("vmdk/ext2.cowd", images::vmdk::DESCRIPTOR),
    ("vmdk/ext2-descriptor.vmdk", images::vmdk::DESCRIPTOR),
    ("vmdk/ext2-cowd-descriptor.vmdk", images::vmdk::DESCRIPTOR),
    ("vmdk/ext2-flat-descriptor.vmdk", images::vmdk::DESCRIPTOR),
    (
      "sparseimage/hfsplus.sparseimage",
      images::sparseimage::DESCRIPTOR,
    ),
    ("udif/hfsplus_zlib.dmg", images::udif::DESCRIPTOR),
    ("apm/apm.dmg", volumes::apm::DESCRIPTOR),
    ("gpt/gpt.raw", volumes::gpt::DESCRIPTOR),
    ("mbr/mbr.raw", volumes::mbr::DESCRIPTOR),
    ("fat/fat12.raw", filesystems::fat::DESCRIPTOR),
    ("ntfs/ntfs.raw", filesystems::ntfs::DESCRIPTOR),
    ("ext/ext2.raw", filesystems::ext::DESCRIPTOR),
    ("hfs/hfs.raw", filesystems::hfs::DESCRIPTOR),
    ("hfs/hfsplus.raw", filesystems::hfs::PLUS_DESCRIPTOR),
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
    volumes::gpt::DESCRIPTOR
  );
  assert!(
    report
      .matches()
      .iter()
      .any(|probe_match| probe_match.format == volumes::mbr::DESCRIPTOR)
  );
}

#[test]
fn builtin_probes_match_resolver_backed_descriptor_formats() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let cases: [(&str, &str, FormatDescriptor); 2] = [
    (
      "pdi/hfsplus.hdd/DiskDescriptor.xml",
      "pdi/hfsplus.hdd",
      images::pdi::DESCRIPTOR,
    ),
    (
      "sparsebundle/hfsplus.sparsebundle/Info.plist",
      "sparsebundle/hfsplus.sparsebundle",
      images::sparsebundle::DESCRIPTOR,
    ),
  ];

  for (source_path, resolver_root, expected) in cases {
    let source = FileDataSource::open(fixture_path(source_path)).unwrap();
    let resolver = FixtureResolver::new(fixture_path(resolver_root));
    let probe_match = registry
      .probe_best_with_resolver(&source, &resolver)
      .unwrap()
      .unwrap();

    assert_eq!(probe_match.format, expected, "fixture: {source_path}");
    assert_eq!(probe_match.confidence, ProbeConfidence::Exact);
  }
}

#[test]
fn builtin_probes_can_fall_back_without_a_resolver_for_descriptor_formats() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let source = FileDataSource::open(fixture_path("pdi/hfsplus.hdd/DiskDescriptor.xml")).unwrap();
  let probe_match = registry.probe_best(&source).unwrap().unwrap();

  assert_eq!(probe_match.format, images::pdi::DESCRIPTOR);
  assert_eq!(probe_match.confidence, ProbeConfidence::Likely);
}

#[test]
fn builtin_probes_accept_source_identity_hints() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let source = FileDataSource::open(fixture_path("gpt/gpt.raw")).unwrap();
  let identity = fixture_identity("gpt/gpt.raw");
  let probe_match = registry
    .probe_best_with_options(&source, ProbeOptions::new().with_source_identity(&identity))
    .unwrap()
    .unwrap();

  assert_eq!(probe_match.format, volumes::gpt::DESCRIPTOR);
}

#[test]
fn splitraw_probe_requires_identity_and_resolver_hints() {
  let registry = formats::probe_registry_from_inventory(formats::builtin_inventory());
  let source = FileDataSource::open(fixture_path("splitraw/ext2.raw.000")).unwrap();
  let resolver = FixtureResolver::new(fixture_path("splitraw"));
  let identity = fixture_identity("ext2.raw.000");

  let hinted_match = registry
    .probe_best_with_options(
      &source,
      ProbeOptions::new()
        .with_resolver(&resolver)
        .with_source_identity(&identity),
    )
    .unwrap()
    .unwrap();
  let unhinted_match = registry
    .probe_best_with_resolver(&source, &resolver)
    .unwrap()
    .unwrap();

  assert_eq!(hinted_match.format, images::splitraw::DESCRIPTOR);
  assert_eq!(unhinted_match.format, filesystems::ext::DESCRIPTOR);
}

#[test]
fn category_specific_registries_limit_probe_scope() {
  let inventory = formats::builtin_inventory();
  let images_registry =
    formats::probe_registry_from_inventory_for_kind(&inventory, FormatKind::Image);
  let volumes_registry =
    formats::probe_registry_from_inventory_for_kind(&inventory, FormatKind::VolumeSystem);
  let source = FileDataSource::open(fixture_path("gpt/gpt.raw")).unwrap();

  assert!(images_registry.probe_best(&source).unwrap().is_none());
  assert_eq!(
    volumes_registry
      .probe_best(&source)
      .unwrap()
      .unwrap()
      .format,
    volumes::gpt::DESCRIPTOR
  );
}
