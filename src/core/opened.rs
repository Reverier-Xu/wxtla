//! Unified opened data-source traits and view metadata.

use super::{
  ByteSource, ByteSourceHandle, Error, FormatDescriptor, NamespaceSource, Result, SourceHints,
};

/// Format driver that opens one logical data source from a byte source.
pub trait Driver: Send + Sync {
  /// Return the descriptor handled by this driver.
  fn descriptor(&self) -> FormatDescriptor;

  /// Open a parsed data source from the provided byte source.
  fn open(
    &self, source: super::ByteSourceHandle, options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>>;
}

/// Opened logical data source exposed by a parser.
pub trait DataSource: Send + Sync {
  /// Return the descriptor for this opened data source.
  fn descriptor(&self) -> FormatDescriptor;

  /// Report which facets are available on this source.
  fn facets(&self) -> DataSourceFacets;

  /// Access the byte facet when one exists.
  fn byte_source(&self) -> Option<&dyn ByteSource> {
    None
  }

  /// Access the namespace facet when one exists.
  fn namespace(&self) -> Option<&dyn NamespaceSource> {
    None
  }

  /// Access the table facet when one exists.
  fn table_source(&self) -> Option<&dyn TableSource> {
    None
  }

  /// Enumerate child views such as partitions, volumes, or snapshots.
  fn views(&self) -> Result<Vec<DataViewRecord>> {
    Ok(Vec::new())
  }

  /// Open a child view by generic selector.
  fn open_view(
    &self, _selector: &DataViewSelector<'_>, _options: OpenOptions<'_>,
  ) -> Result<Box<dyn DataSource>> {
    Err(Error::unsupported(format!(
      "{} does not expose child views",
      self.descriptor().id
    )))
  }

  /// Reopen this data source with different credentials or verification policy.
  fn reopen(&self, _options: OpenOptions<'_>) -> Result<Box<dyn DataSource>> {
    Err(Error::unsupported(format!(
      "{} does not support reopening with different options",
      self.descriptor().id
    )))
  }
}

/// Optional table facet placeholder for future row/column formats.
pub trait TableSource: Send + Sync {
  /// Return a stable label for tracing and diagnostics.
  fn telemetry_name(&self) -> &'static str {
    std::any::type_name::<Self>()
  }
}

/// Generic opened data source that only exposes a byte facet.
pub struct ByteViewSource {
  descriptor: FormatDescriptor,
  bytes: ByteSourceHandle,
}

impl ByteViewSource {
  /// Create a byte-only opened data source.
  pub fn new(descriptor: FormatDescriptor, bytes: ByteSourceHandle) -> Self {
    Self { descriptor, bytes }
  }
}

impl DataSource for ByteViewSource {
  fn descriptor(&self) -> FormatDescriptor {
    self.descriptor
  }

  fn facets(&self) -> DataSourceFacets {
    DataSourceFacets::bytes()
  }

  fn byte_source(&self) -> Option<&dyn ByteSource> {
    Some(self.bytes.as_ref())
  }
}

/// Availability flags for the optional facets of an opened data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataSourceFacets {
  /// Whether the source exposes byte-addressable reads.
  pub bytes: bool,
  /// Whether the source exposes namespace traversal.
  pub namespace: bool,
  /// Whether the source exposes table/row access.
  pub tables: bool,
  /// Whether the source exposes child views.
  pub views: bool,
}

impl DataSourceFacets {
  /// Construct an empty facet set.
  pub const fn none() -> Self {
    Self {
      bytes: false,
      namespace: false,
      tables: false,
      views: false,
    }
  }

  /// Construct a byte-only facet set.
  pub const fn bytes() -> Self {
    Self {
      bytes: true,
      namespace: false,
      tables: false,
      views: false,
    }
  }

  /// Construct a namespace-only facet set.
  pub const fn namespace() -> Self {
    Self {
      bytes: false,
      namespace: true,
      tables: false,
      views: false,
    }
  }

  /// Mark the source as exposing child views.
  pub const fn with_views(mut self) -> Self {
    self.views = true;
    self
  }

  /// Mark the source as exposing byte reads.
  pub const fn with_bytes(mut self) -> Self {
    self.bytes = true;
    self
  }

  /// Mark the source as exposing namespaces.
  pub const fn with_namespace(mut self) -> Self {
    self.namespace = true;
    self
  }

  /// Mark the source as exposing tables.
  pub const fn with_tables(mut self) -> Self {
    self.tables = true;
    self
  }
}

/// Immutable options supplied when opening or reopening a data source.
#[derive(Clone, Copy, Default)]
pub struct OpenOptions<'a> {
  /// Related-source resolver and identity hints.
  pub hints: SourceHints<'a>,
  /// Optional credentials such as passwords or keys.
  pub credentials: &'a [Credential<'a>],
  /// Optional generic child-view selector.
  pub view: Option<DataViewSelector<'a>>,
  /// Verification strictness requested by the caller.
  pub verification: VerificationPolicy,
}

impl<'a> OpenOptions<'a> {
  /// Create empty open options.
  pub fn new() -> Self {
    Self::default()
  }

  /// Attach related-source hints.
  pub fn with_hints(mut self, hints: SourceHints<'a>) -> Self {
    self.hints = hints;
    self
  }

  /// Attach credentials.
  pub fn with_credentials(mut self, credentials: &'a [Credential<'a>]) -> Self {
    self.credentials = credentials;
    self
  }

  /// Attach a child-view selector.
  pub fn with_view(mut self, view: DataViewSelector<'a>) -> Self {
    self.view = Some(view);
    self
  }

  /// Attach a verification policy.
  pub fn with_verification(mut self, verification: VerificationPolicy) -> Self {
    self.verification = verification;
    self
  }
}

/// Generic credential carrier used by drivers that require secrets or keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential<'a> {
  /// A normal password string.
  Password(&'a str),
  /// A recovery password string.
  RecoveryPassword(&'a str),
  /// Raw key bytes.
  KeyData(&'a [u8]),
  /// A named key or secret blob.
  NamedKey(&'a str, &'a [u8]),
}

/// Verification strictness requested by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerificationPolicy {
  /// Best-effort parsing without additional integrity enforcement.
  #[default]
  BestEffort,
  /// Strict metadata validation.
  Strict,
  /// Full verification when the format supports stronger integrity checks.
  Full,
}

/// Opaque identifier for a child view.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataViewId(Box<[u8]>);

impl DataViewId {
  /// Create an identifier from raw bytes.
  pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
    Self(bytes.into().into_boxed_slice())
  }

  /// Create an identifier from a native `u64` value.
  pub fn from_u64(value: u64) -> Self {
    Self::from_bytes(value.to_le_bytes().to_vec())
  }

  /// Return the raw identifier bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

/// Common classifications for child views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataViewKind {
  /// A partition view.
  Partition,
  /// A logical volume view.
  Volume,
  /// A snapshot view.
  Snapshot,
  /// A subvolume-like view.
  Subvolume,
  /// A dataset-like view.
  Dataset,
  /// Another implementation-defined view kind.
  Other,
}

/// Generic key/value selector metadata attached to a child view.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataViewTag {
  /// Tag key.
  pub key: String,
  /// Tag value.
  pub value: String,
}

impl DataViewTag {
  /// Create a new view tag.
  pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
    Self {
      key: key.into(),
      value: value.into(),
    }
  }
}

/// Generic metadata for a child view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataViewRecord {
  /// Opaque child-view identifier.
  pub id: DataViewId,
  /// Generic view classification.
  pub kind: DataViewKind,
  /// Optional display name.
  pub name: Option<String>,
  /// Optional parent child-view identifier.
  pub parent_id: Option<DataViewId>,
  /// Facets exposed by the opened child view.
  pub facets: DataSourceFacets,
  /// Additional selector-friendly metadata.
  pub tags: Vec<DataViewTag>,
}

impl DataViewRecord {
  /// Create a new child-view record.
  pub fn new(id: DataViewId, kind: DataViewKind, facets: DataSourceFacets) -> Self {
    Self {
      id,
      kind,
      name: None,
      parent_id: None,
      facets,
      tags: Vec::new(),
    }
  }

  /// Attach a display name.
  pub fn with_name(mut self, name: impl Into<String>) -> Self {
    self.name = Some(name.into());
    self
  }

  /// Attach a parent identifier.
  pub fn with_parent_id(mut self, parent_id: DataViewId) -> Self {
    self.parent_id = Some(parent_id);
    self
  }

  /// Attach a selector tag.
  pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
    self.tags.push(DataViewTag::new(key, value));
    self
  }

  /// Return a tag value by key.
  pub fn tag_value(&self, key: &str) -> Option<&str> {
    self
      .tags
      .iter()
      .find(|tag| tag.key == key)
      .map(|tag| tag.value.as_str())
  }
}

/// Generic selector used to open child views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataViewSelector<'a> {
  /// Select by opaque identifier.
  Id(&'a DataViewId),
  /// Select by stable index-like position.
  Index(usize),
  /// Select by display name.
  Name(&'a str),
  /// Select by generic key/value tag.
  Tag(&'a str, &'a str),
}

impl DataViewSelector<'_> {
  /// Return whether this selector matches a child-view record.
  pub fn matches(&self, view: &DataViewRecord) -> bool {
    match self {
      Self::Id(id) => view.id == **id,
      Self::Index(index) => {
        view
          .tag_value("index")
          .and_then(|value| value.parse::<usize>().ok())
          == Some(*index)
      }
      Self::Name(name) => view.name.as_deref() == Some(*name),
      Self::Tag(key, value) => view.tag_value(key) == Some(*value),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn selector_matches_index_name_and_tags() {
    let view = DataViewRecord::new(
      DataViewId::from_u64(7),
      DataViewKind::Volume,
      DataSourceFacets::namespace(),
    )
    .with_name("system")
    .with_tag("index", "3")
    .with_tag("role", "system");

    assert!(DataViewSelector::Index(3).matches(&view));
    assert!(DataViewSelector::Name("system").matches(&view));
    assert!(DataViewSelector::Tag("role", "system").matches(&view));
  }
}
