//! Parser-facing resolution of related byte sources.

use std::{fmt, sync::Arc};

use super::{ByteSource, Error, Result};

/// Shared handle to a data source.
pub type ByteSourceHandle = Arc<dyn ByteSource>;

/// Lexical relative path used to look up parser-related sources.
///
/// This path type is host-agnostic. It models logical components such as
/// sibling image segments, bundle bands, or backing files without embedding any
/// platform path behavior into the parser core.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RelatedPathBuf {
  components: Vec<RelatedPathComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RelatedPathComponent {
  Current,
  Parent,
  Normal(String),
}

impl RelatedPathBuf {
  /// Create an empty relative path.
  pub fn new() -> Self {
    Self::default()
  }

  /// Parse a lexical relative path using `/` or `\` separators.
  ///
  /// # Example
  ///
  /// ```rust
  /// use wxtla::RelatedPathBuf;
  ///
  /// let path = RelatedPathBuf::from_relative_path("bands/0").unwrap();
  /// assert_eq!(path.to_string(), "bands/0");
  /// ```
  pub fn from_relative_path(path: &str) -> Result<Self> {
    if path.is_empty() {
      return Ok(Self::new());
    }

    if path.starts_with('/') || path.starts_with('\\') {
      return Err(Error::invalid_source_reference(format!(
        "related path must be relative: {path}"
      )));
    }

    let mut parsed = Self::new();
    for component in path.split(['/', '\\']) {
      if component.is_empty() {
        return Err(Error::invalid_source_reference(format!(
          "related path contains an empty component: {path}"
        )));
      }

      match component {
        "." => {
          parsed.push_current();
        }
        ".." => {
          parsed.push_parent();
        }
        normal => {
          parsed.push_normal(normal)?;
        }
      }
    }

    Ok(parsed)
  }

  /// Append a `.` path component.
  pub fn push_current(&mut self) -> &mut Self {
    self.components.push(RelatedPathComponent::Current);
    self
  }

  /// Append a `..` path component.
  pub fn push_parent(&mut self) -> &mut Self {
    self.components.push(RelatedPathComponent::Parent);
    self
  }

  /// Append a normal lexical path component.
  pub fn push_normal(&mut self, component: impl Into<String>) -> Result<&mut Self> {
    let component = component.into();
    validate_normal_component(&component)?;
    self
      .components
      .push(RelatedPathComponent::Normal(component));
    Ok(self)
  }

  /// Return `true` when the path has no components.
  pub fn is_empty(&self) -> bool {
    self.components.is_empty()
  }

  /// Return the final normal path component when one exists.
  pub fn file_name(&self) -> Option<&str> {
    self
      .components
      .last()
      .and_then(RelatedPathComponent::normal_component)
  }

  /// Iterate over the path components as strings.
  pub fn components(&self) -> impl Iterator<Item = &str> {
    self.components.iter().map(RelatedPathComponent::as_str)
  }

  /// Join two lexical related paths.
  pub fn join(&self, other: &Self) -> Self {
    let mut joined = self.clone();
    joined.components.extend(other.components.iter().cloned());
    joined
  }

  /// Return the lexical parent path when one exists.
  pub fn parent(&self) -> Option<Self> {
    if self.components.is_empty() {
      return None;
    }

    let mut parent = self.clone();
    parent.components.pop();
    Some(parent)
  }
}

impl fmt::Display for RelatedPathBuf {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if self.components.is_empty() {
      return write!(f, ".");
    }

    let mut first = true;
    for component in &self.components {
      if !first {
        write!(f, "/")?;
      }
      first = false;
      write!(f, "{}", component.as_str())?;
    }
    Ok(())
  }
}

impl RelatedPathComponent {
  fn as_str(&self) -> &str {
    match self {
      Self::Current => ".",
      Self::Parent => "..",
      Self::Normal(component) => component.as_str(),
    }
  }

  fn normal_component(&self) -> Option<&str> {
    match self {
      Self::Normal(component) => Some(component.as_str()),
      Self::Current | Self::Parent => None,
    }
  }
}

fn validate_normal_component(component: &str) -> Result<()> {
  if component.is_empty() {
    return Err(Error::invalid_source_reference(
      "related path component must not be empty".to_string(),
    ));
  }

  if component == "." || component == ".." {
    return Err(Error::invalid_source_reference(format!(
      "special path component must use explicit helpers: {component}"
    )));
  }

  if component.contains(['/', '\\', '\0']) {
    return Err(Error::invalid_source_reference(format!(
      "invalid related path component: {component}"
    )));
  }

  Ok(())
}

/// Host-agnostic identity hint for a source presented to a probe or parser.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceIdentity {
  logical_path: RelatedPathBuf,
}

impl SourceIdentity {
  /// Create a new source identity from a logical path.
  pub fn new(logical_path: RelatedPathBuf) -> Self {
    Self { logical_path }
  }

  /// Create a source identity from a relative path string.
  pub fn from_relative_path(path: &str) -> Result<Self> {
    Ok(Self::new(RelatedPathBuf::from_relative_path(path)?))
  }

  /// Return the logical path associated with this identity.
  pub fn logical_path(&self) -> &RelatedPathBuf {
    &self.logical_path
  }

  /// Return the final entry name when one exists.
  pub fn entry_name(&self) -> Option<&str> {
    self.logical_path.file_name()
  }

  /// Return the filename extension when one exists.
  pub fn extension(&self) -> Option<&str> {
    let (_, extension) = self.entry_name()?.rsplit_once('.')?;
    if extension.is_empty() {
      None
    } else {
      Some(extension)
    }
  }

  /// Build a sibling path next to this source identity.
  pub fn sibling_path(&self, entry_name: impl Into<String>) -> Result<RelatedPathBuf> {
    let mut path = self.logical_path.parent().unwrap_or_default();
    path.push_normal(entry_name)?;
    Ok(path)
  }
}

/// Why a parser is asking for another source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelatedSourcePurpose {
  /// A backing image referenced by another image layer.
  BackingFile,
  /// A numbered or named segment in a multipart image set.
  Segment,
  /// A sidecar descriptor or metadata file.
  Descriptor,
  /// A sparse bundle band.
  Band,
  /// A file extent or extent-like child object.
  Extent,
  /// A generic metadata resource.
  Metadata,
  /// Any parser-specific auxiliary source.
  Auxiliary,
}

/// A parser request for a related source.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelatedSourceRequest {
  /// Why the parser is requesting the source.
  pub purpose: RelatedSourcePurpose,
  /// Lexical path inside the resolver's own scope.
  pub path: RelatedPathBuf,
}

impl RelatedSourceRequest {
  /// Create a new related-source request.
  ///
  /// # Example
  ///
  /// ```rust
  /// use wxtla::{RelatedPathBuf, RelatedSourcePurpose, RelatedSourceRequest};
  ///
  /// let request = RelatedSourceRequest::new(
  ///   RelatedSourcePurpose::Band,
  ///   RelatedPathBuf::from_relative_path("bands/0").unwrap(),
  /// );
  /// assert_eq!(request.path.to_string(), "bands/0");
  /// ```
  pub fn new(purpose: RelatedSourcePurpose, path: RelatedPathBuf) -> Self {
    Self { purpose, path }
  }
}

/// Adapter interface for resolving parser-related sources.
pub trait RelatedSourceResolver: Send + Sync {
  /// Resolve a parser-related source within the resolver's own scope.
  fn resolve(&self, request: &RelatedSourceRequest) -> Result<Option<ByteSourceHandle>>;

  /// Return a stable label for tracing and diagnostics.
  fn telemetry_name(&self) -> &'static str {
    std::any::type_name::<Self>()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn related_path_parses_relative_components() {
    let path = RelatedPathBuf::from_relative_path("bands/../bands/0").unwrap();

    assert_eq!(
      path.components().collect::<Vec<_>>(),
      vec!["bands", "..", "bands", "0"]
    );
    assert_eq!(path.to_string(), "bands/../bands/0");
  }

  #[test]
  fn related_path_rejects_absolute_paths() {
    let error = RelatedPathBuf::from_relative_path("/bands/0").unwrap_err();

    assert!(matches!(error, Error::InvalidSourceReference(_)));
  }

  #[test]
  fn related_path_join_preserves_lexical_components() {
    let left = RelatedPathBuf::from_relative_path("images").unwrap();
    let right = RelatedPathBuf::from_relative_path("disk/segments").unwrap();

    assert_eq!(left.join(&right).to_string(), "images/disk/segments");
  }

  #[test]
  fn related_path_reports_final_normal_component() {
    let path = RelatedPathBuf::from_relative_path("images/disk.raw.000").unwrap();

    assert_eq!(path.file_name(), Some("disk.raw.000"));
  }

  #[test]
  fn source_identity_exposes_entry_name_and_extension() {
    let identity = SourceIdentity::from_relative_path("segments/disk.raw.000").unwrap();

    assert_eq!(identity.entry_name(), Some("disk.raw.000"));
    assert_eq!(identity.extension(), Some("000"));
  }

  #[test]
  fn source_identity_builds_sibling_paths() {
    let identity = SourceIdentity::from_relative_path("segments/disk.raw.000").unwrap();

    assert_eq!(
      identity.sibling_path("disk.raw.001").unwrap().to_string(),
      "segments/disk.raw.001"
    );
  }
}
