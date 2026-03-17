//! Common probe traits and helpers for format detection.

use super::{DataSource, ProbeCachedDataSource, Result};

/// Broad category of a parser-visible format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatKind {
  /// Stream/archive containers such as tar or zip.
  Archive,
  /// Disk-image or evidence-image containers.
  Image,
  /// Partition-table style volume maps.
  VolumeSystem,
  /// Logical volume managers such as LVM2.
  VolumeManager,
  /// Read-only filesystems.
  FileSystem,
  /// Helper or sidecar format that is not directly mounted.
  Helper,
}

/// Stable identifier for a probeable format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FormatDescriptor {
  /// Stable machine-readable identifier.
  pub id: &'static str,
  /// Broad parser category.
  pub kind: FormatKind,
}

impl FormatDescriptor {
  /// Construct a format descriptor.
  pub const fn new(id: &'static str, kind: FormatKind) -> Self {
    Self { id, kind }
  }
}

/// Confidence level for a successful probe match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeConfidence {
  /// A weak match based on a small hint.
  Weak,
  /// A likely match with multiple corroborating indicators.
  Likely,
  /// A strong structural match.
  Strong,
  /// An exact or canonical match.
  Exact,
}

/// Successful probe result for a format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbeMatch {
  /// The matched format descriptor.
  pub format: FormatDescriptor,
  /// How confident the probe is.
  pub confidence: ProbeConfidence,
  /// Short human-readable explanation.
  pub detail: &'static str,
}

impl ProbeMatch {
  /// Construct a new probe match.
  pub const fn new(
    format: FormatDescriptor, confidence: ProbeConfidence, detail: &'static str,
  ) -> Self {
    Self {
      format,
      confidence,
      detail,
    }
  }
}

/// Result of probing a source for a specific format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeResult {
  /// The source does not match the format.
  Rejected,
  /// The source matches the format with a given confidence.
  Matched(ProbeMatch),
}

impl ProbeResult {
  /// Create a rejected result.
  pub const fn rejected() -> Self {
    Self::Rejected
  }

  /// Create a matched result.
  pub const fn matched(probe_match: ProbeMatch) -> Self {
    Self::Matched(probe_match)
  }

  /// Return `true` when the probe matched.
  pub const fn is_match(self) -> bool {
    matches!(self, Self::Matched(_))
  }
}

/// Probe matches collected from a registry scan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeReport {
  matches: Vec<ProbeMatch>,
}

impl ProbeReport {
  /// Create an empty probe report.
  pub fn new() -> Self {
    Self::default()
  }

  /// Return the best match, if any.
  pub fn best_match(&self) -> Option<ProbeMatch> {
    self.matches.first().copied()
  }

  /// Return all matches in priority order.
  pub fn matches(&self) -> &[ProbeMatch] {
    &self.matches
  }

  fn push(&mut self, probe_match: ProbeMatch) {
    self.matches.push(probe_match);
  }
}

/// Shared probe helper that provides cached small-window reads.
pub struct ProbeContext<'a> {
  source: &'a dyn DataSource,
  cached: ProbeCachedDataSource<'a>,
}

impl<'a> ProbeContext<'a> {
  /// Create a new probe context around a source.
  ///
  /// # Example
  ///
  /// ```rust,ignore
  /// let context = ProbeContext::new(source);
  /// let header = context.header(512)?;
  /// ```
  pub fn new(source: &'a dyn DataSource) -> Self {
    Self {
      source,
      cached: ProbeCachedDataSource::new(source),
    }
  }

  /// Access the underlying source.
  pub fn source(&self) -> &'a dyn DataSource {
    self.source
  }

  /// Read exactly `buf.len()` bytes through the probe cache.
  pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
    self.cached.read_exact_at(offset, buf)
  }

  /// Read `len` bytes through the probe cache.
  pub fn read_bytes_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
    self.cached.read_bytes_at(offset, len)
  }

  /// Read `len` bytes from the start of the source.
  pub fn header(&self, len: usize) -> Result<Vec<u8>> {
    self.read_bytes_at(0, len)
  }

  /// Return the total size of the source.
  pub fn size(&self) -> Result<u64> {
    self.source.size()
  }
}

/// Trait implemented by individual format probes.
pub trait FormatProbe: Send + Sync {
  /// Return the format described by this probe.
  fn descriptor(&self) -> FormatDescriptor;

  /// Probe a source using the shared probe context.
  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult>;
}

/// Registry of format probes that can scan a source and select the best match.
#[derive(Default)]
pub struct ProbeRegistry {
  probes: Vec<Box<dyn FormatProbe>>,
}

impl ProbeRegistry {
  /// Create an empty probe registry.
  pub fn new() -> Self {
    Self::default()
  }

  /// Register a probe in priority order.
  pub fn register(&mut self, probe: impl FormatProbe + 'static) {
    self.probes.push(Box::new(probe));
  }

  /// Register a probe and return the registry for chaining.
  pub fn with_probe(mut self, probe: impl FormatProbe + 'static) -> Self {
    self.register(probe);
    self
  }

  /// Return the number of registered probes.
  pub fn len(&self) -> usize {
    self.probes.len()
  }

  /// Return `true` when no probes are registered.
  pub fn is_empty(&self) -> bool {
    self.probes.is_empty()
  }

  /// Probe all registered formats and return the ordered report.
  pub fn probe_all(&self, source: &dyn DataSource) -> Result<ProbeReport> {
    let context = ProbeContext::new(source);
    let mut hits = Vec::new();

    for (registration_index, probe) in self.probes.iter().enumerate() {
      if let ProbeResult::Matched(probe_match) = probe.probe(&context)? {
        hits.push((registration_index, probe_match));
      }
    }

    hits.sort_by(|(left_index, left_match), (right_index, right_match)| {
      right_match
        .confidence
        .cmp(&left_match.confidence)
        .then(left_index.cmp(right_index))
    });

    let mut report = ProbeReport::new();
    for (_, probe_match) in hits {
      report.push(probe_match);
    }

    Ok(report)
  }

  /// Return the best probe match for a source, if any.
  pub fn probe_best(&self, source: &dyn DataSource) -> Result<Option<ProbeMatch>> {
    Ok(self.probe_all(source)?.best_match())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  struct MemDataSource {
    data: Vec<u8>,
  }

  impl DataSource for MemDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
      let offset = offset as usize;
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

  #[test]
  fn probe_context_reads_cached_header_bytes() {
    let source = MemDataSource {
      data: b"magic-header-payload".to_vec(),
    };
    let context = ProbeContext::new(&source);

    assert_eq!(context.header(5).unwrap(), b"magic");
    assert_eq!(context.read_bytes_at(6, 6).unwrap(), b"header");
  }

  #[test]
  fn probe_result_reports_matches() {
    let descriptor = FormatDescriptor::new("archive.zip", FormatKind::Archive);
    let result = ProbeResult::matched(ProbeMatch::new(
      descriptor,
      ProbeConfidence::Exact,
      "zip local header found",
    ));

    assert!(result.is_match());
  }

  struct RejectingProbe;

  impl FormatProbe for RejectingProbe {
    fn descriptor(&self) -> FormatDescriptor {
      FormatDescriptor::new("test.reject", FormatKind::Helper)
    }

    fn probe(&self, _context: &ProbeContext<'_>) -> Result<ProbeResult> {
      Ok(ProbeResult::rejected())
    }
  }

  struct MatchingProbe {
    descriptor: FormatDescriptor,
    confidence: ProbeConfidence,
  }

  impl FormatProbe for MatchingProbe {
    fn descriptor(&self) -> FormatDescriptor {
      self.descriptor
    }

    fn probe(&self, _context: &ProbeContext<'_>) -> Result<ProbeResult> {
      Ok(ProbeResult::matched(ProbeMatch::new(
        self.descriptor,
        self.confidence,
        "matched by test probe",
      )))
    }
  }

  #[test]
  fn probe_registry_sorts_by_confidence_then_registration_order() {
    let source = MemDataSource {
      data: b"probe-data".to_vec(),
    };
    let mut registry = ProbeRegistry::new();
    registry.register(MatchingProbe {
      descriptor: FormatDescriptor::new("test.weak", FormatKind::Helper),
      confidence: ProbeConfidence::Weak,
    });
    registry.register(MatchingProbe {
      descriptor: FormatDescriptor::new("test.exact", FormatKind::Helper),
      confidence: ProbeConfidence::Exact,
    });
    registry.register(MatchingProbe {
      descriptor: FormatDescriptor::new("test.exact.second", FormatKind::Helper),
      confidence: ProbeConfidence::Exact,
    });
    registry.register(RejectingProbe);

    let report = registry.probe_all(&source).unwrap();

    assert_eq!(report.best_match().unwrap().format.id, "test.exact");
    assert_eq!(
      report
        .matches()
        .iter()
        .map(|probe_match| probe_match.format.id)
        .collect::<Vec<_>>(),
      vec!["test.exact", "test.exact.second", "test.weak"]
    );
  }
}
