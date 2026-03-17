//! Split raw image descriptor and probe registration.

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, RelatedSourcePurpose, RelatedSourceRequest, Result,
};

/// Split raw image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.splitraw", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

const MIN_SEGMENT_DIGITS: usize = 3;

fn register_probes(registry: &mut ProbeRegistry) {
  registry.register(SplitRawProbe);
}

struct SplitRawProbe;

impl FormatProbe for SplitRawProbe {
  fn descriptor(&self) -> FormatDescriptor {
    DESCRIPTOR
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Some(identity) = context.source_identity() else {
      return Ok(ProbeResult::rejected());
    };
    let Some(entry_name) = identity.entry_name() else {
      return Ok(ProbeResult::rejected());
    };
    let Some(sequence) = SplitSegmentSequence::parse(entry_name) else {
      return Ok(ProbeResult::rejected());
    };
    if !sequence.is_first_segment() || !context.has_resolver() {
      return Ok(ProbeResult::rejected());
    }

    let next_segment = identity.sibling_path(sequence.next_segment_name())?;
    let request = RelatedSourceRequest::new(RelatedSourcePurpose::Segment, next_segment);
    if context.resolve_related(&request)?.is_some() {
      Ok(ProbeResult::matched(ProbeMatch::new(
        DESCRIPTOR,
        ProbeConfidence::Exact,
        "split raw segment sequence found from entry hint and sibling probe",
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SplitSegmentSequence<'a> {
  prefix: &'a str,
  index: u64,
  width: usize,
}

impl<'a> SplitSegmentSequence<'a> {
  fn parse(entry_name: &'a str) -> Option<Self> {
    let (prefix, suffix) = entry_name.rsplit_once('.')?;
    if suffix.len() < MIN_SEGMENT_DIGITS || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
      return None;
    }

    let index = suffix.parse().ok()?;
    Some(Self {
      prefix,
      index,
      width: suffix.len(),
    })
  }

  fn is_first_segment(&self) -> bool {
    self.index == 0
  }

  fn next_segment_name(&self) -> String {
    format!(
      "{}.{:0width$}",
      self.prefix,
      self.index + 1,
      width = self.width
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_split_segment_sequence() {
    let sequence = SplitSegmentSequence::parse("disk.raw.000").unwrap();

    assert!(sequence.is_first_segment());
    assert_eq!(sequence.next_segment_name(), "disk.raw.001");
  }

  #[test]
  fn rejects_non_segment_names() {
    assert!(SplitSegmentSequence::parse("disk.raw").is_none());
    assert!(SplitSegmentSequence::parse("disk.raw.00a").is_none());
    assert!(SplitSegmentSequence::parse("disk.raw.01").is_none());
  }
}
