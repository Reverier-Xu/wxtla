//! Split raw image driver and probe registration.

mod driver;
mod image;

pub use driver::SplitRawDriver;
pub use image::SplitRawImage;

use crate::{
  FormatDescriptor, FormatKind, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch,
  ProbeRegistry, ProbeResult, RelatedSourcePurpose, RelatedSourceRequest, Result,
};

/// Split raw image descriptor.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new("image.splitraw", FormatKind::Image);

inventory::submit! {
  crate::formats::FormatInventoryEntry::new(DESCRIPTOR, register_probes)
}

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

    let next_segment = identity.sibling_path(sequence.segment_name(1)?)?;
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
pub(crate) enum SplitSegmentKind<'a> {
  Numeric {
    prefix: &'a str,
    width: usize,
    first_number: u64,
  },
  Alphabetic {
    prefix: &'a str,
    width: usize,
  },
  XOfN {
    prefix: &'a str,
    total_segments: u64,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SplitSegmentSequence<'a> {
  kind: SplitSegmentKind<'a>,
  ordinal: u64,
}

impl<'a> SplitSegmentSequence<'a> {
  pub(crate) fn parse(entry_name: &'a str) -> Option<Self> {
    parse_xofn(entry_name)
      .or_else(|| parse_numeric(entry_name))
      .or_else(|| parse_alphabetic(entry_name))
  }

  pub(crate) fn is_first_segment(&self) -> bool {
    self.ordinal == 0
  }

  pub(crate) fn segment_name(&self, ordinal: u64) -> Result<String> {
    match self.kind {
      SplitSegmentKind::Numeric {
        prefix,
        width,
        first_number,
      } => Ok(format!(
        "{prefix}{:0width$}",
        first_number + ordinal,
        width = width
      )),
      SplitSegmentKind::Alphabetic { prefix, width } => {
        let mut value = ordinal;
        let mut suffix = vec!['a'; width];
        for slot in (0..width).rev() {
          suffix[slot] = char::from_u32(u32::from(b'a') + (value % 26) as u32).unwrap_or('a');
          value /= 26;
        }
        if value != 0 {
          return Err(crate::Error::InvalidSourceReference(
            "split raw alphabetic segment index exceeds the supported width".to_string(),
          ));
        }
        Ok(format!(
          "{prefix}{}",
          suffix.into_iter().collect::<String>()
        ))
      }
      SplitSegmentKind::XOfN {
        prefix,
        total_segments,
      } => {
        let segment_number = ordinal + 1;
        Ok(format!("{prefix}{segment_number}of{total_segments}"))
      }
    }
  }

  pub(crate) fn expected_total_segments(&self) -> Option<u64> {
    match self.kind {
      SplitSegmentKind::XOfN { total_segments, .. } => Some(total_segments),
      SplitSegmentKind::Numeric { .. } | SplitSegmentKind::Alphabetic { .. } => None,
    }
  }
}

fn parse_xofn(entry_name: &str) -> Option<SplitSegmentSequence<'_>> {
  let bytes = entry_name.as_bytes();
  for (index, _) in entry_name.match_indices("of") {
    let mut start = index;
    while start > 0 && bytes[start - 1].is_ascii_digit() {
      start -= 1;
    }
    let mut end = index + 2;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
      end += 1;
    }
    if start == index || end == index + 2 {
      continue;
    }

    let current = entry_name[start..index].parse::<u64>().ok()?;
    let total = entry_name[index + 2..end].parse::<u64>().ok()?;
    if current == 0 || total == 0 || current > total {
      return None;
    }
    return Some(SplitSegmentSequence {
      kind: SplitSegmentKind::XOfN {
        prefix: &entry_name[..start],
        total_segments: total,
      },
      ordinal: current - 1,
    });
  }
  None
}

fn parse_numeric(entry_name: &str) -> Option<SplitSegmentSequence<'_>> {
  let digit_start = entry_name.rfind(|character: char| !character.is_ascii_digit())? + 1;
  let suffix = &entry_name[digit_start..];
  if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
    return None;
  }

  let number = suffix.parse::<u64>().ok()?;
  let first_number = if number == 0 {
    0
  } else if number == 1 {
    1
  } else {
    0
  };
  Some(SplitSegmentSequence {
    kind: SplitSegmentKind::Numeric {
      prefix: &entry_name[..digit_start],
      width: suffix.len(),
      first_number,
    },
    ordinal: number.saturating_sub(first_number),
  })
}

fn parse_alphabetic(entry_name: &str) -> Option<SplitSegmentSequence<'_>> {
  if entry_name.contains('.') || entry_name.len() < 2 {
    return None;
  }
  let split_index = entry_name.len() - 2;
  let suffix = &entry_name[split_index..];
  if !suffix.bytes().all(|byte| byte.is_ascii_lowercase()) {
    return None;
  }

  let ordinal = suffix
    .bytes()
    .fold(0u64, |value, byte| value * 26 + u64::from(byte - b'a'));
  Some(SplitSegmentSequence {
    kind: SplitSegmentKind::Alphabetic {
      prefix: &entry_name[..split_index],
      width: 2,
    },
    ordinal,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_numeric_split_segment_sequence() {
    let sequence = SplitSegmentSequence::parse("disk.raw.000").unwrap();

    assert!(sequence.is_first_segment());
    assert_eq!(sequence.segment_name(1).unwrap(), "disk.raw.001");
  }

  #[test]
  fn parses_xofn_split_segment_sequence() {
    let sequence = SplitSegmentSequence::parse("disk.1of4").unwrap();

    assert!(sequence.is_first_segment());
    assert_eq!(sequence.expected_total_segments(), Some(4));
    assert_eq!(sequence.segment_name(2).unwrap(), "disk.3of4");
  }

  #[test]
  fn parses_alphabetic_split_segment_sequence() {
    let sequence = SplitSegmentSequence::parse("imageaa").unwrap();

    assert!(sequence.is_first_segment());
    assert_eq!(sequence.segment_name(1).unwrap(), "imageab");
  }

  #[test]
  fn rejects_non_segment_names() {
    assert!(SplitSegmentSequence::parse("disk.raw").is_none());
    assert!(SplitSegmentSequence::parse("disk.raw.00a").is_none());
    assert!(SplitSegmentSequence::parse("disk.raw.zzz").is_none());
  }
}
