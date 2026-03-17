//! Shared helpers for built-in format probes.

use crate::{
  FormatDescriptor, FormatProbe, ProbeConfidence, ProbeContext, ProbeMatch, ProbeResult, Result,
};

pub(crate) struct OffsetMagicProbe {
  descriptor: FormatDescriptor,
  offset: u64,
  magic: &'static [u8],
  confidence: ProbeConfidence,
  detail: &'static str,
}

impl OffsetMagicProbe {
  pub(crate) const fn new(
    descriptor: FormatDescriptor, offset: u64, magic: &'static [u8], confidence: ProbeConfidence,
    detail: &'static str,
  ) -> Self {
    Self {
      descriptor,
      offset,
      magic,
      confidence,
      detail,
    }
  }
}

impl FormatProbe for OffsetMagicProbe {
  fn descriptor(&self) -> FormatDescriptor {
    self.descriptor
  }

  fn probe(&self, context: &ProbeContext<'_>) -> Result<ProbeResult> {
    let Ok(bytes) = context.read_bytes_at(self.offset, self.magic.len()) else {
      return Ok(ProbeResult::rejected());
    };

    if bytes == self.magic {
      Ok(ProbeResult::matched(ProbeMatch::new(
        self.descriptor,
        self.confidence,
        self.detail,
      )))
    } else {
      Ok(ProbeResult::rejected())
    }
  }
}
