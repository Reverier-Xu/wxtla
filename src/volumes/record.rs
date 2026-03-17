//! Shared volume metadata types.

/// Common role classifications for discovered volumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeRole {
  /// A normal primary volume.
  Primary,
  /// A container for logical sub-volumes.
  ExtendedContainer,
  /// A logical volume inside a container.
  Logical,
  /// A protective compatibility volume, such as GPT's protective MBR entry.
  Protective,
  /// A metadata or reserved area surfaced as a volume-like record.
  Metadata,
  /// A volume with no stronger generic classification.
  Unknown,
}

/// Byte span covered by a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSpan {
  /// Start offset of the volume in bytes.
  pub byte_offset: u64,
  /// Size of the volume in bytes.
  pub byte_size: u64,
}

impl VolumeSpan {
  /// Create a new volume span.
  pub const fn new(byte_offset: u64, byte_size: u64) -> Self {
    Self {
      byte_offset,
      byte_size,
    }
  }

  /// Return the exclusive end offset when it fits in `u64`.
  pub fn end_offset(self) -> Option<u64> {
    self.byte_offset.checked_add(self.byte_size)
  }
}

/// Generic metadata for a discovered volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRecord {
  /// Stable index within the opened volume system.
  pub index: usize,
  /// Byte span covered by the volume.
  pub span: VolumeSpan,
  /// Optional display label or partition name.
  pub name: Option<String>,
  /// Common semantic role of the volume.
  pub role: VolumeRole,
}

impl VolumeRecord {
  /// Create a new volume record.
  pub const fn new(index: usize, span: VolumeSpan, role: VolumeRole) -> Self {
    Self {
      index,
      span,
      name: None,
      role,
    }
  }

  /// Attach a display name to the volume record.
  pub fn with_name(mut self, name: impl Into<String>) -> Self {
    self.name = Some(name.into());
    self
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn volume_span_reports_end_offset() {
    let span = VolumeSpan::new(512, 2048);

    assert_eq!(span.end_offset(), Some(2560));
  }

  #[test]
  fn volume_record_accepts_names() {
    let record =
      VolumeRecord::new(1, VolumeSpan::new(0, 4096), VolumeRole::Primary).with_name("system");

    assert_eq!(record.name.as_deref(), Some("system"));
  }
}
