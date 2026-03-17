//! Shared EWF runtime types.

/// Coarse media type encoded in EWF metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EwfMediaType {
  /// Removable media such as floppy disks or USB devices.
  Removable,
  /// Fixed disks.
  Fixed,
  /// Optical discs.
  Optical,
  /// Logical evidence files.
  LogicalEvidence,
  /// Physical memory images.
  Memory,
  /// An unknown media type byte.
  Unknown(u8),
}

impl EwfMediaType {
  pub(super) const fn from_byte(value: u8) -> Self {
    match value {
      0x00 => Self::Removable,
      0x01 => Self::Fixed,
      0x03 => Self::Optical,
      0x0E => Self::LogicalEvidence,
      0x10 => Self::Memory,
      _ => Self::Unknown(value),
    }
  }
}

/// How a logical EWF chunk is stored in the segment file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EwfChunkEncoding {
  /// The chunk is stored as a zlib stream.
  Compressed,
  /// The chunk is stored uncompressed with a trailing Adler-32 checksum.
  Stored,
}

/// Resolved location of a logical EWF chunk inside a segment file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EwfChunkDescriptor {
  /// Stable chunk index in logical image order.
  pub chunk_index: u32,
  /// Segment number containing the stored payload.
  pub segment_number: u16,
  /// Start offset of the chunk within the logical image.
  pub media_offset: u64,
  /// Logical chunk size in bytes.
  pub logical_size: u32,
  /// File offset of the stored chunk payload.
  pub stored_offset: u64,
  /// Stored payload size in bytes.
  pub stored_size: u32,
  /// Storage encoding of the chunk payload.
  pub encoding: EwfChunkEncoding,
}
