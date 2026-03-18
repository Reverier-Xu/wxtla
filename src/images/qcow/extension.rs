//! QCOW header extension parsing.

use crate::{Error, Result};

/// Parsed QCOW header extension kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QcowHeaderExtensionKind {
  /// End marker.
  End,
  /// Feature name table.
  FeatureNameTable,
  /// Backing file format string.
  BackingFileFormat,
  /// External data file path string.
  ExternalDataPath,
  /// Full-disk encryption extension.
  FullDiskEncryption,
  /// Bitmaps extension.
  Bitmaps,
  /// Unknown extension type.
  Unknown(u32),
}

/// Parsed QCOW header extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QcowHeaderExtension {
  /// Extension kind.
  pub kind: QcowHeaderExtensionKind,
  /// Raw extension payload.
  pub data: Vec<u8>,
}

impl QcowHeaderExtension {
  /// Parse the ordered header extension list that follows the base QCOW header.
  pub fn parse_many(data: &[u8]) -> Result<Vec<Self>> {
    let mut cursor = 0usize;
    let mut extensions = Vec::new();

    while cursor < data.len() {
      let header = data.get(cursor..cursor + 8).ok_or_else(|| {
        Error::InvalidFormat("qcow header extension header is truncated".to_string())
      })?;
      let kind_raw = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
      let data_len = usize::try_from(u32::from_be_bytes([
        header[4], header[5], header[6], header[7],
      ]))
      .map_err(|_| Error::InvalidRange("qcow header extension length is too large".to_string()))?;
      cursor += 8;

      if kind_raw == 0 {
        extensions.push(Self {
          kind: QcowHeaderExtensionKind::End,
          data: Vec::new(),
        });
        break;
      }

      let payload = data.get(cursor..cursor + data_len).ok_or_else(|| {
        Error::InvalidFormat("qcow header extension payload is truncated".to_string())
      })?;
      extensions.push(Self {
        kind: kind_from_u32(kind_raw),
        data: payload.to_vec(),
      });
      cursor = cursor
        .checked_add(data_len)
        .ok_or_else(|| Error::InvalidRange("qcow header extension cursor overflow".to_string()))?;

      let padding = (8 - (cursor % 8)) % 8;
      cursor = cursor.checked_add(padding).ok_or_else(|| {
        Error::InvalidRange("qcow header extension alignment overflow".to_string())
      })?;
    }

    Ok(extensions)
  }

  /// Decode the extension payload as a trimmed UTF-8 string when applicable.
  pub fn utf8_string(&self) -> Result<Option<String>> {
    match self.kind {
      QcowHeaderExtensionKind::BackingFileFormat | QcowHeaderExtensionKind::ExternalDataPath => {
        let mut data = self.data.clone();
        while data.last() == Some(&0) {
          data.pop();
        }
        let string = String::from_utf8(data).map_err(|_| {
          Error::InvalidFormat("qcow header extension string is not valid UTF-8".to_string())
        })?;
        Ok(Some(string))
      }
      _ => Ok(None),
    }
  }
}

fn kind_from_u32(value: u32) -> QcowHeaderExtensionKind {
  match value {
    0 => QcowHeaderExtensionKind::End,
    0x6803F857 => QcowHeaderExtensionKind::FeatureNameTable,
    0xE2792ACA => QcowHeaderExtensionKind::BackingFileFormat,
    0x44415441 => QcowHeaderExtensionKind::ExternalDataPath,
    0x0537BE77 => QcowHeaderExtensionKind::FullDiskEncryption,
    0x23852875 => QcowHeaderExtensionKind::Bitmaps,
    other => QcowHeaderExtensionKind::Unknown(other),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_backing_format_extension() {
    let data = [
      0xE2, 0x79, 0x2A, 0xCA, 0x00, 0x00, 0x00, 0x04, b'r', b'a', b'w', 0x00, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0,
    ];
    let extensions = QcowHeaderExtension::parse_many(&data).unwrap();

    assert_eq!(extensions.len(), 2);
    assert_eq!(
      extensions[0].kind,
      QcowHeaderExtensionKind::BackingFileFormat
    );
    assert_eq!(extensions[0].utf8_string().unwrap().as_deref(), Some("raw"));
  }
}
