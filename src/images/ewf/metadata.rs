//! EWF header and header2 metadata parsing.

use std::io::Read;

use flate2::read::ZlibDecoder;

use crate::{Error, Result};

/// Logical metadata category extracted from an EWF header or header2 section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfMetadataCategory {
  /// Category name such as `main`, `srce`, or `sub`.
  pub name: String,
  /// Raw non-empty lines that belong to the category.
  pub lines: Vec<String>,
}

/// Parsed EWF text metadata section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfMetadataSection {
  /// Ordered metadata categories contained in the section.
  pub categories: Vec<EwfMetadataCategory>,
}

impl EwfMetadataSection {
  /// Parse an ASCII `header` section payload.
  pub fn parse_header(data: &[u8]) -> Result<Self> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).map_err(Error::Io)?;
    let text = String::from_utf8(decoded)
      .map_err(|_| Error::invalid_format("ewf header is not valid ASCII/UTF-8 text"))?;

    Self::parse_text(&text)
  }

  /// Parse a UTF-16 `header2` section payload.
  pub fn parse_header2(data: &[u8]) -> Result<Self> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).map_err(Error::Io)?;
    let text = decode_utf16_text(&decoded)?;

    Self::parse_text(&text)
  }

  /// Return the first category with the requested name.
  pub fn category(&self, name: &str) -> Option<&EwfMetadataCategory> {
    self
      .categories
      .iter()
      .find(|category| category.name == name)
  }

  /// Return a field from the `main` category when it is encoded as a key/value
  /// line pair.
  pub fn main_field(&self, key: &str) -> Option<&str> {
    let main = self.category("main")?;
    let keys = main.lines.first()?.split('\t');
    let values = main.lines.get(1)?.split('\t');

    keys
      .zip(values)
      .find(|(candidate_key, _)| *candidate_key == key)
      .map(|(_, value)| value)
  }

  fn parse_text(text: &str) -> Result<Self> {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let category_count = lines
      .first()
      .ok_or_else(|| Error::invalid_format("ewf metadata is missing the category count"))?
      .trim()
      .parse::<usize>()
      .map_err(|_| Error::invalid_format("ewf metadata category count is invalid"))?;

    let mut cursor = 1usize;
    let mut categories = Vec::with_capacity(category_count);
    while cursor < lines.len() && categories.len() < category_count {
      if lines[cursor].trim().is_empty() {
        cursor += 1;
        continue;
      }

      let name = lines[cursor].trim().to_string();
      cursor += 1;
      let mut category_lines = Vec::new();

      while cursor < lines.len() {
        let line = lines[cursor];
        cursor += 1;
        if line.trim().is_empty() {
          break;
        }
        category_lines.push(line.to_string());
      }

      categories.push(EwfMetadataCategory {
        name,
        lines: category_lines,
      });
    }

    if categories.len() != category_count {
      return Err(Error::invalid_format(
        "ewf metadata category count does not match the parsed categories".to_string(),
      ));
    }

    Ok(Self { categories })
  }
}

fn decode_utf16_text(data: &[u8]) -> Result<String> {
  if !data.len().is_multiple_of(2) {
    return Err(Error::invalid_format(
      "ewf header2 decompressed data has an odd byte count".to_string(),
    ));
  }

  let (big_endian, data) = match data {
    [0xFE, 0xFF, rest @ ..] => (true, rest),
    [0xFF, 0xFE, rest @ ..] => (false, rest),
    _ => (false, data),
  };
  if !data.len().is_multiple_of(2) {
    return Err(Error::invalid_format(
      "ewf header2 decompressed data is missing UTF-16 alignment".to_string(),
    ));
  }

  let code_units = data
    .chunks_exact(2)
    .map(|chunk| {
      if big_endian {
        u16::from_be_bytes([chunk[0], chunk[1]])
      } else {
        u16::from_le_bytes([chunk[0], chunk[1]])
      }
    })
    .collect::<Vec<_>>();

  String::from_utf16(&code_units)
    .map_err(|_| Error::invalid_format("ewf header2 text is not valid UTF-16"))
}

#[cfg(test)]
mod tests {
  use std::io::Write;

  use flate2::{Compression, write::ZlibEncoder};

  use super::*;

  fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
  }

  #[test]
  fn parses_ascii_header_values() {
    let compressed = compress(b"1\r\nmain\r\nc\tn\r\ncase\tevidence\r\n\r\n");
    let section = EwfMetadataSection::parse_header(&compressed).unwrap();

    assert_eq!(section.main_field("c"), Some("case"));
    assert_eq!(section.main_field("n"), Some("evidence"));
  }

  #[test]
  fn parses_utf16_header2_values() {
    let text = "\u{feff}1\nmain\na\tc\nalpha\tcase\n\n";
    let utf16: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let compressed = compress(&utf16);
    let section = EwfMetadataSection::parse_header2(&compressed).unwrap();

    assert_eq!(section.main_field("a"), Some("alpha"));
    assert_eq!(section.main_field("c"), Some("case"));
  }
}
