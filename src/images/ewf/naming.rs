//! Segment naming rules for the EWF family.

use super::file_header::{EwfFileHeader, EwfFileSignature};
use crate::{Error, Result, SourceIdentity};

/// EWF family segment naming schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EwfSegmentNamingScheme {
  E01Upper,
  E01Lower,
  S01Upper,
  S01Lower,
  L01Upper,
  L01Lower,
}

/// Parsed information from an EWF segment file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfSegmentPathInfo {
  base_name: String,
  /// The naming scheme of the segment set.
  pub naming_scheme: EwfSegmentNamingScheme,
  /// The segment number encoded in the current entry name.
  pub segment_number: u16,
}

impl EwfSegmentPathInfo {
  /// Parse the segment naming info from a source identity.
  pub fn from_identity(identity: &SourceIdentity) -> Result<Self> {
    let entry_name = identity.entry_name().ok_or_else(|| {
      Error::invalid_source_reference("ewf source identity is missing an entry name")
    })?;
    Self::parse_entry_name(entry_name)
  }

  pub(crate) fn from_identity_and_header(
    identity: &SourceIdentity, file_header: &EwfFileHeader,
  ) -> Result<Self> {
    let entry_name = identity.entry_name().ok_or_else(|| {
      Error::invalid_source_reference("ewf source identity is missing an entry name")
    })?;
    Self::parse_entry_name_with_header(entry_name, file_header)
  }

  /// Parse the segment naming info from an entry name such as `image.E01`.
  pub fn parse_entry_name(entry_name: &str) -> Result<Self> {
    let (base_name, extension) = entry_name.rsplit_once('.').ok_or_else(|| {
      Error::invalid_source_reference(format!(
        "ewf segment file name is missing an extension: {entry_name}"
      ))
    })?;
    if extension.len() != 3 {
      return Err(Error::invalid_source_reference(format!(
        "unsupported ewf segment extension: {extension}"
      )));
    }

    let scheme = match extension.as_bytes()[0] {
      b'E' => EwfSegmentNamingScheme::E01Upper,
      b'e' => EwfSegmentNamingScheme::E01Lower,
      b'S' => EwfSegmentNamingScheme::S01Upper,
      b's' => EwfSegmentNamingScheme::S01Lower,
      b'L' => EwfSegmentNamingScheme::L01Upper,
      b'l' => EwfSegmentNamingScheme::L01Lower,
      _ => {
        return Err(Error::invalid_source_reference(format!(
          "unsupported ewf segment extension prefix: {extension}"
        )));
      }
    };

    let suffix = &extension[1..];
    if !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
      return Err(Error::invalid_source_reference(format!(
        "opening non-numeric ewf segment names directly is not supported: {entry_name}"
      )));
    }
    let segment_number = suffix.parse::<u16>().map_err(|_| {
      Error::invalid_source_reference(format!(
        "invalid ewf segment number in extension: {extension}"
      ))
    })?;
    if segment_number == 0 {
      return Err(Error::invalid_source_reference(
        "ewf segment numbers start at 1".to_string(),
      ));
    }

    Ok(Self {
      base_name: base_name.to_string(),
      naming_scheme: scheme,
      segment_number,
    })
  }

  pub(crate) fn parse_entry_name_with_header(
    entry_name: &str, file_header: &EwfFileHeader,
  ) -> Result<Self> {
    if let Ok(info) = Self::parse_entry_name(entry_name) {
      return Ok(info);
    }

    let (base_name, extension) = entry_name.rsplit_once('.').ok_or_else(|| {
      Error::invalid_source_reference(format!(
        "ewf segment file name is missing an extension: {entry_name}"
      ))
    })?;
    if extension.len() != 3 {
      return Err(Error::invalid_source_reference(format!(
        "unsupported ewf segment extension: {extension}"
      )));
    }

    let candidates = match file_header.signature {
      EwfFileSignature::Evf => [
        EwfSegmentNamingScheme::E01Upper,
        EwfSegmentNamingScheme::E01Lower,
        EwfSegmentNamingScheme::S01Upper,
        EwfSegmentNamingScheme::S01Lower,
      ]
      .as_slice(),
      EwfFileSignature::Lvf => [
        EwfSegmentNamingScheme::L01Upper,
        EwfSegmentNamingScheme::L01Lower,
      ]
      .as_slice(),
    };
    let matches = candidates
      .iter()
      .copied()
      .filter(|scheme| {
        scheme
          .extension_for(file_header.segment_number)
          .ok()
          .as_deref()
          == Some(extension)
      })
      .collect::<Vec<_>>();
    let naming_scheme = match matches.as_slice() {
      [scheme] => *scheme,
      [] => {
        return Err(Error::invalid_source_reference(format!(
          "unable to infer ewf naming scheme from extension: {extension}"
        )));
      }
      _ => {
        return Err(Error::invalid_source_reference(format!(
          "ambiguous ewf segment naming scheme for extension: {extension}"
        )));
      }
    };

    Ok(Self {
      base_name: base_name.to_string(),
      naming_scheme,
      segment_number: file_header.segment_number,
    })
  }

  /// Build the file name for a specific segment number in the same segment set.
  pub fn file_name_for_segment(&self, segment_number: u16) -> Result<String> {
    Ok(format!(
      "{}.{}",
      self.base_name,
      self.naming_scheme.extension_for(segment_number)?
    ))
  }
}

impl EwfSegmentNamingScheme {
  /// Return the file extension for a segment number.
  pub fn extension_for(self, segment_number: u16) -> Result<String> {
    if segment_number == 0 {
      return Err(Error::invalid_source_reference(
        "ewf segment numbers start at 1".to_string(),
      ));
    }

    let first = self.first_letter();
    let alpha_base = self.alpha_base();
    let alpha_limit = self.alpha_limit();

    let extension = if segment_number < 100 {
      format!("{first}{:02}", segment_number)
    } else {
      let mut value = u32::from(segment_number) - 100;
      let third = alpha_base + (value % 26);
      value /= 26;
      let second = alpha_base + (value % 26);
      value /= 26;
      let first_codepoint = u32::from(first) + value;
      if first_codepoint > alpha_limit {
        return Err(Error::invalid_source_reference(format!(
          "ewf segment number {segment_number} exceeds the supported naming schema"
        )));
      }
      let first_character = char::from_u32(first_codepoint).ok_or_else(|| {
        Error::invalid_source_reference(format!(
          "ewf segment number {segment_number} produced an invalid extension prefix"
        ))
      })?;
      let second_character = char::from_u32(second).ok_or_else(|| {
        Error::invalid_source_reference(format!(
          "ewf segment number {segment_number} produced an invalid extension middle character"
        ))
      })?;
      let third_character = char::from_u32(third).ok_or_else(|| {
        Error::invalid_source_reference(format!(
          "ewf segment number {segment_number} produced an invalid extension suffix"
        ))
      })?;
      format!("{}{}{}", first_character, second_character, third_character,)
    };

    Ok(extension)
  }

  fn first_letter(self) -> char {
    match self {
      Self::E01Upper => 'E',
      Self::E01Lower => 'e',
      Self::S01Upper => 'S',
      Self::S01Lower => 's',
      Self::L01Upper => 'L',
      Self::L01Lower => 'l',
    }
  }

  fn alpha_base(self) -> u32 {
    match self {
      Self::E01Upper | Self::S01Upper | Self::L01Upper => u32::from('A'),
      Self::E01Lower | Self::S01Lower | Self::L01Lower => u32::from('a'),
    }
  }

  fn alpha_limit(self) -> u32 {
    match self {
      Self::E01Upper | Self::S01Upper | Self::L01Upper => u32::from('Z'),
      Self::E01Lower | Self::S01Lower | Self::L01Lower => u32::from('z'),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_numeric_segment_file_names() {
    let info = EwfSegmentPathInfo::parse_entry_name("image.E01").unwrap();

    assert_eq!(info.naming_scheme, EwfSegmentNamingScheme::E01Upper);
    assert_eq!(info.segment_number, 1);
    assert_eq!(info.file_name_for_segment(2).unwrap(), "image.E02");
  }

  #[test]
  fn generates_alpha_segment_extensions() {
    assert_eq!(
      EwfSegmentNamingScheme::E01Upper.extension_for(100).unwrap(),
      "EAA"
    );
    assert_eq!(
      EwfSegmentNamingScheme::E01Upper
        .extension_for(14971)
        .unwrap(),
      "ZZZ"
    );
    assert_eq!(
      EwfSegmentNamingScheme::S01Lower.extension_for(100).unwrap(),
      "saa"
    );
  }

  #[test]
  fn parses_alpha_segment_names_with_file_headers() {
    let info = EwfSegmentPathInfo::parse_entry_name_with_header(
      "image.EAA",
      &EwfFileHeader {
        signature: EwfFileSignature::Evf,
        segment_number: 100,
      },
    )
    .unwrap();

    assert_eq!(info.naming_scheme, EwfSegmentNamingScheme::E01Upper);
    assert_eq!(info.segment_number, 100);
    assert_eq!(info.file_name_for_segment(1).unwrap(), "image.E01");
  }
}
