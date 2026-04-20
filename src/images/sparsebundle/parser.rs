//! Sparsebundle metadata parsing.

use std::io::Cursor;

use plist::Value;

use crate::{Error, Result};

pub(super) struct ParsedSparseBundle {
  pub band_size: u64,
  pub media_size: u64,
}

pub(super) fn parse_info_plist(data: &[u8]) -> Result<ParsedSparseBundle> {
  let plist = Value::from_reader_xml(Cursor::new(data)).map_err(|error| {
    Error::invalid_format(format!("unable to parse sparsebundle plist: {error}"))
  })?;
  let root = plist
    .as_dictionary()
    .ok_or_else(|| Error::invalid_format("sparsebundle plist root must be a dictionary"))?;

  let info_version = root
    .get("CFBundleInfoDictionaryVersion")
    .and_then(Value::as_string)
    .ok_or_else(|| {
      Error::invalid_format(
        "sparsebundle plist is missing CFBundleInfoDictionaryVersion".to_string(),
      )
    })?;
  if info_version != "6.0" {
    return Err(Error::invalid_format(format!(
      "unsupported sparsebundle plist dictionary version: {info_version}"
    )));
  }

  let bundle_type = root
    .get("diskimage-bundle-type")
    .and_then(Value::as_string)
    .ok_or_else(|| Error::invalid_format("sparsebundle plist is missing diskimage-bundle-type"))?;
  if bundle_type != "com.apple.diskimage.sparsebundle" {
    return Err(Error::invalid_format(format!(
      "unsupported sparsebundle bundle type: {bundle_type}"
    )));
  }

  let backingstore_version =
    integer_value(root.get("bundle-backingstore-version").ok_or_else(|| {
      Error::invalid_format("sparsebundle plist is missing bundle-backingstore-version")
    })?)?;
  if backingstore_version != 1 {
    return Err(Error::invalid_format(format!(
      "unsupported sparsebundle backingstore version: {backingstore_version}"
    )));
  }

  let band_size = integer_value(
    root
      .get("band-size")
      .ok_or_else(|| Error::invalid_format("sparsebundle plist is missing band-size"))?,
  )?;
  if band_size == 0 {
    return Err(Error::invalid_format(
      "sparsebundle band size must be non-zero".to_string(),
    ));
  }
  let media_size = integer_value(
    root
      .get("size")
      .ok_or_else(|| Error::invalid_format("sparsebundle plist is missing size"))?,
  )?;
  if media_size == 0 {
    return Err(Error::invalid_format(
      "sparsebundle media size must be non-zero".to_string(),
    ));
  }

  Ok(ParsedSparseBundle {
    band_size,
    media_size,
  })
}

fn integer_value(value: &Value) -> Result<u64> {
  if let Some(integer) = value.as_signed_integer() {
    return u64::try_from(integer)
      .map_err(|_| Error::invalid_format("sparsebundle integer value must be non-negative"));
  }
  if let Some(integer) = value.as_unsigned_integer() {
    return Ok(integer);
  }

  Err(Error::invalid_format(
    "sparsebundle plist integer value is invalid".to_string(),
  ))
}
