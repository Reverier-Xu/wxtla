use std::collections::BTreeMap;

use super::model::{
  MetadataLogicalVolume, MetadataPhysicalVolume, MetadataSegment, MetadataStripe, ParsedMetadata,
};
use crate::{Error, Result};

#[derive(Debug, Clone)]
enum Node {
  Object(BTreeMap<String, Node>),
  Number(i128),
  String(String),
  Array(Vec<Node>),
}

#[derive(Debug, Clone)]
enum Token {
  Ident(String),
  String(String),
  Number(i128),
  Eq,
  LBrace,
  RBrace,
  LBracket,
  RBracket,
  Comma,
}

#[derive(Debug, Clone, Copy)]
enum TokenKind {
  Eq,
  LBrace,
  RBrace,
  RBracket,
  Comma,
}

pub(super) fn parse_lvm_metadata(text: &str) -> Result<ParsedMetadata> {
  let tokens = tokenize(text)?;
  let root = parse_root(&tokens)?;
  let mut vg_candidates = root
    .into_iter()
    .filter(|(_, node)| is_volume_group_node(node))
    .collect::<Vec<_>>();
  if vg_candidates.len() != 1 {
    return Err(Error::InvalidFormat(
      "unsupported LVM metadata root layout".to_string(),
    ));
  }

  let (vg_name, vg_node) = vg_candidates
    .pop()
    .ok_or_else(|| Error::InvalidFormat("empty LVM metadata".to_string()))?;
  let vg = as_object(&vg_node)?;

  let seqno = get_number(vg, "seqno")?;
  let extent_size_sectors = get_number(vg, "extent_size")?;
  let extent_size_bytes = extent_size_sectors
    .checked_mul(512)
    .ok_or_else(|| Error::InvalidRange("LVM extent size overflow".to_string()))?;

  let mut physical_volumes = Vec::new();
  if let Some(pv_section) = vg.get("physical_volumes") {
    let pvs = as_object(pv_section)?;
    physical_volumes.reserve(pvs.len());
    for (pv_name, pv_node) in pvs {
      let pv_object = as_object(pv_node)?;
      let id = get_optional_string(pv_object, "id");
      let pe_start_bytes =
        get_optional_number(pv_object, "pe_start").and_then(|value| value.checked_mul(512));
      physical_volumes.push(MetadataPhysicalVolume {
        name: pv_name.clone(),
        id,
        pe_start_bytes,
      });
    }
  }

  let mut logical_volumes = Vec::new();
  let lv_section = vg
    .get("logical_volumes")
    .ok_or_else(|| Error::InvalidFormat("missing logical_volumes section".to_string()))?;
  let lvs = as_object(lv_section)?;
  logical_volumes.reserve(lvs.len());
  for (lv_name, lv_node) in lvs {
    let lv_object = as_object(lv_node)?;
    let id = get_optional_string(lv_object, "id");

    let mut segments = Vec::with_capacity(lv_object.len());
    for (segment_name, segment_node) in lv_object {
      if !segment_name.starts_with("segment") || segment_name == "segment_count" {
        continue;
      }
      let segment_object = as_object(segment_node)?;
      let start_extent = get_number(segment_object, "start_extent")?;
      let extent_count = get_number(segment_object, "extent_count")?;
      let stripe_size_bytes =
        get_optional_number(segment_object, "stripe_size").and_then(|value| value.checked_mul(512));
      let stripes = parse_segment_stripes(segment_object)?;
      segments.push(MetadataSegment {
        start_extent,
        extent_count,
        stripe_size_bytes,
        stripes,
      });
    }

    logical_volumes.push(MetadataLogicalVolume {
      name: lv_name.clone(),
      id,
      segments,
    });
  }

  Ok(ParsedMetadata {
    vg_name,
    seqno,
    extent_size_bytes,
    physical_volumes,
    logical_volumes,
  })
}

fn is_volume_group_node(node: &Node) -> bool {
  let Ok(object) = as_object(node) else {
    return false;
  };
  object.contains_key("id")
    && object.contains_key("seqno")
    && object.contains_key("extent_size")
    && object.contains_key("logical_volumes")
}

fn parse_segment_stripes(segment: &BTreeMap<String, Node>) -> Result<Vec<MetadataStripe>> {
  let stripes = segment
    .get("stripes")
    .ok_or_else(|| Error::InvalidFormat("missing stripes in LVM segment".to_string()))?;
  let values = as_array(stripes)?;
  if values.len() % 2 != 0 {
    return Err(Error::InvalidFormat(
      "invalid stripes list in LVM segment".to_string(),
    ));
  }

  let mut result = Vec::with_capacity(values.len() / 2);
  for pair in values.chunks(2) {
    let pv_name = as_string(&pair[0])?.to_string();
    let start_extent = as_number(&pair[1])?;
    result.push(MetadataStripe {
      pv_name,
      start_extent,
    });
  }
  Ok(result)
}

fn tokenize(text: &str) -> Result<Vec<Token>> {
  let bytes = text.as_bytes();
  let mut index = 0usize;
  let mut tokens = Vec::new();

  while index < bytes.len() {
    let current = bytes[index];
    if current.is_ascii_whitespace() {
      index += 1;
      continue;
    }
    if current == b'#' {
      while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
      }
      continue;
    }

    match current {
      b'{' => {
        tokens.push(Token::LBrace);
        index += 1;
      }
      b'}' => {
        tokens.push(Token::RBrace);
        index += 1;
      }
      b'[' => {
        tokens.push(Token::LBracket);
        index += 1;
      }
      b']' => {
        tokens.push(Token::RBracket);
        index += 1;
      }
      b'=' => {
        tokens.push(Token::Eq);
        index += 1;
      }
      b',' => {
        tokens.push(Token::Comma);
        index += 1;
      }
      b'"' | b'\'' => {
        let quote = current;
        index += 1;
        let mut output = String::new();
        while index < bytes.len() {
          let byte = bytes[index];
          if byte == quote {
            index += 1;
            break;
          }
          if byte == b'\\' {
            index += 1;
            if index >= bytes.len() {
              return Err(Error::InvalidFormat(
                "unterminated escape in LVM metadata string".to_string(),
              ));
            }
            output.push(match bytes[index] {
              b'\\' => '\\',
              b'"' => '"',
              b'\'' => '\'',
              b'n' => '\n',
              b'r' => '\r',
              b't' => '\t',
              other => other as char,
            });
            index += 1;
            continue;
          }
          output.push(byte as char);
          index += 1;
        }
        tokens.push(Token::String(output));
      }
      _ => {
        if current.is_ascii_digit()
          || current == b'-' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit)
        {
          let start = index;
          index += 1;
          while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
          }
          let text = std::str::from_utf8(&bytes[start..index]).map_err(|_| {
            Error::InvalidFormat("invalid numeric token in LVM metadata".to_string())
          })?;
          let value = text
            .parse::<i128>()
            .map_err(|_| Error::InvalidFormat("invalid number in LVM metadata".to_string()))?;
          tokens.push(Token::Number(value));
        } else {
          let start = index;
          index += 1;
          while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric()
              || matches!(bytes[index], b'_' | b'-' | b'.' | b'+'))
          {
            index += 1;
          }
          let ident = std::str::from_utf8(&bytes[start..index])
            .map_err(|_| Error::InvalidFormat("invalid identifier in LVM metadata".to_string()))?;
          tokens.push(Token::Ident(ident.to_string()));
        }
      }
    }
  }

  Ok(tokens)
}

fn parse_root(tokens: &[Token]) -> Result<BTreeMap<String, Node>> {
  let mut parser = Parser { tokens, cursor: 0 };
  let mut root = BTreeMap::new();
  while !parser.is_eof() {
    let key = parser.expect_ident()?;
    if parser.peek_is(TokenKind::LBrace) {
      parser.cursor += 1;
      let object = parser.parse_object()?;
      root.insert(key, Node::Object(object));
      continue;
    }
    if parser.peek_is(TokenKind::Eq) {
      parser.cursor += 1;
      let _ = parser.parse_value()?;
      continue;
    }
    return Err(Error::InvalidFormat(format!(
      "unexpected LVM metadata token at root index {}: expected '{{' or '=', got {}",
      parser.cursor,
      parser.describe_current_token()
    )));
  }
  Ok(root)
}

struct Parser<'a> {
  tokens: &'a [Token],
  cursor: usize,
}

impl Parser<'_> {
  fn is_eof(&self) -> bool {
    self.cursor >= self.tokens.len()
  }

  fn parse_object(&mut self) -> Result<BTreeMap<String, Node>> {
    let mut object = BTreeMap::new();
    while !self.is_eof() {
      if self.peek_is(TokenKind::RBrace) {
        self.cursor += 1;
        break;
      }

      let key = self.expect_ident()?;
      let value = if self.peek_is(TokenKind::LBrace) {
        self.cursor += 1;
        Node::Object(self.parse_object()?)
      } else {
        self.expect_token(TokenKind::Eq)?;
        self.parse_value()?
      };
      object.insert(key, value);
    }
    Ok(object)
  }

  fn parse_value(&mut self) -> Result<Node> {
    let Some(token) = self.tokens.get(self.cursor) else {
      return Err(Error::InvalidFormat(
        "unexpected end of LVM metadata".to_string(),
      ));
    };

    match token {
      Token::String(value) => {
        self.cursor += 1;
        Ok(Node::String(value.clone()))
      }
      Token::Number(value) => {
        self.cursor += 1;
        Ok(Node::Number(*value))
      }
      Token::Ident(value) => {
        self.cursor += 1;
        Ok(Node::String(value.clone()))
      }
      Token::LBracket => {
        self.cursor += 1;
        let mut values = Vec::new();
        while !self.is_eof() {
          if self.peek_is(TokenKind::RBracket) {
            self.cursor += 1;
            break;
          }
          values.push(self.parse_value()?);
          if self.peek_is(TokenKind::Comma) {
            self.cursor += 1;
          }
        }
        Ok(Node::Array(values))
      }
      _ => Err(Error::InvalidFormat(format!(
        "unsupported LVM metadata value token at index {}: {}",
        self.cursor,
        self.describe_current_token()
      ))),
    }
  }

  fn expect_ident(&mut self) -> Result<String> {
    let Some(token) = self.tokens.get(self.cursor) else {
      return Err(Error::InvalidFormat(
        "unexpected end of LVM metadata".to_string(),
      ));
    };
    match token {
      Token::Ident(value) => {
        self.cursor += 1;
        Ok(value.clone())
      }
      _ => Err(Error::InvalidFormat(format!(
        "expected LVM metadata identifier at index {}, got {}",
        self.cursor,
        self.describe_current_token()
      ))),
    }
  }

  fn expect_token(&mut self, kind: TokenKind) -> Result<()> {
    if self.peek_is(kind) {
      self.cursor += 1;
      return Ok(());
    }
    Err(Error::InvalidFormat(format!(
      "unexpected LVM metadata token at index {}: expected {:?}, got {}",
      self.cursor,
      kind,
      self.describe_current_token()
    )))
  }

  fn describe_current_token(&self) -> String {
    match self.tokens.get(self.cursor) {
      Some(token) => format!("{token:?}"),
      None => "<eof>".to_string(),
    }
  }

  fn peek_is(&self, kind: TokenKind) -> bool {
    matches!(
      (self.tokens.get(self.cursor), kind),
      (Some(Token::Eq), TokenKind::Eq)
        | (Some(Token::LBrace), TokenKind::LBrace)
        | (Some(Token::RBrace), TokenKind::RBrace)
        | (Some(Token::RBracket), TokenKind::RBracket)
        | (Some(Token::Comma), TokenKind::Comma)
    )
  }
}

fn as_object(node: &Node) -> Result<&BTreeMap<String, Node>> {
  match node {
    Node::Object(value) => Ok(value),
    _ => Err(Error::InvalidFormat(
      "expected object in LVM metadata".to_string(),
    )),
  }
}

fn as_array(node: &Node) -> Result<&[Node]> {
  match node {
    Node::Array(value) => Ok(value),
    _ => Err(Error::InvalidFormat(
      "expected array in LVM metadata".to_string(),
    )),
  }
}

fn as_string(node: &Node) -> Result<&str> {
  match node {
    Node::String(value) => Ok(value),
    _ => Err(Error::InvalidFormat(
      "expected string in LVM metadata".to_string(),
    )),
  }
}

fn as_number(node: &Node) -> Result<u64> {
  match node {
    Node::Number(value) => u64::try_from(*value).map_err(|_| {
      Error::InvalidFormat("expected a non-negative number in LVM metadata".to_string())
    }),
    _ => Err(Error::InvalidFormat(
      "expected number in LVM metadata".to_string(),
    )),
  }
}

fn get_number(map: &BTreeMap<String, Node>, key: &str) -> Result<u64> {
  let value = map
    .get(key)
    .ok_or_else(|| Error::InvalidFormat(format!("missing key in LVM metadata: {key}")))?;
  as_number(value)
}

fn get_optional_string(map: &BTreeMap<String, Node>, key: &str) -> Option<String> {
  map.get(key).and_then(|value| match value {
    Node::String(value) => Some(value.clone()),
    _ => None,
  })
}

fn get_optional_number(map: &BTreeMap<String, Node>, key: &str) -> Option<u64> {
  map.get(key).and_then(|value| match value {
    Node::Number(value) => u64::try_from(*value).ok(),
    _ => None,
  })
}
