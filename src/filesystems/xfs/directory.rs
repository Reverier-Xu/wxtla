use super::{
  constants::XFS_MAX_INODE_NUMBER,
  io::{be_u16, be_u32, be_u64, read_slice},
};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub(crate) struct XfsDirEntry {
  pub(crate) name: String,
  pub(crate) inode_number: u64,
}

pub(crate) fn parse_shortform_directory(data: &[u8], has_ftype: bool) -> Result<Vec<XfsDirEntry>> {
  if data.len() < 2 {
    return Err(Error::InvalidFormat(
      "xfs shortform directory is too small".to_string(),
    ));
  }

  let count_32 = data[0] as usize;
  let count_64 = data[1] as usize;
  if count_32 != 0 && count_64 != 0 {
    return Err(Error::InvalidFormat(
      "xfs shortform directory mixes 32-bit and 64-bit entry counters".to_string(),
    ));
  }

  let (entry_count, inode_size, mut offset) = if count_64 == 0 {
    (count_32, 4usize, 6usize)
  } else {
    (count_64, 8usize, 10usize)
  };

  let mut entries = Vec::with_capacity(entry_count);
  for _ in 0..entry_count {
    if offset >= data.len() {
      return Err(Error::InvalidFormat(
        "xfs shortform directory entry is out of bounds".to_string(),
      ));
    }

    let name_len = data[offset] as usize;
    let mut entry_size = 3usize
      .checked_add(name_len)
      .ok_or_else(|| Error::InvalidRange("xfs shortform entry size overflow".to_string()))?;
    if has_ftype {
      entry_size = entry_size
        .checked_add(1)
        .ok_or_else(|| Error::InvalidRange("xfs shortform entry size overflow".to_string()))?;
    }
    entry_size = entry_size
      .checked_add(inode_size)
      .ok_or_else(|| Error::InvalidRange("xfs shortform entry size overflow".to_string()))?;

    let _ = read_slice(data, offset, entry_size)?;
    offset += 1;
    offset += 2;

    let name = String::from_utf8_lossy(read_slice(data, offset, name_len)?).to_string();
    offset += name_len;

    if has_ftype {
      offset += 1;
    }

    let inode_number = if inode_size == 4 {
      u64::from(be_u32(read_slice(data, offset, 4)?))
    } else {
      be_u64(read_slice(data, offset, 8)?)
    } & XFS_MAX_INODE_NUMBER;
    offset += inode_size;

    if name != "." && name != ".." {
      entries.push(XfsDirEntry { name, inode_number });
    }
  }

  Ok(entries)
}

pub(crate) fn parse_block_directory(
  data: &[u8], has_ftype: bool, out: &mut Vec<XfsDirEntry>,
) -> Result<()> {
  let signature = read_slice(data, 0, 4)?;
  let (header_size, has_footer) = match signature {
    b"XD2B" | b"XD2D" => (16usize, signature == b"XD2B"),
    b"XDB3" | b"XDD3" => (64usize, signature == b"XDB3"),
    b"XD2L" | b"XD2N" | b"XD2F" | b"XDL3" | b"XDN3" | b"XDF3" => return Ok(()),
    _ => {
      return Err(Error::InvalidFormat(format!(
        "unsupported xfs directory block signature: {:02x}{:02x}{:02x}{:02x}",
        data[0], data[1], data[2], data[3]
      )));
    }
  };

  let entries_end = if has_footer {
    let footer = read_slice(data, data.len() - 8, 8)?;
    let nentries = be_u32(&footer[0..4]) as usize;
    let hash_size = nentries
      .checked_mul(8)
      .ok_or_else(|| Error::InvalidRange("xfs directory hash table overflow".to_string()))?;
    data
      .len()
      .checked_sub(8 + hash_size)
      .ok_or_else(|| Error::InvalidFormat("invalid xfs directory hash region".to_string()))?
  } else {
    data.len()
  };

  let mut offset = header_size;
  while offset < entries_end {
    let header = read_slice(data, offset, 4)?;
    if be_u16(&header[0..2]) == 0xFFFF {
      let size = usize::from(be_u16(&header[2..4]));
      if size < 4 {
        return Err(Error::InvalidFormat(
          "invalid xfs free directory region size".to_string(),
        ));
      }
      offset += size;
      continue;
    }

    let inode_number = be_u64(read_slice(data, offset, 8)?) & XFS_MAX_INODE_NUMBER;
    let name_len = data[offset + 8] as usize;

    let mut entry_size = 9usize
      .checked_add(name_len)
      .and_then(|value| value.checked_add(2))
      .ok_or_else(|| Error::InvalidRange("xfs directory entry size overflow".to_string()))?;
    if has_ftype {
      entry_size += 1;
    }
    let padding = entry_size % 8;
    if padding != 0 {
      entry_size += 8 - padding;
    }

    let name = String::from_utf8_lossy(read_slice(data, offset + 9, name_len)?).to_string();
    if name != "." && name != ".." {
      out.push(XfsDirEntry { name, inode_number });
    }
    offset += entry_size;
  }

  Ok(())
}
