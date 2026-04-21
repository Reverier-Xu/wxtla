use std::{collections::HashMap, io::Read, sync::Arc};

use flate2::read::ZlibDecoder;

use super::{
  DESCRIPTOR, DT_DIR, DT_LNK, DT_REG, JFFS2_COMPR_ZLIB, JFFS2_EMPTY_BITMASK, JFFS2_MAGIC_BITMASK,
  JFFS2_NODETYPE_DIRENT, JFFS2_NODETYPE_INODE, JFFS2_OLD_MAGIC_BITMASK, S_IFDIR, S_IFLNK, S_IFMT,
  S_IFREG, read_u16_be, read_u32_be,
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceReadConcurrency,
  ByteSourceSeekCost, BytesDataSource, Error, NamespaceDirectoryEntry, NamespaceNodeId,
  NamespaceNodeKind, NamespaceNodeRecord, Result, filesystems::FileSystem,
};

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Jffs2InodeInfo {
  ino: u32,
  version: u32,
  mode: u32,
  uid: u16,
  gid: u16,
  isize: u32,
  compr: u8,
  offset: u32,
  csize: u32,
  dsize: u32,
  data_offset: u64,
  node_offset: u64,
}

#[derive(Debug, Clone)]
struct Jffs2DirentInfo {
  pino: u32,
  version: u32,
  ino: u32,
  name: String,
  dtype: u8,
}

type Jffs2Fragment = (u64, u32, u32, u8, u64);

pub struct Jffs2FileSystem {
  source: ByteSourceHandle,
  inodes: HashMap<u32, Vec<Jffs2InodeInfo>>,
  dirents: Vec<Jffs2DirentInfo>,
}

impl Jffs2FileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let size = source.size()?;
    let mut inodes: HashMap<u32, Vec<Jffs2InodeInfo>> = HashMap::new();
    let mut dirents: Vec<Jffs2DirentInfo> = Vec::new();
    let mut offset = 0u64;

    while offset + 12 <= size {
      let Ok(header) = source.read_bytes_at(offset, 12) else {
        offset += 4;
        continue;
      };

      let magic = read_u16_be(&header, 0).unwrap_or(0);
      if magic == JFFS2_EMPTY_BITMASK {
        offset = (offset + 4) & !3;
        continue;
      }
      if magic != JFFS2_MAGIC_BITMASK && magic != JFFS2_OLD_MAGIC_BITMASK {
        offset += 4;
        continue;
      }

      let nodetype = read_u16_be(&header, 2).unwrap_or(0);
      let totlen = read_u32_be(&header, 4).unwrap_or(0) as u64;
      if totlen < 12 {
        offset += 4;
        continue;
      }

      let Ok(node_data) = source.read_bytes_at(offset, totlen as usize) else {
        offset = (offset + 4) & !3;
        continue;
      };

      match nodetype {
        JFFS2_NODETYPE_INODE => {
          if let Ok(info) = Self::parse_inode(&node_data, offset) {
            inodes.entry(info.ino).or_default().push(info);
          }
        }
        JFFS2_NODETYPE_DIRENT => {
          if let Ok(info) = Self::parse_dirent(&node_data) {
            dirents.push(info);
          }
        }
        _ => {}
      }

      offset = (offset + totlen + 3) & !3;
    }

    for versions in inodes.values_mut() {
      versions.sort_by_key(|v| v.version);
    }

    dirents.sort_by_key(|d| d.version);

    Ok(Self {
      source,
      inodes,
      dirents,
    })
  }

  fn parse_inode(data: &[u8], node_offset: u64) -> Result<Jffs2InodeInfo> {
    if data.len() < 68 {
      return Err(Error::invalid_format("jffs2 inode node is too short"));
    }
    let ino = read_u32_be(data, 12)?;
    let version = read_u32_be(data, 16)?;
    let mode = read_u32_be(data, 20)?;
    let uid = read_u16_be(data, 24)?;
    let gid = read_u16_be(data, 26)?;
    let isize = read_u32_be(data, 28)?;
    let offset = read_u32_be(data, 40)?;
    let csize = read_u32_be(data, 44)?;
    let dsize = read_u32_be(data, 48)?;
    let compr = data[52];

    Ok(Jffs2InodeInfo {
      ino,
      version,
      mode,
      uid,
      gid,
      isize,
      compr,
      offset,
      csize,
      dsize,
      data_offset: node_offset + 68,
      node_offset,
    })
  }

  fn parse_dirent(data: &[u8]) -> Result<Jffs2DirentInfo> {
    if data.len() < 40 {
      return Err(Error::invalid_format("jffs2 dirent node is too short"));
    }
    let pino = read_u32_be(data, 12)?;
    let version = read_u32_be(data, 16)?;
    let ino = read_u32_be(data, 20)?;
    let nsize = data[28] as usize;
    let dtype = data[29];

    if 40 + nsize > data.len() {
      return Err(Error::invalid_format("jffs2 dirent name is truncated"));
    }
    let name = String::from_utf8_lossy(&data[40..40 + nsize]).to_string();

    Ok(Jffs2DirentInfo {
      pino,
      version,
      ino,
      name,
      dtype,
    })
  }

  fn get_inode(&self, ino: u32) -> Option<&Jffs2InodeInfo> {
    self.inodes.get(&ino).and_then(|v| v.last())
  }

  fn inode_kind(&self, ino: u32) -> NamespaceNodeKind {
    if let Some(info) = self.get_inode(ino) {
      match info.mode & S_IFMT {
        S_IFDIR => NamespaceNodeKind::Directory,
        S_IFREG => NamespaceNodeKind::File,
        S_IFLNK => NamespaceNodeKind::Symlink,
        _ => NamespaceNodeKind::Special,
      }
    } else {
      NamespaceNodeKind::Directory
    }
  }

  fn read_directory(&self, pino: u32) -> Result<Vec<NamespaceDirectoryEntry>> {
    let mut seen: HashMap<String, Jffs2DirentInfo> = HashMap::new();

    for dirent in &self.dirents {
      if dirent.pino == pino && dirent.ino != 0 {
        seen
          .entry(dirent.name.clone())
          .and_modify(|existing| {
            if dirent.version > existing.version {
              *existing = dirent.clone();
            }
          })
          .or_insert_with(|| dirent.clone());
      }
    }

    let mut entries: Vec<NamespaceDirectoryEntry> = seen
      .into_values()
      .map(|d| {
        NamespaceDirectoryEntry::new(
          d.name,
          NamespaceNodeId::from_u64(d.ino as u64),
          self.dirent_kind(d.dtype),
        )
      })
      .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
  }

  fn dirent_kind(&self, dtype: u8) -> NamespaceNodeKind {
    match dtype {
      DT_DIR => NamespaceNodeKind::Directory,
      DT_REG => NamespaceNodeKind::File,
      DT_LNK => NamespaceNodeKind::Symlink,
      _ => NamespaceNodeKind::Special,
    }
  }

  fn open_file_data(&self, ino: u32) -> Result<ByteSourceHandle> {
    let versions = self
      .inodes
      .get(&ino)
      .ok_or_else(|| Error::not_found(format!("jffs2 inode {ino} was not found")))?;

    let info = versions
      .last()
      .ok_or_else(|| Error::not_found(format!("jffs2 inode {ino} has no versions")))?;

    let file_size = info.isize as u64;

    let mut fragments: Vec<Jffs2Fragment> = Vec::new();
    for v in versions {
      if v.csize > 0 {
        fragments.push((v.offset as u64, v.csize, v.dsize, v.compr, v.data_offset));
      }
    }
    fragments.sort_by_key(|f| f.0);

    Ok(Arc::new(Jffs2FileDataSource {
      source: self.source.clone(),
      fragments: Arc::from(fragments.into_boxed_slice()),
      file_size,
    }) as ByteSourceHandle)
  }
}

impl FileSystem for Jffs2FileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(1)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let ino = decode_node_id(node_id)?;

    if let Some(info) = self.get_inode(ino) {
      Ok(
        NamespaceNodeRecord::new(
          node_id.clone(),
          self.inode_kind(ino),
          if (info.mode & S_IFMT) == S_IFREG {
            info.isize as u64
          } else {
            0
          },
        )
        .with_path(String::new()),
      )
    } else {
      Ok(
        NamespaceNodeRecord::new(node_id.clone(), self.inode_kind(ino), 0).with_path(String::new()),
      )
    }
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let ino = decode_node_id(directory_id)?;
    self.read_directory(ino)
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let ino = decode_node_id(file_id)?;
    let info = self
      .get_inode(ino)
      .ok_or_else(|| Error::not_found(format!("jffs2 inode {ino} was not found")))?;

    if (info.mode & S_IFMT) == S_IFLNK {
      let versions = self
        .inodes
        .get(&ino)
        .ok_or_else(|| Error::not_found(format!("jffs2 inode {ino} was not found")))?;

      for v in versions {
        if v.csize > 0 {
          let data = self.source.read_bytes_at(v.data_offset, v.csize as usize)?;
          let decompressed = if v.compr == JFFS2_COMPR_ZLIB {
            let mut decoder = ZlibDecoder::new(&data[..]);
            let mut out = Vec::new();
            let _ = decoder.read_to_end(&mut out);
            out
          } else {
            data
          };
          return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
            decompressed.into_boxed_slice(),
          ))) as ByteSourceHandle);
        }
      }
      return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
        Vec::<u8>::new().into_boxed_slice(),
      ))) as ByteSourceHandle);
    }

    self.open_file_data(ino)
  }
}

struct Jffs2FileDataSource {
  source: ByteSourceHandle,
  fragments: Arc<[Jffs2Fragment]>,
  file_size: u64,
}

impl ByteSource for Jffs2FileDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;

    while written < remaining {
      let fragment = self.find_fragment(file_offset);
      let (frag_offset, _csize, dsize, compr, data_offset) = match fragment {
        Some(f) => f,
        None => break,
      };

      let frag_relative = file_offset - frag_offset;
      if frag_relative >= dsize as u64 {
        break;
      }

      let step = remaining
        .saturating_sub(written)
        .min((dsize as u64 - frag_relative) as usize);
      if step == 0 {
        break;
      }

      let raw = self
        .source
        .read_bytes_at(data_offset, (dsize as usize).min(4096))?;

      let decompressed = if compr == JFFS2_COMPR_ZLIB {
        let mut decoder = ZlibDecoder::new(&raw[..]);
        let mut out = Vec::new();
        let _ = decoder.read_to_end(&mut out);
        out
      } else {
        raw
      };

      let frag_relative = frag_relative as usize;
      if frag_relative < decompressed.len() {
        let copy = step.min(decompressed.len() - frag_relative);
        buf[written..written + copy]
          .copy_from_slice(&decompressed[frag_relative..frag_relative + copy]);
        written += copy;
        file_offset += copy as u64;
      } else {
        break;
      }
    }

    Ok(written)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.file_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    ByteSourceCapabilities::new(
      ByteSourceReadConcurrency::Serialized,
      ByteSourceSeekCost::Cheap,
    )
  }
}

impl Jffs2FileDataSource {
  fn find_fragment(&self, offset: u64) -> Option<Jffs2Fragment> {
    self
      .fragments
      .iter()
      .find(|(frag_off, _, dsize, ..)| offset >= *frag_off && offset < *frag_off + *dsize as u64)
      .copied()
  }
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u32> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::invalid_format(
      "jffs2 node identifiers must be 8 bytes",
    ));
  }
  let value = u64::from_le_bytes(
    bytes
      .try_into()
      .map_err(|_| Error::invalid_format("jffs2 node id is truncated"))?,
  );
  u32::try_from(value).map_err(|_| Error::invalid_format("jffs2 inode number is too large"))
}

crate::filesystems::driver::impl_file_system_data_source!(Jffs2FileSystem);

#[cfg(test)]
mod tests {
  use super::*;

  fn make_jffs2_node_header(nodetype: u16, totlen: u32) -> Vec<u8> {
    let mut data = vec![0u8; totlen as usize];
    data[0..2].copy_from_slice(&JFFS2_MAGIC_BITMASK.to_be_bytes());
    data[2..4].copy_from_slice(&nodetype.to_be_bytes());
    data[4..8].copy_from_slice(&totlen.to_be_bytes());
    data
  }

  #[test]
  fn parses_inode_node() {
    let mut data = make_jffs2_node_header(JFFS2_NODETYPE_INODE, 68);
    data[12..16].copy_from_slice(&5u32.to_be_bytes());
    data[16..20].copy_from_slice(&1u32.to_be_bytes());
    data[20..24].copy_from_slice(&(S_IFREG | 0o644).to_be_bytes());

    let info = Jffs2FileSystem::parse_inode(&data, 0).unwrap();
    assert_eq!(info.ino, 5);
    assert_eq!(info.version, 1);
    assert_eq!(info.mode & S_IFMT, S_IFREG);
  }

  #[test]
  fn parses_dirent_node() {
    let mut data = make_jffs2_node_header(JFFS2_NODETYPE_DIRENT, 44);
    data[12..16].copy_from_slice(&1u32.to_be_bytes());
    data[16..20].copy_from_slice(&1u32.to_be_bytes());
    data[20..24].copy_from_slice(&5u32.to_be_bytes());
    data[28] = 4;
    data[29] = DT_REG;
    data[40..44].copy_from_slice(b"file");

    let info = Jffs2FileSystem::parse_dirent(&data).unwrap();
    assert_eq!(info.pino, 1);
    assert_eq!(info.ino, 5);
    assert_eq!(info.name, "file");
    assert_eq!(info.dtype, DT_REG);
  }
}
