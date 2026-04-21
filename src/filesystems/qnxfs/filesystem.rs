use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR, QNX4_BLOCK_SIZE, QNX4_DIR_ENTRY_SIZE, QNX4_FILE_LINK, QNX4_FILE_USED,
  QNX4_INODES_PER_BLOCK, QNX4_MAX_XTNTS_PER_XBLK, QNX4_NAME_MAX, QNX4_ROOT_INO,
  QNX4_SHORT_NAME_MAX, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, read_u16_le, read_u32_le,
};
use crate::{
  ByteSource, ByteSourceCapabilities, ByteSourceHandle, ByteSourceReadConcurrency,
  ByteSourceSeekCost, BytesDataSource, Error, NamespaceDirectoryEntry, NamespaceNodeId,
  NamespaceNodeKind, NamespaceNodeRecord, Result,
  filesystems::FileSystem,
};

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Qnx4Inode {
  inum: u32,
  mode: u16,
  size: u32,
  uid: u16,
  gid: u16,
  nlink: u16,
  status: u8,
  first_extent_blk: u32,
  first_extent_size: u32,
  xblk: u32,
  num_extents: u16,
  name: String,
}

impl Qnx4Inode {
  fn parse(data: &[u8], inum: u32) -> Result<Self> {
    if data.len() < QNX4_DIR_ENTRY_SIZE {
      return Err(Error::invalid_format("qnx4 inode entry is too short"));
    }

    let name_bytes = &data[0..QNX4_SHORT_NAME_MAX];
    let name = String::from_utf8_lossy(
      name_bytes
        .split(|&b| b == 0)
        .next()
        .unwrap_or(b""),
    )
    .to_string();

    let size = read_u32_le(data, 16)?;
    let first_extent_blk = read_u32_le(data, 20)?;
    let first_extent_size = read_u32_le(data, 24)?;
    let xblk = read_u32_le(data, 28)?;
    let num_extents = read_u16_le(data, 48)?;
    let mode = read_u16_le(data, 50)?;
    let uid = read_u16_le(data, 52)?;
    let gid = read_u16_le(data, 54)?;
    let nlink = read_u16_le(data, 56)?;
    let status = data[63];

    Ok(Self {
      inum,
      mode,
      size,
      uid,
      gid,
      nlink,
      status,
      first_extent_blk,
      first_extent_size,
      xblk,
      num_extents,
      name,
    })
  }

  fn is_dir(&self) -> bool {
    (self.mode & S_IFMT) == S_IFDIR
  }

  fn is_reg(&self) -> bool {
    (self.mode & S_IFMT) == S_IFREG
  }

  fn is_symlink(&self) -> bool {
    (self.mode & S_IFMT) == S_IFLNK || (self.status & QNX4_FILE_LINK) != 0
  }

  fn node_kind(&self) -> NamespaceNodeKind {
    if self.is_dir() {
      NamespaceNodeKind::Directory
    } else if self.is_symlink() {
      NamespaceNodeKind::Symlink
    } else if self.is_reg() {
      NamespaceNodeKind::File
    } else {
      NamespaceNodeKind::Special
    }
  }

  fn collect_extents(&self, source: &dyn ByteSource) -> Result<Vec<(u64, u64)>> {
    let mut extents = Vec::new();

    if self.num_extents == 0 {
      return Ok(extents);
    }

    let blk = self.first_extent_blk;
    let size = self.first_extent_size as u64;
    if blk > 0 && size > 0 {
      extents.push(((blk - 1) as u64 * QNX4_BLOCK_SIZE, size * QNX4_BLOCK_SIZE));
    }

    let mut remaining = self.num_extents as usize - 1;
    let mut xblk_num = self.xblk;

    while remaining > 0 && xblk_num > 0 {
      let data = source.read_bytes_at(
        (xblk_num - 1) as u64 * QNX4_BLOCK_SIZE,
        QNX4_BLOCK_SIZE as usize,
      )?;

      let sig = &data[data.len() - 16..data.len() - 8];
      if sig != b"IamXblk\0" && sig != b"IamXblk" {
        break;
      }

      let num_in_xblk = data[8] as usize;
      let count = num_in_xblk.min(QNX4_MAX_XTNTS_PER_XBLK).min(remaining);

      let xtnts_offset = 16;
      for i in 0..count {
        let offset = xtnts_offset + i * 8;
        if offset + 8 > data.len() {
          break;
        }
        let ext_blk = u32::from_le_bytes(
          data[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::invalid_format("qnx4 xblk extent is truncated"))?,
        );
        let ext_size = u32::from_le_bytes(
          data[offset + 4..offset + 8]
            .try_into()
            .map_err(|_| Error::invalid_format("qnx4 xblk extent size is truncated"))?,
        );

        if ext_blk > 0 && ext_size > 0 {
          extents.push(((ext_blk - 1) as u64 * QNX4_BLOCK_SIZE, ext_size as u64 * QNX4_BLOCK_SIZE));
        }
      }

      remaining = remaining.saturating_sub(count);
      xblk_num = u32::from_le_bytes(
        data[0..4]
          .try_into()
          .map_err(|_| Error::invalid_format("qnx4 xblk next is truncated"))?,
      );
    }

    Ok(extents)
  }
}

pub struct QnxFsFileSystem {
  source: ByteSourceHandle,
  inode_cache: Mutex<HashMap<u32, Qnx4Inode>>,
}

impl QnxFsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    Ok(Self {
      source,
      inode_cache: Mutex::new(HashMap::new()),
    })
  }

  pub fn symlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    let inum = decode_node_id(node_id)?;
    let inode = self.read_inode(inum)?;
    if !inode.is_symlink() {
      return Ok(None);
    }

    let extents = inode.collect_extents(self.source.as_ref())?;
    if let Some(&(offset, len)) = extents.first() {
      let data = self
        .source
        .read_bytes_at(offset, len.min(inode.size as u64) as usize)?;
      return Ok(Some(
        String::from_utf8_lossy(&data)
          .trim_end_matches('\0')
          .to_string(),
      ));
    }
    Ok(None)
  }

  fn read_inode(&self, inum: u32) -> Result<Qnx4Inode> {
    if let Some(inode) = self
      .inode_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(&inum)
      .cloned()
    {
      return Ok(inode);
    }

    let block = inum / QNX4_INODES_PER_BLOCK;
    let index = (inum % QNX4_INODES_PER_BLOCK) as usize;

    let offset = block as u64 * QNX4_BLOCK_SIZE + index as u64 * QNX4_DIR_ENTRY_SIZE as u64;
    let data = self
      .source
      .read_bytes_at(offset, QNX4_DIR_ENTRY_SIZE)?;

    let inode = Qnx4Inode::parse(&data, inum)?;

    self
      .inode_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .insert(inum, inode.clone());
    Ok(inode)
  }

  fn read_directory(
    &self, inode: &Qnx4Inode,
  ) -> Result<Vec<NamespaceDirectoryEntry>> {
    if !inode.is_dir() {
      return Err(Error::invalid_format(
        "qnx4 directory reads require a directory inode",
      ));
    }

    let extents = inode.collect_extents(self.source.as_ref())?;
    let mut entries = Vec::new();

    for (ext_offset, ext_size) in extents {
      let num_blocks = ext_size / QNX4_BLOCK_SIZE;
      for blk in 0..num_blocks {
        let blk_offset = ext_offset + blk * QNX4_BLOCK_SIZE;
        for i in 0..QNX4_INODES_PER_BLOCK {
          let entry_offset = blk_offset + i as u64 * QNX4_DIR_ENTRY_SIZE as u64;
          let data = self
            .source
            .read_bytes_at(entry_offset, QNX4_DIR_ENTRY_SIZE)?;

          if data[0] == 0 {
            continue;
          }

          let status = data[63];
          if status & (QNX4_FILE_USED | QNX4_FILE_LINK) == 0 {
            continue;
          }

          if (status & QNX4_FILE_LINK) != 0 {
            let link_inode_blk = u32::from_le_bytes(
              data[48..52]
                .try_into()
                .map_err(|_| Error::invalid_format("qnx4 link inode blk is truncated"))?,
            );
            let link_inode_ndx = data[52];
            let child_inum =
              (link_inode_blk - 1) * QNX4_INODES_PER_BLOCK + link_inode_ndx as u32;

            let lfn_blk = u32::from_le_bytes(
              data[56..60]
                .try_into()
                .map_err(|_| Error::invalid_format("qnx4 lfn blk is truncated"))?,
            );

            let name = if lfn_blk > 0 {
              let lfn_data = self
                .source
                .read_bytes_at(
                  (lfn_blk - 1) as u64 * QNX4_BLOCK_SIZE,
                  QNX4_BLOCK_SIZE as usize,
                )?;
              String::from_utf8_lossy(
                lfn_data[6..]
                  .split(|&b| b == 0)
                  .next()
                  .unwrap_or(b""),
              )
              .to_string()
            } else {
              String::from_utf8_lossy(
                data[0..QNX4_NAME_MAX]
                  .split(|&b| b == 0)
                  .next()
                  .unwrap_or(b""),
              )
              .to_string()
            };

            let child = self.read_inode(child_inum)?;
            entries.push(NamespaceDirectoryEntry::new(
              name,
              NamespaceNodeId::from_u64(child_inum as u64),
              child.node_kind(),
            ));
          } else {
            let child_inum = blk as u32 * QNX4_INODES_PER_BLOCK + i;
            let name = String::from_utf8_lossy(
              data[0..QNX4_SHORT_NAME_MAX]
                .split(|&b| b == 0)
                .next()
                .unwrap_or(b""),
            )
            .to_string();

            let child = self.read_inode(child_inum)?;
            entries.push(NamespaceDirectoryEntry::new(
              name,
              NamespaceNodeId::from_u64(child_inum as u64),
              child.node_kind(),
            ));
          }
        }
      }
    }

    Ok(entries)
  }

  fn open_file_data(&self, inode: &Qnx4Inode) -> Result<ByteSourceHandle> {
    if !inode.is_reg() && !inode.is_symlink() {
      return Err(Error::invalid_format(
        "qnx4 file content requires a regular file inode",
      ));
    }

    let extents = inode.collect_extents(self.source.as_ref())?;

    Ok(Arc::new(Qnx4FileDataSource {
      source: self.source.clone(),
      extents: Arc::from(extents.into_boxed_slice()),
      file_size: inode.size as u64,
    }) as ByteSourceHandle)
  }
}

impl FileSystem for QnxFsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64((QNX4_ROOT_INO * QNX4_INODES_PER_BLOCK) as u64)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let inum = decode_node_id(node_id)?;
    let inode = self.read_inode(inum)?;

    Ok(
      NamespaceNodeRecord::new(
        node_id.clone(),
        inode.node_kind(),
        if inode.is_reg() {
          inode.size as u64
        } else {
          0
        },
      )
      .with_path(inode.name),
    )
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let inum = decode_node_id(directory_id)?;
    let inode = self.read_inode(inum)?;
    self.read_directory(&inode)
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let inum = decode_node_id(file_id)?;
    let inode = self.read_inode(inum)?;

    if inode.is_symlink() {
      let extents = inode.collect_extents(self.source.as_ref())?;
      if let Some(&(offset, len)) = extents.first() {
        let data = self
          .source
          .read_bytes_at(offset, len.min(inode.size as u64) as usize)?;
        return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
          data.into_boxed_slice(),
        ))) as ByteSourceHandle);
      }
      return Ok(Arc::new(BytesDataSource::new(Arc::<[u8]>::from(
        Vec::<u8>::new().into_boxed_slice(),
      ))) as ByteSourceHandle);
    }

    self.open_file_data(&inode)
  }
}

struct Qnx4FileDataSource {
  source: ByteSourceHandle,
  extents: Arc<[(u64, u64)]>,
  file_size: u64,
}

impl ByteSource for Qnx4FileDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let remaining = buf.len().min((self.file_size - offset) as usize);
    let mut written = 0usize;
    let mut file_offset = offset;

    while written < remaining {
      let extent = self.find_extent(file_offset);
      let (ext_offset, ext_size) = match extent {
        Some(e) => e,
        None => break,
      };

      let ext_relative = file_offset - ext_offset;
      let step = remaining
        .saturating_sub(written)
        .min((ext_size - ext_relative) as usize);
      if step == 0 {
        break;
      }

      let data = self
        .source
        .read_bytes_at(ext_offset + ext_relative, step)?;
      buf[written..written + step].copy_from_slice(&data[..step]);
      written += step;
      file_offset += step as u64;
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

impl Qnx4FileDataSource {
  fn find_extent(&self, offset: u64) -> Option<(u64, u64)> {
    let mut current = 0u64;
    for &(ext_start, ext_len) in self.extents.iter() {
      let ext_end = current + ext_len;
      if offset >= current && offset < ext_end {
        let ext_relative = offset - current;
        return Some((ext_start + ext_relative, ext_len - ext_relative));
      }
      current = ext_end;
    }
    None
  }
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u32> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::invalid_format(
      "qnx4 node identifiers must be 8 bytes",
    ));
  }
  let value = u64::from_le_bytes(
    bytes
      .try_into()
      .map_err(|_| Error::invalid_format("qnx4 node id is truncated"))?,
  );
  u32::try_from(value).map_err(|_| Error::invalid_format("qnx4 inode number is too large"))
}

crate::filesystems::driver::impl_file_system_data_source!(QnxFsFileSystem);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_qnx4_inode_entry() {
    let mut data = vec![0u8; QNX4_DIR_ENTRY_SIZE];
    data[0] = b't';
    data[1] = b'e';
    data[2] = b's';
    data[3] = b't';
    data[16..20].copy_from_slice(&100u32.to_le_bytes());
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    data[24..28].copy_from_slice(&2u32.to_le_bytes());
    data[48..50].copy_from_slice(&1u16.to_le_bytes());
    data[50..52].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
    data[63] = QNX4_FILE_USED;

    let inode = Qnx4Inode::parse(&data, 8).unwrap();

    assert_eq!(inode.name, "test");
    assert_eq!(inode.size, 100);
    assert!(inode.is_reg());
    assert_eq!(inode.inum, 8);
  }
}
