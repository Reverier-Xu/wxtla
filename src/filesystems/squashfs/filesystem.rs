use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use super::{
  DESCRIPTOR,
  datasource::{SquashFsDataReader, SquashFsFileDataSource},
  directory::parse_directory_block,
  inode::{
    SQUASHFS_BLKDEV_TYPE, SQUASHFS_CHRDEV_TYPE, SQUASHFS_DIR_TYPE, SQUASHFS_FIFO_TYPE,
    SQUASHFS_FILE_TYPE, SQUASHFS_INVALID_FRAG, SQUASHFS_LBLKDEV_TYPE, SQUASHFS_LCHRDEV_TYPE,
    SQUASHFS_LDIR_TYPE, SQUASHFS_LFIFO_TYPE, SQUASHFS_LREG_TYPE, SQUASHFS_LSOCKET_TYPE,
    SQUASHFS_LSYMLINK_TYPE, SQUASHFS_SOCKET_TYPE, SQUASHFS_SYMLINK_TYPE, SquashFsInode,
  },
  superblock::{SquashFsFragmentEntry, SquashFsSuperblock},
};
use crate::{
  ByteSourceHandle, BytesDataSource, Error, NamespaceDirectoryEntry, NamespaceNodeId,
  NamespaceNodeKind, NamespaceNodeRecord, Result, filesystems::FileSystem,
};

pub struct SquashFsFileSystem {
  #[allow(dead_code)]
  source: ByteSourceHandle,
  superblock: SquashFsSuperblock,
  data_reader: Arc<SquashFsDataReader>,
  fragment_blocks: Arc<[SquashFsFragmentEntry]>,
  root_inode_number: u32,
  inodes: Mutex<Option<HashMap<u32, SquashFsInode>>>,
  directory_cache: Mutex<HashMap<u32, Vec<NamespaceDirectoryEntry>>>,
}

impl SquashFsFileSystem {
  pub fn open(source: ByteSourceHandle) -> Result<Self> {
    let superblock = SquashFsSuperblock::read(source.as_ref())?;

    let data_reader = Arc::new(SquashFsDataReader::new(source.clone(), superblock.clone()));

    let fragment_blocks: Arc<[SquashFsFragmentEntry]> =
      if superblock.has_fragments() && superblock.fragment_count > 0 {
        let fragment_table_size = superblock.fragment_count as usize * 16;
        let raw = source.read_bytes_at(superblock.fragment_table_start, fragment_table_size)?;
        let fragments: Vec<SquashFsFragmentEntry> = raw
          .chunks_exact(16)
          .filter_map(|chunk| SquashFsFragmentEntry::parse(chunk).ok())
          .collect();
        Arc::from(fragments.into_boxed_slice())
      } else {
        Arc::from(Vec::<SquashFsFragmentEntry>::new().into_boxed_slice())
      };

    let root_inode_number = {
      let fs = Self {
        source: source.clone(),
        superblock: superblock.clone(),
        data_reader: data_reader.clone(),
        fragment_blocks: fragment_blocks.clone(),
        root_inode_number: 0,
        inodes: Mutex::new(None),
        directory_cache: Mutex::new(HashMap::new()),
      };
      let inode = fs.read_inode_at_offset(superblock.root_inode_offset)?;
      inode.inode_number
    };

    Ok(Self {
      source,
      superblock,
      data_reader,
      fragment_blocks,
      root_inode_number,
      inodes: Mutex::new(None),
      directory_cache: Mutex::new(HashMap::new()),
    })
  }

  pub fn symlink_target(&self, node_id: &NamespaceNodeId) -> Result<Option<String>> {
    let inode_number = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_number)?;
    if !is_symlink_type(inode.inode_type) {
      return Ok(None);
    }
    Ok(Some(inode.symlink_target.clone()))
  }

  fn read_inode_at_offset(&self, target_offset: u64) -> Result<SquashFsInode> {
    let block_size = u64::from(self.superblock.block_size);
    let mut table_offset = self.superblock.inode_table_start;
    let mut cumulative = 0u64;

    loop {
      let data = self.data_reader.read_metadata_block(table_offset)?;
      if data.is_empty() {
        return Err(Error::not_found(format!(
          "squashfs inode at offset {target_offset} not found"
        )));
      }

      if target_offset >= cumulative && target_offset < cumulative + data.len() as u64 {
        let local_offset = (target_offset - cumulative) as usize;
        return SquashFsInode::parse(&data[local_offset..], block_size);
      }

      cumulative += data.len() as u64;
      table_offset += crate::filesystems::squashfs::superblock::METADATA_SIZE;
    }
  }

  fn read_inode(&self, inode_number: u32) -> Result<SquashFsInode> {
    let mut cache = self
      .inodes
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(inodes) = cache.as_ref() {
      return inodes
        .get(&inode_number)
        .cloned()
        .ok_or_else(|| Error::not_found(format!("squashfs inode {inode_number} was not found")));
    }

    let inodes = self.read_all_inodes()?;
    let result = inodes
      .get(&inode_number)
      .cloned()
      .ok_or_else(|| Error::not_found(format!("squashfs inode {inode_number} was not found")))?;
    *cache = Some(inodes);
    Ok(result)
  }

  fn read_all_inodes(&self) -> Result<HashMap<u32, SquashFsInode>> {
    let mut inodes = HashMap::new();
    let mut table_offset = self.superblock.inode_table_start;
    let total_inodes = self.superblock.inode_count;
    let block_size = u64::from(self.superblock.block_size);

    let mut parsed = 0u32;
    while parsed < total_inodes {
      let data = self.data_reader.read_metadata_block(table_offset)?;
      if data.is_empty() {
        break;
      }

      let mut offset = 0usize;
      while offset < data.len() && parsed < total_inodes {
        let remaining = &data[offset..];
        let inode = SquashFsInode::parse(remaining, block_size)?;
        let inode_size = inode_size_bytes(&inode, block_size);
        inodes.insert(inode.inode_number, inode);
        parsed += 1;
        offset += inode_size;
      }

      table_offset += crate::filesystems::squashfs::superblock::METADATA_SIZE;
    }

    Ok(inodes)
  }

  fn read_directory(&self, inode: &SquashFsInode) -> Result<Vec<NamespaceDirectoryEntry>> {
    let inode_num = inode.inode_number;
    {
      let cache = self
        .directory_cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
      if let Some(entries) = cache.get(&inode_num) {
        return Ok(entries.clone());
      }
    }

    let entries = if inode.file_size == 0 {
      Vec::new()
    } else {
      let mut all_entries = Vec::new();
      let mut dir_offset = self.superblock.directory_table_start + inode.start_block;
      let dir_size = inode.file_size;
      let mut skip_first = inode.fragment_offset as usize;

      let mut read = 0u64;
      while read < dir_size {
        let data = self.data_reader.read_metadata_block(dir_offset)?;
        if data.is_empty() {
          break;
        }

        let effective_data = if skip_first < data.len() {
          &data[skip_first..]
        } else {
          skip_first -= data.len();
          read += data.len() as u64;
          dir_offset += crate::filesystems::squashfs::superblock::METADATA_SIZE;
          continue;
        };
        skip_first = 0;

        let parsed = parse_directory_block(effective_data)?;
        let namespace_entries: Vec<NamespaceDirectoryEntry> = parsed
          .iter()
          .map(|entry| {
            NamespaceDirectoryEntry::new(
              entry.name.clone(),
              NamespaceNodeId::from_u64(entry.inode_number as u64),
              super::directory::entry_type_to_kind(entry.entry_type),
            )
          })
          .collect();

        read += data.len() as u64;
        dir_offset += crate::filesystems::squashfs::superblock::METADATA_SIZE;
        all_entries.extend(namespace_entries);
      }
      all_entries
    };

    let mut cache = self
      .directory_cache
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.insert(inode_num, entries.clone());
    Ok(entries)
  }

  fn open_file_data(&self, inode: &SquashFsInode) -> Result<ByteSourceHandle> {
    if !is_reg_type(inode.inode_type) {
      return Err(Error::invalid_format(
        "squashfs file content requires a regular file inode",
      ));
    }

    let block_count = inode.block_count(u64::from(self.superblock.block_size));
    let block_sizes = if block_count == 0 {
      Arc::from(Vec::<u32>::new().into_boxed_slice())
    } else {
      Arc::from(inode.block_sizes.clone().into_boxed_slice())
    };

    if block_count == 0 && inode.fragment_block_index == SQUASHFS_INVALID_FRAG {
      return Ok(
        Arc::new(BytesDataSource::new(Arc::<[u8]>::from(Vec::<u8>::new()))) as ByteSourceHandle,
      );
    }

    Ok(Arc::new(SquashFsFileDataSource::new(
      self.data_reader.clone(),
      block_sizes,
      self.fragment_blocks.clone(),
      inode.file_size,
      inode.start_block,
      inode.fragment_block_index,
      inode.fragment_offset,
    )) as ByteSourceHandle)
  }
}

impl FileSystem for SquashFsFileSystem {
  fn descriptor(&self) -> crate::FormatDescriptor {
    DESCRIPTOR
  }

  fn root_node_id(&self) -> NamespaceNodeId {
    NamespaceNodeId::from_u64(self.root_inode_number as u64)
  }

  fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord> {
    let inode_number = decode_node_id(node_id)?;
    let inode = self.read_inode(inode_number)?;
    let kind = inode_type_to_kind(inode.inode_type);

    Ok(
      NamespaceNodeRecord::new(
        node_id.clone(),
        kind,
        if is_reg_type(inode.inode_type) {
          inode.file_size
        } else {
          0
        },
      )
      .with_path(String::new()),
    )
  }

  fn read_dir(&self, directory_id: &NamespaceNodeId) -> Result<Vec<NamespaceDirectoryEntry>> {
    let inode_number = decode_node_id(directory_id)?;
    let inode = self.read_inode(inode_number)?;

    if !is_dir_type(inode.inode_type) {
      return Err(Error::invalid_format(
        "squashfs directory reads require a directory inode",
      ));
    }

    self.read_directory(&inode)
  }

  fn open_file(&self, file_id: &NamespaceNodeId) -> Result<ByteSourceHandle> {
    let inode_number = decode_node_id(file_id)?;
    let inode = self.read_inode(inode_number)?;

    match inode.inode_type {
      SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => Ok(Arc::new(BytesDataSource::new(
        Arc::<[u8]>::from(inode.symlink_target.as_bytes().to_vec().into_boxed_slice()),
      )) as ByteSourceHandle),
      _ => self.open_file_data(&inode),
    }
  }
}

fn decode_node_id(node_id: &NamespaceNodeId) -> Result<u32> {
  let bytes = node_id.as_bytes();
  if bytes.len() != 8 {
    return Err(Error::invalid_format(
      "squashfs node identifiers must be 8 bytes",
    ));
  }
  let value = u64::from_le_bytes(
    bytes
      .try_into()
      .map_err(|_| Error::invalid_format("squashfs node id is truncated"))?,
  );
  u32::try_from(value).map_err(|_| Error::invalid_format("squashfs inode number is too large"))
}

fn inode_type_to_kind(inode_type: u16) -> NamespaceNodeKind {
  match inode_type {
    SQUASHFS_DIR_TYPE | SQUASHFS_LDIR_TYPE => NamespaceNodeKind::Directory,
    SQUASHFS_FILE_TYPE | SQUASHFS_LREG_TYPE => NamespaceNodeKind::File,
    SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => NamespaceNodeKind::Symlink,
    SQUASHFS_BLKDEV_TYPE
    | SQUASHFS_LBLKDEV_TYPE
    | SQUASHFS_CHRDEV_TYPE
    | SQUASHFS_LCHRDEV_TYPE
    | SQUASHFS_FIFO_TYPE
    | SQUASHFS_LFIFO_TYPE
    | SQUASHFS_SOCKET_TYPE
    | SQUASHFS_LSOCKET_TYPE => NamespaceNodeKind::Special,
    _ => NamespaceNodeKind::Special,
  }
}

fn is_dir_type(inode_type: u16) -> bool {
  matches!(inode_type, SQUASHFS_DIR_TYPE | SQUASHFS_LDIR_TYPE)
}

fn is_reg_type(inode_type: u16) -> bool {
  matches!(inode_type, SQUASHFS_FILE_TYPE | SQUASHFS_LREG_TYPE)
}

fn is_symlink_type(inode_type: u16) -> bool {
  matches!(inode_type, SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE)
}

fn inode_size_bytes(inode: &SquashFsInode, block_size: u64) -> usize {
  match inode.inode_type {
    SQUASHFS_DIR_TYPE => super::inode::DIR_INODE_SIZE,
    SQUASHFS_LDIR_TYPE => super::inode::LDIR_INODE_SIZE + inode.dir_index_count as usize * 12,
    SQUASHFS_FILE_TYPE => super::inode::REG_INODE_SIZE + inode.block_count(block_size) * 4,
    SQUASHFS_LREG_TYPE => super::inode::LREG_INODE_SIZE + inode.block_count(block_size) * 4,
    SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => {
      super::inode::SYMLINK_INODE_SIZE + inode.symlink_target.len()
    }
    SQUASHFS_BLKDEV_TYPE | SQUASHFS_CHRDEV_TYPE => super::inode::DEV_INODE_SIZE,
    SQUASHFS_LBLKDEV_TYPE | SQUASHFS_LCHRDEV_TYPE => super::inode::LDEV_INODE_SIZE,
    SQUASHFS_FIFO_TYPE | SQUASHFS_SOCKET_TYPE => super::inode::IPC_INODE_SIZE,
    SQUASHFS_LFIFO_TYPE | SQUASHFS_LSOCKET_TYPE => super::inode::LIPC_INODE_SIZE,
    _ => super::inode::IPC_INODE_SIZE,
  }
}

crate::filesystems::driver::impl_file_system_data_source!(SquashFsFileSystem);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn inode_type_to_kind_maps_correctly() {
    assert_eq!(
      inode_type_to_kind(SQUASHFS_DIR_TYPE),
      NamespaceNodeKind::Directory
    );
    assert_eq!(
      inode_type_to_kind(SQUASHFS_FILE_TYPE),
      NamespaceNodeKind::File
    );
    assert_eq!(
      inode_type_to_kind(SQUASHFS_SYMLINK_TYPE),
      NamespaceNodeKind::Symlink
    );
    assert_eq!(
      inode_type_to_kind(SQUASHFS_FIFO_TYPE),
      NamespaceNodeKind::Special
    );
  }
}
