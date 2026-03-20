pub(crate) const SB_MAGIC: &[u8; 4] = b"XFSB";
pub(crate) const INODE_MAGIC: &[u8; 2] = b"IN";

pub(crate) const FORK_INLINE: u8 = 1;
pub(crate) const FORK_EXTENTS: u8 = 2;
pub(crate) const FORK_BTREE: u8 = 3;

pub(crate) const FILETYPE_MASK: u16 = 0xF000;
pub(crate) const FILETYPE_FIFO: u16 = 0x1000;
pub(crate) const FILETYPE_CHAR_DEVICE: u16 = 0x2000;
pub(crate) const FILETYPE_DIR: u16 = 0x4000;
pub(crate) const FILETYPE_BLOCK_DEVICE: u16 = 0x6000;
pub(crate) const FILETYPE_REGULAR: u16 = 0x8000;
pub(crate) const FILETYPE_SYMLINK: u16 = 0xA000;
pub(crate) const FILETYPE_SOCKET: u16 = 0xC000;

pub(crate) const SECONDARY_FEATURE_FILETYPE: u32 = 0x0000_0200;

pub(crate) const DIR_LEAF_OFFSET: u64 = 0x0000_0008_0000_0000;

pub(crate) const BTREE_SIG_V4: &[u8; 4] = b"BMAP";
pub(crate) const BTREE_SIG_V5: &[u8; 4] = b"BMA3";
pub(crate) const INOBT_SIG_V4: &[u8; 4] = b"IABT";
pub(crate) const INOBT_SIG_V5: &[u8; 4] = b"IAB3";

pub(crate) const INODES_PER_CHUNK: u64 = 64;
pub(crate) const XFS_MAX_INODE_NUMBER: u64 = (1u64 << 56) - 1;
