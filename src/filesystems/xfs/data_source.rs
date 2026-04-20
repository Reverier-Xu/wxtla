use super::extent::XfsExtent;
use crate::{ByteSource, ByteSourceCapabilities, ByteSourceHandle, Error, Result};

pub(crate) struct XfsExtentDataSource {
  pub(crate) source: ByteSourceHandle,
  pub(crate) block_size: u64,
  pub(crate) file_size: u64,
  pub(crate) extents: Vec<XfsExtent>,
}

impl XfsExtentDataSource {
  fn find_extent(&self, block_index: u64) -> Option<&XfsExtent> {
    let index = self
      .extents
      .partition_point(|extent| extent.logical_block <= block_index)
      .checked_sub(1)?;
    let extent = self.extents.get(index)?;
    let extent_end = extent.logical_block.checked_add(extent.number_of_blocks)?;

    (block_index < extent_end).then_some(extent)
  }
}

impl ByteSource for XfsExtentDataSource {
  fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
    if offset >= self.file_size || buf.is_empty() {
      return Ok(0);
    }

    let mut remaining = buf.len().min((self.file_size - offset) as usize);
    let mut out_offset = 0usize;
    let mut file_offset = offset;

    while remaining > 0 {
      let block_index = file_offset / self.block_size;
      let block_inner = file_offset % self.block_size;
      let extent = self
        .find_extent(block_index)
        .ok_or_else(|| Error::invalid_format("xfs extent is missing for a data block"))?;

      let blocks_left = (extent.logical_block + extent.number_of_blocks) - block_index;
      let bytes_left = blocks_left * self.block_size - block_inner;
      let step = remaining.min(bytes_left as usize);

      if extent.is_sparse {
        buf[out_offset..out_offset + step].fill(0);
      } else {
        let physical_block = extent.physical_block + (block_index - extent.logical_block);
        let physical_offset = physical_block * self.block_size + block_inner;
        self
          .source
          .read_exact_at(physical_offset, &mut buf[out_offset..out_offset + step])?;
      }

      out_offset += step;
      remaining -= step;
      file_offset += step as u64;
    }

    Ok(out_offset)
  }

  fn size(&self) -> Result<u64> {
    Ok(self.file_size)
  }

  fn capabilities(&self) -> ByteSourceCapabilities {
    self.source.capabilities()
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::BytesDataSource;

  #[test]
  fn xfs_extent_data_source_handles_fragmented_random_reads() {
    let mut backing = vec![0u8; 16 * 1024];
    backing[4096..8192].fill(0x55);
    backing[12 * 1024..16 * 1024].fill(0x66);
    let source = XfsExtentDataSource {
      source: Arc::new(BytesDataSource::new(backing)),
      block_size: 4096,
      file_size: 8192,
      extents: vec![
        XfsExtent {
          logical_block: 0,
          physical_block: 1,
          number_of_blocks: 1,
          is_sparse: false,
        },
        XfsExtent {
          logical_block: 1,
          physical_block: 3,
          number_of_blocks: 1,
          is_sparse: false,
        },
      ],
    };
    let mut buf = [0u8; 1024];

    let read = source.read_at(5120, &mut buf).unwrap();

    assert_eq!(read, buf.len());
    assert!(buf.iter().all(|byte| *byte == 0x66));
  }
}
