use super::extent::XfsExtent;
use crate::{DataSource, DataSourceCapabilities, DataSourceHandle, Error, Result};

pub(crate) struct XfsExtentDataSource {
  pub(crate) source: DataSourceHandle,
  pub(crate) block_size: u64,
  pub(crate) file_size: u64,
  pub(crate) extents: Vec<XfsExtent>,
}

impl XfsExtentDataSource {
  fn find_extent(&self, block_index: u64) -> Option<&XfsExtent> {
    self.extents.iter().find(|extent| {
      block_index >= extent.logical_block
        && block_index < extent.logical_block + extent.number_of_blocks
    })
  }
}

impl DataSource for XfsExtentDataSource {
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
      let extent = self.find_extent(block_index).ok_or_else(|| {
        Error::InvalidFormat("xfs extent is missing for a data block".to_string())
      })?;

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

  fn capabilities(&self) -> DataSourceCapabilities {
    self.source.capabilities()
  }
}
