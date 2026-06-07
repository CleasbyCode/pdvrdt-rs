use anyhow::{bail, Result};

fn has_range(data_len: usize, index: usize, length: usize) -> bool {
    index <= data_len && length <= data_len.saturating_sub(index)
}

pub fn get_value(data: &[u8], index: usize, length: usize) -> Result<usize> {
    if !has_range(data.len(), index, length) {
        bail!("getValue: index out of bounds");
    }

    match length {
        2 => Ok(u16::from_be_bytes(data[index..index + 2].try_into().unwrap()) as usize),
        4 => Ok(u32::from_be_bytes(data[index..index + 4].try_into().unwrap()) as usize),
        8 => Ok(u64::from_be_bytes(data[index..index + 8].try_into().unwrap()) as usize),
        _ => bail!("getValue: unsupported length {}", length),
    }
}
