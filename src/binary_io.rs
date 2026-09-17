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
        8 => usize::try_from(u64::from_be_bytes(
            data[index..index + 8].try_into().unwrap(),
        ))
        .map_err(|_| anyhow::anyhow!("getValue: integer does not fit this platform")),
        _ => bail!("getValue: unsupported length {}", length),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_value_be_integers() {
        let data = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x2A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        ];
        assert_eq!(get_value(&data, 0, 2).unwrap(), 1);
        assert_eq!(get_value(&data, 2, 4).unwrap(), 42);
        if usize::BITS == 64 {
            assert_eq!(get_value(&data, 6, 8).unwrap(), usize::MAX - 1);
        } else {
            assert!(get_value(&data, 6, 8).is_err());
        }
    }

    #[test]
    fn get_value_rejects_oob_and_bad_len() {
        let data = [1u8, 2, 3];
        assert!(get_value(&data, 2, 2).is_err());
        assert!(get_value(&data, 0, 3).is_err());
    }
}
