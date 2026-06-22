use crate::binary_io::get_value;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Cursor;

pub struct ImageCheckResult {
    pub has_bad_dims: bool,
}

const INDEXED_PLTE: u8 = 3;
const TRUECOLOR_RGB: u8 = 2;
const TRUECOLOR_RGBA: u8 = 6;

pub fn optimize_image(image_file_vec: &mut Vec<u8>) -> Result<ImageCheckResult> {
    const MIN_DIMS: u32 = 68;
    const MAX_PLTE_DIMS: u32 = 4096;
    const MAX_RGB_DIMS: u32 = 900;
    const MIN_RGB_COLORS: usize = 257;

    // Decode the PNG to get raw pixel data.
    let decoder = png::Decoder::new(Cursor::new(&image_file_vec));
    let mut reader = decoder.read_info()?;
    let info = reader.info().clone();

    let width = info.width;
    let height = info.height;
    let color_type = info.color_type;
    let mut image = vec![0u8; reader.output_buffer_size()];
    let output_info = reader.next_frame(&mut image)?;
    image.truncate(output_info.buffer_size());

    let check_dims = |max_dim: u32| -> bool {
        width < MIN_DIMS || height < MIN_DIMS || width > max_dim || height > max_dim
    };

    // Determine color type as raw byte value.
    let color_type_byte = match color_type {
        png::ColorType::Grayscale => 0,
        png::ColorType::Rgb => TRUECOLOR_RGB,
        png::ColorType::Indexed => INDEXED_PLTE,
        png::ColorType::GrayscaleAlpha => 4,
        png::ColorType::Rgba => TRUECOLOR_RGBA,
    };

    let is_truecolor = color_type_byte == TRUECOLOR_RGB || color_type_byte == TRUECOLOR_RGBA;

    // Count unique colors to decide if palette conversion is beneficial.
    if is_truecolor {
        let channels: usize = if color_type_byte == TRUECOLOR_RGBA {
            4
        } else {
            3
        };
        let pixel_count = (width as usize) * (height as usize);
        let mut unique_colors: HashMap<u32, u8> = HashMap::new();

        for i in 0..pixel_count {
            let offset = i * channels;
            let key = if channels == 4 {
                (image[offset] as u32) << 24
                    | (image[offset + 1] as u32) << 16
                    | (image[offset + 2] as u32) << 8
                    | image[offset + 3] as u32
            } else {
                (image[offset] as u32) << 24
                    | (image[offset + 1] as u32) << 16
                    | (image[offset + 2] as u32) << 8
                    | 255u32
            };
            if unique_colors.len() >= MIN_RGB_COLORS && !unique_colors.contains_key(&key) {
                break;
            }
            unique_colors.entry(key).or_insert(0);
        }

        if unique_colors.len() < MIN_RGB_COLORS {
            convert_to_palette(
                image_file_vec,
                &image,
                width,
                height,
                &unique_colors,
                channels,
            )?;
            return Ok(ImageCheckResult {
                has_bad_dims: check_dims(MAX_PLTE_DIMS),
            });
        }
    }

    strip_and_copy_chunks(image_file_vec, color_type_byte)?;
    Ok(ImageCheckResult {
        has_bad_dims: check_dims(MAX_RGB_DIMS),
    })
}

fn convert_to_palette(
    image_file_vec: &mut Vec<u8>,
    image: &[u8],
    width: u32,
    height: u32,
    unique_colors: &HashMap<u32, u8>,
    channels: usize,
) -> Result<()> {
    const MAX_PALETTE_SIZE: usize = 256;

    let palette_size = unique_colors.len();
    if palette_size == 0 {
        bail!("convertToPalette: Palette is empty.");
    }
    if palette_size > MAX_PALETTE_SIZE {
        bail!(
            "convertToPalette: Palette has {} colors, exceeds maximum of {}.",
            palette_size,
            MAX_PALETTE_SIZE
        );
    }

    // Build palette (RGBA entries) and color-to-index map.
    let mut palette_rgba: Vec<u8> = Vec::with_capacity(palette_size * 4);
    let mut color_to_index: HashMap<u32, u8> = HashMap::with_capacity(palette_size);
    let mut idx: u8 = 0;

    for &key in unique_colors.keys() {
        let r = ((key >> 24) & 0xFF) as u8;
        let g = ((key >> 16) & 0xFF) as u8;
        let b = ((key >> 8) & 0xFF) as u8;
        let a = (key & 0xFF) as u8;
        palette_rgba.extend_from_slice(&[r, g, b, a]);
        color_to_index.insert(key, idx);
        idx += 1;
    }

    // Map each pixel to its palette index.
    let pixel_count = (width as usize) * (height as usize);
    let mut indexed_image = vec![0u8; pixel_count];

    for i in 0..pixel_count {
        let offset = i * channels;
        let key = if channels == 4 {
            (image[offset] as u32) << 24
                | (image[offset + 1] as u32) << 16
                | (image[offset + 2] as u32) << 8
                | image[offset + 3] as u32
        } else {
            (image[offset] as u32) << 24
                | (image[offset + 1] as u32) << 16
                | (image[offset + 2] as u32) << 8
                | 255u32
        };
        indexed_image[i] = *color_to_index
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("Pixel {} has color not found in palette.", i))?;
    }

    // Encode as 8-bit palette PNG.
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut output), width, height);
        encoder.set_color(png::ColorType::Indexed);
        encoder.set_depth(png::BitDepth::Eight);

        // Build separate palette (RGB) and trns (alpha) arrays.
        let mut plte = Vec::with_capacity(palette_size * 3);
        let mut trns = Vec::with_capacity(palette_size);
        let mut has_transparency = false;

        for i in 0..palette_size {
            plte.push(palette_rgba[i * 4]);
            plte.push(palette_rgba[i * 4 + 1]);
            plte.push(palette_rgba[i * 4 + 2]);
            let alpha = palette_rgba[i * 4 + 3];
            trns.push(alpha);
            if alpha != 255 {
                has_transparency = true;
            }
        }

        encoder.set_palette(plte);
        if has_transparency {
            encoder.set_trns(trns);
        }

        let mut writer = encoder.write_header()?;
        writer.write_image_data(&indexed_image)?;
        writer.finish()?;
    }

    *image_file_vec = output;
    Ok(())
}

fn span_has_range(data: &[u8], start: usize, length: usize) -> bool {
    start <= data.len() && length <= data.len().saturating_sub(start)
}

fn strip_and_copy_chunks(image_file_vec: &mut Vec<u8>, color_type: u8) -> Result<()> {
    const PNG_SIG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const TYPE_IHDR: &[u8] = &[0x49, 0x48, 0x44, 0x52];
    const TYPE_PLTE: &[u8] = &[0x50, 0x4C, 0x54, 0x45];
    const TYPE_TRNS: &[u8] = &[0x74, 0x52, 0x4E, 0x53];
    const TYPE_IDAT: &[u8] = &[0x49, 0x44, 0x41, 0x54];
    const TYPE_IEND: &[u8] = &[0x49, 0x45, 0x4E, 0x44];
    const PDVRDT_IDAT_PREFIX: &[u8] = &[0x78, 0x5E, 0x5C];
    const PDVRDT_SIG: &[u8] = &[0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9];

    const PNG_HEADER_SIZE: usize = 8;
    const IHDR_DATA_SIZE: usize = 13;
    const CHUNK_OVERHEAD: usize = 12;
    const MIN_PNG_SIZE: usize = PNG_HEADER_SIZE + CHUNK_OVERHEAD + IHDR_DATA_SIZE + CHUNK_OVERHEAD;
    const PDVRDT_SCAN_LIMIT: usize = 4096;

    let require_range = |start: usize, length: usize, message: &str| -> Result<()> {
        if !span_has_range(image_file_vec, start, length) {
            bail!("{}", message);
        }
        Ok(())
    };

    let looks_like_pdvrdt_idat = |chunk_data: &[u8]| -> bool {
        if chunk_data.len() < PDVRDT_IDAT_PREFIX.len() {
            return false;
        }
        if !chunk_data.starts_with(PDVRDT_IDAT_PREFIX) {
            return false;
        }
        let scan_len = chunk_data.len().min(PDVRDT_SCAN_LIMIT);
        chunk_data[..scan_len]
            .windows(PDVRDT_SIG.len())
            .any(|w| w == PDVRDT_SIG)
    };

    if image_file_vec.len() < MIN_PNG_SIZE {
        bail!("PNG Error: File too small to contain valid PNG structure.");
    }
    if !image_file_vec.starts_with(PNG_SIG) {
        bail!("PNG Error: Invalid PNG signature.");
    }

    let mut pos = PNG_HEADER_SIZE;
    require_range(pos, 8, "PNG Error: Corrupt IHDR chunk header.")?;
    let ihdr_len = get_value(image_file_vec, pos, 4)?;
    let ihdr_type = &image_file_vec[pos + 4..pos + 8];
    if ihdr_len != IHDR_DATA_SIZE || ihdr_type != TYPE_IHDR {
        bail!("PNG Error: Missing or corrupt IHDR chunk.");
    }
    let ihdr_chunk_size = ihdr_len
        .checked_add(CHUNK_OVERHEAD)
        .ok_or_else(|| anyhow::anyhow!("PNG Error: Corrupt IHDR chunk length."))?;
    require_range(
        pos,
        ihdr_chunk_size,
        "PNG Error: Corrupt IHDR chunk length.",
    )?;

    let mut cleaned_png = Vec::with_capacity(image_file_vec.len());
    cleaned_png.extend_from_slice(&image_file_vec[..pos + ihdr_chunk_size]);
    pos += ihdr_chunk_size;

    let mut has_iend = false;
    while pos < image_file_vec.len() {
        require_range(pos, 8, "PNG Error: Corrupt PNG chunk header.")?;

        let chunk_len = get_value(image_file_vec, pos, 4)?;
        let type_index = pos + 4;
        let data_index = type_index + 4;
        if chunk_len > image_file_vec.len().saturating_sub(data_index)
            || 4 > image_file_vec.len().saturating_sub(data_index + chunk_len)
        {
            bail!("PNG Error: Corrupt PNG chunk length.");
        }

        let crc_index = data_index + chunk_len;
        let chunk_size = chunk_len
            .checked_add(CHUNK_OVERHEAD)
            .ok_or_else(|| anyhow::anyhow!("PNG Error: Corrupt PNG chunk length."))?;

        let chunk_type = &image_file_vec[type_index..type_index + 4];
        let chunk_data = &image_file_vec[data_index..data_index + chunk_len];

        let stored_crc = get_value(image_file_vec, crc_index, 4)? as u32;
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&image_file_vec[type_index..type_index + 4 + chunk_len]);
        let computed_crc = hasher.finalize();
        if stored_crc != computed_crc {
            bail!("PNG Error: Corrupt PNG chunk CRC.");
        }

        let keep_chunk = (chunk_type == TYPE_PLTE && color_type == INDEXED_PLTE)
            || chunk_type == TYPE_TRNS
            || (chunk_type == TYPE_IDAT && !looks_like_pdvrdt_idat(chunk_data))
            || chunk_type == TYPE_IEND;
        if keep_chunk {
            cleaned_png.extend_from_slice(&image_file_vec[pos..pos + chunk_size]);
        }

        pos += chunk_size;
        if chunk_type == TYPE_IEND {
            has_iend = true;
            break;
        }
    }

    if !has_iend {
        bail!("PNG Error: Missing IEND chunk.");
    }

    *image_file_vec = cleaned_png;
    Ok(())
}
