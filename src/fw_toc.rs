/*++

Licensed under the Apache-2.0 license.

File Name:

   fw_toc.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use crate::config;

use colored::*;
use core::mem::size_of;
use log::debug;
use memoffset::offset_of;
use std::fs::File;
use std::io;
use std::io::Result;
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::str;
use zerocopy::{FromBytes, Immutable, IntoBytes};

// pub const FLASH_HEADER_MAGIC: u32 = 0x48534C46; // "FLSH"
pub const TOC_HEADER_MAGIC: u32 = 0x434F5441; // "ATOC"
pub const IMAGE_COUNT: usize = 32;
pub const FILENAME_LEN: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct FlashHeader {
    pub magic: u32,
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
    pub header_checksum: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct ImageHeader {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
    pub image_checksum: u32,
    pub image_header_checksum: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct FlashImagePayload {
    pub image_info: [ImageHeader; IMAGE_COUNT],
    pub filenames: [[u8; FILENAME_LEN]; IMAGE_COUNT],
}

#[repr(C)]
#[derive(Debug)]
pub struct FirmwareTOC {
    pub header: FlashHeader,
    pub payload: FlashImagePayload,
}

fn read_flash_header(file: &mut File) -> Result<FlashHeader> {
    // Read and interpret the header bytes directly into a FlashHeader
    let mut buf = [0u8; std::mem::size_of::<FlashHeader>()];
    file.read_exact(&mut buf)?;
    Ok(unsafe { std::ptr::read(buf.as_ptr() as *const FlashHeader) })
}

fn read_image_headers(
    file: &mut File,
    count: usize,
    offset: u64,
) -> std::io::Result<Vec<ImageHeader>> {
    // Seek to the image headers region and read 'count' headers
    let mut headers = Vec::with_capacity(count);
    file.seek(SeekFrom::Start(offset))?;

    for _ in 0..count {
        let mut buf = [0u8; std::mem::size_of::<ImageHeader>()];
        file.read_exact(&mut buf)?;
        let ih: ImageHeader = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
        headers.push(ih);
    }

    Ok(headers)
}

fn set_filename(dst: &mut [u8; FILENAME_LEN], path_str: &str) -> io::Result<()> {
    // Use Path to extract the base filename (last path segment)
    let filename = Path::new(path_str)
        .file_name() // e.g. "/foo/bar/caliptra.bin" -> "caliptra.bin"
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid filename in path '{}'", path_str),
            )
        })?;

    let bytes = filename.as_bytes();

    if bytes.len() > FILENAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "filename '{}' too long (max {} bytes)",
                filename, FILENAME_LEN
            ),
        ));
    }

    // Zero-initialize the destination buffer
    dst.fill(0);

    // Copy the filename bytes (up to actual length)
    dst[..bytes.len()].copy_from_slice(bytes);

    Ok(())
}

const fn fw_filenames_base_offset() -> usize {
    size_of::<FlashHeader>() + size_of::<ImageHeader>() * IMAGE_COUNT
}

const fn fw_toc_filename_offset(n: usize) -> usize {
    fw_filenames_base_offset() + n * FILENAME_LEN
}

fn calculate_checksum(data: &[u8]) -> u32 {
    let sum = data
        .iter()
        .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32));
    0u32.wrapping_sub(sum)
}

fn cstr_from_buf(buf: &[u8]) -> &str {
    // Find NUL terminator if present; otherwise use the full buffer
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    str::from_utf8(&buf[..end]).unwrap_or("<invalid utf-8>")
}

pub fn create_fw_toc_from_flash_image(
    path: &config::AspeedManifestCreationPath,
    cfg: &config::AspeedAuthManifestConfigFromFile,
) -> Result<()> {
    // Build a FirmwareTOC from an existing flash image and provided config
    let flash_path = path.flash_image.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "flash_image path is missing",
        )
    })?;

    let fw_toc_path = path.fw_toc.as_ref().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "fw_toc path is missing")
    })?;

    let mut fw_toc_file = File::create(&fw_toc_path)?;
    let mut flash_file = File::open(flash_path)?;

    // Read FlashHeader
    let mut header = read_flash_header(&mut flash_file)?;
    header.magic = TOC_HEADER_MAGIC;
    header.header_checksum =
        calculate_checksum(header.as_bytes()[..offset_of!(FlashHeader, header_checksum)].as_ref());
    debug!("TOC HEADER = {:#?}", header);

    // Determine how many ImageHeaders to read
    let img_count = header.image_count as usize;
    if img_count > IMAGE_COUNT {
        panic!("image_count {} over limit {}", img_count, IMAGE_COUNT);
    }

    // Read the ImageHeader section based on image_count
    let image_headers = read_image_headers(
        &mut flash_file,
        img_count,
        header.image_headers_offset as u64,
    )?;

    debug!("Loaded {} ImageHeaders", image_headers.len());

    let mut payload = FlashImagePayload {
        image_info: [ImageHeader {
            identifier: 0,
            offset: 0,
            size: 0,
            image_checksum: 0,
            image_header_checksum: 0,
        }; IMAGE_COUNT],
        filenames: [[0u8; FILENAME_LEN]; IMAGE_COUNT],
    };

    for i in 0..img_count {
        payload.image_info[i] = image_headers[i];
        payload.image_info[i].offset = fw_toc_filename_offset(i) as u32;
        payload.image_info[i].image_header_checksum = calculate_checksum(
            payload.image_info[i].as_bytes()[..offset_of!(ImageHeader, image_header_checksum)]
                .as_ref(),
        );
    }

    set_filename(
        &mut payload.filenames[0],
        &cfg.image_runtime_list.caliptra_file,
    )?;
    let manifest_str = path
        .manifest
        .as_ref()
        .and_then(|p| p.to_str().map(|s| s.to_owned()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid manifest path"))?;
    set_filename(&mut payload.filenames[1], &manifest_str)?;
    set_filename(&mut payload.filenames[2], &cfg.image_runtime_list.mcu_file)?;

    let mut cur_img_count = 3;
    cfg.image_metadata_list
        .iter()
        .filter(|img| img.fw_id != unsafe { config::MCU_RUN_TIME_FW_ID })
        .map(|img| img.file.as_str()) // &str
        .enumerate() // produce (idx, &str)
        .try_for_each(|(_idx, name)| {
            if cur_img_count >= IMAGE_COUNT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("too many images (max {})", IMAGE_COUNT),
                ));
            }

            set_filename(&mut payload.filenames[cur_img_count], name)?;
            cur_img_count += 1;
            Ok(())
        })?; // propagate Result

    // 1) Compute the max filename width in *character count* (NOT bytes)
    let mut max_name_chars: usize = 0;
    for i in 0..cur_img_count {
        let name = cstr_from_buf(&payload.filenames[i]);
        let c = name.chars().count(); // character length
        if c > max_name_chars {
            max_name_chars = c;
        }
    }
    max_name_chars = max_name_chars + 1;

    println!("================================================================= ImageHeaders =================================================================");
    for i in 0..img_count {
        let name = cstr_from_buf(&payload.filenames[i]);

        // 2) Right-align by character width
        // NOTE: format width uses "display width" roughly as chars count for most cases.
        // For full terminal display width correctness (emoji/CJK), you'd need unicode-width.
        let name_aligned = format!("{:>width$}", name, width = max_name_chars).bright_cyan();

        println!(
        "ImageHeader[{:>2}]: id={:#010X} offset={:#010X} size={:#010X} chk={:#010X} hdr_chk={:#010X} filename=#{}#",
        i,
        image_headers[i].identifier,
        image_headers[i].offset,
        image_headers[i].size,
        image_headers[i].image_checksum,
        image_headers[i].image_header_checksum,
        name_aligned
    );
    }

    let fw_toc = FirmwareTOC { header, payload };

    // Write the FirmwareTOC
    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &fw_toc as *const FirmwareTOC as *const u8,
            std::mem::size_of::<FirmwareTOC>(),
        )
    };
    fw_toc_file.write_all(header_bytes)?;

    Ok(())
}
