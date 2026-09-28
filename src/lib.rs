//! pdvrdt-rs: PNG data-vehicle steganography CLI library (Linux only).
//!
//! Cover images and encrypted profiles are bounded in memory; ordinary input and
//! recovered payload files are compressed/decompressed through validated file
//! descriptors so large secrets are not first copied wholesale into RAM.

#![cfg(target_os = "linux")]

pub mod args;
pub mod binary_io;
pub mod common;
pub mod compression;
pub mod conceal;
pub mod crypto;
pub mod encryption;
pub mod file_utils;
pub mod image;
pub mod pin_input;
pub mod recover;
pub mod reddit_steg;
