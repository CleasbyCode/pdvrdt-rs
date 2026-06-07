// PNG Data Vehicle (pdvrdt v4.8). Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023

mod args;
mod binary_io;
mod common;
mod compression;
mod conceal;
#[allow(dead_code)]
mod crypto;
mod encryption;
mod file_utils;
mod image;
mod pin_input;
mod recover;

use args::ProgramArgs;
use common::{FileTypeCheck, Mode};
use file_utils::read_file;

fn main() {
    if let Err(e) = run() {
        eprintln!("\n{}\n", e);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    crate::crypto::init().map_err(|_| anyhow::anyhow!("Libsodium initialization failed!"))?;

    let args: Vec<String> = std::env::args().collect();
    let args_opt = ProgramArgs::parse(&args)?;
    let Some(program_args) = args_opt else {
        return Ok(());
    };

    let file_type = if program_args.mode == Mode::Conceal {
        FileTypeCheck::CoverImage
    } else {
        FileTypeCheck::EmbeddedImage
    };

    let mut png_vec = read_file(&program_args.image_file_path, file_type)?;

    match program_args.mode {
        Mode::Conceal => {
            conceal::conceal_data(
                &mut png_vec,
                program_args.option,
                &program_args.data_file_path,
            )?;
        }
        Mode::Recover => {
            recover::recover_data(&mut png_vec)?;
        }
    }

    Ok(())
}
