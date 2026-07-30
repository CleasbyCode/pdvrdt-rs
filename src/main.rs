// PNG Data Vehicle (pdvrdt). Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023
// Linux-only CLI binary for the pdvrdt library.

#[cfg(not(target_os = "linux"))]
compile_error!("pdvrdt-rs is a Linux-only tool");

use pdvrdt::args::ProgramArgs;
use pdvrdt::common::{FileTypeCheck, Mode};
use pdvrdt::conceal;
use pdvrdt::file_utils::read_file;
use pdvrdt::recover;

fn main() {
    if let Err(e) = run() {
        eprintln!("\n{}\n", e);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    pdvrdt::crypto::init()
        .map_err(|_: pdvrdt::crypto::Error| anyhow::anyhow!("Libsodium initialization failed!"))?;

    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
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
