use std::fs;
use std::path::PathBuf;

use clap::Parser;
use unlink::{
    Result, UnlinkError, default_output_path, extract_function_object, extract_function_objects,
    parse_address,
};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract Win32 PE functions into standalone COFF object files.",
    long_about = "Extract Win32 PE/i386 functions from an executable and write standalone COFF object files.\n\nBy default, unlink discovers functions automatically and writes one object file per discovered function. Use --address when you want to extract exactly one known function by virtual address or RVA.",
    arg_required_else_help = true,
    after_help = "Examples:\n  unlink input.exe -o extracted-objects\n  unlink input.exe --address 0x401000 -o sub_00401000.obj\n\nOutput:\n  Without --address, -o/--output is an output directory. If omitted, objects are written to the current directory.\n  With --address, -o/--output is the object file path. If omitted, the symbol name is used."
)]
struct Args {
    /// PE32 executable to extract from.
    #[arg(value_name = "INPUT_EXE")]
    input: PathBuf,

    /// Function address to extract, as decimal or 0x-prefixed hex. Omitting this discovers functions automatically.
    #[arg(short, long, value_name = "ADDRESS")]
    address: Option<String>,

    /// Output object path for --address, or output directory for automatic discovery.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let input = fs::read(&args.input).map_err(|err| {
        UnlinkError::new(format!("failed to read `{}`: {err}", args.input.display()))
    })?;

    if let Some(address) = args.address {
        let address = parse_address(&address)?;
        let extracted = extract_function_object(&input, address)?;
        let output = args
            .output
            .unwrap_or_else(|| default_output_path(&extracted.symbol_name));
        fs::write(&output, &extracted.bytes).map_err(|err| {
            UnlinkError::new(format!("failed to write `{}`: {err}", output.display()))
        })?;
        println!(
            "wrote {} bytes for {} to {}",
            extracted.function_len,
            extracted.symbol_name,
            output.display()
        );
        return Ok(());
    }

    let output_dir = args.output.unwrap_or_else(|| PathBuf::from("."));
    if output_dir.exists() && !output_dir.is_dir() {
        return Err(UnlinkError::new(format!(
            "automatic discovery output `{}` exists and is not a directory",
            output_dir.display()
        )));
    }
    fs::create_dir_all(&output_dir).map_err(|err| {
        UnlinkError::new(format!(
            "failed to create output directory `{}`: {err}",
            output_dir.display()
        ))
    })?;

    let extracted = extract_function_objects(&input)?;
    for object in &extracted {
        let output = output_dir.join(default_output_path(&object.symbol_name));
        fs::write(&output, &object.bytes).map_err(|err| {
            UnlinkError::new(format!("failed to write `{}`: {err}", output.display()))
        })?;
    }
    println!(
        "wrote {} functions to {}",
        extracted.len(),
        output_dir.display()
    );
    Ok(())
}
