use std::fs;
use std::path::PathBuf;

use clap::Parser;
use unlink::{Result, UnlinkError, default_output_path, extract_function_object, parse_address};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    /// PE32 executable to extract from.
    input: PathBuf,

    /// Function address to extract, as decimal or 0x-prefixed hex.
    #[arg(short, long)]
    address: Option<String>,

    /// Output COFF object path. Defaults to sub_XXXXXXXX.obj.
    #[arg(short, long)]
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
    let address = args.address.as_deref().ok_or_else(|| {
        UnlinkError::new("automatic function discovery is not implemented yet; pass --address")
    })?;
    let address = parse_address(address)?;
    let input = fs::read(&args.input).map_err(|err| {
        UnlinkError::new(format!("failed to read `{}`: {err}", args.input.display()))
    })?;
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
    Ok(())
}
