use std::fs;
use std::path::PathBuf;

use clap::Parser;
use gannondorf::{
    Error, Result, default_output_path, extract_function_object, extract_function_objects,
    extract_functions_object, parse_address,
};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract Win32 PE functions into standalone COFF object files.",
    long_about = "Extract Win32 PE/i386 functions from an executable and write standalone COFF object files.\n\nBy default, unlink discovers functions automatically and writes one object file per discovered function. Use --address when you want to extract one or more known functions by virtual address or RVA.",
    arg_required_else_help = true,
    after_help = "Examples:\n  unlink input.exe -o extracted-objects\n  unlink input.exe --address 0x401000 -o sub_00401000.obj\n  unlink input.exe --address 0x401000 --address 0x401050 -o selected.obj\n\nOutput:\n  Without --address, -o/--output is an output directory. If omitted, objects are written to the current directory.\n  With one --address, -o/--output is the object file path. If omitted, the symbol name is used.\n  With multiple --address values, -o/--output is required and names the combined object file."
)]
struct Args {
    /// PE32 executable to extract from.
    #[arg(value_name = "INPUT_EXE")]
    input: PathBuf,

    /// Function address to extract, as decimal or 0x-prefixed hex. May be repeated.
    #[arg(short, long, value_name = "ADDRESS", num_args = 1..)]
    address: Vec<String>,

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
    if args.address.len() > 1 && args.output.is_none() {
        return Err(Error::new(
            "-o/--output is required when extracting multiple addresses into one object",
        ));
    }

    let input = fs::read(&args.input)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", args.input.display())))?;

    if !args.address.is_empty() {
        let addresses = args
            .address
            .iter()
            .map(|address| parse_address(address))
            .collect::<Result<Vec<_>>>()?;

        if addresses.len() == 1 {
            let extracted = extract_function_object(&input, addresses[0])?;
            let output = args
                .output
                .unwrap_or_else(|| default_output_path(&extracted.symbol_name));
            fs::write(&output, &extracted.bytes).map_err(|err| {
                Error::new(format!("failed to write `{}`: {err}", output.display()))
            })?;
            println!(
                "wrote {} bytes for {} to {}",
                extracted.function_len,
                extracted.symbol_name,
                output.display()
            );
            return Ok(());
        }

        let output = args.output.expect("multi-address output was checked");
        let extracted = extract_functions_object(&input, &addresses)?;
        fs::write(&output, &extracted.bytes)
            .map_err(|err| Error::new(format!("failed to write `{}`: {err}", output.display())))?;
        let names = extracted
            .functions
            .iter()
            .map(|function| function.symbol_name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "wrote {} functions ({}) to {}",
            extracted.functions.len(),
            names,
            output.display()
        );
        return Ok(());
    }

    let output_dir = args.output.unwrap_or_else(|| PathBuf::from("."));
    if output_dir.exists() && !output_dir.is_dir() {
        return Err(Error::new(format!(
            "automatic discovery output `{}` exists and is not a directory",
            output_dir.display()
        )));
    }
    fs::create_dir_all(&output_dir).map_err(|err| {
        Error::new(format!(
            "failed to create output directory `{}`: {err}",
            output_dir.display()
        ))
    })?;

    let extracted = extract_function_objects(&input)?;
    for object in &extracted {
        let output = output_dir.join(default_output_path(&object.symbol_name));
        fs::write(&output, &object.bytes)
            .map_err(|err| Error::new(format!("failed to write `{}`: {err}", output.display())))?;
    }
    println!(
        "wrote {} functions to {}",
        extracted.len(),
        output_dir.display()
    );
    Ok(())
}
