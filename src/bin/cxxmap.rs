use std::fs;
use std::path::PathBuf;

use clap::Parser;
use gannondorf::{Error, FunctionMapping, Result, extract_function_mapping};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract binary/function address mappings from annotated C++ source.",
    long_about = "Extract mappings from //! FILE and //! FUNC annotations in C++ source. The tool parses C++ syntax, attaches each FUNC annotation to the next function declaration or definition, and prints a simple mapping to stdout.",
    arg_required_else_help = true,
    after_help = "Examples:\n  cxxmap tests/mapping_test.cpp\n\nAnnotations:\n  //! FILE TI.EXE\n  //! FUNC 0x0041bb40\n  void fn_0041bb40();"
)]
struct Args {
    /// C++ source file to parse.
    #[arg(value_name = "INPUT_CPP")]
    input: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let source = fs::read_to_string(&args.input)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", args.input.display())))?;

    let mapping = extract_function_mapping(&source)?;

    print_mapping(&mapping);
    Ok(())
}

fn print_mapping(mapping: &FunctionMapping) {
    match &mapping.binary {
        Some(binary) => println!("binary = \"{}\"", escape_string(binary)),
        None => println!("binary = null"),
    }

    println!("map = {{");
    for entry in &mapping.map {
        println!(
            "  \"{}\": 0x{:08X},",
            escape_string(&entry.name),
            entry.address
        );
    }
    println!("}}");
}

fn escape_string(value: &str) -> String {
    value.escape_default().collect()
}
