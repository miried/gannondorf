use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use gannondorf::{Error, MappingEntry, Result, extract_function_mapping, extract_functions_object};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract mapped C++ functions from an annotated binary.",
    long_about = "Parse //! FILE and //! FUNC annotations from C++ source, resolve the FILE entry under a binary directory, and extract the mapped function addresses into one combined COFF object.",
    arg_required_else_help = true,
    after_help = "Examples:\n  cxxunlink tests/mapping_test.cpp tests/bin -o mapped.obj\n\nAnnotations:\n  //! FILE TI.EXE\n  //! FUNC 0x0041bb40\n  void fn_0041bb40();\n\nOutput:\n  The executable is resolved as BINARY_DIR/FILE. The output is a combined COFF object containing every unique mapped function address. If -o/--output is omitted, the output defaults to INPUT_CPP's file stem with a .obj extension."
)]
struct Args {
    /// C++ source file to parse.
    #[arg(value_name = "INPUT_CPP")]
    input: PathBuf,

    /// Directory containing the binary named by the source FILE annotation.
    #[arg(value_name = "BINARY_DIR")]
    binary_dir: PathBuf,

    /// Output COFF object path. Defaults to INPUT_CPP's file stem with a .obj extension.
    #[arg(short, long, value_name = "OUTPUT_OBJ")]
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
    let source = fs::read_to_string(&args.input)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", args.input.display())))?;

    let mapping = extract_function_mapping(&source)?;
    let binary = mapping.binary.as_deref().ok_or_else(|| {
        Error::new("source mapping does not include a FILE annotation for the target binary")
    })?;
    if mapping.map.is_empty() {
        return Err(Error::new(
            "source mapping does not include any FUNC annotations",
        ));
    }

    let input_exe = args.binary_dir.join(binary);
    let input = fs::read(&input_exe)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", input_exe.display())))?;
    let addresses = unique_addresses(&mapping.map);
    let extracted = extract_functions_object(&input, &addresses)?;

    let output = args
        .output
        .unwrap_or_else(|| default_output_path(&args.input));
    fs::write(&output, &extracted.bytes)
        .map_err(|err| Error::new(format!("failed to write `{}`: {err}", output.display())))?;

    let names = extracted
        .functions
        .iter()
        .map(|function| function.symbol_name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "wrote {} function(s) ({}) from {} to {}",
        extracted.functions.len(),
        names,
        input_exe.display(),
        output.display()
    );
    Ok(())
}

fn unique_addresses(entries: &[MappingEntry]) -> Vec<u64> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .filter_map(|entry| seen.insert(entry.address).then_some(entry.address))
        .collect()
}

fn default_output_path(input: &Path) -> PathBuf {
    let mut output = input
        .file_stem()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mapped"));
    output.set_extension("obj");
    output
}
