use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use gannondorf::{Error, FunctionMapping, Result, extract_function_mapping};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract binary/function address mappings from annotated C++ source.",
    long_about = "Extract mappings from //! FILE and //! FUNC annotations in C++ source. The tool parses C++ syntax, attaches each FUNC annotation to the next function declaration or definition, and prints a simple mapping to stdout or to a .map file.",
    arg_required_else_help = true,
    after_help = "Examples:\n  cxxmap tests/mapping_test.cpp\n  cxxmap tests/mapping_test.cpp -o build/maps\n\nAnnotations:\n  //! FILE TI.EXE\n  //! FUNC 0x0041bb40\n  void fn_0041bb40();"
)]
struct Args {
    /// C++ source file to parse.
    #[arg(value_name = "INPUT_CPP")]
    input: PathBuf,

    /// Output directory. Writes INPUT_CPP's file stem with a .map extension.
    #[arg(short, long, value_name = "OUTPUT_DIR")]
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
    let text = render_mapping(&mapping);

    if let Some(output_dir) = &args.output {
        write_mapping_file(output_dir, &args.input, &text)?;
    } else {
        print!("{text}");
    }

    Ok(())
}

fn render_mapping(mapping: &FunctionMapping) -> String {
    if mapping.map.is_empty() {
        return String::new();
    }

    let mut output = String::new();
    match &mapping.binary {
        Some(binary) => output.push_str(&format!("binary = \"{}\"\n", escape_string(binary))),
        None => output.push_str("binary = null\n"),
    }

    output.push_str("map = {\n");
    for entry in &mapping.map {
        output.push_str(&format!(
            "  \"{}\": 0x{:08X},",
            escape_string(&entry.name),
            entry.address
        ));
        output.push('\n');
    }
    output.push_str("}\n");
    output
}

fn write_mapping_file(output_dir: &Path, input: &Path, text: &str) -> Result<()> {
    let output = output_dir.join(default_output_file_name(input));
    if output.exists() {
        let existing = fs::read(&output)
            .map_err(|err| Error::new(format!("failed to read `{}`: {err}", output.display())))?;
        if existing == text.as_bytes() {
            return Ok(());
        }
    }

    fs::create_dir_all(output_dir).map_err(|err| {
        Error::new(format!(
            "failed to create output directory `{}`: {err}",
            output_dir.display()
        ))
    })?;
    fs::write(&output, text)
        .map_err(|err| Error::new(format!("failed to write `{}`: {err}", output.display())))
}

fn default_output_file_name(input: &Path) -> PathBuf {
    let mut output = input
        .file_stem()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mapped"));
    output.set_extension("map");
    output
}

fn escape_string(value: &str) -> String {
    value.escape_default().collect()
}
