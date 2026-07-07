use std::fs;
use std::path::{Path, PathBuf};

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
    long_about = "Extract Win32 PE/i386 functions from an executable and write standalone COFF object files.\n\nBy default, unlink discovers functions automatically and writes one object file per discovered function. Use --address when you want to extract one or more known functions by virtual address or RVA. Use --map to extract the addresses listed in a cxxmap .map file into one object.",
    arg_required_else_help = true,
    after_help = "Examples:\n  unlink input.exe -o extracted-objects\n  unlink input.exe --address 0x401000 -o sub_00401000.obj\n  unlink input.exe --address 0x401000 --address 0x401050 -o selected.obj\n  unlink bin --map maps/main.map -o target/main.obj\n\nOutput:\n  Without --address or --map, -o/--output is an output directory. If omitted, objects are written to the current directory.\n  With one --address, -o/--output is the object file path. If omitted, the symbol name is used.\n  With multiple --address values, -o/--output is required and names the combined object file.\n  With --map, INPUT_EXE may also be a binary directory. The map's binary entry selects the executable, and -o/--output defaults to the map file stem with a .obj extension."
)]
struct Args {
    /// PE32 executable to extract from, or binary directory for --map.
    #[arg(value_name = "INPUT_EXE")]
    input: PathBuf,

    /// Function address to extract, as decimal or 0x-prefixed hex. May be repeated.
    #[arg(short, long, value_name = "ADDRESS", num_args = 1..)]
    address: Vec<String>,

    /// cxxmap .map file to extract into one object.
    #[arg(long, value_name = "INPUT_MAP")]
    map: Option<PathBuf>,

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
    if args.map.is_some() && !args.address.is_empty() {
        return Err(Error::new("--map cannot be combined with --address"));
    }
    if args.address.len() > 1 && args.output.is_none() {
        return Err(Error::new(
            "-o/--output is required when extracting multiple addresses into one object",
        ));
    }

    if let Some(map) = &args.map {
        return extract_map_object(&args.input, map, args.output.as_deref());
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapExtraction {
    binary: Option<String>,
    entries: Vec<MapEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapEntry {
    name: String,
    address: u64,
}

fn extract_map_object(input: &Path, map: &Path, output: Option<&Path>) -> Result<()> {
    let text = fs::read_to_string(map)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", map.display())))?;
    let mapping = parse_mapping_file(&text)?;
    let output = output
        .map(PathBuf::from)
        .unwrap_or_else(|| default_map_output_path(map));

    if mapping.entries.is_empty() {
        println!(
            "skipped {} because it does not contain mapped functions",
            map.display()
        );
        return Ok(());
    }

    let input_exe = resolve_map_input(input, &mapping)?;
    let input_bytes = fs::read(&input_exe)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", input_exe.display())))?;
    let addresses = unique_map_addresses(&mapping.entries);
    let extracted = extract_functions_object(&input_bytes, &addresses)?;
    fs::write(&output, &extracted.bytes)
        .map_err(|err| Error::new(format!("failed to write `{}`: {err}", output.display())))?;

    let names = mapping
        .entries
        .iter()
        .map(|entry| format!("{}=0x{:08X}", entry.name, entry.address))
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

fn parse_mapping_file(text: &str) -> Result<MapExtraction> {
    let mut binary = None;
    let mut entries = Vec::new();
    let mut in_map = false;

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if in_map {
            if line == "}" {
                in_map = false;
                continue;
            }
            entries.push(parse_mapping_entry_line(line, line_number)?);
            continue;
        }

        if let Some(value) = line.strip_prefix("binary") {
            binary = Some(parse_binary_line(value, line_number)?);
        } else if line == "map = {" {
            in_map = true;
        } else {
            return Err(Error::new(format!(
                "unexpected mapping line {line_number}: `{line}`"
            )));
        }
    }

    if in_map {
        return Err(Error::new("mapping file ended before closing `}`"));
    }

    Ok(MapExtraction {
        binary: binary.flatten(),
        entries,
    })
}

fn parse_binary_line(value: &str, line_number: usize) -> Result<Option<String>> {
    let value = value
        .trim_start()
        .strip_prefix('=')
        .ok_or_else(|| Error::new(format!("invalid binary entry on line {line_number}")))?
        .trim();
    if value == "null" {
        return Ok(None);
    }
    parse_quoted_string(value, line_number).map(Some)
}

fn parse_mapping_entry_line(line: &str, line_number: usize) -> Result<MapEntry> {
    let line = line.strip_suffix(',').unwrap_or(line).trim_end();
    let (name, address) = line
        .split_once(':')
        .ok_or_else(|| Error::new(format!("invalid map entry on line {line_number}")))?;
    Ok(MapEntry {
        name: parse_quoted_string(name.trim(), line_number)?,
        address: parse_address(address.trim())?,
    })
}

fn parse_quoted_string(value: &str, line_number: usize) -> Result<String> {
    serde_json::from_str(value)
        .map_err(|err| Error::new(format!("invalid string on line {line_number}: {err}")))
}

fn resolve_map_input(input: &Path, mapping: &MapExtraction) -> Result<PathBuf> {
    if !input.is_dir() {
        return Ok(input.to_path_buf());
    }

    let binary = mapping.binary.as_deref().ok_or_else(|| {
        Error::new(
            "mapping file does not include a binary entry, so INPUT_EXE cannot be a directory",
        )
    })?;
    Ok(input.join(binary))
}

fn unique_map_addresses(entries: &[MapEntry]) -> Vec<u64> {
    let mut addresses = entries
        .iter()
        .map(|entry| entry.address)
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn default_map_output_path(map: &Path) -> PathBuf {
    let mut output = map
        .file_stem()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mapped"));
    output.set_extension("obj");
    output
}
