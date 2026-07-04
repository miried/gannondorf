use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use gannondorf::{
    Error, ExtractedFunction, MappingEntry, Result, extract_function_mapping,
    extract_functions_object,
};
use object::{Object, ObjectSymbol, SymbolKind};
use serde_json::{Map, Value};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract mapped C++ functions from an annotated binary.",
    long_about = "Parse //! FILE and //! FUNC annotations from C++ source, resolve the FILE entry under a binary directory, and extract the mapped function addresses into one combined COFF object.",
    arg_required_else_help = true,
    after_help = "Examples:\n  cxxunlink tests/mapping_test.cpp tests/bin -o mapped.obj\n  cxxunlink src/sub_004321D0.cpp bin -o target/sub_004321D0.obj --objdiff-json objdiff.json --objdiff-base-path build/sub_004321D0.obj --objdiff-unit-name WinMain\n\nAnnotations:\n  //! FILE TI.EXE\n  //! FUNC 0x0041bb40\n  void fn_0041bb40();\n\nOutput:\n  The executable is resolved as BINARY_DIR/FILE. The output is a combined COFF object containing every unique mapped function address. If -o/--output is omitted, the output defaults to INPUT_CPP's file stem with a .obj extension.\n\nObjdiff:\n  With --objdiff-json, cxxunlink creates or updates a unit with target_path, optional base_path, metadata.source_path, and symbol_mappings. If the base object exists, mappings use its actual COFF symbol names; otherwise they use parsed source names."
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

    /// Objdiff JSON config to create or update with a unit for this extraction.
    #[arg(long, value_name = "OBJDIFF_JSON")]
    objdiff_json: Option<PathBuf>,

    /// Objdiff unit display name. Defaults to OUTPUT_OBJ's file stem.
    #[arg(long, value_name = "NAME", requires = "objdiff_json")]
    objdiff_unit_name: Option<String>,

    /// Objdiff target_path value. Defaults to OUTPUT_OBJ.
    #[arg(long, value_name = "PATH", requires = "objdiff_json")]
    objdiff_target_path: Option<PathBuf>,

    /// Objdiff base_path value for the object built from source.
    #[arg(long, value_name = "PATH", requires = "objdiff_json")]
    objdiff_base_path: Option<PathBuf>,

    /// Objdiff metadata.source_path value. Defaults to INPUT_CPP.
    #[arg(long, value_name = "PATH", requires = "objdiff_json")]
    objdiff_source_path: Option<PathBuf>,
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
        .clone()
        .unwrap_or_else(|| default_output_path(&args.input));
    fs::write(&output, &extracted.bytes)
        .map_err(|err| Error::new(format!("failed to write `{}`: {err}", output.display())))?;

    if let Some(objdiff_json) = &args.objdiff_json {
        let unit = build_objdiff_unit(&args, &output, &mapping.map, &extracted.functions)?;
        write_objdiff_unit(objdiff_json, unit)?;
    }

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

#[derive(Debug, Clone)]
struct ObjdiffUnit {
    name: String,
    target_path: PathBuf,
    base_path: Option<PathBuf>,
    source_path: PathBuf,
    symbol_mappings: Map<String, Value>,
}

fn build_objdiff_unit(
    args: &Args,
    output: &Path,
    entries: &[MappingEntry],
    functions: &[ExtractedFunction],
) -> Result<ObjdiffUnit> {
    let source_names = unique_source_names(entries);
    let base_symbols = load_base_symbols(args.objdiff_base_path.as_deref())?;
    let mut symbol_mappings = Map::new();

    for (source_name, function) in source_names.iter().zip(functions) {
        symbol_mappings.insert(
            function.symbol_name.clone(),
            Value::String(resolve_base_symbol(source_name, &base_symbols)),
        );
    }

    Ok(ObjdiffUnit {
        name: args
            .objdiff_unit_name
            .clone()
            .unwrap_or_else(|| default_unit_name(output)),
        target_path: args
            .objdiff_target_path
            .clone()
            .unwrap_or_else(|| output.to_path_buf()),
        base_path: args.objdiff_base_path.clone(),
        source_path: args
            .objdiff_source_path
            .clone()
            .unwrap_or_else(|| args.input.clone()),
        symbol_mappings,
    })
}

fn unique_addresses(entries: &[MappingEntry]) -> Vec<u64> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .filter_map(|entry| seen.insert(entry.address).then_some(entry.address))
        .collect()
}

fn unique_source_names(entries: &[MappingEntry]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .filter_map(|entry| seen.insert(entry.address).then(|| entry.name.clone()))
        .collect()
}

fn load_base_symbols(base_path: Option<&Path>) -> Result<Vec<String>> {
    let Some(base_path) = base_path.filter(|path| path.exists()) else {
        return Ok(Vec::new());
    };

    let data = fs::read(base_path)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", base_path.display())))?;
    let file = object::File::parse(&*data)
        .map_err(|err| Error::new(format!("failed to parse `{}`: {err}", base_path.display())))?;

    Ok(file
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text)
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .collect())
}

fn resolve_base_symbol(source_name: &str, base_symbols: &[String]) -> String {
    if base_symbols.iter().any(|symbol| symbol == source_name) {
        return source_name.to_owned();
    }

    let matches = base_symbols
        .iter()
        .filter(|symbol| symbol_matches_source_name(symbol, source_name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [symbol] => (*symbol).clone(),
        _ => source_name.to_owned(),
    }
}

fn symbol_matches_source_name(symbol: &str, source_name: &str) -> bool {
    if c_symbol_matches_source_name(symbol, source_name) {
        return true;
    }
    if let Some(symbol) = symbol.strip_prefix('_') {
        return c_symbol_matches_source_name(symbol, source_name);
    }
    if let Some(symbol) = symbol.strip_prefix('?')
        && let Some(suffix) = symbol.strip_prefix(source_name)
    {
        return suffix.starts_with('@');
    }
    false
}

fn c_symbol_matches_source_name(symbol: &str, source_name: &str) -> bool {
    if symbol == source_name {
        return true;
    }
    symbol.strip_prefix(source_name).is_some_and(|suffix| {
        suffix.starts_with('@') && suffix[1..].bytes().all(|b| b.is_ascii_digit())
    })
}

fn default_output_path(input: &Path) -> PathBuf {
    let mut output = input
        .file_stem()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mapped"));
    output.set_extension("obj");
    output
}

fn default_unit_name(output: &Path) -> String {
    output
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("mapped")
        .to_owned()
}

fn write_objdiff_unit(path: &Path, unit: ObjdiffUnit) -> Result<()> {
    let mut config = read_objdiff_config(path)?;
    upsert_objdiff_unit(&mut config, unit)?;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| {
            Error::new(format!(
                "failed to create objdiff JSON directory `{}`: {err}",
                parent.display()
            ))
        })?;
    }

    let text = serde_json::to_string_pretty(&config)
        .map_err(|err| Error::new(format!("failed to render objdiff JSON: {err}")))?;
    fs::write(path, format!("{text}\n"))
        .map_err(|err| Error::new(format!("failed to write `{}`: {err}", path.display())))
}

fn read_objdiff_config(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }

    let data = fs::read(path)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", path.display())))?;
    serde_json::from_slice(&data)
        .map_err(|err| Error::new(format!("failed to parse `{}`: {err}", path.display())))
}

fn upsert_objdiff_unit(config: &mut Value, unit: ObjdiffUnit) -> Result<()> {
    if !config.is_object() {
        *config = Value::Object(Map::new());
    }
    let config = config
        .as_object_mut()
        .expect("objdiff config was converted to an object");
    let units = config
        .entry("units")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !units.is_array() {
        *units = Value::Array(Vec::new());
    }
    let units = units
        .as_array_mut()
        .expect("objdiff units was converted to an array");

    let unit_name = unit.name.clone();
    let target_path = json_path(&unit.target_path);
    let unit_value = objdiff_unit_value(unit);
    if let Some(existing) = units
        .iter_mut()
        .find(|existing| objdiff_unit_matches(existing, &unit_name, &target_path))
    {
        merge_objdiff_unit(existing, unit_value)?;
    } else {
        units.push(unit_value);
    }
    Ok(())
}

fn objdiff_unit_value(unit: ObjdiffUnit) -> Value {
    let mut object = Map::new();
    object.insert("name".to_owned(), Value::String(unit.name));
    object.insert(
        "target_path".to_owned(),
        Value::String(json_path(&unit.target_path)),
    );
    if let Some(base_path) = unit.base_path {
        object.insert("base_path".to_owned(), Value::String(json_path(&base_path)));
    }

    let mut metadata = Map::new();
    metadata.insert(
        "source_path".to_owned(),
        Value::String(json_path(&unit.source_path)),
    );
    object.insert("metadata".to_owned(), Value::Object(metadata));
    object.insert(
        "symbol_mappings".to_owned(),
        Value::Object(unit.symbol_mappings),
    );
    Value::Object(object)
}

fn objdiff_unit_matches(unit: &Value, name: &str, target_path: &str) -> bool {
    unit.get("name").and_then(Value::as_str) == Some(name)
        || unit.get("target_path").and_then(Value::as_str) == Some(target_path)
}

fn merge_objdiff_unit(existing: &mut Value, replacement: Value) -> Result<()> {
    if !existing.is_object() {
        *existing = Value::Object(Map::new());
    }
    let existing = existing
        .as_object_mut()
        .expect("objdiff unit was converted to an object");
    let replacement = replacement
        .as_object()
        .ok_or_else(|| Error::new("replacement objdiff unit is not an object"))?;

    for (key, value) in replacement {
        if key == "metadata" {
            merge_objdiff_metadata(existing, value.clone());
        } else {
            existing.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

fn merge_objdiff_metadata(existing: &mut Map<String, Value>, replacement: Value) {
    let metadata = existing
        .entry("metadata")
        .or_insert_with(|| Value::Object(Map::new()));
    if !metadata.is_object() {
        *metadata = Value::Object(Map::new());
    }
    let metadata = metadata
        .as_object_mut()
        .expect("objdiff metadata was converted to an object");
    if let Some(replacement) = replacement.as_object() {
        for (key, value) in replacement {
            metadata.insert(key.clone(), value.clone());
        }
    }
}

fn json_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
