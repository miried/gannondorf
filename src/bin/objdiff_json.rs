use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use gannondorf::{Error, FunctionMapping, MappingEntry, Result, parse_mapping_file};
use object::{Object, ObjectSymbol, SymbolKind};
use serde_json::{Map, Value};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Create or incrementally update objdiff JSON units from cxxmap .map files.",
    long_about = "Create or incrementally update an objdiff.json config from cxxmap .map files. Only units corresponding to the map files passed on the command line are changed; every other existing unit is left untouched. Passing an empty map removes that map's unit so the config contains units only for non-empty maps.",
    arg_required_else_help = true,
    after_help = "Examples:\n  objdiff-json --json objdiff.json --target-dir target --build-dir build --source-dir src maps/main.map\n  objdiff-json --json objdiff.json maps/main.map maps/stubs.map"
)]
struct Args {
    /// cxxmap .map files to apply to the objdiff config.
    #[arg(value_name = "INPUT_MAP", required = true)]
    maps: Vec<PathBuf>,

    /// Objdiff JSON config to create or update.
    #[arg(
        long,
        short,
        value_name = "OBJDIFF_JSON",
        default_value = "objdiff.json"
    )]
    json: PathBuf,

    /// Directory containing extracted target objects.
    #[arg(long, value_name = "DIR", default_value = "target")]
    target_dir: PathBuf,

    /// Directory containing compiler-built base objects.
    #[arg(long, value_name = "DIR", default_value = "build")]
    build_dir: PathBuf,

    /// Directory containing source files corresponding to maps.
    #[arg(long, value_name = "DIR", default_value = "src")]
    source_dir: PathBuf,

    /// Source extension to use for metadata.source_path.
    #[arg(long, value_name = "EXT", default_value = "cpp")]
    source_ext: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let mut config = read_objdiff_config(&args.json)?;
    let mut changed_units = 0usize;

    for map in &args.maps {
        let paths = objdiff_paths_for_map(&args, map);
        let text = fs::read_to_string(map)
            .map_err(|err| Error::new(format!("failed to read `{}`: {err}", map.display())))?;
        let mapping = parse_mapping_file(&text)?;
        if mapping.map.is_empty() && mapping.data.is_empty() {
            if remove_objdiff_unit(&mut config, &paths) {
                changed_units += 1;
                println!(
                    "removed objdiff unit {} for empty map {}",
                    paths.name,
                    map.display()
                );
            }
            continue;
        }

        let unit = build_objdiff_unit(paths, &mapping)?;
        upsert_objdiff_unit(&mut config, unit)?;
        changed_units += 1;
        println!("updated objdiff unit from {}", map.display());
    }

    write_objdiff_config_if_changed(&args.json, &config)?;
    println!("applied {changed_units} objdiff unit change(s)");
    Ok(())
}

#[derive(Debug, Clone)]
struct ObjdiffPaths {
    name: String,
    target_path: PathBuf,
    base_path: PathBuf,
    source_path: PathBuf,
}

#[derive(Debug, Clone)]
struct ObjdiffUnit {
    paths: ObjdiffPaths,
    symbol_mappings: Map<String, Value>,
}

fn objdiff_paths_for_map(args: &Args, map: &Path) -> ObjdiffPaths {
    let name = map
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("mapped")
        .to_owned();
    let source_ext = args.source_ext.trim_start_matches('.');

    ObjdiffPaths {
        target_path: args.target_dir.join(format!("{name}.obj")),
        base_path: args.build_dir.join(format!("{name}.obj")),
        source_path: args.source_dir.join(format!("{name}.{source_ext}")),
        name,
    }
}

fn build_objdiff_unit(paths: ObjdiffPaths, mapping: &FunctionMapping) -> Result<ObjdiffUnit> {
    let base_symbols = load_base_symbols(&paths.base_path)?;
    let mut symbol_mappings = Map::new();

    for entry in unique_entries_by_address(&mapping.map) {
        symbol_mappings.insert(
            code_symbol_name(entry.address),
            Value::String(resolve_base_symbol(
                &entry.name,
                &base_symbols,
                SymbolKind::Text,
            )),
        );
    }

    for entry in &mapping.data {
        symbol_mappings.insert(
            format!("data_{:08X}", entry.address),
            Value::String(resolve_base_symbol(
                &entry.name,
                &base_symbols,
                SymbolKind::Data,
            )),
        );
    }

    Ok(ObjdiffUnit {
        paths,
        symbol_mappings,
    })
}

fn unique_entries_by_address(entries: &[MappingEntry]) -> Vec<&MappingEntry> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .filter(|entry| seen.insert(entry.address))
        .collect()
}

fn load_base_symbols(base_path: &Path) -> Result<Vec<(String, SymbolKind)>> {
    if !base_path.exists() {
        return Ok(Vec::new());
    }

    let data = fs::read(base_path)
        .map_err(|err| Error::new(format!("failed to read `{}`: {err}", base_path.display())))?;
    let file = object::File::parse(&*data)
        .map_err(|err| Error::new(format!("failed to parse `{}`: {err}", base_path.display())))?;

    Ok(file
        .symbols()
        .filter(|symbol| matches!(symbol.kind(), SymbolKind::Text | SymbolKind::Data))
        .filter_map(|symbol| {
            symbol
                .name()
                .ok()
                .map(|name| (name.to_owned(), symbol.kind()))
        })
        .collect())
}

fn resolve_base_symbol(
    source_name: &str,
    base_symbols: &[(String, SymbolKind)],
    kind: SymbolKind,
) -> String {
    let base_symbols = base_symbols
        .iter()
        .filter(|(_, candidate_kind)| *candidate_kind == kind)
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();
    if base_symbols
        .iter()
        .any(|symbol| symbol.as_str() == source_name)
    {
        return source_name.to_owned();
    }

    let matches = base_symbols
        .iter()
        .filter(|symbol| symbol_matches_source_name(symbol, source_name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [symbol] => (**symbol).clone(),
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
    let units = objdiff_units_mut(config);
    let unit_name = unit.paths.name.clone();
    let target_path = json_path(&unit.paths.target_path);
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

fn remove_objdiff_unit(config: &mut Value, paths: &ObjdiffPaths) -> bool {
    let units = objdiff_units_mut(config);
    let target_path = json_path(&paths.target_path);
    let original_len = units.len();
    units.retain(|unit| !objdiff_unit_matches(unit, &paths.name, &target_path));
    units.len() != original_len
}

fn objdiff_units_mut(config: &mut Value) -> &mut Vec<Value> {
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
    units
        .as_array_mut()
        .expect("objdiff units was converted to an array")
}

fn objdiff_unit_value(unit: ObjdiffUnit) -> Value {
    let mut object = Map::new();
    object.insert("name".to_owned(), Value::String(unit.paths.name));
    object.insert(
        "target_path".to_owned(),
        Value::String(json_path(&unit.paths.target_path)),
    );
    object.insert(
        "base_path".to_owned(),
        Value::String(json_path(&unit.paths.base_path)),
    );

    let mut metadata = Map::new();
    metadata.insert(
        "source_path".to_owned(),
        Value::String(json_path(&unit.paths.source_path)),
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

fn write_objdiff_config_if_changed(path: &Path, config: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(config)
        .map_err(|err| Error::new(format!("failed to render objdiff JSON: {err}")))?;
    let text = format!("{text}\n");

    if path.exists() {
        let existing = fs::read(path)
            .map_err(|err| Error::new(format!("failed to read `{}`: {err}", path.display())))?;
        if existing == text.as_bytes() {
            return Ok(());
        }
    }

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
    fs::write(path, text)
        .map_err(|err| Error::new(format!("failed to write `{}`: {err}", path.display())))
}

fn code_symbol_name(va: u64) -> String {
    format!("sub_{va:08X}")
}

fn json_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_data_by_kind_without_guessing_ambiguous_names() {
        let symbols = vec![
            ("?value@@3HA".into(), SymbolKind::Data),
            ("?value@@YAHXZ".into(), SymbolKind::Text),
            ("_plain".into(), SymbolKind::Data),
            ("?shared@A@@2HA".into(), SymbolKind::Data),
            ("?shared@B@@2HA".into(), SymbolKind::Data),
            ("?values@@3PAHA".into(), SymbolKind::Data),
            ("_prefixExtra".into(), SymbolKind::Data),
        ];
        for (source, expected) in [
            ("value", "?value@@3HA"),
            ("plain", "_plain"),
            ("values", "?values@@3PAHA"),
            ("shared", "shared"),
            ("prefix", "prefix"),
            ("missing", "missing"),
            ("?value@@3HA", "?value@@3HA"),
        ] {
            assert_eq!(
                resolve_base_symbol(source, &symbols, SymbolKind::Data),
                expected
            );
        }
        assert_eq!(
            resolve_base_symbol("value", &symbols, SymbolKind::Text),
            "?value@@YAHXZ"
        );
        let exact = vec![
            ("plain".into(), SymbolKind::Data),
            ("_plain".into(), SymbolKind::Data),
        ];
        assert_eq!(
            resolve_base_symbol("plain", &exact, SymbolKind::Data),
            "plain"
        );
    }
}
