use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use object::SymbolKind;
use object::read::{Object as _, ObjectSection as _, ObjectSymbol as _};
use serde_json::Value;

static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

#[test]
fn compiled_basic_fixture_matches_extracted_objects() {
    let build = build_and_extract_fixture("basic.cpp");
    assert_objdiff_matches(
        &build,
        &[
            "_fixture_no_refs",
            "_fixture_uses_global",
            "_fixture_calls_function",
        ],
    );
}

#[test]
fn compiled_control_flow_fixture_matches_extracted_objects() {
    let build = build_and_extract_fixture("control_flow.cpp");
    assert_objdiff_matches(
        &build,
        &[
            "_fixture_if_else",
            "_fixture_loop_sum",
            "_fixture_nested_branches",
        ],
    );
}

#[test]
fn single_function_extraction_accepts_va_and_rva() {
    let build = compile_fixture("basic.cpp");
    let symbol = "_fixture_no_refs";
    let va = linked_va_for_source_symbol(&build, symbol);
    let rva = va - image_base(&build.exe);

    let va_output = build.dir.join("single-va.obj");
    run_unlink_address(&build.exe, va, &va_output);
    assert_objdiff_symbol_matches(&va_output, &build.obj, &format_code_symbol(va), symbol);

    let rva_output = build.dir.join("single-rva.obj");
    run_unlink_address(&build.exe, rva, &rva_output);
    assert_objdiff_symbol_matches(&rva_output, &build.obj, &format_code_symbol(va), symbol);
}

struct FixtureBuild {
    dir: PathBuf,
    exe: PathBuf,
    obj: PathBuf,
    extracted_dir: PathBuf,
}

fn build_and_extract_fixture(source_name: &str) -> FixtureBuild {
    let build = compile_fixture(source_name);
    run_unlink_discovery(&build.exe, &build.extracted_dir);
    build
}

fn compile_fixture(source_name: &str) -> FixtureBuild {
    let project_root = project_root();
    let source_path = project_root
        .join("tests")
        .join("fixtures")
        .join(source_name);
    let source_stem = source_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("fixture source has a UTF-8 stem");
    let dir = new_test_dir(source_stem);
    let local_source = dir.join(source_path.file_name().expect("fixture source has a name"));
    fs::copy(&source_path, &local_source).unwrap_or_else(|err| {
        panic!(
            "failed to copy fixture `{}` to `{}`: {err}",
            source_path.display(),
            local_source.display()
        )
    });

    let tools = project_root.join("tools");
    let compiler = tools.join("MSDEV").join("BIN").join("CL.EXE");
    let include = tools.join("MSDEV").join("INCLUDE");
    let lib = tools.join("MSDEV").join("LIB");
    assert!(
        compiler.exists(),
        "missing compiler `{}`; see tools/TOOLS.md",
        compiler.display()
    );

    let output = Command::new("wine")
        .arg(&compiler)
        .arg("/nologo")
        .arg(local_source.file_name().expect("local source has a name"))
        .current_dir(&dir)
        .env("include", &include)
        .env("INCLUDE", &include)
        .env("lib", &lib)
        .env("LIB", &lib)
        .output()
        .expect("failed to run Wine/MSVC compiler");
    assert_success("compile fixture with MSVC", &output);

    let exe = dir.join(format!("{source_stem}.exe"));
    let obj = dir.join(format!("{source_stem}.obj"));
    assert!(exe.exists(), "compiler did not produce `{}`", exe.display());
    assert!(obj.exists(), "compiler did not produce `{}`", obj.display());

    FixtureBuild {
        extracted_dir: dir.join("extracted"),
        dir,
        exe,
        obj,
    }
}

fn run_unlink_discovery(exe: &Path, output_dir: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_unlink"))
        .arg(exe)
        .arg("-o")
        .arg(output_dir)
        .output()
        .expect("failed to run unlink discovery");
    assert_success("run unlink discovery", &output);
}

fn run_unlink_address(exe: &Path, address: u64, output_obj: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_unlink"))
        .arg(exe)
        .arg("--address")
        .arg(format!("0x{address:X}"))
        .arg("-o")
        .arg(output_obj)
        .output()
        .expect("failed to run unlink address extraction");
    assert_success("run unlink address extraction", &output);
}

fn assert_objdiff_matches(build: &FixtureBuild, source_symbols: &[&str]) {
    for source_symbol in source_symbols {
        let va = linked_va_for_source_symbol(build, source_symbol);
        let target_symbol = format_code_symbol(va);
        let target_obj = build.extracted_dir.join(format!("{target_symbol}.obj"));
        assert!(
            target_obj.exists(),
            "automatic extraction did not produce `{}` for `{source_symbol}`",
            target_obj.display()
        );
        assert_objdiff_symbol_matches(&target_obj, &build.obj, &target_symbol, source_symbol);
    }
}

fn assert_objdiff_symbol_matches(
    target_obj: &Path,
    base_obj: &Path,
    target_symbol: &str,
    base_symbol: &str,
) {
    let report = run_objdiff(target_obj, base_obj, target_symbol);
    let left_symbol = find_symbol(&report["left"], target_symbol);
    let right_symbol = find_symbol(&report["right"], base_symbol);

    assert_eq!(left_symbol["kind"], "SYMBOL_FUNCTION");
    assert_eq!(right_symbol["kind"], "SYMBOL_FUNCTION");
    assert_eq!(
        parse_u64(&left_symbol["size"]),
        parse_u64(&right_symbol["size"]),
        "objdiff function size mismatch for {target_symbol} vs {base_symbol}"
    );

    let left_instructions = normalized_instructions(left_symbol);
    let right_instructions = normalized_instructions(right_symbol);
    assert_eq!(
        left_instructions, right_instructions,
        "objdiff instruction mismatch for {target_symbol} vs {base_symbol}"
    );
}

fn run_objdiff(target_obj: &Path, base_obj: &Path, target_symbol: &str) -> Value {
    let objdiff = project_root().join("tools").join("objdiff-cli-macos-arm64");
    assert!(
        objdiff.exists(),
        "missing objdiff CLI `{}`; see tools/TOOLS.md",
        objdiff.display()
    );

    let output = Command::new(objdiff)
        .arg("--no-color")
        .arg("diff")
        .arg("-1")
        .arg(target_obj)
        .arg("-2")
        .arg(base_obj)
        .arg(target_symbol)
        .arg("--format")
        .arg("json")
        .arg("-o")
        .arg("-")
        .output()
        .expect("failed to run objdiff");
    assert_success("run objdiff", &output);

    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "failed to parse objdiff JSON for `{}` vs `{}`: {err}\nstdout:\n{}\nstderr:\n{}",
            target_obj.display(),
            base_obj.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn linked_va_for_source_symbol(build: &FixtureBuild, source_symbol: &str) -> u64 {
    text_base(&build.exe) + object_symbol_offset(&build.obj, source_symbol)
}

fn object_symbol_offset(obj: &Path, source_symbol: &str) -> u64 {
    let data =
        fs::read(obj).unwrap_or_else(|err| panic!("failed to read `{}`: {err}", obj.display()));
    let file = object::File::parse(&*data)
        .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", obj.display()));
    let symbol = file
        .symbols()
        .find(|symbol| symbol.name() == Ok(source_symbol))
        .unwrap_or_else(|| panic!("missing symbol `{source_symbol}` in `{}`", obj.display()));
    assert_eq!(
        symbol.kind(),
        SymbolKind::Text,
        "`{source_symbol}` in `{}` is not a text symbol",
        obj.display()
    );
    symbol.address()
}

fn image_base(exe: &Path) -> u64 {
    text_base(exe) - text_rva(exe)
}

fn text_base(exe: &Path) -> u64 {
    let data =
        fs::read(exe).unwrap_or_else(|err| panic!("failed to read `{}`: {err}", exe.display()));
    let file = object::File::parse(&*data)
        .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", exe.display()));
    file.section_by_name(".text")
        .unwrap_or_else(|| panic!("missing .text in `{}`", exe.display()))
        .address()
}

fn text_rva(exe: &Path) -> u64 {
    let data =
        fs::read(exe).unwrap_or_else(|err| panic!("failed to read `{}`: {err}", exe.display()));
    let file = object::File::parse(&*data)
        .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", exe.display()));
    file.section_by_name(".text")
        .unwrap_or_else(|| panic!("missing .text in `{}`", exe.display()))
        .address()
        - file.relative_address_base()
}

fn find_symbol<'a>(side: &'a Value, name: &str) -> &'a Value {
    side["symbols"]
        .as_array()
        .and_then(|symbols| {
            symbols
                .iter()
                .find(|symbol| symbol["name"].as_str() == Some(name))
        })
        .unwrap_or_else(|| panic!("objdiff output missing symbol `{name}`"))
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedInstruction {
    offset: u64,
    size: u64,
    parts: Vec<String>,
    branch_dest: Option<u64>,
    relocation: Option<String>,
}

fn normalized_instructions(symbol: &Value) -> Vec<NormalizedInstruction> {
    let symbol_base = symbol.get("address").map(parse_u64).unwrap_or(0);
    symbol["instructions"]
        .as_array()
        .unwrap_or_else(|| panic!("symbol `{}` has no instructions", symbol["name"]))
        .iter()
        .map(|entry| {
            let instruction = &entry["instruction"];
            NormalizedInstruction {
                offset: instruction
                    .get("address")
                    .map(parse_u64)
                    .unwrap_or(0)
                    .checked_sub(symbol_base)
                    .expect("instruction address precedes symbol base"),
                size: parse_u64(&instruction["size"]),
                parts: normalized_parts(instruction, symbol_base),
                branch_dest: instruction.get("branch_dest").map(parse_u64).map(|dest| {
                    dest.checked_sub(symbol_base)
                        .expect("branch before symbol base")
                }),
                relocation: instruction["relocation"]["type_name"]
                    .as_str()
                    .map(ToOwned::to_owned),
            }
        })
        .collect()
}

fn normalized_parts(instruction: &Value, symbol_base: u64) -> Vec<String> {
    instruction["parts"]
        .as_array()
        .unwrap_or_else(|| panic!("instruction `{instruction}` has no parts"))
        .iter()
        .map(|part| {
            if let Some(opcode) = part.get("opcode") {
                return format!("opcode:{}", opcode["mnemonic"].as_str().unwrap_or(""));
            }
            if let Some(basic) = part.get("basic") {
                return format!("basic:{}", basic.as_str().unwrap_or(""));
            }
            let arg = part
                .get("arg")
                .unwrap_or_else(|| panic!("unknown objdiff instruction part `{part}`"));
            if arg.get("reloc").and_then(Value::as_bool) == Some(true) {
                return "arg:reloc".to_owned();
            }
            if let Some(dest) = arg.get("branch_dest") {
                let offset = parse_u64(dest)
                    .checked_sub(symbol_base)
                    .expect("branch destination precedes symbol base");
                return format!("arg:branch_dest:{offset}");
            }
            for key in ["opaque", "signed", "unsigned"] {
                if let Some(value) = arg.get(key) {
                    return format!("arg:{key}:{}", value.as_str().unwrap_or(""));
                }
            }
            panic!("unknown objdiff argument `{arg}`");
        })
        .collect()
}

fn parse_u64(value: &Value) -> u64 {
    if let Some(value) = value.as_u64() {
        return value;
    }
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected integer string or number, got `{value}`"))
        .parse()
        .unwrap_or_else(|err| panic!("failed to parse integer `{value}`: {err}"))
}

fn format_code_symbol(va: u64) -> String {
    format!("sub_{va:08X}")
}

fn new_test_dir(fixture: &str) -> PathBuf {
    let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is before UNIX_EPOCH")
        .as_nanos();
    let dir = project_root()
        .join("target")
        .join("integration-tests")
        .join(format!(
            "{fixture}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
    fs::create_dir_all(&dir)
        .unwrap_or_else(|err| panic!("failed to create `{}`: {err}", dir.display()));
    dir
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn assert_success(context: &str, output: &Output) {
    if output.status.success() {
        return;
    }
    panic!(
        "{context} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        DisplayStatus(output.status),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct DisplayStatus(std::process::ExitStatus);

impl fmt::Display for DisplayStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.code() {
            Some(code) => write!(f, "{code}"),
            None => f.write_str("terminated by signal"),
        }
    }
}
