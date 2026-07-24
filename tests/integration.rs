use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use gannondorf::discover_functions;
use iced_x86::{Decoder, DecoderOptions};
use object::endian::LittleEndian as LE;
use object::pe;
use object::read::FileKind;
use object::read::pe::{
    ImageNtHeaders, PeFile, PeFile32, PeFile64, ResourceDirectory, ResourceDirectoryEntryData,
    ResourceDirectoryTable, ResourceNameOrId,
};
use object::read::{Object as _, ObjectSection as _, ObjectSymbol as _};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use serde_json::{Value, json};

static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);
static TI_FUNCTION_COMPARISON: OnceLock<TiFunctionComparison> = OnceLock::new();

const KNOWN_TI_DISASSEMBLY_BYTE_DIFFERENCES: &[u64] = &[];
const EXPECTED_TI_COMMON_FUNCTIONS: usize = 1471;
const EXPECTED_TI_SCANNER_ONLY_FUNCTIONS: &[u64] = &[
    0x0044FF1E, 0x0044FF61, 0x00451EA8, 0x00453F69, 0x00453F80, 0x004541D0, 0x00454250, 0x00454806,
    0x00454819, 0x00454A41, 0x00454A56, 0x00454C5C, 0x00454D0E, 0x00454F14, 0x00456B50, 0x00456C70,
    0x00456DF0,
];
const EXPECTED_TI_GHIDRA_ONLY_FUNCTIONS: &[u64] = &[
    0x00407140, 0x00407220, 0x0041B840, 0x0041D9D0, 0x00421040, 0x00424240, 0x0042B7D0, 0x0042B890,
    0x00430F70, 0x004325B0, 0x0044E3D0, 0x00451F65, 0x00452DB0, 0x00456A00, 0x00458010, 0x00458580,
];

#[test]
fn help_describes_discovery_and_single_function_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_unlink"))
        .arg("--help")
        .output()
        .expect("failed to run unlink --help");
    assert_success("run unlink --help", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "Extract Win32 PE/i386 functions");
    assert_contains(&stdout, "unlink input.exe -o extracted-objects");
    assert_contains(
        &stdout,
        "unlink input.exe --address 0x401000 -o sub_00401000.obj",
    );
    assert_contains(
        &stdout,
        "unlink input.exe --address 0x401000 --address 0x401050 -o selected.obj",
    );
    assert_contains(
        &stdout,
        "Without --address or --map, -o/--output is an output directory",
    );
    assert_contains(
        &stdout,
        "With one --address, -o/--output is the object file path",
    );
    assert_contains(
        &stdout,
        "With multiple --address values, -o/--output is required",
    );
}

#[test]
fn missing_args_prints_usage_hints() {
    let output = Command::new(env!("CARGO_BIN_EXE_unlink"))
        .output()
        .expect("failed to run unlink without arguments");
    let output_text = combined_output(&output);

    assert_contains(&output_text, "Usage: unlink [OPTIONS] <INPUT_EXE>");
    assert_contains(&output_text, "Examples:");
    assert_contains(&output_text, "unlink input.exe -o extracted-objects");
    assert!(
        !output_text.contains("required arguments were not provided"),
        "expected missing arguments to print help, got:\n{output_text}"
    );
}

#[test]
fn cxxmap_writes_derived_map_without_rewriting_unchanged_file() {
    let dir = new_test_dir("cxxmap");
    let source = dir.join("foo.cpp");
    fs::write(
        &source,
        "//! FILE basic.exe\n\
         \n\
         //! FUNC 0x00401000\n\
         extern \"C\" int foo();\n",
    )
    .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", source.display()));
    let output_dir = dir.join("maps");

    let output = Command::new(env!("CARGO_BIN_EXE_cxxmap"))
        .arg(&source)
        .arg("-o")
        .arg(&output_dir)
        .output()
        .expect("failed to run cxxmap");
    assert_success("run cxxmap output", &output);
    assert!(
        output.stdout.is_empty(),
        "expected cxxmap -o to avoid stdout, got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let map_path = output_dir.join("foo.map");
    let map_text = fs::read_to_string(&map_path)
        .unwrap_or_else(|err| panic!("failed to read `{}`: {err}", map_path.display()));
    assert_contains(&map_text, "binary = \"basic.exe\"");
    assert_contains(&map_text, "\"foo\": 0x00401000,");

    let mut permissions = fs::metadata(&map_path)
        .unwrap_or_else(|err| panic!("failed to stat `{}`: {err}", map_path.display()))
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&map_path, permissions)
        .unwrap_or_else(|err| panic!("failed to make `{}` read-only: {err}", map_path.display()));

    let second_output = Command::new(env!("CARGO_BIN_EXE_cxxmap"))
        .arg(&source)
        .arg("-o")
        .arg(&output_dir)
        .output()
        .expect("failed to rerun cxxmap");

    let mut permissions = fs::metadata(&map_path)
        .unwrap_or_else(|err| panic!("failed to stat `{}`: {err}", map_path.display()))
        .permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&map_path, permissions)
        .unwrap_or_else(|err| panic!("failed to make `{}` writable: {err}", map_path.display()));

    assert_success("rerun cxxmap output", &second_output);
    assert!(
        second_output.stdout.is_empty(),
        "expected cxxmap -o to avoid stdout, got:\n{}",
        String::from_utf8_lossy(&second_output.stdout)
    );
    assert_eq!(
        fs::read_to_string(&map_path)
            .unwrap_or_else(|err| panic!("failed to read `{}`: {err}", map_path.display())),
        map_text
    );
}

#[test]
fn cxxmap_prints_nothing_for_source_without_mappings() {
    let dir = new_test_dir("cxxmap-empty");
    let source = dir.join("empty.cpp");
    fs::write(&source, "int helper() { return 0; }\n")
        .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", source.display()));

    let output = Command::new(env!("CARGO_BIN_EXE_cxxmap"))
        .arg(&source)
        .output()
        .expect("failed to run cxxmap");

    assert_success("run cxxmap without mappings", &output);
    assert!(
        output.stdout.is_empty(),
        "expected cxxmap to avoid stdout for an unmapped source, got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn objdiff_json_updates_only_passed_map_units() {
    let dir = new_test_dir("objdiff-json");
    fs::create_dir_all(dir.join("maps"))
        .unwrap_or_else(|err| panic!("failed to create maps dir: {err}"));
    fs::create_dir_all(dir.join("build"))
        .unwrap_or_else(|err| panic!("failed to create build dir: {err}"));
    write_test_coff(&dir.join("build/main.obj"), &["_foo@4", "?Bar@@YAXXZ"]);

    fs::write(
        dir.join("objdiff.json"),
        serde_json::to_string_pretty(&json!({
            "build_base": true,
            "units": [
                {
                    "name": "main",
                    "target_path": "old/main.obj",
                    "metadata": {
                        "complete": true,
                        "source_path": "old/main.cpp"
                    },
                    "symbol_mappings": {
                        "old": "old"
                    }
                },
                {
                    "name": "stubs",
                    "target_path": "target/stubs.obj",
                    "base_path": "build/stubs.obj"
                },
                {
                    "name": "other",
                    "target_path": "target/other.obj",
                    "metadata": {
                        "complete": true,
                        "source_path": "src/other.cpp"
                    },
                    "custom": "preserved"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap_or_else(|err| panic!("failed to write objdiff JSON: {err}"));
    fs::write(
        dir.join("maps/main.map"),
        "binary = \"basic.exe\"\nmap = {\n  \"foo\": 0x00401000,\n  \"Bar\": 0x00401010,\n}\n",
    )
    .unwrap_or_else(|err| panic!("failed to write main map: {err}"));
    fs::write(dir.join("maps/stubs.map"), "")
        .unwrap_or_else(|err| panic!("failed to write stubs map: {err}"));

    let output = Command::new(env!("CARGO_BIN_EXE_objdiff-json"))
        .current_dir(&dir)
        .arg("--json")
        .arg("objdiff.json")
        .arg("--target-dir")
        .arg("target")
        .arg("--build-dir")
        .arg("build")
        .arg("--source-dir")
        .arg("src")
        .arg("maps/main.map")
        .arg("maps/stubs.map")
        .output()
        .expect("failed to run objdiff-json");
    assert_success("run objdiff-json", &output);

    let generated_json = fs::read_to_string(dir.join("objdiff.json"))
        .unwrap_or_else(|err| panic!("failed to read objdiff JSON: {err}"));
    let config: Value = serde_json::from_str(&generated_json)
        .unwrap_or_else(|err| panic!("failed to parse generated objdiff JSON: {err}"));
    assert_eq!(config["build_base"], true);
    assert_eq!(config["units"].as_array().unwrap().len(), 2);

    let main = unit_by_name(&config, "main");
    assert_eq!(main["target_path"], "target/main.obj");
    assert_eq!(main["base_path"], "build/main.obj");
    assert_eq!(main["metadata"]["complete"], true);
    assert_eq!(main["metadata"]["source_path"], "src/main.cpp");
    assert_eq!(main["symbol_mappings"]["sub_00401000"], "_foo@4");
    assert_eq!(main["symbol_mappings"]["sub_00401010"], "?Bar@@YAXXZ");

    assert!(unit_by_name_opt(&config, "stubs").is_none());
    assert_eq!(
        unit_by_name(&config, "other"),
        &json!({
            "name": "other",
            "target_path": "target/other.obj",
            "metadata": {
                "complete": true,
                "source_path": "src/other.cpp"
            },
            "custom": "preserved"
        })
    );
}

#[test]
fn unres_extracts_resources_to_msvc_resource_script() {
    let build = compile_resource_fixture();
    let generated_rc = build.dir.join("resources.rc");
    let generated_header = build.dir.join("resources.h");
    run_unres_default(&build.exe, &build.dir);

    let generated_text = fs::read_to_string(&generated_rc)
        .unwrap_or_else(|err| panic!("failed to read `{}`: {err}", generated_rc.display()));
    let generated_header_text = fs::read_to_string(&generated_header)
        .unwrap_or_else(|err| panic!("failed to read `{}`: {err}", generated_header.display()));
    assert_contains(&generated_text, "#include \"resources.h\"");
    assert_contains(&generated_text, "LANGUAGE 9, 1");
    assert_contains(&generated_text, "STRINGTABLE");
    assert_contains(&generated_text, "IDS_0001 \"Hello from resources\"");
    assert_contains(&generated_text, "IDS_0011 \"Second block\"");
    assert_contains(
        &generated_text,
        "IDI_0001 ICON \"resources/icon_id_0001_lang_0409.ico\"",
    );
    assert_contains(
        &generated_text,
        "IDC_0002 CURSOR \"resources/cursor_id_0002_lang_0409.cur\"",
    );
    assert_contains(
        &generated_text,
        "IDR_RESOURCE_0066 RT_UNRES_00C8 \"resources/resource_type_id_00C8_name_id_0066_lang_0409.bin\"",
    );
    assert_contains(
        &generated_header_text,
        "#define IDS_0001                         1",
    );
    assert_contains(
        &generated_header_text,
        "#define IDS_0011                         17",
    );
    assert_contains(
        &generated_header_text,
        "#define IDI_0001                         1",
    );
    assert_contains(
        &generated_header_text,
        "#define IDC_0002                         2",
    );
    assert_contains(
        &generated_header_text,
        "#define IDR_RESOURCE_0066                102",
    );
    assert_contains(
        &generated_header_text,
        "#define RT_UNRES_00C8                    200",
    );

    assert_nonempty_file(&build.dir.join("resources/icon_id_0001_lang_0409.ico"));
    assert_nonempty_file(&build.dir.join("resources/cursor_id_0002_lang_0409.cur"));
    assert_nonempty_file(
        &build
            .dir
            .join("resources/resource_type_id_00C8_name_id_0066_lang_0409.bin"),
    );
    run_resource_compiler(&generated_rc);
}

#[test]
fn ti_resources_roundtrip_through_unres_and_msvc() {
    let input_exe = ti_exe_path();
    let dir = new_test_dir("ti-resources");
    let generated_rc = dir.join("ti.rc");
    run_unres(&input_exe, &generated_rc);

    let rebuilt_exe = compile_empty_winmain_resource_app(&generated_rc);

    assert_resource_fingerprints_match(&input_exe, &rebuilt_exe);
    assert_resource_order_fingerprints_match(&input_exe, &rebuilt_exe);
    assert_resource_physical_order_matches(&input_exe, &rebuilt_exe);
}

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

#[test]
fn multi_function_extraction_writes_one_object_with_all_symbols() {
    let build = compile_fixture("basic.cpp");
    let symbols = [
        "_fixture_no_refs",
        "_fixture_calls_function",
        "_fixture_uses_global",
    ];
    let addresses = symbols
        .iter()
        .map(|symbol| linked_va_for_source_symbol(&build, symbol))
        .collect::<Vec<_>>();
    let output = build.dir.join("selected.obj");

    run_unlink_addresses(&build.exe, &addresses, &output);

    for (address, symbol) in addresses.iter().zip(symbols) {
        assert_objdiff_symbol_matches(&output, &build.obj, &format_code_symbol(*address), symbol);
    }
}

#[test]
fn map_file_extraction_writes_one_object_with_all_symbols() {
    let build = compile_fixture("basic.cpp");
    let symbols = [
        "_fixture_no_refs",
        "_fixture_calls_function",
        "_fixture_uses_global",
    ];
    let addresses = symbols
        .iter()
        .map(|symbol| linked_va_for_source_symbol(&build, symbol))
        .collect::<Vec<_>>();
    let map = build.dir.join("basic.map");
    fs::write(
        &map,
        format!(
            "binary = \"basic.exe\"\n\
             map = {{\n\
               \"fixture_no_refs\": 0x{:08X},\n\
               \"fixture_calls_function\": 0x{:08X},\n\
               \"fixture_uses_global\": 0x{:08X},\n\
             }}\n",
            addresses[0], addresses[1], addresses[2]
        ),
    )
    .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", map.display()));
    let output = build.dir.join("mapped.obj");

    run_unlink_map(&build.dir, &map, &output);

    for (address, symbol) in addresses.iter().zip(symbols) {
        assert_objdiff_symbol_matches(&output, &build.obj, &format_code_symbol(*address), symbol);
    }
}

#[test]
fn empty_map_file_skips_output_object() {
    let dir = new_test_dir("empty-map");
    let map = dir.join("empty.map");
    let output_obj = dir.join("empty.obj");
    fs::write(&map, "").unwrap_or_else(|err| panic!("failed to write `{}`: {err}", map.display()));

    run_unlink_empty_map(&dir, &map, &output_obj);

    assert!(
        !output_obj.exists(),
        "`{}` should not be created for an empty map",
        output_obj.display()
    );
}

#[test]
#[ignore = "tracking scanner/Ghidra function-set delta while discovery is being hardened"]
fn ti_function_discovery_known_delta_matches_ghidra_export() {
    let comparison = ti_function_comparison();

    assert!(
        comparison.common.len() == EXPECTED_TI_COMMON_FUNCTIONS
            && comparison.scanner_only.as_slice() == EXPECTED_TI_SCANNER_ONLY_FUNCTIONS
            && comparison.ghidra_only.as_slice() == EXPECTED_TI_GHIDRA_ONLY_FUNCTIONS,
        "unlink and Ghidra function-set delta changed in TI.EXE\n\
         common: {}\n\
         unlink only ({}): {}\n\
         Ghidra only ({}): {}",
        comparison.common.len(),
        comparison.scanner_only.len(),
        format_address_list(&comparison.scanner_only),
        comparison.ghidra_only.len(),
        format_address_list(&comparison.ghidra_only)
    );
}

#[test]
fn ti_common_function_disassembly_matches_ghidra_export() {
    let comparison = ti_function_comparison();
    let mut mismatches = Vec::new();
    let mut known_mismatches = BTreeSet::new();

    for address in &comparison.common {
        let scanner = comparison
            .scanner_functions
            .get(address)
            .expect("common function missing from scanner map");
        let ghidra = comparison
            .ghidra_functions
            .get(address)
            .expect("common function missing from Ghidra map");

        if ti_instruction_byte_stream(scanner) != ti_instruction_byte_stream(ghidra) {
            if KNOWN_TI_DISASSEMBLY_BYTE_DIFFERENCES.contains(address) {
                known_mismatches.insert(*address);
            } else {
                mismatches.push(format_ti_disassembly_mismatch(*address, scanner, ghidra));
            }
        }
    }

    let resolved_known_mismatches = KNOWN_TI_DISASSEMBLY_BYTE_DIFFERENCES
        .iter()
        .copied()
        .filter(|address| !known_mismatches.contains(address))
        .collect::<Vec<_>>();

    assert!(
        mismatches.is_empty() && resolved_known_mismatches.is_empty(),
        "unlink and Ghidra instruction bytes differed unexpectedly for {} common TI.EXE function(s)\n\
         resolved known mismatch(es): {}\n\n{}",
        mismatches.len(),
        format_address_list(&resolved_known_mismatches),
        mismatches.join("\n\n")
    );
}

struct FixtureBuild {
    dir: PathBuf,
    exe: PathBuf,
    obj: PathBuf,
    extracted_dir: PathBuf,
}

struct ResourceFixtureBuild {
    dir: PathBuf,
    exe: PathBuf,
}

fn build_and_extract_fixture(source_name: &str) -> FixtureBuild {
    let build = compile_fixture(source_name);
    run_unlink_discovery(&build.exe, &build.extracted_dir);
    build
}

fn compile_resource_fixture() -> ResourceFixtureBuild {
    let dir = new_test_dir("resources");
    let main = dir.join("main.cpp");
    fs::write(&main, "int main() { return 0; }\n")
        .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", main.display()));

    let source_icon = test_tools_dir()
        .join("MSDEV")
        .join("SAMPLES")
        .join("APPWIZ")
        .join("LOGOWIZ")
        .join("RES")
        .join("LOGOWIZ.ICO");
    let source_cursor = test_tools_dir()
        .join("MSDEV")
        .join("SAMPLES")
        .join("SDK")
        .join("OLE")
        .join("OUTLINE")
        .join("BTTNCUR")
        .join("RES")
        .join("MAGNIFY.CUR");
    fs::copy(&source_icon, dir.join("input.ico")).unwrap_or_else(|err| {
        panic!(
            "failed to copy `{}` into resource fixture: {err}",
            source_icon.display()
        )
    });
    fs::copy(&source_cursor, dir.join("input.cur")).unwrap_or_else(|err| {
        panic!(
            "failed to copy `{}` into resource fixture: {err}",
            source_cursor.display()
        )
    });
    fs::write(dir.join("payload.bin"), b"raw resource payload").unwrap();

    let resource_rc = dir.join("input.rc");
    fs::write(
        &resource_rc,
        "LANGUAGE 9, 1\n\
         STRINGTABLE\n\
         BEGIN\n\
             1 \"Hello from resources\"\n\
             17 \"Second block\"\n\
         END\n\
         \n\
         1 ICON \"input.ico\"\n\
         2 CURSOR \"input.cur\"\n\
         102 200 \"payload.bin\"\n",
    )
    .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", resource_rc.display()));

    let resource_res = run_resource_compiler(&resource_rc);
    let compiler = test_tools_dir().join("MSDEV").join("BIN").join("CL.EXE");
    let include = test_tools_dir().join("MSDEV").join("INCLUDE");
    let lib = test_tools_dir().join("MSDEV").join("LIB");
    let output = Command::new("wine")
        .arg(&compiler)
        .arg("/nologo")
        .arg(main.file_name().expect("main source has a name"))
        .arg(
            resource_res
                .file_name()
                .expect("resource output has a name"),
        )
        .current_dir(&dir)
        .env("include", &include)
        .env("INCLUDE", &include)
        .env("lib", &lib)
        .env("LIB", &lib)
        .output()
        .expect("failed to run Wine/MSVC compiler");
    assert_success("compile resource fixture with MSVC", &output);

    let exe = dir.join("main.exe");
    assert!(exe.exists(), "compiler did not produce `{}`", exe.display());
    ResourceFixtureBuild { dir, exe }
}

fn compile_empty_winmain_resource_app(resource_rc: &Path) -> PathBuf {
    let dir = resource_rc
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let main = dir.join("empty_winmain.cpp");
    fs::write(
        &main,
        "#include <windows.h>\n\
         int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) { return 0; }\n",
    )
    .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", main.display()));

    let resource_res = run_resource_compiler(resource_rc);
    let compiler = test_tools_dir().join("MSDEV").join("BIN").join("CL.EXE");
    let include = test_tools_dir().join("MSDEV").join("INCLUDE");
    let lib = test_tools_dir().join("MSDEV").join("LIB");
    assert!(
        compiler.exists(),
        "missing compiler `{}`; see tests/tools/TOOLS.md",
        compiler.display()
    );

    let output_name = "empty_winmain.exe";
    let output = Command::new("wine")
        .arg(&compiler)
        .arg("/nologo")
        .arg(format!("/Fe{output_name}"))
        .arg(main.file_name().expect("WinMain source has a name"))
        .arg(
            resource_res
                .file_name()
                .expect("resource output has a name"),
        )
        .arg("/link")
        .arg("/subsystem:windows")
        .current_dir(dir)
        .env("include", &include)
        .env("INCLUDE", &include)
        .env("lib", &lib)
        .env("LIB", &lib)
        .output()
        .expect("failed to run Wine/MSVC compiler");
    assert_success("compile empty WinMain resource app with MSVC", &output);

    let exe = dir.join(output_name);
    assert!(exe.exists(), "compiler did not produce `{}`", exe.display());
    exe
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

    let tools = test_tools_dir();
    let compiler = tools.join("MSDEV").join("BIN").join("CL.EXE");
    let include = tools.join("MSDEV").join("INCLUDE");
    let lib = tools.join("MSDEV").join("LIB");
    assert!(
        compiler.exists(),
        "missing compiler `{}`; see tests/tools/TOOLS.md",
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

fn run_unlink_addresses(exe: &Path, addresses: &[u64], output_obj: &Path) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_unlink"));
    command.arg(exe);
    for address in addresses {
        command.arg("--address").arg(format!("0x{address:X}"));
    }
    let output = command
        .arg("-o")
        .arg(output_obj)
        .output()
        .expect("failed to run unlink multi-address extraction");
    assert_success("run unlink multi-address extraction", &output);
}

fn run_unlink_map(input: &Path, map: &Path, output_obj: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_unlink"))
        .arg(input)
        .arg("--map")
        .arg(map)
        .arg("-o")
        .arg(output_obj)
        .output()
        .expect("failed to run unlink map extraction");
    assert_success("run unlink map extraction", &output);
}

fn run_unlink_empty_map(input: &Path, map: &Path, output_obj: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_unlink"))
        .arg(input)
        .arg("--map")
        .arg(map)
        .arg("-o")
        .arg(output_obj)
        .output()
        .expect("failed to run unlink empty map extraction");
    assert_success("run unlink empty map extraction", &output);
    assert_contains(
        &String::from_utf8_lossy(&output.stdout),
        "does not contain mapped functions",
    );
}

fn run_unres(exe: &Path, output_rc: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_unres"))
        .arg(exe)
        .arg("-o")
        .arg(output_rc)
        .output()
        .expect("failed to run unres");
    assert_success("run unres resource extraction", &output);
}

fn run_unres_default(exe: &Path, current_dir: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_unres"))
        .current_dir(current_dir)
        .arg(exe)
        .output()
        .expect("failed to run unres");
    assert_success("run unres resource extraction", &output);
}

fn run_resource_compiler(rc: &Path) -> PathBuf {
    let compiler = test_tools_dir().join("MSDEV").join("BIN").join("RC.EXE");
    assert!(
        compiler.exists(),
        "missing resource compiler `{}`; see tests/tools/TOOLS.md",
        compiler.display()
    );
    let dir = rc
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let output = Command::new("wine")
        .arg(&compiler)
        .arg(rc.file_name().expect("resource script has a name"))
        .current_dir(dir)
        .output()
        .expect("failed to run Wine/MSVC resource compiler");
    assert_success("compile resource script with RC.EXE", &output);

    let lowercase = rc.with_extension("res");
    let uppercase = rc.with_extension("RES");
    if lowercase.exists() {
        lowercase
    } else {
        assert!(
            uppercase.exists(),
            "resource compiler produced neither `{}` nor `{}`",
            lowercase.display(),
            uppercase.display()
        );
        uppercase
    }
}

fn assert_nonempty_file(path: &Path) {
    let metadata = fs::metadata(path)
        .unwrap_or_else(|err| panic!("failed to stat `{}`: {err}", path.display()));
    assert!(
        metadata.len() > 0,
        "`{}` should be non-empty",
        path.display()
    );
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TestResourceKey {
    Id(u16),
    Name(String),
}

#[derive(Debug, Clone)]
struct TestResourceLeaf {
    typ: TestResourceKey,
    name: TestResourceKey,
    language: u16,
    data_rva: u32,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceFingerprint {
    Leaf {
        typ: TestResourceKey,
        name: TestResourceKey,
        language: u16,
        data: Vec<u8>,
    },
    IconOrCursorGroup {
        typ: u16,
        name: TestResourceKey,
        language: u16,
        group_without_image_ids: Vec<u8>,
        image_payloads: Vec<Vec<u8>>,
    },
    UngroupedIconOrCursor {
        typ: u16,
        language: u16,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysicalResourceFingerprint {
    typ: TestResourceKey,
    name: TestResourceKey,
    language: u16,
    data: Vec<u8>,
}

fn assert_resource_fingerprints_match(original: &Path, rebuilt: &Path) {
    let original_fingerprint = resource_fingerprint(original);
    let rebuilt_fingerprint = resource_fingerprint(rebuilt);
    if original_fingerprint != rebuilt_fingerprint {
        panic!(
            "{}",
            resource_fingerprint_mismatch(
                original,
                rebuilt,
                &original_fingerprint,
                &rebuilt_fingerprint
            )
        );
    }
}

fn assert_resource_physical_order_matches(original: &Path, rebuilt: &Path) {
    let original_fingerprint = resource_physical_order_fingerprint(original);
    let rebuilt_fingerprint = resource_physical_order_fingerprint(rebuilt);
    if original_fingerprint != rebuilt_fingerprint {
        panic!(
            "{}",
            resource_physical_order_mismatch(
                original,
                rebuilt,
                &original_fingerprint,
                &rebuilt_fingerprint
            )
        );
    }
}

fn assert_resource_order_fingerprints_match(original: &Path, rebuilt: &Path) {
    let original_fingerprint = resource_order_fingerprint(original);
    let rebuilt_fingerprint = resource_order_fingerprint(rebuilt);
    if original_fingerprint != rebuilt_fingerprint {
        panic!(
            "{}",
            resource_fingerprint_mismatch(
                original,
                rebuilt,
                &original_fingerprint,
                &rebuilt_fingerprint
            )
        );
    }
}

fn resource_fingerprint_mismatch(
    original: &Path,
    rebuilt: &Path,
    original_fingerprint: &[ResourceFingerprint],
    rebuilt_fingerprint: &[ResourceFingerprint],
) -> String {
    let first_difference = original_fingerprint
        .iter()
        .zip(rebuilt_fingerprint)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| original_fingerprint.len().min(rebuilt_fingerprint.len()));
    format!(
        "resource fingerprint mismatch after round-trip\n\
         original: {} ({} entries)\n\
         rebuilt: {} ({} entries)\n\
         first difference: {}\n\
         original entry: {}\n\
         rebuilt entry: {}",
        original.display(),
        original_fingerprint.len(),
        rebuilt.display(),
        rebuilt_fingerprint.len(),
        first_difference,
        original_fingerprint
            .get(first_difference)
            .map(resource_fingerprint_summary)
            .unwrap_or_else(|| "<missing>".to_owned()),
        rebuilt_fingerprint
            .get(first_difference)
            .map(resource_fingerprint_summary)
            .unwrap_or_else(|| "<missing>".to_owned())
    )
}

fn resource_fingerprint_summary(fingerprint: &ResourceFingerprint) -> String {
    match fingerprint {
        ResourceFingerprint::Leaf {
            typ,
            name,
            language,
            data,
        } => format!(
            "leaf type={} name={} language={language:04X} len={} hash={:08X}",
            resource_key_summary(typ),
            resource_key_summary(name),
            data.len(),
            hash_bytes(data)
        ),
        ResourceFingerprint::IconOrCursorGroup {
            typ,
            name,
            language,
            group_without_image_ids,
            image_payloads,
        } => {
            let payloads = image_payloads
                .iter()
                .map(|payload| format!("{}:{:08X}", payload.len(), hash_bytes(payload)))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "icon/cursor group type={typ} name={} language={language:04X} group_len={} group_hash={:08X} payloads=[{}]",
                resource_key_summary(name),
                group_without_image_ids.len(),
                hash_bytes(group_without_image_ids),
                payloads
            )
        }
        ResourceFingerprint::UngroupedIconOrCursor {
            typ,
            language,
            data,
        } => format!(
            "ungrouped icon/cursor type={typ} language={language:04X} len={} hash={:08X}",
            data.len(),
            hash_bytes(data)
        ),
    }
}

fn resource_physical_order_mismatch(
    original: &Path,
    rebuilt: &Path,
    original_fingerprint: &[PhysicalResourceFingerprint],
    rebuilt_fingerprint: &[PhysicalResourceFingerprint],
) -> String {
    let first_difference = original_fingerprint
        .iter()
        .zip(rebuilt_fingerprint)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| original_fingerprint.len().min(rebuilt_fingerprint.len()));
    format!(
        "physical resource order mismatch after round-trip\n\
         original: {} ({} entries)\n\
         rebuilt: {} ({} entries)\n\
         first difference: {}\n\
         original entry: {}\n\
         rebuilt entry: {}",
        original.display(),
        original_fingerprint.len(),
        rebuilt.display(),
        rebuilt_fingerprint.len(),
        first_difference,
        original_fingerprint
            .get(first_difference)
            .map(resource_physical_fingerprint_summary)
            .unwrap_or_else(|| "<missing>".to_owned()),
        rebuilt_fingerprint
            .get(first_difference)
            .map(resource_physical_fingerprint_summary)
            .unwrap_or_else(|| "<missing>".to_owned())
    )
}

fn resource_physical_fingerprint_summary(fingerprint: &PhysicalResourceFingerprint) -> String {
    format!(
        "leaf type={} name={} language={:04X} len={} hash={:08X}",
        resource_key_summary(&fingerprint.typ),
        resource_key_summary(&fingerprint.name),
        fingerprint.language,
        fingerprint.data.len(),
        hash_bytes(&fingerprint.data)
    )
}

fn resource_key_summary(key: &TestResourceKey) -> String {
    match key {
        TestResourceKey::Id(id) => format!("#{id}"),
        TestResourceKey::Name(name) => name.clone(),
    }
}

fn hash_bytes(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811C_9DC5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn resource_fingerprint(exe: &Path) -> Vec<ResourceFingerprint> {
    let mut fingerprints = resource_order_fingerprint(exe);
    fingerprints.sort();
    fingerprints
}

fn resource_order_fingerprint(exe: &Path) -> Vec<ResourceFingerprint> {
    let leaves = read_resource_leaves(exe);
    let mut fingerprints = Vec::new();
    let mut grouped_images = BTreeSet::new();

    for leaf in &leaves {
        let TestResourceKey::Id(group_type) = leaf.typ else {
            continue;
        };
        let Some(image_type) = grouped_image_type(group_type) else {
            continue;
        };

        for image_id in group_resource_image_ids(leaf) {
            grouped_images.insert((image_type, leaf.language, image_id));
        }
    }

    let mut leaves_by_data = leaves.iter().collect::<Vec<_>>();
    leaves_by_data.sort_by_key(|leaf| leaf.data_rva);
    for leaf in leaves_by_data {
        match leaf.typ.clone() {
            TestResourceKey::Id(resource_type) if grouped_image_type(resource_type).is_some() => {
                let image_type = grouped_image_type(resource_type).expect("group type was checked");
                let image_ids = group_resource_image_ids(leaf);
                let image_payloads = image_ids
                    .iter()
                    .map(|image_id| {
                        resource_leaf_data(&leaves, image_type, leaf.language, *image_id)
                            .unwrap_or_else(|| {
                                panic!(
                                    "{} group {:?} language {:04X} references missing image resource {}",
                                    exe.display(),
                                    leaf.name,
                                    leaf.language,
                                    image_id
                                )
                            })
                            .to_vec()
                    })
                    .collect::<Vec<_>>();

                fingerprints.push(ResourceFingerprint::IconOrCursorGroup {
                    typ: resource_type,
                    name: leaf.name.clone(),
                    language: leaf.language,
                    group_without_image_ids: group_resource_without_image_ids(leaf),
                    image_payloads,
                });
            }
            TestResourceKey::Id(resource_type)
                if resource_type == pe::RT_ICON || resource_type == pe::RT_CURSOR =>
            {
                let Some(resource_id) = numeric_resource_key(&leaf.name) else {
                    fingerprints.push(ResourceFingerprint::Leaf {
                        typ: TestResourceKey::Id(resource_type),
                        name: leaf.name.clone(),
                        language: leaf.language,
                        data: leaf.data.clone(),
                    });
                    continue;
                };
                if !grouped_images.contains(&(resource_type, leaf.language, resource_id)) {
                    fingerprints.push(ResourceFingerprint::UngroupedIconOrCursor {
                        typ: resource_type,
                        language: leaf.language,
                        data: leaf.data.clone(),
                    });
                }
            }
            typ => fingerprints.push(ResourceFingerprint::Leaf {
                typ: typ.clone(),
                name: leaf.name.clone(),
                language: leaf.language,
                data: leaf.data.clone(),
            }),
        }
    }
    fingerprints
}

fn resource_physical_order_fingerprint(exe: &Path) -> Vec<PhysicalResourceFingerprint> {
    let mut leaves = read_resource_leaves(exe);
    leaves.sort_by_key(|leaf| leaf.data_rva);
    leaves
        .into_iter()
        .map(|leaf| PhysicalResourceFingerprint {
            typ: leaf.typ,
            name: leaf.name,
            language: leaf.language,
            data: leaf.data,
        })
        .collect()
}

fn grouped_image_type(resource_type: u16) -> Option<u16> {
    match resource_type {
        pe::RT_GROUP_ICON => Some(pe::RT_ICON),
        pe::RT_GROUP_CURSOR => Some(pe::RT_CURSOR),
        _ => None,
    }
}

fn group_resource_image_ids(group: &TestResourceLeaf) -> Vec<u16> {
    let count = read_resource_u16_at(&group.data, 4) as usize;
    (0..count)
        .map(|index| read_resource_u16_at(&group.data, 6 + index * 14 + 12))
        .collect()
}

fn group_resource_without_image_ids(group: &TestResourceLeaf) -> Vec<u8> {
    let mut data = group.data.clone();
    let count = read_resource_u16_at(&data, 4) as usize;
    for index in 0..count {
        let id_offset = 6 + index * 14 + 12;
        data[id_offset] = 0;
        data[id_offset + 1] = 0;
    }
    data
}

fn read_resource_u16_at(data: &[u8], offset: usize) -> u16 {
    let bytes = data
        .get(offset..offset + 2)
        .unwrap_or_else(|| panic!("resource data ended before offset 0x{offset:X}"));
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn resource_leaf_data(
    leaves: &[TestResourceLeaf],
    resource_type: u16,
    language: u16,
    resource_id: u16,
) -> Option<&[u8]> {
    leaves
        .iter()
        .find(|leaf| {
            leaf.typ == TestResourceKey::Id(resource_type)
                && leaf.name == TestResourceKey::Id(resource_id)
                && leaf.language == language
        })
        .map(|leaf| leaf.data.as_slice())
}

fn numeric_resource_key(key: &TestResourceKey) -> Option<u16> {
    match key {
        TestResourceKey::Id(id) => Some(*id),
        TestResourceKey::Name(_) => None,
    }
}

fn read_resource_leaves(exe: &Path) -> Vec<TestResourceLeaf> {
    let image =
        fs::read(exe).unwrap_or_else(|err| panic!("failed to read `{}`: {err}", exe.display()));
    match FileKind::parse(&*image)
        .unwrap_or_else(|err| panic!("failed to identify `{}`: {err}", exe.display()))
    {
        FileKind::Pe32 => {
            let file = PeFile32::parse(&*image)
                .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", exe.display()));
            read_pe_resource_leaves(&file, exe)
        }
        FileKind::Pe64 => {
            let file = PeFile64::parse(&*image)
                .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", exe.display()));
            read_pe_resource_leaves(&file, exe)
        }
        kind => panic!("unsupported test image `{}` kind {kind:?}", exe.display()),
    }
}

fn read_pe_resource_leaves<Pe>(file: &PeFile<'_, Pe>, exe: &Path) -> Vec<TestResourceLeaf>
where
    Pe: ImageNtHeaders,
{
    let Some(directory) = file
        .data_directories()
        .resource_directory(file.data(), &file.section_table())
        .unwrap_or_else(|err| {
            panic!(
                "failed to read PE resources from `{}`: {err}",
                exe.display()
            )
        })
    else {
        return Vec::new();
    };
    let root = directory.root().unwrap_or_else(|err| {
        panic!(
            "failed to parse PE resource root in `{}`: {err}",
            exe.display()
        )
    });
    collect_test_resource_leaves(file, directory, &root, exe)
}

fn collect_test_resource_leaves<Pe>(
    file: &PeFile<'_, Pe>,
    directory: ResourceDirectory<'_>,
    root: &ResourceDirectoryTable<'_>,
    exe: &Path,
) -> Vec<TestResourceLeaf>
where
    Pe: ImageNtHeaders,
{
    let mut leaves = Vec::new();
    for type_entry in root.entries {
        let typ = test_resource_key(type_entry.name_or_id(), directory, exe);
        let name_table = test_resource_entry_table(type_entry, directory, "type", exe);
        for name_entry in name_table.entries {
            let name = test_resource_key(name_entry.name_or_id(), directory, exe);
            let language_table = test_resource_entry_table(name_entry, directory, "name", exe);
            for language_entry in language_table.entries {
                let language =
                    test_resource_language_id(language_entry.name_or_id(), directory, exe);
                let data_entry = match language_entry.data(directory).unwrap_or_else(|err| {
                    panic!(
                        "failed to read resource data entry in `{}`: {err}",
                        exe.display()
                    )
                }) {
                    ResourceDirectoryEntryData::Data(data) => data,
                    ResourceDirectoryEntryData::Table(_) => {
                        panic!(
                            "resource language entry in `{}` points to another table",
                            exe.display()
                        )
                    }
                };
                let rva = data_entry.offset_to_data.get(LE);
                let size = data_entry.size.get(LE) as usize;
                let data = file
                    .section_table()
                    .pe_data_at(file.data(), rva)
                    .and_then(|bytes| bytes.get(..size))
                    .unwrap_or_else(|| {
                        panic!(
                            "resource data in `{}` at RVA 0x{rva:08X} size 0x{size:X} is outside section data",
                            exe.display()
                        )
                    })
                    .to_vec();
                leaves.push(TestResourceLeaf {
                    typ: typ.clone(),
                    name: name.clone(),
                    language,
                    data_rva: rva,
                    data,
                });
            }
        }
    }
    leaves
}

fn test_resource_key(
    name_or_id: ResourceNameOrId,
    directory: ResourceDirectory<'_>,
    exe: &Path,
) -> TestResourceKey {
    match name_or_id {
        ResourceNameOrId::Id(id) => TestResourceKey::Id(id),
        ResourceNameOrId::Name(name) => {
            TestResourceKey::Name(name.to_string_lossy(directory).unwrap_or_else(|err| {
                panic!(
                    "failed to decode resource name in `{}`: {err}",
                    exe.display()
                )
            }))
        }
    }
}

fn test_resource_language_id(
    name_or_id: ResourceNameOrId,
    directory: ResourceDirectory<'_>,
    exe: &Path,
) -> u16 {
    match test_resource_key(name_or_id, directory, exe) {
        TestResourceKey::Id(id) => id,
        TestResourceKey::Name(name) => {
            panic!(
                "unsupported named resource language `{name}` in `{}`",
                exe.display()
            )
        }
    }
}

fn test_resource_entry_table<'data>(
    entry: &pe::ImageResourceDirectoryEntry,
    directory: ResourceDirectory<'data>,
    context: &str,
    exe: &Path,
) -> ResourceDirectoryTable<'data> {
    match entry.data(directory).unwrap_or_else(|err| {
        panic!(
            "failed to read resource {context} table in `{}`: {err}",
            exe.display()
        )
    }) {
        ResourceDirectoryEntryData::Table(table) => table,
        ResourceDirectoryEntryData::Data(_) => {
            panic!(
                "resource {context} entry in `{}` points directly to data",
                exe.display()
            )
        }
    }
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
    let objdiff = test_tools_dir().join("objdiff-cli-macos-arm64");
    assert!(
        objdiff.exists(),
        "missing objdiff CLI `{}`; see tests/tools/TOOLS.md",
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

#[derive(Debug)]
struct TiFunctionComparison {
    scanner_functions: BTreeMap<u64, Vec<TiInstruction>>,
    ghidra_functions: BTreeMap<u64, Vec<TiInstruction>>,
    common: Vec<u64>,
    scanner_only: Vec<u64>,
    ghidra_only: Vec<u64>,
}

#[derive(Debug, Clone)]
struct TiInstruction {
    va: u64,
    bytes: Vec<u8>,
    text: String,
}

#[derive(Debug)]
struct TiImage {
    file_bytes: Vec<u8>,
    sections: Vec<TiImageSection>,
}

#[derive(Debug)]
struct TiImageSection {
    va: u64,
    bytes: Vec<u8>,
}

impl TiImage {
    fn bytes_at(&self, va: u64, len: usize) -> Vec<u8> {
        let section = self
            .section_containing(va)
            .unwrap_or_else(|| panic!("0x{va:08X} is outside TI.EXE sections"));
        let offset = va
            .checked_sub(section.va)
            .expect("section lookup returned a section after the requested VA")
            as usize;
        section
            .bytes
            .get(offset..offset + len)
            .unwrap_or_else(|| panic!("0x{va:08X}+0x{len:X} is outside TI.EXE section bytes"))
            .to_vec()
    }

    fn decode_instruction_len_at(&self, va: u64) -> usize {
        let section = self
            .section_containing(va)
            .unwrap_or_else(|| panic!("0x{va:08X} is outside TI.EXE sections"));
        let offset = va
            .checked_sub(section.va)
            .expect("section lookup returned a section after the requested VA")
            as usize;
        let bytes = section
            .bytes
            .get(offset..)
            .unwrap_or_else(|| panic!("0x{va:08X} is outside TI.EXE section bytes"));
        let mut decoder = Decoder::with_ip(32, bytes, va, DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert!(
            !instruction.is_invalid() && instruction.len() > 0,
            "failed to decode instruction length at 0x{va:08X}"
        );
        instruction.len()
    }

    fn section_containing(&self, va: u64) -> Option<&TiImageSection> {
        self.sections.iter().find(|section| {
            va >= section.va && va < section.va.saturating_add(section.bytes.len() as u64)
        })
    }
}

fn load_ti_function_comparison() -> TiFunctionComparison {
    let image = load_ti_image();
    let scanner_functions = load_ti_scanner_functions(&image);
    let ghidra_functions = load_ti_ghidra_functions(&image);

    let scanner_addresses = scanner_functions.keys().copied().collect::<BTreeSet<_>>();
    let ghidra_addresses = ghidra_functions.keys().copied().collect::<BTreeSet<_>>();
    let common = scanner_addresses
        .intersection(&ghidra_addresses)
        .copied()
        .collect();
    let scanner_only = scanner_addresses
        .difference(&ghidra_addresses)
        .copied()
        .collect();
    let ghidra_only = ghidra_addresses
        .difference(&scanner_addresses)
        .copied()
        .collect();

    TiFunctionComparison {
        scanner_functions,
        ghidra_functions,
        common,
        scanner_only,
        ghidra_only,
    }
}

fn ti_function_comparison() -> &'static TiFunctionComparison {
    TI_FUNCTION_COMPARISON.get_or_init(load_ti_function_comparison)
}

fn load_ti_image() -> TiImage {
    let exe = ti_exe_path();
    assert!(
        exe.exists(),
        "missing test binary `{}`; see tests/tools/TOOLS.md",
        exe.display()
    );
    let file_bytes =
        fs::read(&exe).unwrap_or_else(|err| panic!("failed to read `{}`: {err}", exe.display()));
    let file = object::File::parse(&*file_bytes)
        .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", exe.display()));
    let sections = file
        .sections()
        .map(|section| TiImageSection {
            va: section.address(),
            bytes: section
                .data()
                .unwrap_or_else(|err| panic!("failed to read section data from TI.EXE: {err}"))
                .to_vec(),
        })
        .collect();

    TiImage {
        file_bytes,
        sections,
    }
}

fn load_ti_scanner_functions(image: &TiImage) -> BTreeMap<u64, Vec<TiInstruction>> {
    discover_functions(&image.file_bytes)
        .unwrap_or_else(|err| panic!("failed to discover functions in TI.EXE: {err}"))
        .into_iter()
        .map(|function| {
            (
                function.function_va,
                function
                    .instructions
                    .into_iter()
                    .map(|instruction| TiInstruction {
                        va: instruction.va,
                        bytes: image.bytes_at(instruction.va, instruction.len as usize),
                        text: instruction.text,
                    })
                    .collect(),
            )
        })
        .collect()
}

fn load_ti_ghidra_functions(image: &TiImage) -> BTreeMap<u64, Vec<TiInstruction>> {
    let path = project_root()
        .join("tests")
        .join("tools")
        .join("functions.json");
    assert!(
        path.exists(),
        "missing Ghidra export `{}`; run tests/tools/export_functions.py",
        path.display()
    );
    let data =
        fs::read(&path).unwrap_or_else(|err| panic!("failed to read `{}`: {err}", path.display()));
    let export: Value = serde_json::from_slice(&data)
        .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", path.display()));
    assert_eq!(
        export["binary_file"].as_str(),
        Some("TI.EXE"),
        "`{}` was not exported from TI.EXE",
        path.display()
    );

    export["functions"]
        .as_array()
        .unwrap_or_else(|| panic!("`{}` has no functions array", path.display()))
        .iter()
        .map(|function| {
            let address = parse_hex_address(
                function["address"]
                    .as_str()
                    .unwrap_or_else(|| panic!("Ghidra function has no address: {function}")),
            );
            (address, parse_ghidra_function(image, address, function))
        })
        .collect()
}

fn parse_ghidra_function(
    image: &TiImage,
    function_va: u64,
    function: &Value,
) -> Vec<TiInstruction> {
    if let Some(instructions) = function["instructions"].as_array()
        && !instructions.is_empty()
    {
        return instructions
            .iter()
            .map(|instruction| {
                let address = instruction["address"].as_str().unwrap_or_else(|| {
                    panic!("Ghidra function 0x{function_va:08X} has an instruction with no address")
                });
                let bytes = instruction["bytes"].as_str().unwrap_or_else(|| {
                    panic!("Ghidra instruction `{instruction}` has no byte string")
                });
                TiInstruction {
                    va: parse_hex_address(address),
                    bytes: parse_hex_bytes(bytes),
                    text: instruction["text"].as_str().unwrap_or("").to_owned(),
                }
            })
            .collect();
    }

    let disassembly = function["disassembly"]
        .as_str()
        .unwrap_or_else(|| panic!("Ghidra function 0x{function_va:08X} has no disassembly"));
    let mut instructions = disassembly
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (address, text) = line.split_once(' ').unwrap_or_else(|| {
                panic!("malformed Ghidra disassembly line for 0x{function_va:08X}: `{line}`")
            });
            TiInstruction {
                va: parse_hex_address(address),
                bytes: Vec::new(),
                text: text.to_owned(),
            }
        })
        .collect::<Vec<_>>();
    for instruction in &mut instructions {
        let va = instruction.va;
        let len = image.decode_instruction_len_at(va);
        instruction.bytes = image.bytes_at(va, len);
    }
    instructions
}

fn ti_instruction_byte_stream(instructions: &[TiInstruction]) -> Vec<(u64, Vec<u8>)> {
    instructions
        .iter()
        .map(|instruction| (instruction.va, instruction.bytes.clone()))
        .collect()
}

fn format_ti_disassembly_mismatch(
    address: u64,
    scanner: &[TiInstruction],
    ghidra: &[TiInstruction],
) -> String {
    let scanner_bytes = ti_instruction_byte_stream(scanner);
    let ghidra_bytes = ti_instruction_byte_stream(ghidra);
    let first_difference = scanner_bytes
        .iter()
        .zip(&ghidra_bytes)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| scanner_bytes.len().min(ghidra_bytes.len()));

    format!(
        "0x{address:08X}: unlink {} instruction(s), Ghidra {} instruction(s), first difference at instruction {}\n\
         unlink: {}\n\
         Ghidra: {}",
        scanner.len(),
        ghidra.len(),
        first_difference,
        scanner
            .get(first_difference)
            .map(format_ti_instruction)
            .unwrap_or_else(|| "<end of function>".to_owned()),
        ghidra
            .get(first_difference)
            .map(format_ti_instruction)
            .unwrap_or_else(|| "<end of function>".to_owned())
    )
}

fn format_ti_instruction(instruction: &TiInstruction) -> String {
    format!(
        "0x{:08X} {:<24} {}",
        instruction.va,
        format_hex_bytes(&instruction.bytes),
        instruction.text
    )
}

fn parse_hex_address(input: &str) -> u64 {
    let digits = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or_else(|| input.trim());
    u64::from_str_radix(digits, 16)
        .unwrap_or_else(|err| panic!("failed to parse hex address `{input}`: {err}"))
}

fn parse_hex_bytes(input: &str) -> Vec<u8> {
    assert!(
        input.len().is_multiple_of(2),
        "hex byte string has odd length: `{input}`"
    );
    (0..input.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&input[index..index + 2], 16)
                .unwrap_or_else(|err| panic!("failed to parse hex byte `{input}`: {err}"))
        })
        .collect()
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_address_list(addresses: &[u64]) -> String {
    const LIMIT: usize = 80;

    let mut values = addresses
        .iter()
        .take(LIMIT)
        .map(|address| format!("0x{address:08X}"))
        .collect::<Vec<_>>();
    if addresses.len() > LIMIT {
        values.push(format!("... and {} more", addresses.len() - LIMIT));
    }
    values.join(", ")
}

fn format_code_symbol(va: u64) -> String {
    format!("sub_{va:08X}")
}

fn unit_by_name<'a>(config: &'a Value, name: &str) -> &'a Value {
    unit_by_name_opt(config, name).unwrap_or_else(|| panic!("missing objdiff unit `{name}`"))
}

fn unit_by_name_opt<'a>(config: &'a Value, name: &str) -> Option<&'a Value> {
    config["units"].as_array()?.iter().find(|unit| {
        unit.get("name")
            .and_then(Value::as_str)
            .is_some_and(|unit_name| unit_name == name)
    })
}

fn write_test_coff(path: &Path, symbols: &[&str]) {
    let mut object =
        object::write::Object::new(BinaryFormat::Coff, Architecture::I386, Endianness::Little);
    object.set_mangling(object::write::Mangling::None);
    let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);

    for symbol in symbols {
        let offset = object.append_section_data(text, &[0xC3], 1);
        object.add_symbol(object::write::Symbol {
            name: symbol.as_bytes().to_vec(),
            value: offset,
            size: 1,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }

    let data = object
        .write()
        .unwrap_or_else(|err| panic!("failed to render test COFF: {err}"));
    fs::write(path, data)
        .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", path.display()));
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

fn test_tools_dir() -> PathBuf {
    project_root().join("tests").join("tools")
}

fn ti_exe_path() -> PathBuf {
    project_root().join("tests").join("bin").join("TI.EXE")
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

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected output to contain `{needle}`, got:\n{haystack}"
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
