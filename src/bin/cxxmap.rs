use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use gannondorf::{Error, FunctionMapping, Result, extract_function_mapping};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract binary/function address mappings from annotated C++ source.",
    long_about = "Extract mappings from //! FILE and //! FUNC annotations in C++ source. The tool runs clang's JSON AST dump, reads doc comments attached to function declarations, and prints a simple mapping to stdout.",
    arg_required_else_help = true,
    after_help = "Examples:\n  cxxmap tests/mapping_test.cpp\n  cxxmap source.cpp --compile-flags compile_flags.txt\n  cxxmap source.cpp -- -Iinclude -DWINAPI=\n\nThe tool passes compile_flags.txt to clang as a response file: clang @compile_flags.txt source.cpp. When --compile-flags is omitted, it searches upward from the source path and current directory.\n\nAnnotations:\n  //! FILE TI.EXE\n  //! FUNC 0x0041bb40\n  void fn_0041bb40();"
)]
struct Args {
    /// C++ source file to parse.
    #[arg(value_name = "INPUT_CPP")]
    input: PathBuf,

    /// Clang response file to pass as @PATH. Defaults to nearest compile_flags.txt.
    #[arg(long, value_name = "PATH")]
    compile_flags: Option<PathBuf>,

    /// Extra arguments forwarded to clang after `--`.
    #[arg(
        value_name = "CLANG_ARG",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    clang_args: Vec<OsString>,
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

    let flags_file = resolve_compile_flags(&args.input, args.compile_flags)?;
    let ast_json = dump_clang_ast(&args.input, flags_file.as_deref(), args.clang_args)?;
    let mapping = extract_function_mapping(&source, &ast_json)?;

    print_mapping(&mapping);
    Ok(())
}

fn dump_clang_ast(
    input: &Path,
    flags_file: Option<&Path>,
    clang_args: Vec<OsString>,
) -> Result<String> {
    let mut command = Command::new("clang");
    command
        .arg("-Xclang")
        .arg("-ast-dump=json")
        .arg("-fsyntax-only");

    if let Some(flags_file) = flags_file {
        command.arg(response_file_arg(flags_file));
    }
    command.args(clang_args);
    command.arg(input);

    let output = command.output().map_err(|err| {
        Error::new(format!(
            "failed to run clang; install clang or pass a configured compiler through PATH: {err}"
        ))
    })?;

    if !output.stdout.is_empty() {
        return String::from_utf8(output.stdout)
            .map_err(|err| Error::new(format!("clang AST output was not UTF-8: {err}")));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Err(Error::new("clang did not print an AST JSON document"))
    } else {
        Err(Error::new(format!(
            "clang failed without producing AST JSON:\n{}",
            stderr.trim_end()
        )))
    }
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

fn resolve_compile_flags(input: &Path, explicit_path: Option<PathBuf>) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit_path {
        if !path.is_file() {
            return Err(Error::new(format!(
                "compile flags file `{}` does not exist or is not a file",
                path.display()
            )));
        }
        return Ok(Some(path));
    }

    find_compile_flags(input)
}

fn find_compile_flags(input: &Path) -> Result<Option<PathBuf>> {
    let input = fs::canonicalize(input).map_err(|err| {
        Error::new(format!(
            "failed to resolve source path `{}`: {err}",
            input.display()
        ))
    })?;

    if let Some(path) = find_compile_flags_from(input.parent()) {
        return Ok(Some(path));
    }

    let current_dir = std::env::current_dir()
        .map_err(|err| Error::new(format!("failed to resolve current directory: {err}")))?;
    Ok(find_compile_flags_from(Some(&current_dir)))
}

fn find_compile_flags_from(start: Option<&Path>) -> Option<PathBuf> {
    let mut dir = start?;
    loop {
        let candidate = dir.join("compile_flags.txt");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
}

fn response_file_arg(path: &Path) -> OsString {
    let mut value = OsString::from("@");
    value.push(path);
    value
}
