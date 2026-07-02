use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use unlink::{Result, UnlinkError, extract_resource_script};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract Win32 PE resources into an MSVC resource script.",
    long_about = "Extract resources from a PE executable and write an MSVC-compatible .rc script plus sidecar files for binary resources such as icons, cursors, and raw data.",
    arg_required_else_help = true,
    after_help = "Examples:\n  unres input.exe -o resources.rc\n  unres input.exe -o resources.rc --asset-dir resources_assets\n\nOutput:\n  The .rc file references sidecar assets using paths relative to the .rc file directory when --asset-dir is relative."
)]
struct Args {
    /// PE executable to extract resources from.
    #[arg(value_name = "INPUT_EXE")]
    input: PathBuf,

    /// Output resource script path. Defaults to INPUT_STEM.rc in the current directory.
    #[arg(short, long, value_name = "OUTPUT_RC")]
    output: Option<PathBuf>,

    /// Directory for sidecar assets. Relative paths are resolved next to OUTPUT_RC.
    #[arg(long, value_name = "ASSET_DIR")]
    asset_dir: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let input = fs::read(&args.input).map_err(|err| {
        UnlinkError::new(format!("failed to read `{}`: {err}", args.input.display()))
    })?;

    let output = args
        .output
        .unwrap_or_else(|| default_output_path(&args.input));
    let output_dir = output.parent().filter(|path| !path.as_os_str().is_empty());
    if let Some(output_dir) = output_dir {
        fs::create_dir_all(output_dir).map_err(|err| {
            UnlinkError::new(format!(
                "failed to create output directory `{}`: {err}",
                output_dir.display()
            ))
        })?;
    }

    let (asset_write_base, asset_rc_prefix) =
        resolve_asset_directory(args.asset_dir.as_deref(), &output);
    let extracted = extract_resource_script(&input, &asset_rc_prefix)?;

    for asset in &extracted.assets {
        let path = asset_write_base.join(&asset.relative_path);
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|err| {
                UnlinkError::new(format!(
                    "failed to create asset directory `{}`: {err}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, &asset.bytes).map_err(|err| {
            UnlinkError::new(format!("failed to write `{}`: {err}", path.display()))
        })?;
    }

    fs::write(&output, extracted.rc_text).map_err(|err| {
        UnlinkError::new(format!("failed to write `{}`: {err}", output.display()))
    })?;
    println!(
        "wrote {} resource asset(s) and {}",
        extracted.assets.len(),
        output.display()
    );
    Ok(())
}

fn default_output_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("resources");
    PathBuf::from(format!("{stem}.rc"))
}

fn resolve_asset_directory(asset_dir: Option<&Path>, output: &Path) -> (PathBuf, String) {
    let output_base = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match asset_dir {
        Some(path) if path.is_absolute() => (PathBuf::new(), rc_path(path)),
        Some(path) => (output_base.to_path_buf(), rc_path(path)),
        None => {
            let stem = output
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| !stem.is_empty())
                .unwrap_or("resources");
            let dir = format!("{stem}_resources");
            (output_base.to_path_buf(), dir)
        }
    }
}

fn rc_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
