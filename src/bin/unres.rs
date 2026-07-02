use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use unlink::{Result, UnlinkError, extract_resource_script};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Extract Win32 PE resources into an MSVC resource script.",
    long_about = "Extract resources from a PE executable and write an MSVC-compatible .rc script, resources.h header, and sidecar files for binary resources such as icons, cursors, and raw data.",
    arg_required_else_help = true,
    after_help = "Examples:\n  unres input.exe\n  unres input.exe -o generated.rc --asset-dir resources_assets\n\nOutput:\n  The .rc file includes resources.h from the same directory and references sidecar assets using paths relative to the .rc file directory when --asset-dir is relative."
)]
struct Args {
    /// PE executable to extract resources from.
    #[arg(value_name = "INPUT_EXE")]
    input: PathBuf,

    /// Output resource script path. Defaults to resources.rc in the current directory.
    #[arg(short, long, value_name = "OUTPUT_RC")]
    output: Option<PathBuf>,

    /// Directory for sidecar assets. Defaults to resources next to OUTPUT_RC.
    /// Relative paths are resolved next to OUTPUT_RC.
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

    let output = args.output.unwrap_or_else(default_output_path);
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
    let header_output = header_output_path(&output);

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
    fs::write(&header_output, extracted.header_text).map_err(|err| {
        UnlinkError::new(format!(
            "failed to write `{}`: {err}",
            header_output.display()
        ))
    })?;
    println!(
        "wrote {} resource asset(s), {}, and {}",
        extracted.assets.len(),
        output.display(),
        header_output.display()
    );
    Ok(())
}

fn default_output_path() -> PathBuf {
    PathBuf::from("resources.rc")
}

fn header_output_path(output: &Path) -> PathBuf {
    output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("resources.h")
}

fn resolve_asset_directory(asset_dir: Option<&Path>, output: &Path) -> (PathBuf, String) {
    let output_base = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match asset_dir {
        Some(path) if path.is_absolute() => (PathBuf::new(), rc_path(path)),
        Some(path) => (output_base.to_path_buf(), rc_path(path)),
        None => (output_base.to_path_buf(), "resources".to_owned()),
    }
}

fn rc_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
