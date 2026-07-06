# Gannondorf

Gannondorf is a Rust project for pulling apart Win32 PE executables. It builds
several sibling command-line tools:

- `unlink` extracts discovered functions into isolated COFF object files,
  creating relocations where necessary.
- `cxxmap` extracts binary/function address mappings from annotated C++ source.
- `cxxunlink` parses those source annotations and extracts the mapped functions
  from the annotated binary.
- `unres` extracts PE resources into an MSVC-compatible resource script,
  generated header, and sidecar asset files.

## `unlink`

To extract one known function:

```sh
unlink input.exe --address 0x401000 -o sub_00401000.obj
```

To extract several known functions into one object:

```sh
unlink input.exe --address 0x401000 --address 0x401050 -o selected.obj
```

When `--address` is omitted, `unlink` discovers PE32/i386 functions automatically and writes one `sub_XXXXXXXX.obj` file per discovered function. In this mode, `-o/--output` is an output directory:

```sh
unlink input.exe -o extracted-objects
```

## `cxxmap` and `cxxunlink`

Annotated source files can name the target executable and function addresses:

```cpp
//! FILE TI.EXE

//! FUNC 0x0041bb40
void fn_0041bb40();
```

`cxxmap` prints the parsed mapping:

```sh
cxxmap tests/mapping_test.cpp
```

It can also write `mapping_test.map` into an output directory:

```sh
cxxmap tests/mapping_test.cpp -o build/maps
```

`cxxunlink` resolves the `FILE` annotation under a binary directory and writes a
combined object for every mapped function address:

```sh
cxxunlink tests/mapping_test.cpp tests/bin -o mapped.obj
```

It can also create or update an objdiff `units` entry for the extracted object:

```sh
cxxunlink src/sub_004321D0.cpp bin \
  -o target/sub_004321D0.obj \
  --objdiff-json objdiff.json \
  --objdiff-unit-name WinMain \
  --objdiff-base-path build/sub_004321D0.obj
```

The generated unit includes `target_path`, `base_path` when supplied,
`metadata.source_path`, and `symbol_mappings` from extracted `sub_XXXXXXXX`
symbols to the corresponding source-object symbols.

## `unres`

To extract PE resources into an MSVC resource script:

```sh
unres input.exe
```

`unres` writes the `.rc` file, a sibling `resources.h` with generated resource
ID definitions, and sidecar assets for binary resources such as icons, cursors,
and raw resource data. By default, sidecar files are written next to the script
in a `resources` directory, and the script is written as `resources.rc`.

## Testing

`cargo test` runs helper-level unit tests plus integration tests that compile the
sources in `tests/fixtures` with the bundled MSVC compiler under Wine, extract
objects with `unlink`, and compare the result against the compiler-generated
COFF object with `tests/tools/objdiff-cli-macos-arm64`.
