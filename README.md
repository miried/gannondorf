# Gannondorf

Gannondorf is a Rust project for pulling apart Win32 PE executables. It builds
several sibling command-line tools:

- `unlink` extracts discovered functions into isolated COFF object files,
  creating relocations where necessary.
- `cxxmap` extracts binary/function address mappings from annotated C++ source.
- `objdiff-json` creates or incrementally updates objdiff config units from
  cxxmap `.map` files.
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

## `cxxmap`

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

Pass the generated map to `unlink` to resolve its `binary` entry under a binary
directory and extract all mapped functions into one object:

```sh
unlink tests/bin --map build/maps/mapping_test.map -o target/mapping_test.obj
```

## `objdiff-json`

To create or update objdiff units for changed map files:

```sh
objdiff-json --json objdiff.json --target-dir target --build-dir build --source-dir src maps/main.map
```

Only units for the map files passed on the command line are changed. Non-empty
maps add or update their unit with target, base, source, and symbol mapping
information; empty maps remove their unit.

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
