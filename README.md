# unlink

This tool takes a Win32 PE executable as input and extracts discovered functions into isolated COFF object files, creating relocations where necessary.

To extract one known function:

```sh
unlink input.exe --address 0x401000 -o sub_00401000.obj
```

When `--address` is omitted, `unlink` discovers PE32/i386 functions automatically and writes one `sub_XXXXXXXX.obj` file per discovered function. In this mode, `-o/--output` is an output directory:

```sh
unlink input.exe -o extracted-objects
```

To extract PE resources into an MSVC resource script:

```sh
unres input.exe
```

`unres` writes the `.rc` file plus sidecar assets for binary resources such as
icons, cursors, and raw resource data. By default, sidecar files are written next
to the script in a `resources` directory, and the script is written as
`resources.rc`.

## Testing

`cargo test` runs helper-level unit tests plus integration tests that compile the
sources in `tests/fixtures` with the bundled MSVC compiler under Wine, extract
objects with `unlink`, and compare the result against the compiler-generated
COFF object with `tests/tools/objdiff-cli-macos-arm64`.
