# HANDOVER

## Current State

This repo is the `gannondorf` Rust prototype for pulling apart Win32 PE
executables. It currently builds two sibling CLI tools:

- `unlink`, for extracting functions into standalone COFF object files.
- `unres`, for extracting PE resources into MSVC-compatible `.rc` output,
  generated `resources.h` definitions, and sidecar asset files.

The current implementation is an MVP for extracting functions from PE32/i386 images:

- CLI: `unlink <input.exe> --address <addr> [-o <output.obj>]`
- CLI: `unlink <input.exe> --address <addr> --address <addr>... -o <output.obj>`
- CLI: `unlink <input.exe> [-o <output-dir>]`
- Library entrypoints: `extract_function_object(image, requested_address)` and `extract_functions_object(image, requested_addresses)`
- Library entrypoints: `discover_function_addresses(image)` and `extract_function_objects(image)`
- Address parsing accepts decimal and `0x`/`0X` hex.
- Addresses below the PE image base are treated as RVAs; addresses at or above image base are treated as VAs.
- Only PE32/i386 is supported.
- Omitting `--address` discovers functions automatically and writes one `sub_XXXXXXXX.obj` per function. In automatic mode, `-o/--output` is an output directory.
- Passing multiple `--address` values writes one COFF object containing all requested functions. In this mode, `-o/--output` is required and names the object file.
- Resource extraction accepts PE32 and PE32+ inputs.

Local test tools live under `tests/tools/`.

## Implemented Behavior

Function extraction is implemented in `src/functions.rs`.

- Parses PE32 with `object::read::pe::PeFile32`.
- Validates architecture is `Architecture::I386`.
- Finds the containing `.text` section for the requested function address.
- Decodes from the requested address with `iced_x86::Decoder::with_ip(32, ...)`.
- Stops extraction at the first return instruction after any forward non-call branch targets seen so far.
- Discovers automatic function candidates from:
  - The PE `.text` entrypoint.
  - Direct call targets found while scanning `.text`.
  - Direct call/unconditional-branch targets found while decoding discovered functions.
  - Common i386 frame prologues (`push ebp; mov ebp, esp`) as a fallback.
- Automatic outputs are sorted by VA and named deterministically as `sub_XXXXXXXX.obj`.
- Reconstructs COFF relocations:
  - PE `IMAGE_REL_BASED_HIGHLOW` entries inside the extracted byte range become `IMAGE_REL_I386_DIR32`.
  - Direct external near calls/jumps discovered via iced-x86 branch immediates become `IMAGE_REL_I386_REL32`.
  - Internal direct branches stay encoded as-is.
  - Relocated fields are zeroed in section bytes before writing the COFF object.
- Emits one COFF-i386 object with:
  - `.text` section.
  - Public function symbol named `sub_XXXXXXXX`.
  - Synthetic undefined symbols:
    - `sub_XXXXXXXX` for external code references.
    - `data_XXXXXXXX` for external data references.

Resource extraction is implemented in `src/resources.rs`.

- Parses the PE resource tree for PE32 and PE32+ images.
- Renders an MSVC-compatible `.rc` script and generated `resources.h`.
- Rebuilds icon/cursor group resources into `.ico`/`.cur` sidecar assets.
- Emits sidecar files for raw resource payloads.

CLI implementations are in `src/bin/unlink.rs` and `src/bin/unres.rs`.

Dependencies of note:

- `iced-x86 = "1.21.0"`
- `object = { version = "0.39.1", features = ["write"] }`
- `clap = { version = "4.6.1", features = ["derive"] }`

## Verification Performed

Passing commands:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

CLI smoke tests performed:

```sh
cargo run --bin unlink -- tests/TEST00.exe --address 0x401035 -o /tmp/unlink-test.obj
llvm-readobj --sections --symbols --relocations /tmp/unlink-test.obj
```

Observed expected result:

- COFF-i386 object.
- One `.text` relocation:
  - `0xB IMAGE_REL_I386_REL32 sub_00401000`

```sh
cargo run --bin unlink -- tests/TEST00.exe --address 0x401017 -o /tmp/unlink-global.obj
llvm-readobj --sections --symbols --relocations /tmp/unlink-global.obj
```

Observed expected result:

- COFF-i386 object.
- Two `.text` relocations:
  - `0xB IMAGE_REL_I386_DIR32 data_00406030`
  - `0x10 IMAGE_REL_I386_DIR32 data_00406030`

Automatic discovery smoke test performed:

```sh
cargo run --bin unlink -- tests/TEST00.exe -o /tmp/unlink-auto-test
llvm-readobj --file-headers --sections --symbols --relocations /tmp/unlink-auto-test/sub_004010C0.obj
```

Observed expected result:

- 74 function objects written for `TEST00.exe`.
- Entry object `sub_004010C0.obj` is COFF-i386.
- Entry object has `.text` relocations for external code and data references.

Unit tests in `src/functions.rs` and `src/resources.rs` cover pure helpers:

- Address parsing.
- Default output naming.
- RVA-to-VA normalization.
- Range containment boundaries.
- Resource rendering and parsing helpers.

Integration tests in `tests/integration.rs` cover the fixture-level flow:

- Compile source fixtures in `tests/fixtures` with the bundled MSVC compiler through Wine.
- Use the `unlink` CLI to extract objects from the linked executable.
- Compare selected extracted functions against the compiler-generated object with `tests/tools/objdiff-cli-macos-arm64`.
- Cover no-reference functions, absolute data relocations, relative call relocations, conditional branches, loops, nested branches, and VA/RVA address extraction.

## Known Limits

- Function boundary detection is still mostly linear. It tracks forward non-call branch targets, but does not yet build a full CFG.
- Automatic function discovery is heuristic and can include runtime helper thunks, exception handlers, and other code labels from `.text`, not just source-level functions.
- No PE64/x86_64 support.
- No import table symbol naming; unresolved references use synthetic names.
- No original symbol recovery from PDB, exports, maps, or COFF symbol tables.
- Data extraction is not implemented; data references become undefined symbols rather than copied data sections.
- Indirect calls/jumps and memory-indirect references are not converted into useful symbols.
- The current output is intended for inspection and first-pass relinking experiments, not full production relinkability.

## Good Next Steps

1. Improve function boundary detection.
   - Build a small CFG from direct branches/calls using iced-x86.
   - Stop at the reachable instruction set rather than first return.
   - Handle multiple returns and internal forward/backward branches.

2. Improve automatic discovery precision for PE32/i386.
   - Reduce false candidates from linear `.text` scanning.
   - Distinguish source-level function starts from exception handlers, thunks, and internal labels where possible.
   - Use exports/symbols when available as stronger seeds.

3. Improve symbol naming.
   - Use PE exports when available.
   - Parse imports/IAT and name imported call/data references.
   - Keep synthetic `sub_`/`data_` names as fallback.

4. Add data-section extraction.
   - For referenced initialized data, emit `.data`/`.rdata` chunks with relocations.
   - Preserve alignment and section characteristics where useful.

5. Add PE64/x86_64 support.
   - Extend address-size and relocation handling.
   - Use AMD64 relocation kinds, including `REL32_*` variants where instruction displacement distance requires them.

6. Broaden integration fixtures further.
   - Add cases for import thunks, indirect control flow, switch tables, and initialized data once the extractor supports those behaviors.
   - Eventually attempt relinking with MSVC/LLVM tools if available.

## Useful Files

- `README.md`: original project goal.
- `src/lib.rs`: shared crate facade and public error/result types.
- `src/functions.rs`: function extraction logic and tests.
- `src/resources.rs`: resource extraction logic and tests.
- `src/bin/unlink.rs`: function extraction CLI.
- `src/bin/unres.rs`: resource extraction CLI.
- `tests/fixtures/basic.cpp`: source fixture for no-ref, data-reloc, and call-reloc checks.
- `tests/fixtures/control_flow.cpp`: source fixture for conditional, loop, and nested-branch checks.
- `tests/integration.rs`: compiles fixtures, runs `unlink`, and compares with `objdiff`.
