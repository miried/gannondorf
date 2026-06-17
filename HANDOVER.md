# HANDOVER

## Current State

This repo is a Rust prototype for extracting functions from Win32 PE executables into standalone COFF object files.

The current implementation is an MVP for explicit-address extraction from PE32/i386 images:

- CLI: `unlink <input.exe> --address <addr> [-o <output.obj>]`
- Library entrypoint: `extract_function_object(image, requested_address)`
- Address parsing accepts decimal and `0x`/`0X` hex.
- Addresses below the PE image base are treated as RVAs; addresses at or above image base are treated as VAs.
- Only PE32/i386 is supported.
- Automatic all-function discovery is not implemented yet; omitting `--address` returns a clear error.

The repo is currently entirely untracked in git (`git status --short` shows all files as `??`), so do not assume `git diff` will show useful changes until files are added.

## Implemented Behavior

Core implementation is in `src/lib.rs`.

- Parses PE32 with `object::read::pe::PeFile32`.
- Validates architecture is `Architecture::I386`.
- Finds the containing `.text` section for the requested function address.
- Decodes from the requested address with `iced_x86::Decoder::with_ip(32, ...)`.
- Stops extraction at the first return instruction.
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

CLI implementation is in `src/main.rs`.

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
cargo run -- tests/TEST00.exe --address 0x401035 -o /tmp/unlink-test.obj
llvm-readobj --sections --symbols --relocations /tmp/unlink-test.obj
```

Observed expected result:

- COFF-i386 object.
- One `.text` relocation:
  - `0xB IMAGE_REL_I386_REL32 sub_00401000`

```sh
cargo run -- tests/TEST00.exe --address 0x401017 -o /tmp/unlink-global.obj
llvm-readobj --sections --symbols --relocations /tmp/unlink-global.obj
```

Observed expected result:

- COFF-i386 object.
- Two `.text` relocations:
  - `0xB IMAGE_REL_I386_DIR32 data_00406030`
  - `0x10 IMAGE_REL_I386_DIR32 data_00406030`

Unit tests in `src/lib.rs` cover:

- Address parsing.
- Extracting `0x401000` with no relocations.
- Extracting `0x401017` with two absolute relocations.
- Extracting `0x401035` with one relative call relocation.
- Treating small addresses as RVAs.
- Erroring on non-executable addresses.

## Known Limits

- Function boundary detection is linear and stops at the first return. It does not yet follow control flow or handle multiple returns robustly.
- No automatic function discovery.
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

2. Add automatic function discovery for PE32/i386.
   - Start with `.text` entrypoint plus direct branch/call targets.
   - Consider prologue heuristics only as a fallback.
   - Emit one object per discovered function, with deterministic output names.

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

6. Add integration-style fixture checks.
   - Generate objects into a temp directory.
   - Inspect with `object` or `llvm-readobj`.
   - Eventually attempt relinking with MSVC/LLVM tools if available.

## Useful Files

- `README.md`: original project goal.
- `src/lib.rs`: extraction logic and tests.
- `src/main.rs`: CLI.
- `tests/TEST00.CPP`: source for the PE/object fixture.
- `tests/TEST00.exe`: PE32 fixture used by tests.
- `tests/TEST00.obj`: original COFF object fixture for comparison.

