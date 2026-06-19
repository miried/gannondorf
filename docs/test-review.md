# Test review: `tests/` (unlink)

Date: 2026-06-18
Scope: `tests/integration.rs`, `tests/fixtures/`

Baseline: all 5 integration tests pass in ~6.7s with the full toolchain
(wine + bundled MSVC + `tests/tools/objdiff-cli-macos-arm64`) present.

The suite is solid — real end-to-end coverage (compile -> extract -> `objdiff`
compare), robust `parse_u64`, signal-aware status display, and helpful panic
messages. Improvements below are ordered by impact.

## High impact — reliability & portability

### 1. Toolchain-dependent tests hard-fail instead of skipping
`integration.rs:134-138`, `integration.rs:230-234`
`compile_fixture` / `run_objdiff` `assert!`/`panic!` when wine, MSVC, or objdiff
are absent. `tests/tools/objdiff-cli-macos-arm64` is mac-arm64-only and gitignored, so
plain `cargo test` cannot pass on Linux CI, Intel macs, or any contributor
checkout without the bundled tools.
Fix (pick one):
- Mark these `#[ignore]` and run in CI with `cargo test -- --ignored` (keeps
  `cargo test` fast/hermetic for everyone), or
- Gate on an env var (e.g. `UNLINK_INTEGRATION=1`) and soft-skip
  (`eprintln!` + `return`) when tools are missing.

### 2. Parallel `wine` runs share one `~/.wine` prefix
`integration.rs:140-151`
Cargo runs the three compile-heavy tests concurrently; simultaneous wine-prefix
initialization can race/corrupt on a fresh machine -> flaky first run.
Fix: set a per-test `WINEPREFIX`, pre-initialize once via `OnceLock`, or
serialize compilation.

### 3. No cleanup — test dirs accumulate
`new_test_dir` `integration.rs:408-424`
15 leftover dirs already exist under `target/integration-tests/`. `FixtureBuild`
has no `Drop`.
Fix: remove the dir on success, keep on failure for debugging (a `Drop` guard
checking `std::thread::panicking()`, or the `tempfile` crate).

### 4. No negative / error-path coverage
Every integration test is happy-path; CLI error handling (exit code + stderr) is
untested.
Fix: add cases for non-existent input, non-PE/garbage input, PE64
(unsupported-arch message), and `--address` outside `.text` range.

## Medium impact — maintainability

### 5. Redundant read+parse of the same file
`text_base:289`, `text_rva:299`, `image_base:285`, `object_symbol_offset:267`
`image_base` parses the exe twice; `linked_va_for_source_symbol` parses it again.
Fix: a single `with_parsed_object(path, |file| ...)` helper (or return base+rva
from one parse).

### 6. `basic.cpp` is compiled twice
`integration.rs:57` and `integration.rs:83`
`single_function_extraction` recompiles what `compiled_basic_fixture` already
built.
Fix: compile each fixture once via `OnceLock` / `once_cell`.

### 7. Split helpers from cases
467 lines in one file. Move process/objdiff/object-parsing helpers into
`tests/common/mod.rs` so the test functions read clearly.

### 8. Poor diff on instruction mismatch
`integration.rs:222-225`
`assert_eq!` on two long `Vec<NormalizedInstruction>` dumps raw Debug.
Fix: a per-instruction comparison printing the first differing offset.

### 9. Document the objdiff symbol-lookup assumption
`run_objdiff:228`, lookups `integration.rs:209-210`
Only `target_symbol` is passed to objdiff, yet the right side is looked up by a
different `base_symbol`. This relies on objdiff emitting both objects' full
symbol lists regardless of the selector — add a one-line comment so it isn't
mistaken for a bug.

## Low impact — nice to have

- Assert discovery mode actually creates the `-o` directory and writes >=1
  object, not just that specific known symbols exist.
- Fixture symbol names (`_fixture_*`) are duplicated between `.cpp` and test
  arrays — a shared `const` list would prevent drift.

## Suggested order of execution

1. #1 + #3 — gate/ignore toolchain tests and add cleanup (unblocks CI, stops dir
   accumulation).
2. #4 — error-path tests.
3. #2, #5, #6, #7 — flakiness + maintainability.
4. #8, #9, low-impact items.
