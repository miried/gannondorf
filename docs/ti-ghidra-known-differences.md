# TI/Ghidra Known Difference Tests

These tests compare `tests/bin/TI.EXE` against the Ghidra export in
`tests/tools/functions.json`. They live in `tests/integration.rs`.

## Status Summary

| Test | Current status | Purpose |
| --- | --- | --- |
| `ti_common_function_disassembly_matches_ghidra_export` | Passing | Default guard for instruction byte streams across every function discovered by both unlink and Ghidra. `KNOWN_TI_DISASSEMBLY_BYTE_DIFFERENCES` is currently empty. |
| `ti_function_discovery_known_delta_matches_ghidra_export` | Ignored, passing | Tracks the remaining function-entry-set delta while broader indirect function-pointer discovery is being hardened. |

Run the discovery tracker with:

```sh
cargo test ti_function_discovery_known_delta_matches_ghidra_export -- --ignored --exact --nocapture
```

## Function Discovery Tracker

The remaining discovery delta is:

- Common functions: 1471
- unlink-only functions: 17
- Ghidra-only functions: 16

unlink-only entries:

```text
0x0044FF1E, 0x0044FF61, 0x00451EA8, 0x00453F69, 0x00453F80,
0x004541D0, 0x00454250, 0x00454806, 0x00454819, 0x00454A41,
0x00454A56, 0x00454C5C, 0x00454D0E, 0x00454F14, 0x00456B50,
0x00456C70, 0x00456DF0
```

Ghidra-only entries:

```text
0x00407140, 0x00407220, 0x0041B840, 0x0041D9D0, 0x00421040,
0x00424240, 0x0042B7D0, 0x0042B890, 0x00430F70, 0x004325B0,
0x0044E3D0, 0x00451F65, 0x00452DB0, 0x00456A00, 0x00458010,
0x00458580
```

The remaining Ghidra-only entries are mostly indirect callback/function-pointer
roots. The remaining unlink-only entries are mostly CRT/x87 internal call
targets that Ghidra models as labels rather than exported functions.

## Fix Workflow

1. Harden discovery for a specific entry class, such as callback roots passed
   through imports or initialized function-pointer tables.
2. Run the default suite:

   ```sh
   cargo test
   ```

3. Run the ignored tracker:

   ```sh
   cargo test -- --ignored
   ```

4. Update `EXPECTED_TI_SCANNER_ONLY_FUNCTIONS`,
   `EXPECTED_TI_GHIDRA_ONLY_FUNCTIONS`, and `EXPECTED_TI_COMMON_FUNCTIONS` in
   `tests/integration.rs` when the discovery delta changes.
