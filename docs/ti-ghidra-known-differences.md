# TI/Ghidra Known Difference Tests

These tests compare `tests/bin/TI.EXE` against the Ghidra export in
`tests/tools/functions.json`. They live in `tests/integration.rs`.

## Status Summary

| Test | Current status | Why it fails or passes | What needs to change |
| --- | --- | --- | --- |
| `ti_common_function_disassembly_matches_ghidra_export` | Passing | This is the default guard. It compares instruction byte streams for every function both tools found, but allows the current known mismatches through `KNOWN_TI_DISASSEMBLY_BYTE_DIFFERENCES`. | Remove addresses from `ti_known_disassembly_differences!` as individual ignored tests start passing. |
| `ti_function_discovery_matches_ghidra_export` | Ignored, failing | unlink and Ghidra currently disagree on the function entry set: 1330 common entries, 16 unlink-only entries, and 157 Ghidra-only entries. | Harden function discovery and function-boundary detection so entry-point discovery matches Ghidra more closely. |
| `ti_known_diff_*_matches_ghidra` | Ignored, failing | Each generated test checks one currently allowlisted byte-stream mismatch. | Fix the scanner/decoder behavior for the listed function, then remove that address from `ti_known_disassembly_differences!`. |

Run the failing trackers with:

```sh
cargo test ti_function_discovery_matches_ghidra_export -- --ignored --exact --nocapture
cargo test ti_known_diff_ -- --ignored --nocapture
```

## Function Discovery Tracker

`ti_function_discovery_matches_ghidra_export` fails because the two tools do
not identify the same set of functions.

Observed summary:

- Common functions: 1330
- unlink-only functions: 16
- Ghidra-only functions: 157

unlink-only entries from the current failure:

```text
0x00422090, 0x00451EA8, 0x00453F69, 0x00453F80, 0x004541D0,
0x00454250, 0x00454806, 0x00454819, 0x00454A41, 0x00454A56,
0x00454C5C, 0x00454D0E, 0x00454F14, 0x00456B50, 0x00456C70,
0x00456DF0
```

The Ghidra-only side is much larger and includes many addresses that also show
up as overrun boundaries in the disassembly tests, for example `0x0040B610`,
`0x0040D130`, `0x0041EAA0`, `0x00438D20`, `0x00439FC0`, and `0x0043DF70`.
That points at two related fixes: find more real function starts, and stop
current functions before flowing into those starts.

## Per-Function Disassembly Trackers

All tests in this table are generated from `ti_known_disassembly_differences!`
and are ignored today. They fail because unlink's instruction byte stream does
not match Ghidra's byte stream for the same function entry.

| Test | Observed failure | What needs to be fixed |
| --- | --- | --- |
| `ti_known_diff_00402ef0_matches_ghidra` | unlink finds 126 instructions, Ghidra finds 3056. First divergence: unlink jumps to `0x004030D0 ADD EAX, 4`; Ghidra continues at `0x00402F64 MOV EBP,[ESP+0x48]`. | Recover the missing non-linear body, likely switch or jump-table driven CFG blocks. |
| `ti_known_diff_00405c50_matches_ghidra` | unlink finds 27 instructions, Ghidra finds 336. First divergence: unlink reaches `0x00405CC4 MOV EAX,[ESP+4]`; Ghidra continues at `0x00405C9A CMP word ptr [ESP+4],0x4`. | Include the internal branch/body blocks that are currently skipped. |
| `ti_known_diff_00406150_matches_ghidra` | unlink finds 13 instructions, Ghidra finds 27. unlink ends where Ghidra continues at `0x00406182 MOV AX,0x1`. | Include the later reachable block after the early return or branch. |
| `ti_known_diff_004061e0_matches_ghidra` | unlink finds 266 instructions, Ghidra finds 375. First divergence: unlink reaches `0x00406576 LEA EDI,[ESI+8]`; Ghidra continues at `0x0040645E MOV EBX,[ESP+0x28]`. | Recover the missing non-linear CFG path and use stable block ordering. |
| `ti_known_diff_0040b370_matches_ghidra` | unlink finds 31 instructions, Ghidra finds 9. unlink continues into `0x0040B610 SUB ESP,0x100` after Ghidra ended. | Stop the function before the next Ghidra function/prologue. |
| `ti_known_diff_0040bb60_matches_ghidra` | unlink finds 11 instructions, Ghidra finds 241. First divergence: unlink jumps to epilogue at `0x0040BE64 POP EDI`; Ghidra continues at `0x0040BB7A MOV EAX,[ESP+0x34]`. | Include the skipped body blocks instead of taking only the early epilogue path. |
| `ti_known_diff_0040beb0_matches_ghidra` | unlink finds 17 instructions, Ghidra finds 214. First divergence: unlink reaches `0x0040C189 POP ESI`; Ghidra continues at `0x0040BEE4 CMP word ptr [0x00460de4],0x2`. | Include missing conditional/body blocks. |
| `ti_known_diff_0040cd50_matches_ghidra` | unlink finds 68 instructions, Ghidra finds 19. unlink continues into `0x0040D130 PUSH EBX` after Ghidra ended. | Stop before the next function/prologue. |
| `ti_known_diff_0040f260_matches_ghidra` | unlink finds 49 instructions, Ghidra finds 71. First divergence: unlink reaches `0x0040F369 ADD ESP,0xb0`; Ghidra continues at `0x0040F315 MOVSX EAX,word ptr [ESP+0x2a]`. | Recover the missing conditional/internal block. |
| `ti_known_diff_00412260_matches_ghidra` | unlink finds 28 instructions, Ghidra finds 63. First divergence: unlink reaches `0x004122CF SUB SI,BX`; Ghidra continues at `0x00412292 SUB DI,BX`. | Recover the missing branch path and block order. |
| `ti_known_diff_00417450_matches_ghidra` | Same shape as `0x0040F260`: unlink reaches stack cleanup before Ghidra's remaining conditional block. | Recover the missing conditional/internal block. |
| `ti_known_diff_0041a2c0_matches_ghidra` | unlink finds 104 instructions, Ghidra finds 120. First divergence: unlink reaches `0x0041A3AF IMUL EBX,ECX`; Ghidra continues at `0x0041A3A3 MOV AX,0x1`. | Include the small internal branch block. |
| `ti_known_diff_0041a450_matches_ghidra` | unlink finds 107 instructions, Ghidra finds 122. First divergence: unlink reaches `0x0041A4A3 CMP [ESP+0x28],0`; Ghidra continues at `0x0041A475 MOV DI,0x2`. | Include the early branch block that Ghidra keeps in the body. |
| `ti_known_diff_0041bb40_matches_ghidra` | unlink finds 651 instructions, Ghidra finds 640. First divergence: unlink has `0x0041BC44 ADD ESP,4`; Ghidra has `0x0041BC47 LEA EAX,[ESP+0x84]`. | Investigate instruction-boundary or CFG path handling around this call/stack-cleanup area. |
| `ti_known_diff_0041e090_matches_ghidra` | unlink finds 105 instructions, Ghidra finds 4. unlink continues into `0x0041EAA0 SUB ESP,0x1c` after Ghidra ended. | Stop at the thunk/tail-jump/function boundary instead of following into another function. |
| `ti_known_diff_0041ec10_matches_ghidra` | unlink finds 124 instructions, Ghidra finds 317. First divergence: unlink reaches `0x0041EEC3 PUSH 0xb6`; Ghidra continues at `0x0041EC7F PUSH 0xa8`. | Recover the missing branch or table-driven path. |
| `ti_known_diff_00425400_matches_ghidra` | unlink finds 62 instructions, Ghidra finds 1997. First divergence: unlink reaches `0x00425B28 LEA EAX,[ESP+8]`; Ghidra continues at `0x00425460 LEA EAX,[ESP+8]`. | Recover the large non-linear CFG, likely jump-table driven. |
| `ti_known_diff_00426f40_matches_ghidra` | unlink finds 52 instructions, Ghidra finds 74. First divergence: unlink reaches `0x0042702F ADD ESP,0x18`; Ghidra continues at `0x00426FE4 MOVSX EAX,word ptr [ESP+2]`. | Recover the missing conditional block. |
| `ti_known_diff_00427050_matches_ghidra` | unlink finds 49 instructions, Ghidra finds 71. First divergence: unlink reaches `0x0042713B ADD ESP,0x3c`; Ghidra continues at `0x004270F0 MOVSX EAX,word ptr [ESP+0x14]`. | Recover the missing conditional block. |
| `ti_known_diff_00428d90_matches_ghidra` | unlink finds 35 instructions, Ghidra finds 57. First divergence: unlink reaches `0x00428E58 ADD ESP,8`; Ghidra continues at `0x00428DF8 MOV ECX,[ESP+0x18]`. | Recover the missing conditional block. |
| `ti_known_diff_00428e70_matches_ghidra` | Same shape as `0x00428D90`: unlink reaches stack cleanup before Ghidra's remaining conditional block. | Recover the missing conditional block. |
| `ti_known_diff_00429b70_matches_ghidra` | unlink finds 11 instructions, Ghidra finds 365. First divergence: unlink jumps to epilogue at `0x0042A06C POP EDI`; Ghidra continues at `0x00429B8A CMP word ptr [0x0048a134],0`. | Include the large skipped body, likely branch-table driven. |
| `ti_known_diff_0042b8a0_matches_ghidra` | unlink finds 899 instructions, Ghidra finds 7865. First divergence: unlink reaches `0x0042C715 TEST EDX,EDX`; Ghidra continues at `0x0042B99A MOV EAX,[EBP-0xc]`. | Recover the huge function CFG and jump-table paths. |
| `ti_known_diff_004316e0_matches_ghidra` | unlink finds 102 instructions, Ghidra finds 407. First divergence: unlink reaches `0x00431BE5 CALL 0x0041df10`; Ghidra continues at `0x004317EA LEA EAX,[ESP+0x2c]`. | Include the missing internal CFG block. |
| `ti_known_diff_00431de0_matches_ghidra` | unlink starts at `0x00431DE0 PUSH 1`, while the Ghidra body comparison starts with `0x00422090 RET`. | Verify Ghidra export body association for this entry and handle thunks/non-contiguous function bodies correctly. |
| `ti_known_diff_00438a10_matches_ghidra` | unlink finds 11 instructions, Ghidra finds 171. First divergence: unlink jumps to epilogue at `0x00438C44 POP EDI`; Ghidra continues at `0x00438A2A MOV EAX,[ESP+0x30]`. | Include the skipped body blocks. |
| `ti_known_diff_00438c90_matches_ghidra` | unlink finds 69 instructions, Ghidra finds 30. unlink continues into `0x00438D20 SUB ESP,8` after Ghidra ended. | Stop before the next function/prologue. |
| `ti_known_diff_00439700_matches_ghidra` | unlink finds 169 instructions, Ghidra finds 17. unlink continues into `0x00439FC0 SUB ESP,0x30` after Ghidra ended. | Stop before the next function/prologue. |
| `ti_known_diff_0043b000_matches_ghidra` | unlink finds 6 instructions, Ghidra finds 145. unlink reaches `0x0043B195 RET`; Ghidra continues at `0x0043B01A MOV EAX,[ESP+8]`. | Include the missing branch/body blocks. |
| `ti_known_diff_0043c2c0_matches_ghidra` | unlink finds 60 instructions, Ghidra finds 1544. First divergence: unlink reaches `0x0043CE4C LEA EAX,[ESP+8]`; Ghidra continues at `0x0043C320 LEA EAX,[ESP+8]`. | Recover the large non-linear CFG, likely jump-table driven. |
| `ti_known_diff_0043df60_matches_ghidra` | unlink finds 83 instructions, Ghidra finds 3. unlink continues into `0x004420E0 PUSH EBX` after Ghidra ended. | Stop before the next function/prologue. |
| `ti_known_diff_00442670_matches_ghidra` | unlink finds 59 instructions, Ghidra finds 83. First divergence: unlink reaches `0x0044276B MOV AX,[ESP+6]`; Ghidra continues at `0x00442723 PUSH 0x48a148`. | Include the missing internal block. |
| `ti_known_diff_00443730_matches_ghidra` | unlink finds 176 instructions, Ghidra finds 326. First divergence: unlink reaches `0x0044386F LEA EAX,[ESP+0x10]`; Ghidra continues at `0x004437E2 LEA EAX,[ESP+0x10]`. | Recover the missing CFG path. |
| `ti_known_diff_00444620_matches_ghidra` | unlink finds 14 instructions, Ghidra finds 50. unlink ends where Ghidra continues at `0x0044464E MOV EAX,[ESP+8]`. | Include the later reachable block. |
| `ti_known_diff_00447640_matches_ghidra` | unlink finds 168 instructions, Ghidra finds 821. First divergence: unlink reaches `0x00447DB7 MOV EAX,[ESP+0x1c]`; Ghidra continues at `0x004477DC LEA EAX,[ESP+0x1c]`. | Recover the large non-linear CFG. |
| `ti_known_diff_00449310_matches_ghidra` | unlink finds 103 instructions, Ghidra finds 688. First divergence: unlink reaches `0x004496FC MOV EAX,[0x48cbd4]`; Ghidra continues at `0x00449408 TEST byte ptr [ESP+0x2a],0x1`. | Recover the large non-linear CFG. |
| `ti_known_diff_0044a000_matches_ghidra` | unlink finds 17 instructions, Ghidra finds 72. First divergence: unlink reaches `0x0044A0E0 XOR AX,AX`; Ghidra continues at `0x0044A043 MOV EAX,[0x0048cbf8]`. | Include the missing body blocks. |
| `ti_known_diff_0044aab0_matches_ghidra` | unlink finds 44 instructions, Ghidra finds 314. First divergence: unlink reaches `0x0044ADA3 MOV AX,BX`; Ghidra continues at `0x0044AB40 LEA EAX,[ESP+0xc]`. | Recover the non-linear CFG. |
| `ti_known_diff_0044e3a0_matches_ghidra` | x87 wait-prefix grouping differs. unlink emits `FNSTCW [EBP-2]`, while Ghidra's stream shifts around a following `WAIT`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_0044e440_matches_ghidra` | unlink finds 76 instructions, Ghidra finds 125. First divergence: unlink reaches `0x0044E4B8 CMP ECX,0xc`; Ghidra continues at `0x0044E488 MOV AX,word ptr [ESI]`. | Recover the missing CFG path. |
| `ti_known_diff_0044e652_matches_ghidra` | unlink finds 22 instructions, Ghidra finds 2. unlink continues into `0x0044FFD0 PUSH EBP` after Ghidra ended. | Stop before the next function/prologue. |
| `ti_known_diff_0045000e_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTCW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_0045004b_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTCW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_00450093_matches_ghidra` | unlink finds 95 instructions, Ghidra finds 1. unlink continues after a single-instruction Ghidra function. | Stop at the function boundary or reclassify this as a code label rather than a full function body. |
| `ti_known_diff_004501cb_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTCW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_004504b0_matches_ghidra` | unlink finds 243 instructions, Ghidra finds 889. First divergence: unlink reaches `0x00450668 INC byte ptr [ESP+0x17]`; Ghidra continues at `0x00450616 INC byte ptr [ESP+0x15]`. | Recover the non-linear CFG, likely with jump-table paths. |
| `ti_known_diff_00452750_matches_ghidra` | unlink finds 9 instructions, Ghidra finds 17. unlink ends where Ghidra continues at `0x00452770 MOV EAX,0x411`. | Include the later reachable block. |
| `ti_known_diff_00452c10_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTCW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_00453db0_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTSW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_00453e17_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTSW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_00454fe0_matches_ghidra` | unlink finds 79 instructions, Ghidra finds 90. First divergence: unlink reaches `0x00455028 XOR EDI,EDI`; Ghidra continues at `0x00455006 MOV EDI,0x8`. | Include the missing branch path. |
| `ti_known_diff_00455d80_matches_ghidra` | unlink finds 144 instructions, Ghidra finds 452. First divergence: unlink reaches `0x00456235 CMP ECX,0xa`; Ghidra continues at `0x00455DEC CMP BL,0x31`. | Recover the non-linear CFG, likely table/string parsing control flow. |
| `ti_known_diff_00456ea0_matches_ghidra` | unlink finds 277 instructions, Ghidra finds 290. First divergence: unlink reaches `0x004571A2 MOV EAX,[ESP+0x14]`; Ghidra continues at `0x00457174 AND dword ptr [EBX],0xfffff3ff`. | Include the missing later internal block. |
| `ti_known_diff_00457510_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTSW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_00457550_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTCW`. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |
| `ti_known_diff_00457590_matches_ghidra` | x87 wait-prefix grouping differs around `FNSTSW AX` and the surrounding x87 sequence. | Normalize or decode x87 `WAIT`/`FWAIT`-prefixed instructions consistently with Ghidra. |

## Fix Workflow

1. Run one ignored test, for example:

   ```sh
   cargo test ti_known_diff_00402ef0_matches_ghidra -- --ignored --exact --nocapture
   ```

2. Fix the scanner, boundary detection, instruction decoding, or Ghidra export
   normalization for that address.

3. Remove the fixed address from `ti_known_disassembly_differences!` in
   `tests/integration.rs`.

4. Run the default suite:

   ```sh
   cargo test
   ```

The aggregate `ti_common_function_disassembly_matches_ghidra_export` test will
fail if an allowlisted mismatch has been fixed but the allowlist was not
updated.
