#!/usr/bin/env -S uv run --script
#
# /// script
# dependencies = ["pyghidra"]
# ///

import argparse
import json
import re
from pathlib import Path

import pyghidra

ROOT_DIR = Path(__file__).resolve().parents[0]
PROJECT_DIR = ROOT_DIR / "ghidra"
DEFAULT_PROJECT_NAME = "taoot"
DEFAULT_BINARY_FILE = "TI.EXE"
DEFAULT_OUTPUT_FILE = ROOT_DIR / "functions.json"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export decompiler and disassembly output from the local Ghidra project."
    )
    parser.add_argument("--project-name", default=DEFAULT_PROJECT_NAME)
    parser.add_argument("--binary-file", default=DEFAULT_BINARY_FILE)
    parser.add_argument("--output-file", type=Path, default=DEFAULT_OUTPUT_FILE)
    parser.add_argument(
        "--function",
        action="append",
        default=[],
        metavar="ADDR_OR_NAME",
        help=(
            "Only export matching function(s). May be repeated. Accepts names, "
            "hex entry addresses such as 0041bb40, or 0x0041bb40."
        ),
    )
    parser.add_argument(
        "--skip-decompile",
        action="store_true",
        help="Export signatures and disassembly only.",
    )
    parser.add_argument(
        "--skip-disassembly",
        action="store_true",
        help="Export signatures and decompiler output only.",
    )
    parser.add_argument(
        "--decompile-timeout",
        type=int,
        default=30,
        help="Per-function decompiler timeout in seconds.",
    )
    return parser.parse_args()


def _normalize_address(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if re.fullmatch(r"[0-9a-f]+", text):
        return text.zfill(8)
    return text


def _function_address(function) -> str:
    return str(function.getEntryPoint()).lower()


def _matches_selector(function, selectors: set[str]) -> bool:
    if not selectors:
        return True

    address = _function_address(function)
    return address in selectors or function.getName().lower() in selectors


def _function_signature(function) -> str:
    signature = function.getSignature()
    if signature is not None:
        return str(signature)
    return function.getName()


def _function_disassembly(listing, function) -> str:
    lines = []
    for instruction in listing.getInstructions(function.getBody(), True):
        lines.append(f"{instruction.getAddress()} {instruction}")
    return "\n".join(lines)


def _instruction_bytes(instruction) -> str:
    return bytes((byte & 0xFF for byte in instruction.getBytes())).hex()


def _function_instructions(listing, function) -> list[dict[str, str]]:
    instructions = []
    for instruction in listing.getInstructions(function.getBody(), True):
        instructions.append(
            {
                "address": str(instruction.getAddress()).lower(),
                "bytes": _instruction_bytes(instruction),
                "text": str(instruction),
            }
        )
    return instructions


def _decompile_functions(program):
    from ghidra.app.decompiler import DecompInterface

    decompiler = DecompInterface()
    decompiler.openProgram(program)
    return decompiler


def _function_decompiled_code(decompiler, function, timeout: int) -> str:
    result = decompiler.decompileFunction(function, timeout, pyghidra.task_monitor())
    if not result or not result.decompileCompleted():
        return ""

    decompiled_function = result.getDecompiledFunction()
    if decompiled_function is None:
        return ""
    return decompiled_function.getC()


def _export_functions(
    program,
    selectors: set[str],
    *,
    include_decompiled_code: bool,
    include_disassembly: bool,
    decompile_timeout: int,
) -> list[dict[str, str]]:
    functions = []
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    decompiler = _decompile_functions(program) if include_decompiled_code else None

    try:
        for function in function_manager.getFunctions(True):
            if not _matches_selector(function, selectors):
                continue

            functions.append(
                {
                    "address": _function_address(function),
                    "name": function.getName(),
                    "signature": _function_signature(function),
                    "disassembly": (
                        _function_disassembly(listing, function) if include_disassembly else ""
                    ),
                    "instructions": (
                        _function_instructions(listing, function) if include_disassembly else []
                    ),
                    "decompiled_code": (
                        _function_decompiled_code(decompiler, function, decompile_timeout)
                        if decompiler is not None
                        else ""
                    ),
                }
            )
    finally:
        if decompiler is not None:
            decompiler.dispose()

    return functions


def main() -> None:
    args = _parse_args()
    selectors = {_normalize_address(selector) for selector in args.function}
    pyghidra.start()

    with pyghidra.open_project(PROJECT_DIR, args.project_name, create=True) as project:
        print(f"Opened Ghidra project: {project.name} ({PROJECT_DIR})")
        with pyghidra.program_context(project, f"/{args.binary_file}") as program:
            output_path = args.output_file
            if not output_path.is_absolute():
                output_path = ROOT_DIR / output_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            export = {
                "project_name": args.project_name,
                "binary_file": args.binary_file,
                "selectors": sorted(selectors),
                "functions": _export_functions(
                    program,
                    selectors,
                    include_decompiled_code=not args.skip_decompile,
                    include_disassembly=not args.skip_disassembly,
                    decompile_timeout=args.decompile_timeout,
                ),
            }
            output_path.write_text(json.dumps(export, indent=2), encoding="utf-8")
            print(f"Exported {len(export['functions'])} functions to {output_path}")
            if selectors and not export["functions"]:
                print(f"No functions matched: {', '.join(sorted(selectors))}")


if __name__ == "__main__":
    main()
