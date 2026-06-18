#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ps2dwarf1.cli import default_output, fail, parse_int, resolve_input_path, resolve_output_path, write_json
from ps2dwarf1.model import build_model, make_summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory recoverable DWARF v1 data in a PS2 ELF.")
    parser.add_argument("elf", nargs="?", help="Path to an unstripped PS2 ELF.")
    parser.add_argument("-o", "--output", help="Output summary JSON path.")
    parser.add_argument("--debug-section", default=".debug")
    parser.add_argument("--line-section", default=".line")
    parser.add_argument("--no-lines", action="store_true")
    parser.add_argument("--image-base", type=parse_int)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    elf_path = resolve_input_path(args.elf)
    out = resolve_output_path(args.output, default_output(elf_path, "dwarf1.summary.json"))
    try:
        model = build_model(
            elf_path,
            debug_section=args.debug_section,
            line_section=args.line_section,
            include_lines=not args.no_lines,
            image_base=args.image_base,
            strict=args.strict,
        )
        summary = make_summary(model)
    except Exception as exc:
        fail(exc)

    write_json(out, summary, indent=2)
    meta = summary["meta"]
    print(f"summary: {out}")
    print(f"DIEs walked        : {meta.get('dies', 0):,}")
    print(f".debug size        : {meta.get('debug_size', 0):,} bytes")
    print(f".line size         : {meta.get('line_size', 0):,} bytes")
    print(f"compile units      : {meta.get('compile_units', 0):,}")
    print(f"source files       : {meta.get('files', 0):,}")
    print(f"types              : {meta.get('types', 0):,} {summary.get('type_kinds', {})}")
    print(f"functions          : {meta.get('funcs', 0):,}")
    print(f"globals            : {meta.get('globals', 0):,}")
    print(f"line records       : {meta.get('lines', 0):,}")
    warnings = meta.get("warnings") or []
    if warnings:
        print(f"warnings           : {len(warnings):,}")
        for item in warnings[:10]:
            print(f"  - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
