#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ps2dwarf1.cli import default_output, fail, parse_int, resolve_input_path, resolve_output_path, write_json
from ps2dwarf1.model import build_model


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract a normalized DWARF v1 model from an ELF32/MIPS PS2 executable."
    )
    parser.add_argument("elf", nargs="?", help="Path to an unstripped PS2 ELF.")
    parser.add_argument("-o", "--output", help="Output model JSON path.")
    parser.add_argument("--debug-section", default=".debug", help="DWARF v1 DIE section name.")
    parser.add_argument("--line-section", default=".line", help="DWARF v1 line section name.")
    parser.add_argument("--no-lines", action="store_true", help="Do not parse the .line section.")
    parser.add_argument("--image-base", type=parse_int, help="Override image base metadata.")
    parser.add_argument("--strict", action="store_true", help="Abort on malformed DWARF records.")
    parser.add_argument("--compact", action="store_true", help="Write compact JSON.")
    args = parser.parse_args()

    elf_path = resolve_input_path(args.elf)
    out = resolve_output_path(args.output, default_output(elf_path, "dwarf1.model.json"))
    try:
        model = build_model(
            elf_path,
            debug_section=args.debug_section,
            line_section=args.line_section,
            include_lines=not args.no_lines,
            image_base=args.image_base,
            strict=args.strict,
        )
    except Exception as exc:
        fail(exc)
    write_json(out, model, indent=None if args.compact else 2)

    meta = model["meta"]
    print(f"wrote: {out}")
    print(f"ELF: {elf_path}")
    print(f"DIEs: {meta.get('dies', 0):,}")
    print(f"types/functions/globals: {meta.get('types', 0):,} / {meta.get('funcs', 0):,} / {meta.get('globals', 0):,}")
    print(f"files/lines: {meta.get('files', 0):,} / {meta.get('lines', 0):,}")
    warnings = meta.get("warnings") or []
    if warnings:
        print(f"warnings: {len(warnings):,} (kept in meta.warnings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
