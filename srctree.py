#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from ps2dwarf1.cli import default_output, fail, load_json, resolve_input_path, resolve_output_path, write_json
from ps2dwarf1.model import build_model, source_tree


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate source paths and function counts from a DWARF v1 model or ELF.")
    parser.add_argument("input", nargs="?", help="Path to model JSON or an unstripped PS2 ELF.")
    parser.add_argument("-o", "--output", help="Output source tree JSON path.")
    parser.add_argument("--from-elf", action="store_true", help="Force parsing input as an ELF instead of model JSON.")
    parser.add_argument("--debug-section", default=".debug")
    parser.add_argument("--line-section", default=".line")
    args = parser.parse_args()

    path = resolve_input_path(args.input, "Path to model JSON or PS2 ELF: ")
    out = resolve_output_path(args.output, default_output(path, "dwarf1.srctree.json"))
    try:
        if not args.from_elf and path.suffix.lower() == ".json":
            model = load_json(path)
        else:
            model = build_model(path, debug_section=args.debug_section, line_section=args.line_section)
        tree = source_tree(model)
    except Exception as exc:
        fail(exc)

    write_json(out, tree, indent=2)
    print(f"source tree: {out}")
    print(f"unique source files: {len(tree['files']):,}")
    print("top roots:")
    for root, count in list(tree["roots"].items())[:20]:
        print(f"  {count:6}  {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
