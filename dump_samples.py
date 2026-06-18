#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from ps2dwarf1.cli import fail, load_json, resolve_input_path
from ps2dwarf1.model import build_model


def main() -> int:
    parser = argparse.ArgumentParser(description="Print C-like samples from a DWARF v1 model or ELF.")
    parser.add_argument("input", nargs="?", help="Path to model JSON or an unstripped PS2 ELF.")
    parser.add_argument("--from-elf", action="store_true")
    parser.add_argument("--struct", action="append", default=[], help="Struct/class/union name to print. May repeat.")
    parser.add_argument("--func-prefix", action="append", default=[], help="Function name prefix to print. May repeat.")
    parser.add_argument("--enum", action="append", default=[], help="Enum name to print. May repeat.")
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    path = resolve_input_path(args.input, "Path to model JSON or PS2 ELF: ")
    try:
        if not args.from_elf and path.suffix.lower() == ".json":
            model = load_json(path)
        else:
            model = build_model(path)
    except Exception as exc:
        fail(exc)

    printed = 0
    for rec in model.get("types", {}).values():
        if rec.get("kind") not in ("struct", "class", "union"):
            continue
        if args.struct and rec.get("name") not in args.struct:
            continue
        print_aggregate(rec, model)
        printed += 1
        if printed >= args.limit:
            break

    printed = 0
    prefixes = tuple(args.func_prefix)
    for func in model.get("funcs", []):
        if prefixes and not func.get("name", "").startswith(prefixes):
            continue
        print_func(func, model)
        printed += 1
        if printed >= args.limit:
            break

    printed = 0
    for rec in model.get("types", {}).values():
        if rec.get("kind") != "enum":
            continue
        if args.enum and rec.get("name") not in args.enum:
            continue
        print_enum(rec)
        printed += 1
        if printed >= args.limit:
            break
    return 0


def print_aggregate(rec: Dict[str, Any], model: Dict[str, Any]) -> None:
    kind = "struct" if rec.get("kind") == "class" else rec.get("kind", "struct")
    print(f"{kind} {rec.get('name', 'anon')} {{    /* sizeof 0x{rec.get('size', 0):x} */")
    for member in rec.get("members", []):
        off = member.get("off")
        off_text = "????" if off is None else f"{off:04x}"
        print(f"    /* +0x{off_text} */ {type_name(member.get('ref'), model)} {member.get('name', 'field')};")
    print("};\n")


def print_func(func: Dict[str, Any], model: Dict[str, Any]) -> None:
    params = ", ".join(
        f"{type_name(p.get('ref'), model)} {p.get('name', 'param')}" for p in func.get("params", [])
    )
    if not params:
        params = "void"
    print(f"{type_name(func.get('ret'), model)} {func.get('name')}({params});  /* 0x{func.get('low', 0):x} */")


def print_enum(rec: Dict[str, Any]) -> None:
    print(f"enum {rec.get('name', 'anon')} {{")
    for name, value in rec.get("consts", [])[:64]:
        print(f"    {name} = {value},")
    print("};\n")


def type_name(ref: Any, model: Dict[str, Any]) -> str:
    if not isinstance(ref, dict):
        return "void"
    k = ref.get("k")
    if k == "f":
        return model.get("fundamental_types", {}).get(str(ref.get("t")), f"FT_{ref.get('t')}")
    if k == "u":
        rec = model.get("types", {}).get(str(ref.get("o")))
        if not rec:
            return f"udt_{ref.get('o'):x}"
        kind = rec.get("kind")
        prefix = {"struct": "struct ", "class": "struct ", "union": "union ", "enum": "enum "}.get(kind, "")
        return prefix + rec.get("name", f"anon_{ref.get('o'):x}")
    if k in ("ptr", "ref"):
        return type_name(ref.get("e"), model) + (" *" if k == "ptr" else " &")
    if k in ("const", "vol", "mod"):
        return type_name(ref.get("e"), model)
    return "void"


if __name__ == "__main__":
    raise SystemExit(main())
