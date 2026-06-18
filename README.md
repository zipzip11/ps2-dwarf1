# PS2 DWARF v1 Toolkit

Standalone extractor and Ghidra import scripts for PlayStation 2 ELF32/MIPS
executables that contain DWARF version 1 debug information in `.debug` and,
optionally, line records in `.line`.

The toolkit is intentionally title-agnostic:

- no hard-coded game paths, names, symbols, or image base;
- standard-library Python only;
- endian-aware ELF32 section parsing;
- generic DWARF v1 DIE, type, function, global, source-file, and line extraction;
- generic Ghidra scripts that consume the normalized JSON model.

## Scope

Supported:

- ELF32 MIPS/PS2 executables;
- DWARF v1 `.debug` DIE streams using `length, tag, attributes`;
- CodeWarrior-style modifier blocks such as `AT_mod_fund_type` and
  `AT_mod_u_d_type`;
- simple DWARF v1 `.line` programs shaped as
  `u32 length, u32 base_pc, {u32 line, u16 column, u32 pc_offset}...`;
- structs, classes, unions, enums, arrays, typedefs, function-pointer types,
  functions, globals, source files, and source line comments.

Not supported:

- DWARF 2-5 (`.debug_info`, `.debug_abbrev`, `.debug_line`, etc.);
- MIPS ECOFF/STABS `.mdebug`;
- reconstructing local variable storage in Ghidra. Raw location bytes are kept in
  the JSON model, but applying them portably needs compiler/ABI-specific work.

## Quick Start

Run directly from a checkout:

```powershell
python .\extract.py C:\path\to\GAME.ELF
```

Or install the console commands:

```powershell
python -m pip install .
ps2-dwarf1-extract C:\path\to\GAME.ELF
```

The default output is:

```text
out/GAME.dwarf1.model.json
```

Use `-o` to write somewhere else:

```powershell
ps2-dwarf1-extract C:\path\to\GAME.ELF -o C:\work\game.model.json
```

If a target uses nonstandard section names:

```powershell
ps2-dwarf1-extract GAME.ELF --debug-section .debug --line-section .line
```

If Ghidra has loaded the ELF at a different address than the DWARF records use,
keep the extracted model as-is and pass a delta to the Ghidra scripts, for
example `delta=-0x100000`.

## Command-Line Tools

| Tool | Purpose |
|------|---------|
| `ps2-dwarf1-extract` / `extract.py` | Parse an ELF and emit the normalized model JSON. |
| `ps2-dwarf1-analyze` / `analyze.py` | Parse an ELF and emit/print inventory counts and top source files. |
| `ps2-dwarf1-srctree` / `srctree.py` | Aggregate source paths and function counts from a model or ELF. |
| `ps2-dwarf1-samples` / `dump_samples.py` | Print C-like samples for selected structs/functions/enums. |

Examples:

```powershell
ps2-dwarf1-analyze GAME.ELF
ps2-dwarf1-srctree out\GAME.dwarf1.model.json
ps2-dwarf1-samples out\GAME.dwarf1.model.json --struct Player --func-prefix Player
```

## Development

The Python package has no runtime dependencies outside the standard library.
Run the test suite with:

```powershell
python -m unittest discover -s tests
```

Generated models, local analysis output, Python bytecode, and likely proprietary
game/media inputs are ignored by default.

## Ghidra Import

Copy or add `ghidra` as a Ghidra script directory. Run scripts in this
order:

1. `Dwarf1Types.java`
2. `Dwarf1Functions.java`
3. `Dwarf1Globals.java`
4. `Dwarf1Lines.java` (optional; this can create a lot of comments)

Each script prompts for the model JSON.

Common script arguments:

```text
category=/dwarf1
delta=0x0
```

`Dwarf1Functions.java` also accepts:

```text
some/source/path/filter.c
create=true
```

`Dwarf1Globals.java` also accepts:

```text
data=true
```

`Dwarf1Lines.java` also accepts:

```text
some/source/path/filter.c
mode=eol
```

Duplicate named types are preserved by suffixing the DWARF DIE offset, such as
`Foo__1a2b`, instead of assuming that every repeated C tag name has the same
layout. Anonymous names become `anon_<dieoff>`.

## Model Shape

Extracted data is written as a normalized JSON model:

```json
{
  "meta": {},
  "compile_units": [],
  "types": {},
  "funcs": [],
  "globals": [],
  "files": [],
  "lines": []
}
```

Type references are recursive JSON tokens:

```json
{"k": "f", "t": 7}
{"k": "u", "o": 1234}
{"k": "ptr", "e": {"k": "u", "o": 1234}}
{"k": "const", "e": {"k": "f", "t": 9}}
```

The extractor also records `meta.warnings` when it can recover past malformed or
producer-specific records. Run with `--strict` if you want malformed DWARF to
abort the extraction instead.
