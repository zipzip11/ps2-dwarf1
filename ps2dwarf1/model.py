from __future__ import annotations

import collections
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .dwarf1 import (
    A_BIT_OFFSET,
    A_BIT_SIZE,
    A_BYTE_SIZE,
    A_COMP_DIR,
    A_ELEMENT_LIST,
    A_HIGH_PC,
    A_LANGUAGE,
    A_LOCATION,
    A_LOW_PC,
    A_NAME,
    A_PRODUCER,
    A_STMT_LIST,
    AT,
    FT,
    TAG,
    T_ARRAY,
    T_CLASS,
    T_COMPILE_UNIT,
    T_ENUM,
    T_FORMAL_PARAM,
    T_GLOBAL_SUBROUTINE,
    T_GLOBAL_VARIABLE,
    T_LOCAL_VARIABLE,
    T_MEMBER,
    T_POINTER,
    T_REFERENCE,
    T_STRUCT,
    T_SUBROUTINE,
    T_SUBROUTINE_TYPE,
    T_TYPEDEF,
    T_UNION,
    Die,
    attr_value,
    child_indices,
    decode_array_subscript,
    decode_location,
    global_address,
    member_offset,
    parse_debug_section,
    parse_line_section,
    type_ref,
)
from .elf import ElfError, ElfFile


class ModelError(RuntimeError):
    pass


def build_model(
    elf_path: Path | str,
    debug_section: str = ".debug",
    line_section: str = ".line",
    include_lines: bool = True,
    image_base: Optional[int] = None,
    strict: bool = False,
) -> Dict[str, Any]:
    elf = ElfFile.from_path(Path(elf_path))
    debug = elf.section(debug_section)
    if not debug:
        available = ", ".join(s.name for s in elf.sections if s.name)
        raise ModelError(f"missing {debug_section!r} section; available sections: {available}")

    debug_blob = elf.section_data(debug)
    parsed = parse_debug_section(debug_blob, elf.endian, elf.address_size, strict)
    dies = parsed.dies
    off_to_index = {die.offset: i for i, die in enumerate(dies)}

    file_ids: Dict[str, int] = {}
    files: List[str] = []

    def file_id(path: Optional[str]) -> Optional[int]:
        if path is None:
            return None
        if path not in file_ids:
            file_ids[path] = len(files)
            files.append(path)
        return file_ids[path]

    current_file: Optional[int] = None
    compile_units: List[Dict[str, Any]] = []
    stmt_to_file: Dict[int, int] = {}
    die_to_file: Dict[int, Optional[int]] = {}

    for die in dies:
        if die.tag == T_COMPILE_UNIT:
            name = _str_or_none(die.attr(A_NAME))
            current_file = file_id(name)
            stmt = _int_or_none(die.attr(A_STMT_LIST))
            if stmt is not None and current_file is not None:
                stmt_to_file[stmt] = current_file
            compile_units.append(
                _drop_none(
                    {
                        "die": die.offset,
                        "name": name,
                        "file": current_file,
                        "comp_dir": _str_or_none(die.attr(A_COMP_DIR)),
                        "producer": _str_or_none(die.attr(A_PRODUCER)),
                        "language": _int_or_none(die.attr(A_LANGUAGE)),
                        "low": _int_or_none(die.attr(A_LOW_PC)),
                        "high": _int_or_none(die.attr(A_HIGH_PC)),
                        "stmt_list": stmt,
                    }
                )
            )
        die_to_file[die.offset] = current_file

    types: Dict[str, Dict[str, Any]] = {}
    funcs: List[Dict[str, Any]] = []
    globals_: List[Dict[str, Any]] = []
    array_warnings: List[str] = []

    for index, die in enumerate(dies):
        attrs = die.attrs
        name = _str_or_none(die.attr(A_NAME))
        file_ref = die_to_file.get(die.offset)

        if die.tag in (T_STRUCT, T_UNION, T_CLASS):
            kind = "union" if die.tag == T_UNION else ("class" if die.tag == T_CLASS else "struct")
            rec: Dict[str, Any] = _drop_none(
                {
                    "kind": kind,
                    "name": name or f"@anon_{die.offset:x}",
                    "size": _int_or_none(die.attr(A_BYTE_SIZE), 0),
                    "file": file_ref,
                    "members": [],
                }
            )
            members: List[Dict[str, Any]] = rec["members"]
            for child_index in child_indices(dies, index, off_to_index):
                child = dies[child_index]
                if child.tag != T_MEMBER:
                    continue
                child_name = _str_or_none(child.attr(A_NAME)) or f"field_{child.offset:x}"
                loc = decode_location(child.attr(A_LOCATION), elf.endian, elf.address_size)
                member = _drop_none(
                    {
                        "name": child_name,
                        "off": member_offset(child.attrs, elf.endian),
                        "ref": type_ref(child.attrs, elf.endian),
                        "bit_size": _int_or_none(child.attr(A_BIT_SIZE)),
                        "bit_offset": _int_or_none(child.attr(A_BIT_OFFSET)),
                        "loc": loc,
                    }
                )
                members.append(member)
            types[str(die.offset)] = rec

        elif die.tag == T_ENUM:
            size = _int_or_none(die.attr(A_BYTE_SIZE), 4)
            types[str(die.offset)] = _drop_none(
                {
                    "kind": "enum",
                    "name": name or f"@anon_{die.offset:x}",
                    "size": size,
                    "file": file_ref,
                    "consts": _decode_enum_consts(die.attr(A_ELEMENT_LIST), size, elf.endian),
                }
            )

        elif die.tag == T_ARRAY:
            elem, count, counts, warnings = decode_array_subscript(attrs, elf.endian, elf.address_size)
            array_warnings.extend(f"DIE 0x{die.offset:x}: {w}" for w in warnings)
            types[str(die.offset)] = _drop_none(
                {
                    "kind": "array",
                    "ref": elem,
                    "count": count,
                    "counts": counts,
                    "size": _int_or_none(die.attr(A_BYTE_SIZE)),
                    "file": file_ref,
                }
            )

        elif die.tag == T_SUBROUTINE_TYPE:
            params = []
            for child_index in child_indices(dies, index, off_to_index):
                child = dies[child_index]
                if child.tag == T_FORMAL_PARAM:
                    params.append(type_ref(child.attrs, elf.endian))
            types[str(die.offset)] = {
                "kind": "func",
                "ret": _die_return_type(die, elf.endian),
                "params": params,
                "file": file_ref,
            }

        elif die.tag in (T_POINTER, T_REFERENCE):
            inner = type_ref(attrs, elf.endian)
            types[str(die.offset)] = {
                "kind": "ptr" if die.tag == T_POINTER else "ref",
                "ref": inner,
                "size": elf.address_size,
                "file": file_ref,
            }

        elif die.tag == T_TYPEDEF and name:
            types[str(die.offset)] = _drop_none(
                {
                    "kind": "typedef",
                    "name": name,
                    "ref": type_ref(attrs, elf.endian),
                    "file": file_ref,
                }
            )

        elif die.tag in (T_GLOBAL_SUBROUTINE, T_SUBROUTINE) and name and die.attr(A_LOW_PC) is not None:
            params = []
            locals_ = []
            for child_index in child_indices(dies, index, off_to_index):
                child = dies[child_index]
                child_name = _str_or_none(child.attr(A_NAME))
                if child.tag == T_FORMAL_PARAM and child_name:
                    params.append(
                        _drop_none(
                            {
                                "name": child_name,
                                "ref": type_ref(child.attrs, elf.endian),
                                "loc": _location_raw(child),
                            }
                        )
                    )
                elif child.tag == T_LOCAL_VARIABLE and child_name:
                    locals_.append(
                        _drop_none(
                            {
                                "name": child_name,
                                "ref": type_ref(child.attrs, elf.endian),
                                "loc": _location_raw(child),
                            }
                        )
                    )
            funcs.append(
                _drop_none(
                    {
                        "name": name,
                        "die": die.offset,
                        "low": _int_or_none(die.attr(A_LOW_PC)),
                        "high": _int_or_none(die.attr(A_HIGH_PC)),
                        "ret": _die_return_type(die, elf.endian),
                        "params": params,
                        "locals": locals_,
                        "file": file_ref,
                    }
                )
            )

        elif die.tag == T_GLOBAL_VARIABLE and name:
            loc = decode_location(die.attr(A_LOCATION), elf.endian, elf.address_size)
            addr = global_address(attrs, elf.endian, elf.address_size)
            if addr is not None:
                globals_.append(
                    _drop_none(
                        {
                            "name": name,
                            "die": die.offset,
                            "addr": addr,
                            "ref": type_ref(attrs, elf.endian),
                            "loc": loc,
                            "file": file_ref,
                        }
                    )
                )

    lines: List[List[Optional[int]]] = []
    line_warnings: List[str] = []
    line_sec = elf.section(line_section)
    if include_lines and line_sec:
        line_programs, line_warnings = parse_line_section(elf.section_data(line_sec), elf.endian)
        sorted_stmt_offsets = sorted(stmt_to_file)

        def owner(offset: int) -> Optional[int]:
            if offset in stmt_to_file:
                return stmt_to_file[offset]
            previous = [x for x in sorted_stmt_offsets if x <= offset]
            return stmt_to_file[previous[-1]] if previous else None

        for program in line_programs:
            fid = owner(program["offset"])
            for entry in program["entries"]:
                lines.append([entry["pc"], fid, entry["line"]])
        lines.sort(key=lambda x: (x[0] if x[0] is not None else -1, x[2] if x[2] else -1))
    elif include_lines and not line_sec:
        line_warnings.append(f"missing optional {line_section!r} section")

    tag_hist = collections.Counter(TAG.get(die.tag, f"0x{die.tag:04x}") for die in dies)
    attr_hist = collections.Counter(
        AT.get(code, f"0x{code:04x}") for die in dies for code in die.attr_order
    )
    producers = sorted(
        {
            cu.get("producer")
            for cu in compile_units
            if isinstance(cu.get("producer"), str) and cu.get("producer")
        }
    )
    comments = elf.comment_strings()
    base = image_base if image_base is not None else elf.image_base()

    model = {
        "meta": _drop_none(
            {
                "model_version": 2,
                "tool": "ps2_dwarf1",
                "source_elf": str(Path(elf_path)),
                "elf_machine": elf.machine_name(),
                "elf_machine_id": elf.e_machine,
                "endian": elf.endian_name,
                "pointer_size": elf.address_size,
                "image_base": base,
                "entry": elf.e_entry,
                "debug_section": debug_section,
                "line_section": line_section if line_sec else None,
                "debug_size": debug.size,
                "line_size": line_sec.size if line_sec else 0,
                "dwarf_version": 1,
                "comments": comments,
                "producers": producers,
                "dies": len(dies),
                "types": len(types),
                "funcs": len(funcs),
                "globals": len(globals_),
                "files": len(files),
                "compile_units": len(compile_units),
                "lines": len(lines),
                "tag_hist": dict(tag_hist.most_common()),
                "attr_hist": dict(attr_hist.most_common()),
                "warnings": parsed.warnings + array_warnings + line_warnings,
            }
        ),
        "compile_units": compile_units,
        "types": types,
        "funcs": funcs,
        "globals": globals_,
        "files": files,
        "lines": lines,
        "fundamental_types": {str(k): v for k, v in FT.items()},
    }
    return model


def make_summary(model: Dict[str, Any]) -> Dict[str, Any]:
    files = model.get("files", [])
    funcs = model.get("funcs", [])
    globals_ = model.get("globals", [])
    types = model.get("types", {})
    funcs_by_file: Dict[str, int] = collections.Counter()
    globals_by_file: Dict[str, int] = collections.Counter()
    type_kinds: Dict[str, int] = collections.Counter()
    for func in funcs:
        path = _file_name(files, func.get("file"))
        if path:
            funcs_by_file[path] += 1
    for glob in globals_:
        path = _file_name(files, glob.get("file"))
        if path:
            globals_by_file[path] += 1
    for rec in types.values():
        type_kinds[rec.get("kind", "?")] += 1

    return {
        "meta": model.get("meta", {}),
        "type_kinds": dict(type_kinds.most_common()),
        "top_files_by_functions": dict(funcs_by_file.most_common(50)),
        "top_files_by_globals": dict(globals_by_file.most_common(50)),
        "source_files": sorted(files),
    }


def source_tree(model: Dict[str, Any]) -> Dict[str, Any]:
    files = model.get("files", [])
    funcs = model.get("funcs", [])
    counts: Dict[str, int] = collections.Counter()
    for func in funcs:
        path = _file_name(files, func.get("file"))
        if path:
            counts[_norm(path)] += 1
    roots: Dict[str, int] = collections.Counter()
    for path, count in counts.items():
        parts = path.split("/")
        root = parts[0] if len(parts) < 3 else "/".join(parts[:3])
        roots[root] += count
    return {
        "files": dict(sorted(counts.items())),
        "roots": dict(roots.most_common()),
        "top_files": dict(counts.most_common(100)),
    }


def _decode_enum_consts(raw: Any, byte_size: Optional[int], endian: str) -> List[List[Any]]:
    if not isinstance(raw, (bytes, bytearray)):
        return []
    widths = []
    if byte_size in (1, 2, 4, 8):
        widths.append(byte_size)
    for width in (4, 2, 1, 8):
        if width not in widths:
            widths.append(width)
    for width in widths:
        values = _parse_enum_consts(raw, int(width), endian)
        if values:
            return values
    return []


def _parse_enum_consts(raw: bytes, width: int, endian: str) -> List[List[Any]]:
    out: List[List[Any]] = []
    p = 0
    byte_order = "little" if endian == "<" else "big"
    while p + width < len(raw):
        value = int.from_bytes(raw[p : p + width], byte_order, signed=True)
        p += width
        end = raw.find(b"\0", p)
        if end < 0:
            return []
        name = raw[p:end].decode("latin1", "replace")
        if not name:
            return []
        out.append([name, value])
        p = end + 1
    return out


def _die_return_type(die: Die, endian: str) -> Dict[str, Any]:
    if any(code in die.attrs for code in (0x0050, 0x0060, 0x0070, 0x0080)):
        return type_ref(die.attrs, endian)
    return {"k": "f", "t": 0x14}


def _location_raw(die: Die) -> Optional[str]:
    raw = die.attr(A_LOCATION)
    return raw.hex() if isinstance(raw, (bytes, bytearray)) else None


def _int_or_none(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    return default


def _str_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _drop_none(record: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in record.items() if v is not None}


def _file_name(files: List[str], file_id: Any) -> Optional[str]:
    if isinstance(file_id, int) and 0 <= file_id < len(files):
        return files[file_id]
    return None


def _norm(path: str) -> str:
    return path.replace("\\", "/")
