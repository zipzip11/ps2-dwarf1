from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


FORM_ADDR = 0x1
FORM_REF = 0x2
FORM_BLOCK2 = 0x3
FORM_BLOCK4 = 0x4
FORM_DATA2 = 0x5
FORM_DATA4 = 0x6
FORM_DATA8 = 0x7
FORM_STRING = 0x8

TAG = {
    0x0001: "array_type",
    0x0002: "class_type",
    0x0003: "entry_point",
    0x0004: "enumeration_type",
    0x0005: "formal_parameter",
    0x0006: "global_subroutine",
    0x0007: "global_variable",
    0x0008: "imported_declaration",
    0x000A: "label",
    0x000B: "lexical_block",
    0x000C: "local_variable",
    0x000D: "member",
    0x000F: "pointer_type",
    0x0010: "reference_type",
    0x0011: "compile_unit",
    0x0012: "string_type",
    0x0013: "structure_type",
    0x0014: "subroutine",
    0x0015: "subroutine_type",
    0x0016: "typedef",
    0x0017: "union_type",
    0x0018: "unspecified_parameters",
    0x0019: "variant",
    0x001A: "common_block",
    0x001B: "common_inclusion",
    0x001C: "inheritance",
    0x001D: "inlined_subroutine",
    0x001E: "module",
    0x001F: "ptr_to_member_type",
    0x0020: "set_type",
    0x0021: "subrange_type",
    0x0022: "with_stmt",
}

AT = {
    0x0010: "sibling",
    0x0020: "location",
    0x0030: "name",
    0x0050: "fund_type",
    0x0060: "mod_fund_type",
    0x0070: "user_def_type",
    0x0080: "mod_u_d_type",
    0x0090: "ordering",
    0x00A0: "subscr_data",
    0x00B0: "byte_size",
    0x00C0: "bit_offset",
    0x00D0: "bit_size",
    0x00F0: "element_list",
    0x0100: "stmt_list",
    0x0110: "low_pc",
    0x0120: "high_pc",
    0x0130: "language",
    0x0140: "member",
    0x0150: "discr",
    0x0160: "discr_value",
    0x0170: "visibility",
    0x0180: "import",
    0x0190: "string_length",
    0x01A0: "common_reference",
    0x01B0: "comp_dir",
    0x01C0: "const_value",
    0x01D0: "containing_type",
    0x01E0: "default_value",
    0x0200: "friends",
    0x0210: "inline",
    0x0220: "is_optimized",
    0x0230: "abstract_origin",
    0x0240: "extension",
    0x0250: "prototyped",
    0x0260: "specification",
    0x0270: "lower_bound",
    0x0290: "producer",
    0x02A0: "return_addr",
    0x02E0: "upper_bound",
}

FT = {
    0x0001: "char",
    0x0002: "signed char",
    0x0003: "unsigned char",
    0x0004: "short",
    0x0005: "signed short",
    0x0006: "unsigned short",
    0x0007: "int",
    0x0008: "signed int",
    0x0009: "unsigned int",
    0x000A: "long",
    0x000B: "signed long",
    0x000C: "unsigned long",
    0x000D: "pointer",
    0x000E: "float",
    0x000F: "double",
    0x0010: "long double",
    0x0011: "complex",
    0x0012: "double complex",
    0x0013: "long long",
    0x0014: "void",
    0x0015: "bool",
    0x8008: "long long",
    0x8108: "unsigned long long",
    0x8208: "signed long long",
}

A_SIBLING = 0x0010
A_LOCATION = 0x0020
A_NAME = 0x0030
A_FUND_TYPE = 0x0050
A_MOD_FUND_TYPE = 0x0060
A_USER_DEF_TYPE = 0x0070
A_MOD_USER_DEF_TYPE = 0x0080
A_SUBSCR_DATA = 0x00A0
A_BYTE_SIZE = 0x00B0
A_BIT_OFFSET = 0x00C0
A_BIT_SIZE = 0x00D0
A_ELEMENT_LIST = 0x00F0
A_STMT_LIST = 0x0100
A_LOW_PC = 0x0110
A_HIGH_PC = 0x0120
A_LANGUAGE = 0x0130
A_COMP_DIR = 0x01B0
A_PRODUCER = 0x0290

T_ARRAY = 0x0001
T_CLASS = 0x0002
T_ENUM = 0x0004
T_FORMAL_PARAM = 0x0005
T_GLOBAL_SUBROUTINE = 0x0006
T_GLOBAL_VARIABLE = 0x0007
T_LOCAL_VARIABLE = 0x000C
T_MEMBER = 0x000D
T_POINTER = 0x000F
T_REFERENCE = 0x0010
T_COMPILE_UNIT = 0x0011
T_STRUCT = 0x0013
T_SUBROUTINE = 0x0014
T_SUBROUTINE_TYPE = 0x0015
T_TYPEDEF = 0x0016
T_UNION = 0x0017


class Dwarf1Error(RuntimeError):
    pass


@dataclass
class Attribute:
    name: int
    form: int
    value: Any
    offset: int


@dataclass
class Die:
    offset: int
    tag: int
    length: int
    attrs: Dict[int, Attribute]
    attr_order: List[int]

    def attr(self, code: int, default: Any = None) -> Any:
        attr = self.attrs.get(code)
        return attr.value if attr else default


@dataclass
class ParseResult:
    dies: List[Die]
    warnings: List[str]


def parse_debug_section(
    blob: bytes,
    endian: str = "<",
    address_size: int = 4,
    strict: bool = False,
) -> ParseResult:
    dies: List[Die] = []
    warnings: List[str] = []
    p = 0
    size = len(blob)
    while p + 4 <= size:
        die_off = p
        length = _u32(blob, p, endian)
        if length == 0:
            p += 4
            continue
        if length < 6:
            warnings.append(f"short/null DIE at 0x{die_off:x}: length={length}")
            if length < 4:
                break
            p += length
            continue
        if p + length > size:
            msg = f"DIE at 0x{die_off:x} extends beyond .debug: length=0x{length:x}"
            if strict:
                raise Dwarf1Error(msg)
            warnings.append(msg)
            break
        tag = _u16(blob, p + 4, endian)
        ap = p + 6
        end = p + length
        attrs: Dict[int, Attribute] = {}
        order: List[int] = []
        try:
            while ap < end:
                attr, ap = read_attribute(blob, ap, endian, address_size)
                attrs[attr.name] = attr
                order.append(attr.name)
                if ap > end:
                    raise Dwarf1Error(
                        f"attribute 0x{attr.name:x} at DIE 0x{die_off:x} overran DIE"
                    )
        except Exception as exc:
            if strict:
                raise
            warnings.append(f"DIE 0x{die_off:x}: stopped attribute decode: {exc}")
        dies.append(Die(die_off, tag, length, attrs, order))
        p += length
    return ParseResult(dies, warnings)


def read_attribute(blob: bytes, offset: int, endian: str, address_size: int = 4) -> Tuple[Attribute, int]:
    start = offset
    if offset + 2 > len(blob):
        raise Dwarf1Error(f"truncated attribute header at 0x{offset:x}")
    encoded = _u16(blob, offset, endian)
    offset += 2
    form = encoded & 0xF
    name = encoded & 0xFFF0
    if form == FORM_ADDR:
        value = _uint(blob, offset, address_size, endian)
        offset += address_size
    elif form == FORM_REF:
        value = _u32(blob, offset, endian)
        offset += 4
    elif form == FORM_BLOCK2:
        n = _u16(blob, offset, endian)
        offset += 2
        value = blob[offset : offset + n]
        offset += n
    elif form == FORM_BLOCK4:
        n = _u32(blob, offset, endian)
        offset += 4
        value = blob[offset : offset + n]
        offset += n
    elif form == FORM_DATA2:
        value = _u16(blob, offset, endian)
        offset += 2
    elif form == FORM_DATA4:
        value = _u32(blob, offset, endian)
        offset += 4
    elif form == FORM_DATA8:
        value = _u64(blob, offset, endian)
        offset += 8
    elif form == FORM_STRING:
        end = blob.find(b"\0", offset)
        if end < 0:
            end = len(blob)
        value = blob[offset:end].decode("latin1", "replace")
        offset = end + 1 if end < len(blob) else end
    else:
        raise Dwarf1Error(f"unknown FORM 0x{form:x} at 0x{start:x}")
    if offset > len(blob):
        raise Dwarf1Error(f"attribute at 0x{start:x} extends beyond buffer")
    return Attribute(name, form, value, start), offset


def child_indices(
    dies: List[Die],
    index: int,
    off_to_index: Optional[Dict[int, int]] = None,
) -> List[int]:
    """Return direct child DIE indices using DWARF1 AT_sibling spans."""

    sibling = dies[index].attr(A_SIBLING)
    if sibling is None or sibling <= dies[index].offset:
        return []
    if off_to_index is None:
        off_to_index = {die.offset: i for i, die in enumerate(dies)}
    out: List[int] = []
    j = index + 1
    while j < len(dies):
        child = dies[j]
        if child.offset >= sibling:
            break
        out.append(j)
        child_sibling = child.attr(A_SIBLING)
        if child_sibling is not None and child_sibling > child.offset:
            next_index = off_to_index.get(child_sibling)
            if next_index is not None and next_index > j:
                j = next_index
                continue
        j += 1
    return out


def attr_value(attrs: Dict[int, Attribute], code: int, default: Any = None) -> Any:
    attr = attrs.get(code)
    return attr.value if attr else default


def type_ref(attrs: Dict[int, Attribute], endian: str = "<") -> Dict[str, Any]:
    if A_FUND_TYPE in attrs:
        return {"k": "f", "t": attrs[A_FUND_TYPE].value}
    if A_USER_DEF_TYPE in attrs:
        return {"k": "u", "o": attrs[A_USER_DEF_TYPE].value}
    if A_MOD_FUND_TYPE in attrs:
        raw = attrs[A_MOD_FUND_TYPE].value
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 2:
            return {"k": "f", "t": 0x14}
        base = {"k": "f", "t": _u16(raw, len(raw) - 2, endian)}
        return wrap_modifiers(raw[:-2], base)
    if A_MOD_USER_DEF_TYPE in attrs:
        raw = attrs[A_MOD_USER_DEF_TYPE].value
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 4:
            return {"k": "f", "t": 0x14}
        base = {"k": "u", "o": _u32(raw, len(raw) - 4, endian)}
        return wrap_modifiers(raw[:-4], base)
    return {"k": "f", "t": 0x14}


def wrap_modifiers(modifiers: Iterable[int], inner: Dict[str, Any]) -> Dict[str, Any]:
    out = inner
    for mod in modifiers:
        if mod == 0x01:
            out = {"k": "ptr", "e": out}
        elif mod == 0x02:
            out = {"k": "ref", "e": out}
        elif mod == 0x03:
            out = {"k": "const", "e": out}
        elif mod == 0x04:
            out = {"k": "vol", "e": out}
        else:
            out = {"k": "mod", "m": mod, "e": out}
    return out


def decode_array_subscript(
    attrs: Dict[int, Attribute],
    endian: str = "<",
    address_size: int = 4,
) -> Tuple[Dict[str, Any], Optional[int], List[Optional[int]], List[str]]:
    raw = attr_value(attrs, A_SUBSCR_DATA)
    if not isinstance(raw, (bytes, bytearray)):
        return {"k": "f", "t": 0x14}, None, [], []

    warnings: List[str] = []
    q = 0
    counts: List[Optional[int]] = []
    element: Optional[Dict[str, Any]] = None
    try:
        while q < len(raw):
            fmt = raw[q]
            q += 1
            if fmt == 0x08:
                attr, q = read_attribute(raw, q, endian, address_size)
                element = _type_ref_from_encoded_attr(attr, endian)
                break
            if 0x00 <= fmt <= 0x07:
                is_user_type = fmt >= 0x04
                bound_fmt = fmt - 0x04 if is_user_type else fmt
                q += 4 if is_user_type else 2
                low, q = _read_array_bound(raw, q, endian, bound_fmt in (0x00, 0x01))
                high, q = _read_array_bound(raw, q, endian, bound_fmt in (0x00, 0x02))
                if low is not None and high is not None:
                    counts.append(high - low + 1)
                else:
                    counts.append(None)
                continue
            warnings.append(f"unknown array subscript format 0x{fmt:x} at byte 0x{q - 1:x}")
            break
    except Exception as exc:
        warnings.append(f"array subscript decode failed: {exc}")

    count = None
    for item in reversed(counts):
        if item is not None:
            count = item
            break
    return element or {"k": "f", "t": 0x14}, count, counts, warnings


def decode_location(raw: Any, endian: str = "<", address_size: int = 4) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        return None
    op = raw[0]
    if op == 0x03 and len(raw) >= 1 + address_size:
        return {"kind": "addr", "value": _uint(raw, 1, address_size, endian), "raw": raw.hex()}
    if op == 0x04 and len(raw) >= 5:
        return {"kind": "const", "value": _u32(raw, 1, endian), "raw": raw.hex()}
    return {"kind": "raw", "raw": raw.hex()}


def member_offset(attrs: Dict[int, Attribute], endian: str = "<") -> Optional[int]:
    loc = decode_location(attr_value(attrs, A_LOCATION), endian, 4)
    if loc and loc.get("kind") == "const":
        return int(loc["value"])
    return None


def global_address(attrs: Dict[int, Attribute], endian: str = "<", address_size: int = 4) -> Optional[int]:
    loc = decode_location(attr_value(attrs, A_LOCATION), endian, address_size)
    if loc and loc.get("kind") == "addr":
        return int(loc["value"])
    return None


def parse_line_section(blob: bytes, endian: str = "<") -> Tuple[List[Dict[str, Any]], List[str]]:
    programs: List[Dict[str, Any]] = []
    warnings: List[str] = []
    p = 0
    while p + 8 <= len(blob):
        start = p
        length = _u32(blob, p, endian)
        if length == 0:
            p += 4
            continue
        if length < 8 or p + length > len(blob):
            warnings.append(f"bad .line program at 0x{start:x}: length=0x{length:x}")
            break
        base = _u32(blob, p + 4, endian)
        entries = []
        q = p + 8
        end = p + length
        while q + 10 <= end:
            line = _u32(blob, q, endian)
            column = _u16(blob, q + 4, endian)
            pc_offset = _u32(blob, q + 6, endian)
            entries.append({"line": line, "column": column, "pc": base + pc_offset})
            q += 10
        if q != end:
            warnings.append(f".line program 0x{start:x} has {end - q} trailing bytes")
        programs.append({"offset": start, "length": length, "base": base, "entries": entries})
        p += length
    return programs, warnings


def _type_ref_from_encoded_attr(attr: Attribute, endian: str) -> Dict[str, Any]:
    if attr.name == A_FUND_TYPE and attr.form == FORM_DATA2:
        return {"k": "f", "t": attr.value}
    if attr.name == A_USER_DEF_TYPE and attr.form == FORM_REF:
        return {"k": "u", "o": attr.value}
    if attr.name == A_MOD_FUND_TYPE and attr.form in (FORM_BLOCK2, FORM_BLOCK4):
        raw = attr.value
        if isinstance(raw, (bytes, bytearray)) and len(raw) >= 2:
            return wrap_modifiers(raw[:-2], {"k": "f", "t": _u16(raw, len(raw) - 2, endian)})
    if attr.name == A_MOD_USER_DEF_TYPE and attr.form in (FORM_BLOCK2, FORM_BLOCK4):
        raw = attr.value
        if isinstance(raw, (bytes, bytearray)) and len(raw) >= 4:
            return wrap_modifiers(raw[:-4], {"k": "u", "o": _u32(raw, len(raw) - 4, endian)})
    return {"k": "f", "t": 0x14}


def _read_array_bound(blob: bytes, offset: int, endian: str, is_const: bool) -> Tuple[Optional[int], int]:
    if is_const:
        return _i32(blob, offset, endian), offset + 4
    if offset + 2 > len(blob):
        return None, len(blob)
    n = _u16(blob, offset, endian)
    return None, offset + 2 + n


def _uint(blob: bytes, offset: int, size: int, endian: str) -> int:
    if size == 2:
        return _u16(blob, offset, endian)
    if size == 4:
        return _u32(blob, offset, endian)
    if size == 8:
        return _u64(blob, offset, endian)
    return int.from_bytes(blob[offset : offset + size], "little" if endian == "<" else "big")


def _u16(blob: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "H", blob, offset)[0]


def _u32(blob: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "I", blob, offset)[0]


def _i32(blob: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "i", blob, offset)[0]


def _u64(blob: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "Q", blob, offset)[0]
