import struct
import unittest

from ps2dwarf1.dwarf1 import (
    A_NAME,
    A_SIBLING,
    FORM_REF,
    FORM_STRING,
    T_COMPILE_UNIT,
    T_MEMBER,
    child_indices,
    decode_location,
    parse_debug_section,
    parse_line_section,
    wrap_modifiers,
)


def _attribute(code: int, form: int, payload: bytes) -> bytes:
    return struct.pack("<H", code | form) + payload


def _die(tag: int, attrs: bytes) -> bytes:
    return struct.pack("<IH", 6 + len(attrs), tag) + attrs


class Dwarf1ParserTests(unittest.TestCase):
    def test_parse_debug_section_decodes_dies_and_children(self) -> None:
        child = _die(T_MEMBER, _attribute(A_NAME, FORM_STRING, b"field\0"))
        parent_len = 6 + 6 + len(_attribute(A_NAME, FORM_STRING, b"unit.c\0"))
        sibling_offset = parent_len + len(child)
        parent = _die(
            T_COMPILE_UNIT,
            _attribute(A_SIBLING, FORM_REF, struct.pack("<I", sibling_offset))
            + _attribute(A_NAME, FORM_STRING, b"unit.c\0"),
        )

        result = parse_debug_section(parent + child)

        self.assertEqual(result.warnings, [])
        self.assertEqual([die.tag for die in result.dies], [T_COMPILE_UNIT, T_MEMBER])
        self.assertEqual(result.dies[0].attr(A_NAME), "unit.c")
        self.assertEqual(result.dies[1].attr(A_NAME), "field")
        self.assertEqual(child_indices(result.dies, 0), [1])

    def test_decode_location_understands_address_and_constant_forms(self) -> None:
        self.assertEqual(
            decode_location(b"\x03\x34\x12\x00\x80"),
            {"kind": "addr", "value": 0x80001234, "raw": "0334120080"},
        )
        self.assertEqual(
            decode_location(b"\x04\x10\x00\x00\x00"),
            {"kind": "const", "value": 0x10, "raw": "0410000000"},
        )

    def test_wrap_modifiers_preserves_modifier_order(self) -> None:
        ref = wrap_modifiers([0x01, 0x03], {"k": "f", "t": 0x07})
        self.assertEqual(ref, {"k": "const", "e": {"k": "ptr", "e": {"k": "f", "t": 0x07}}})

    def test_parse_line_section_decodes_simple_program(self) -> None:
        blob = struct.pack("<II", 18, 0x1000) + struct.pack("<IHI", 42, 7, 4)
        programs, warnings = parse_line_section(blob)

        self.assertEqual(warnings, [])
        self.assertEqual(
            programs,
            [{"offset": 0, "length": 18, "base": 0x1000, "entries": [{"line": 42, "column": 7, "pc": 0x1004}]}],
        )


if __name__ == "__main__":
    unittest.main()
