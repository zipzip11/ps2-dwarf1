import struct
import unittest

from ps2dwarf1.elf import ElfFile


def _section_header(
    name: int,
    section_type: int,
    flags: int,
    addr: int,
    offset: int,
    size: int,
    link: int = 0,
    info: int = 0,
    addralign: int = 1,
    entsize: int = 0,
) -> bytes:
    return struct.pack(
        "<IIIIIIIIII",
        name,
        section_type,
        flags,
        addr,
        offset,
        size,
        link,
        info,
        addralign,
        entsize,
    )


class ElfFileTests(unittest.TestCase):
    def test_reads_elf32_sections_and_named_section_data(self) -> None:
        names = b"\0.shstrtab\0.debug\0"
        name_debug = names.index(b".debug")
        data = bytearray(0x200)
        data[0x80 : 0x80 + len(names)] = names
        data[0xA0:0xA4] = b"DBG!"

        ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
        data[:52] = struct.pack(
            "<16sHHIIIIIHHHHHH",
            ident,
            2,
            8,
            1,
            0x1000,
            0,
            0x100,
            0,
            52,
            0,
            0,
            40,
            3,
            1,
        )
        data[0x100 : 0x100 + 40] = bytes(40)
        data[0x128 : 0x128 + 40] = _section_header(1, 3, 0, 0, 0x80, len(names))
        data[0x150 : 0x150 + 40] = _section_header(name_debug, 1, 0, 0, 0xA0, 4)

        elf = ElfFile(bytes(data))
        debug = elf.section(".debug")

        self.assertEqual(elf.machine_name(), "MIPS")
        self.assertIsNotNone(debug)
        self.assertEqual(elf.section_data(debug), b"DBG!")


if __name__ == "__main__":
    unittest.main()
