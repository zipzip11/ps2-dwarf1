from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


class ElfError(RuntimeError):
    pass


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int

    def contains_file_range(self, off: int, size: int = 1) -> bool:
        return self.offset <= off and off + size <= self.offset + self.size


@dataclass(frozen=True)
class ProgramHeader:
    p_type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int


class ElfFile:
    """Small ELF reader intentionally limited to the 32-bit PS2/MIPS use case."""

    def __init__(self, data: bytes, path: Optional[Path] = None) -> None:
        if len(data) < 52:
            raise ElfError("file is too small to be a 32-bit ELF")
        if data[:4] != b"\x7fELF":
            raise ElfError("file does not start with the ELF magic")
        if data[4] != 1:
            raise ElfError("only ELF32 is supported")
        if data[5] == 1:
            self.endian = "<"
            self.endian_name = "little"
        elif data[5] == 2:
            self.endian = ">"
            self.endian_name = "big"
        else:
            raise ElfError("ELF has an unsupported data encoding")

        self.path = path
        self.data = data
        hdr = struct.unpack_from(self.endian + "16sHHIIIIIHHHHHH", data, 0)
        (
            _ident,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = hdr
        self.address_size = 4
        self.sections = self._read_sections()
        self.sections_by_name: Dict[str, Section] = {}
        for section in self.sections:
            self.sections_by_name.setdefault(section.name, section)
        self.program_headers = self._read_program_headers()

    @classmethod
    def from_path(cls, path: Path | str) -> "ElfFile":
        p = Path(path)
        return cls(p.read_bytes(), p)

    def _read_sections(self) -> List[Section]:
        if self.e_shoff == 0 or self.e_shnum == 0:
            return []
        if self.e_shentsize < 40:
            raise ElfError("ELF section header size is smaller than ELF32")
        if self.e_shoff + self.e_shentsize * self.e_shnum > len(self.data):
            raise ElfError("ELF section table extends beyond the file")

        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            raw.append(struct.unpack_from(self.endian + "IIIIIIIIII", self.data, off))

        if not (0 <= self.e_shstrndx < len(raw)):
            names = b""
        else:
            shstr = raw[self.e_shstrndx]
            names = self.data[shstr[4] : shstr[4] + shstr[5]]

        sections: List[Section] = []
        for i, sh in enumerate(raw):
            name_off, sh_type, flags, addr, offset, size, link, info, addralign, entsize = sh
            name = _cstring(names, name_off)
            sections.append(
                Section(i, name, sh_type, flags, addr, offset, size, link, info, addralign, entsize)
            )
        return sections

    def _read_program_headers(self) -> List[ProgramHeader]:
        if self.e_phoff == 0 or self.e_phnum == 0:
            return []
        if self.e_phentsize < 32:
            return []
        if self.e_phoff + self.e_phentsize * self.e_phnum > len(self.data):
            return []
        headers: List[ProgramHeader] = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            values = struct.unpack_from(self.endian + "IIIIIIII", self.data, off)
            headers.append(ProgramHeader(*values))
        return headers

    def section(self, name: str) -> Optional[Section]:
        return self.sections_by_name.get(name)

    def section_data(self, section: Section) -> bytes:
        end = section.offset + section.size
        if section.offset < 0 or end > len(self.data):
            raise ElfError(f"section {section.name!r} extends beyond the file")
        return self.data[section.offset:end]

    def comment_strings(self) -> List[str]:
        sec = self.section(".comment")
        if not sec:
            return []
        raw = self.section_data(sec)
        return [p.decode("latin1", "replace") for p in raw.split(b"\0") if p]

    def allocated_sections(self) -> Iterable[Section]:
        for section in self.sections:
            if section.flags & 0x2 and section.size:
                yield section

    def image_base(self) -> Optional[int]:
        load_vaddrs = [
            ph.vaddr
            for ph in self.program_headers
            if ph.p_type == 1 and ph.memsz > 0 and ph.vaddr != 0
        ]
        if load_vaddrs:
            return min(load_vaddrs)
        addrs = [section.addr for section in self.allocated_sections() if section.addr != 0]
        return min(addrs) if addrs else None

    def machine_name(self) -> str:
        if self.e_machine == 8:
            return "MIPS"
        return f"EM_{self.e_machine}"


def _cstring(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("latin1", "replace")
