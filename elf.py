"""Minimal ELF32/ELF64 parser (little- and big-endian), stdlib only.

Extracts what an audit needs: sections (names, vaddrs, file ranges),
program headers, symbol tables (.symtab / .dynsym) with their string tables,
and dynamic-section import names (DT_NEEDED + undefined symbols).

Stripped binaries (no .symtab) parse fine -- symbols just come back empty
while .dynsym imports still work. Binaries without section headers fall back
to PT_LOAD program headers for address mapping.
"""

import struct


class ELFError(Exception):
    """Raised when bytes are not a parseable ELF file."""


# e_ident indexes
EI_CLASS = 4
EI_DATA = 5
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

# Section types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

# Section flags
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Segment types
PT_LOAD = 1

# Dynamic tags
DT_NULL = 0
DT_NEEDED = 1

SHN_UNDEF = 0

# struct formats (after the 16-byte e_ident)
_EHDR_FMT = {32: "HHIIIIIHHHHHH", 64: "HHIQQQIHHHHHH"}
_SHDR_FMT = {32: "IIIIIIIIII", 64: "IIQQQQIIQQ"}
_PHDR_FMT = {32: "IIIIIIII", 64: "IIQQQQQQ"}
_SYM_FMT = {32: "IBBHII", 64: "IBBHQQ"}
_DYN_FMT = {32: "iI", 64: "qQ"}


class Section:
    """One ELF section header."""

    __slots__ = ("name", "type", "flags", "vaddr", "offset", "size",
                 "link", "info", "addralign", "entsize")

    def __init__(self, name, type_, flags, vaddr, offset, size,
                 link, info, addralign, entsize):
        self.name = name
        self.type = type_
        self.flags = flags
        self.vaddr = vaddr
        self.offset = offset
        self.size = size
        self.link = link
        self.info = info
        self.addralign = addralign
        self.entsize = entsize

    def contains_vaddr(self, vaddr):
        return self.vaddr <= vaddr < self.vaddr + self.size

    def contains_offset(self, offset):
        return self.offset <= offset < self.offset + self.size

    def __repr__(self):
        return "Section(%r, vaddr=%#x, size=%#x)" % (self.name, self.vaddr, self.size)


class ProgramHeader:
    """One ELF program header."""

    __slots__ = ("type", "offset", "vaddr", "paddr", "filesz",
                 "memsz", "flags", "align")

    def __init__(self, type_, offset, vaddr, paddr, filesz, memsz, flags, align):
        self.type = type_
        self.offset = offset
        self.vaddr = vaddr
        self.paddr = paddr
        self.filesz = filesz
        self.memsz = memsz
        self.flags = flags
        self.align = align


class Symbol:
    """One symbol table entry."""

    __slots__ = ("name", "value", "size", "bind", "type", "shndx")

    def __init__(self, name, value, size, bind, type_, shndx):
        self.name = name
        self.value = value
        self.size = size
        self.bind = bind
        self.type = type_
        self.shndx = shndx

    @property
    def is_undefined(self):
        return self.shndx == SHN_UNDEF

    def __repr__(self):
        return "Symbol(%r, value=%#x)" % (self.name, self.value)


def detect(data):
    """True if data starts with the ELF magic."""
    return len(data) >= 4 and data[:4] == b"\x7fELF"


class ELFFile:
    """Parsed ELF image with audit helpers."""

    def __init__(self):
        self.bits = 64
        self.little_endian = True
        self.entry = 0
        self.sections = []
        self.program_headers = []
        self.symbols = []       # from .symtab (may be empty if stripped)
        self.dyn_symbols = []   # from .dynsym
        self.imported_symbols = []  # undefined dynsym names
        self.needed_libs = []       # DT_NEEDED library names

    # -- address mapping -------------------------------------------------
    def mapped_ranges(self):
        """Yield (start, end, name) for every mappable region.

        Prefers allocated sections; falls back to PT_LOAD segments when the
        binary has no section headers (common in packed samples).
        """
        alloc = [s for s in self.sections
                 if s.type != SHT_NULL and (s.flags & SHF_ALLOC) and s.size]
        if alloc:
            return [(s.vaddr, s.vaddr + s.size, s.name or "section@%#x" % s.vaddr)
                    for s in alloc]
        return [(p.vaddr, p.vaddr + p.memsz, "LOAD@%#x" % p.vaddr)
                for p in self.program_headers if p.type == PT_LOAD and p.memsz]

    def section_at_vaddr(self, vaddr):
        for s in self.sections:
            if s.type != SHT_NULL and s.contains_vaddr(vaddr):
                return s
        return None

    def vaddr_of_offset(self, offset):
        """Map a file offset to a virtual address, or None."""
        for s in self.sections:
            if s.type != SHT_NULL and s.contains_offset(offset) and s.vaddr:
                return s.vaddr + (offset - s.offset)
        for p in self.program_headers:
            if p.type == PT_LOAD and p.offset <= offset < p.offset + p.filesz:
                return p.vaddr + (offset - p.offset)
        return None

    def symbol(self, name):
        for sym in self.symbols + self.dyn_symbols:
            if sym.name == name:
                return sym
        return None


def _read_cstring(data, offset):
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    try:
        return data[offset:end].decode("ascii", errors="replace")
    except Exception:
        return ""


def parse_elf(data):
    """Parse ELF bytes into an ELFFile. Raises ELFError on bad input."""
    if not detect(data):
        raise ELFError("not an ELF file (bad magic)")
    if len(data) < 52:
        raise ELFError("truncated ELF header")

    ei_class = data[EI_CLASS]
    ei_data = data[EI_DATA]
    if ei_class not in (ELFCLASS32, ELFCLASS64):
        raise ELFError("unsupported ELF class: %r" % ei_class)
    if ei_data not in (ELFDATA2LSB, ELFDATA2MSB):
        raise ELFError("unsupported ELF data encoding: %r" % ei_data)

    bits = 32 if ei_class == ELFCLASS32 else 64
    le = ei_data == ELFDATA2LSB
    endian = "<" if le else ">"

    ehdr_size = 16 + struct.calcsize(endian + _EHDR_FMT[bits])
    if len(data) < ehdr_size:
        raise ELFError("truncated ELF header")
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from(endian + _EHDR_FMT[bits], data, 16)

    elf = ELFFile()
    elf.bits = bits
    elf.little_endian = le
    elf.entry = e_entry

    # Program headers
    phdr_size = struct.calcsize(endian + _PHDR_FMT[bits])
    if e_phoff and e_phnum and e_phentsize >= phdr_size:
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + phdr_size > len(data):
                break
            vals = struct.unpack_from(endian + _PHDR_FMT[bits], data, off)
            elf.program_headers.append(ProgramHeader(*vals))

    # Section headers
    shdr_size = struct.calcsize(endian + _SHDR_FMT[bits])
    raw_sections = []
    if e_shoff and e_shnum and e_shentsize >= shdr_size:
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + shdr_size > len(data):
                break
            vals = struct.unpack_from(endian + _SHDR_FMT[bits], data, off)
            raw_sections.append(vals)

    # Section-name string table
    shstrtab = b""
    if raw_sections and 0 <= e_shstrndx < len(raw_sections):
        s = raw_sections[e_shstrndx]
        str_off, str_size = s[4], s[5]
        if 0 <= str_off and str_off + str_size <= len(data):
            shstrtab = data[str_off:str_off + str_size]

    def sh_name(idx):
        if not shstrtab or idx >= len(shstrtab):
            return ""
        return _read_cstring(shstrtab, idx)

    for vals in raw_sections:
        elf.sections.append(Section(
            sh_name(vals[0]), vals[1], vals[2], vals[3], vals[4], vals[5],
            vals[6], vals[7], vals[8], vals[9]))

    def section_bytes(sec):
        if sec.offset and sec.offset + sec.size <= len(data):
            return data[sec.offset:sec.offset + sec.size]
        return b""

    # Symbol tables
    sym_size = struct.calcsize(endian + _SYM_FMT[bits])
    for sec in elf.sections:
        if sec.type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if not (0 <= sec.link < len(elf.sections)):
            continue
        strtab = section_bytes(elf.sections[sec.link])
        blob = section_bytes(sec)
        entsize = sec.entsize or sym_size
        target = elf.symbols if sec.type == SHT_SYMTAB else elf.dyn_symbols
        for off in range(0, len(blob) - sym_size + 1, entsize):
            try:
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from(endian + _SYM_FMT[bits], blob, off)
            except struct.error:
                break
            name = _read_cstring(strtab, st_name) if st_name < len(strtab) else ""
            target.append(Symbol(name, st_value, st_size,
                                 st_info >> 4, st_info & 0xF, st_shndx))

    # Imports: undefined dynamic symbols + DT_NEEDED libraries
    elf.imported_symbols = [s.name for s in elf.dyn_symbols
                            if s.is_undefined and s.name]
    dyn_size = struct.calcsize(endian + _DYN_FMT[bits])
    for sec in elf.sections:
        if sec.type != SHT_DYNAMIC:
            continue
        if not (0 <= sec.link < len(elf.sections)):
            continue
        strtab = section_bytes(elf.sections[sec.link])
        blob = section_bytes(sec)
        entsize = sec.entsize or dyn_size
        for off in range(0, len(blob) - dyn_size + 1, entsize):
            try:
                d_tag, d_val = struct.unpack_from(endian + _DYN_FMT[bits], blob, off)
            except struct.error:
                break
            if d_tag == DT_NULL:
                break
            if d_tag == DT_NEEDED:
                name = _read_cstring(strtab, d_val) if d_val < len(strtab) else ""
                if name:
                    elf.needed_libs.append(name)

    return elf
