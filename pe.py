"""Minimal PE32/PE32+ parser, stdlib only.

Extracts what an audit needs: the section table (names, RVAs, raw ranges),
the import directory (DLL names + Hint/Name entries + IAT), the export
directory (exported names), and a rich-header presence note. RVAs are
resolved to file offsets through the section table; no external tools.
"""

import struct


class PEError(Exception):
    """Raised when bytes are not a parseable PE file."""


IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

OPTIONAL_MAGIC_PE32 = 0x10B
OPTIONAL_MAGIC_PE32P = 0x20B

# Data directory indexes
DIR_EXPORT = 0
DIR_IMPORT = 1

_ORDINAL_FLAG_32 = 0x80000000
_ORDINAL_FLAG_64 = 0x8000000000000000


class PESection:
    """One COFF section header."""

    __slots__ = ("name", "virtual_size", "vaddr", "raw_size", "raw_offset",
                 "characteristics")

    def __init__(self, name, virtual_size, vaddr, raw_size, raw_offset,
                 characteristics):
        self.name = name
        self.virtual_size = virtual_size
        self.vaddr = vaddr
        self.raw_size = raw_size
        self.raw_offset = raw_offset
        self.characteristics = characteristics

    def contains_rva(self, rva):
        span = max(self.virtual_size, self.raw_size)
        return self.vaddr <= rva < self.vaddr + span

    def __repr__(self):
        return "PESection(%r, rva=%#x)" % (self.name, self.vaddr)


class PEImport:
    """One imported DLL with its imported functions."""

    __slots__ = ("dll", "functions")

    def __init__(self, dll, functions):
        self.dll = dll            # str
        self.functions = functions  # list of (hint:int, name:str) or ("ordinal", n)

    def __repr__(self):
        return "PEImport(%r, %d functions)" % (self.dll, len(self.functions))


class PEFile:
    """Parsed PE image with audit helpers."""

    def __init__(self):
        self.machine = 0
        self.is_64 = False
        self.image_base = 0
        self.entry_rva = 0
        self.size_of_headers = 0
        self.sections = []
        self.imports = []        # list[PEImport]
        self.exports = []       # list[str]
        self.export_dll_name = ""
        self.rich_present = False
        self._data_len = 0

    @property
    def entry_vaddr(self):
        return self.image_base + self.entry_rva

    def rva_to_offset(self, rva):
        """Resolve an RVA to a file offset, or None."""
        if rva < self.size_of_headers:
            return rva if rva < self._data_len else None
        for s in self.sections:
            if s.contains_rva(rva):
                off = s.raw_offset + (rva - s.vaddr)
                if s.raw_offset <= off < s.raw_offset + s.raw_size:
                    return off
                return None
        return None

    def mapped_ranges(self):
        return [(s.vaddr, s.vaddr + max(s.virtual_size, s.raw_size), s.name)
                for s in self.sections if max(s.virtual_size, s.raw_size)]

    def vaddr_of_offset(self, offset):
        """Map a file offset to a virtual address, or None."""
        for s in self.sections:
            if s.raw_offset <= offset < s.raw_offset + s.raw_size:
                return s.vaddr + (offset - s.raw_offset)
        return None


def detect(data):
    """True if data looks like a PE (MZ + PE signature)."""
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return False
    return (0 < e_lfanew < len(data) - 6 and
            data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00")


class _Reader:
    """Bounds-checked little-endian reader over bytes."""

    def __init__(self, data):
        self.data = data

    def u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off):
        return struct.unpack_from("<Q", self.data, off)[0]

    def cstring(self, off, limit=512):
        if off is None or off < 0 or off >= len(self.data):
            return ""
        end = self.data.find(b"\x00", off, off + limit)
        if end == -1:
            end = min(len(self.data), off + limit)
        try:
            return self.data[off:end].decode("ascii", errors="replace")
        except Exception:
            return ""


def _check_rich(data, e_lfanew):
    """Note rich-header presence between the DOS stub and the PE header."""
    start = 0x40
    if not (0 < e_lfanew <= len(data)) or start >= e_lfanew:
        return False
    return b"Rich" in data[start:e_lfanew]


def parse_pe(data):
    """Parse PE bytes into a PEFile. Raises PEError on bad input."""
    if len(data) < 64 or data[:2] != b"MZ":
        raise PEError("not a PE file (missing MZ)")
    r = _Reader(data)
    try:
        e_lfanew = r.u32(0x3C)
    except struct.error:
        raise PEError("truncated DOS header")
    if not (0 < e_lfanew < len(data) - 6):
        raise PEError("bad e_lfanew")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("missing PE signature")

    pe = PEFile()
    pe._data_len = len(data)
    pe.rich_present = _check_rich(data, e_lfanew)

    coff = e_lfanew + 4
    try:
        pe.machine = r.u16(coff)
        num_sections = r.u16(coff + 2)
        # timedatestamp = r.u32(coff + 4)
        # ptr_symtab = r.u32(coff + 8)
        # num_symbols = r.u32(coff + 12)
        size_opt = r.u16(coff + 16)
        # characteristics = r.u16(coff + 18)
    except struct.error:
        raise PEError("truncated COFF header")

    opt = coff + 20
    try:
        magic = r.u16(opt)
    except struct.error:
        raise PEError("truncated optional header")
    if magic == OPTIONAL_MAGIC_PE32:
        pe.is_64 = False
    elif magic == OPTIONAL_MAGIC_PE32P:
        pe.is_64 = True
    else:
        raise PEError("unknown optional header magic %#x" % magic)

    try:
        if pe.is_64:
            pe.entry_rva = r.u32(opt + 16)
            pe.image_base = r.u64(opt + 24)
            pe.size_of_headers = r.u32(opt + 60)
            num_rva_sizes = r.u32(opt + 108)
            dirs_off = opt + 112
        else:
            pe.entry_rva = r.u32(opt + 16)
            # base_of_code = r.u32(opt + 20); base_of_data = r.u32(opt + 24)
            pe.image_base = r.u32(opt + 28)
            pe.size_of_headers = r.u32(opt + 60)
            num_rva_sizes = r.u32(opt + 92)
            dirs_off = opt + 96
    except struct.error:
        raise PEError("truncated optional header fields")

    data_dirs = []
    for i in range(min(num_rva_sizes, 16)):
        try:
            data_dirs.append((r.u32(dirs_off + i * 8), r.u32(dirs_off + i * 8 + 4)))
        except struct.error:
            break
    while len(data_dirs) < 16:
        data_dirs.append((0, 0))

    # Section table
    sectab = opt + size_opt
    for i in range(num_sections):
        off = sectab + i * 40
        try:
            raw_name = data[off:off + 8]
            virtual_size, vaddr = r.u32(off + 8), r.u32(off + 12)
            raw_size, raw_offset = r.u32(off + 16), r.u32(off + 20)
            characteristics = r.u32(off + 36)
        except (struct.error, IndexError):
            raise PEError("truncated section table")
        name = raw_name.split(b"\x00")[0].decode("ascii", errors="replace")
        pe.sections.append(PESection(name, virtual_size, vaddr, raw_size,
                                     raw_offset, characteristics))

    def walk_int_array(rva, entry_size, limit=4096):
        """Yield successive integer entries of an RVA-addressed table."""
        off = pe.rva_to_offset(rva)
        if off is None:
            return
        fmt = "<Q" if entry_size == 8 else "<I"
        for _ in range(limit):
            if off + entry_size > len(data):
                return
            yield struct.unpack_from(fmt, data, off)[0]
            off += entry_size

    # Import directory
    import_rva, import_size = data_dirs[DIR_IMPORT]
    if import_rva and import_size:
        entry_size = 8 if pe.is_64 else 4
        ordinal_flag = _ORDINAL_FLAG_64 if pe.is_64 else _ORDINAL_FLAG_32
        desc_off = pe.rva_to_offset(import_rva)
        # 20-byte IMAGE_IMPORT_DESCRIPTORs, terminated by an all-zero entry
        while desc_off is not None and desc_off + 20 <= len(data):
            try:
                ilt_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from(
                    "<5I", data, desc_off)
            except struct.error:
                break
            if not any((ilt_rva, name_rva, iat_rva)):
                break
            dll = r.cstring(pe.rva_to_offset(name_rva))
            funcs = []
            lookup_rva = ilt_rva or iat_rva
            if lookup_rva:
                for entry in walk_int_array(lookup_rva, entry_size):
                    if entry == 0:
                        break
                    if entry & ordinal_flag:
                        funcs.append(("ordinal", entry & 0xFFFF))
                    else:
                        hn_off = pe.rva_to_offset(entry & 0x7FFFFFFF)
                        hint = r.u16(hn_off) if hn_off is not None else 0
                        name = r.cstring(hn_off + 2 if hn_off is not None else None)
                        if name:
                            funcs.append((hint, name))
            pe.imports.append(PEImport(dll, funcs))
            desc_off += 20

    # Export directory
    export_rva, export_size = data_dirs[DIR_EXPORT]
    if export_rva and export_size:
        exp_off = pe.rva_to_offset(export_rva)
        if exp_off is not None and exp_off + 40 <= len(data):
            # IMAGE_EXPORT_DIRECTORY: 2 DWORD, 2 WORD, 7 DWORD = 40 bytes
            try:
                (_chars, _ts, _maj, _mn, name_rva, _base, _num_funcs,
                 num_names, _addr_funcs, addr_names,
                 _addr_ordinals) = struct.unpack_from("<IIHHIIIIIII",
                                                     data, exp_off)
            except struct.error:
                num_names = 0
            else:
                pe.export_dll_name = r.cstring(pe.rva_to_offset(name_rva))
                for i in range(min(num_names, 4096)):
                    name_ptr_off = pe.rva_to_offset(addr_names)
                    if name_ptr_off is None:
                        break
                    try:
                        fn_rva = r.u32(name_ptr_off + i * 4)
                    except struct.error:
                        break
                    fname = r.cstring(pe.rva_to_offset(fn_rva))
                    if fname:
                        pe.exports.append(fname)

    return pe
