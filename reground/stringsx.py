"""Multi-encoding string extractor over raw binary bytes, stdlib only.

Three passes: ASCII, UTF-16LE, UTF-16BE. Each yields (encoding, file offset,
virtual address, value). The caller supplies an optional offset -> vaddr
mapping so findings carry the address an agent would cite.

Known ambiguity: ASCII-range UTF-16 text decodes identically as UTF-16LE at
offset N and UTF-16BE at offset N-1, so both readings are reported. This is
inherent to byte-level string extraction, not a bug.
"""


class ExtractedString:
    __slots__ = ("encoding", "offset", "vaddr", "value")

    def __init__(self, encoding, offset, vaddr, value):
        self.encoding = encoding      # "ascii" | "utf16le" | "utf16be"
        self.offset = offset          # file offset of first byte
        self.vaddr = vaddr            # virtual address, or None if unmappable
        self.value = value            # decoded str

    def __repr__(self):
        return "ExtractedString(%r, %#x, %r)" % (self.encoding, self.offset,
                                                self.value[:32])


def _is_printable(byte):
    return 0x20 <= byte <= 0x7E


def _scan_ascii(data, min_length):
    """Yield (offset, value) for runs of printable ASCII."""
    n = len(data)
    i = 0
    while i < n:
        if _is_printable(data[i]):
            start = i
            while i < n and _is_printable(data[i]):
                i += 1
            if i - start >= min_length:
                yield start, data[start:i].decode("ascii")
        else:
            i += 1


def _scan_utf16(data, min_length, little_endian):
    """Yield (offset, value) for runs of ASCII-range UTF-16 code units."""
    n = len(data)
    i = 0
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if little_endian:
            text_byte, zero_byte = lo, hi
        else:
            text_byte, zero_byte = hi, lo
        if zero_byte == 0 and _is_printable(text_byte):
            start = i
            chars = []
            while i + 1 < n:
                lo, hi = data[i], data[i + 1]
                if little_endian:
                    text_byte, zero_byte = lo, hi
                else:
                    text_byte, zero_byte = hi, lo
                if not (zero_byte == 0 and _is_printable(text_byte)):
                    break
                chars.append(chr(text_byte))
                i += 2
            if len(chars) >= min_length:
                yield start, "".join(chars)
        else:
            i += 1


def extract_strings(data, min_length=4, vaddr_of=None):
    """Yield ExtractedString for ASCII, UTF-16LE and UTF-16BE passes.

    vaddr_of: optional callable(file_offset) -> vaddr or None.
    """
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    passes = (("ascii", lambda: _scan_ascii(data, min_length)),
              ("utf16le", lambda: _scan_utf16(data, min_length, True)),
              ("utf16be", lambda: _scan_utf16(data, min_length, False)))
    for encoding, scan in passes:
        for offset, value in scan():
            vaddr = vaddr_of(offset) if vaddr_of is not None else None
            yield ExtractedString(encoding, offset, vaddr, value)
