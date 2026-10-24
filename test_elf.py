"""Tests for reground.elf -- synthetic ELF64/ELF32 fixtures parsed back."""

import unittest

from reground import elf
from tests.fixtures import build_elf, TEXT_VADDR, RODATA_VADDR


class TestELF64(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = build_elf(bits=64)
        cls.elf = elf.parse_elf(cls.data)

    def test_detect(self):
        self.assertTrue(elf.detect(self.data))
        self.assertFalse(elf.detect(b"MZ" + b"\x00" * 62))

    def test_header(self):
        self.assertEqual(self.elf.bits, 64)
        self.assertTrue(self.elf.little_endian)
        self.assertEqual(self.elf.entry, TEXT_VADDR)

    def test_section_names(self):
        names = [s.name for s in self.elf.sections if s.name]
        self.assertEqual(names, [".text", ".rodata", ".symtab", ".strtab",
                                 ".dynsym", ".dynstr", ".dynamic",
                                 ".shstrtab"])

    def test_section_at_vaddr(self):
        self.assertEqual(self.elf.section_at_vaddr(TEXT_VADDR).name, ".text")
        self.assertEqual(self.elf.section_at_vaddr(TEXT_VADDR + 63).name,
                         ".text")
        self.assertEqual(self.elf.section_at_vaddr(RODATA_VADDR).name,
                         ".rodata")
        self.assertIsNone(self.elf.section_at_vaddr(0x900000))

    def test_symbol_lookup(self):
        main = self.elf.symbol("main")
        self.assertIsNotNone(main)
        self.assertEqual(main.value, TEXT_VADDR)
        helper = self.elf.symbol("helper")
        self.assertEqual(helper.value, TEXT_VADDR + 0x10)
        self.assertIsNone(self.elf.symbol("no_such_symbol"))

    def test_imports(self):
        self.assertIn("puts", self.elf.imported_symbols)
        self.assertIn("printf", self.elf.imported_symbols)
        self.assertEqual(self.elf.needed_libs, ["libc.so.6"])

    def test_mapped_ranges(self):
        ranges = self.elf.mapped_ranges()
        rodata = next(s for s in self.elf.sections if s.name == ".rodata")
        self.assertIn((TEXT_VADDR, TEXT_VADDR + 64, ".text"), ranges)
        self.assertIn((RODATA_VADDR, RODATA_VADDR + rodata.size, ".rodata"),
                      ranges)

    def test_vaddr_of_offset(self):
        text = next(s for s in self.elf.sections if s.name == ".text")
        self.assertEqual(self.elf.vaddr_of_offset(text.offset), TEXT_VADDR)
        self.assertEqual(self.elf.vaddr_of_offset(text.offset + 10),
                         TEXT_VADDR + 10)
        self.assertIsNone(self.elf.vaddr_of_offset(0))

    def test_truncated_raises(self):
        with self.assertRaises(elf.ELFError):
            elf.parse_elf(b"\x7fELF")
        with self.assertRaises(elf.ELFError):
            elf.parse_elf(b"definitely not an elf binary........")


class TestStrippedELF(unittest.TestCase):
    def test_stripped_parses(self):
        parsed = elf.parse_elf(build_elf(bits=64, strip=True))
        self.assertEqual(parsed.symbols, [])
        # dynamic symbols still work -- imports survive stripping
        self.assertIn("puts", parsed.imported_symbols)
        self.assertEqual(parsed.needed_libs, ["libc.so.6"])
        names = [s.name for s in parsed.sections]
        self.assertNotIn(".symtab", names)
        self.assertIn(".text", names)


class TestELF32(unittest.TestCase):
    def test_elf32_parses(self):
        parsed = elf.parse_elf(build_elf(bits=32))
        self.assertEqual(parsed.bits, 32)
        self.assertTrue(parsed.little_endian)
        self.assertEqual(parsed.entry, TEXT_VADDR)
        self.assertEqual(parsed.symbol("main").value, TEXT_VADDR)
        self.assertIn("puts", parsed.imported_symbols)
        self.assertEqual(parsed.needed_libs, ["libc.so.6"])
        self.assertEqual(parsed.section_at_vaddr(TEXT_VADDR).name, ".text")


if __name__ == "__main__":
    unittest.main()
