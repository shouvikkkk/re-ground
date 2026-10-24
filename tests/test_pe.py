"""Tests for reground.pe -- synthetic PE32 fixture parsed back."""

import unittest

from reground import pe
from tests.fixtures import build_pe32


class TestPE32(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = build_pe32()
        cls.pe = pe.parse_pe(cls.data)

    def test_detect(self):
        self.assertTrue(pe.detect(self.data))
        self.assertFalse(pe.detect(b"\x7fELF" + b"\x00" * 60))

    def test_header(self):
        self.assertEqual(self.pe.machine, 0x14C)
        self.assertFalse(self.pe.is_64)
        self.assertEqual(self.pe.image_base, 0x400000)
        self.assertEqual(len(self.pe.sections), 2)

    def test_section_names(self):
        self.assertEqual([s.name for s in self.pe.sections],
                         [".text", ".rdata"])

    def test_rva_to_offset(self):
        self.assertEqual(self.pe.rva_to_offset(0x1000), 0x200)
        self.assertEqual(self.pe.rva_to_offset(0x2000), 0x400)
        self.assertEqual(self.pe.rva_to_offset(0x2080), 0x480)
        self.assertIsNone(self.pe.rva_to_offset(0x9999))

    def test_imports(self):
        self.assertEqual(len(self.pe.imports), 1)
        imp = self.pe.imports[0]
        self.assertEqual(imp.dll, "KERNEL32.dll")
        names = [name for _hint, name in imp.functions]
        self.assertIn("CreateFileW", names)

    def test_exports(self):
        self.assertEqual(self.pe.exports, ["SampleExport"])
        self.assertEqual(self.pe.export_dll_name, "sample.dll")

    def test_entry(self):
        self.assertEqual(self.pe.entry_rva, 0x1000)
        self.assertEqual(self.pe.entry_vaddr, 0x401000)

    def test_rich_absent(self):
        self.assertFalse(self.pe.rich_present)

    def test_mapped_ranges(self):
        ranges = self.pe.mapped_ranges()
        self.assertIn((0x1000, 0x1200, ".text"), ranges)
        self.assertIn((0x2000, 0x2200, ".rdata"), ranges)

    def test_vaddr_of_offset(self):
        self.assertEqual(self.pe.vaddr_of_offset(0x200), 0x1000)
        self.assertEqual(self.pe.vaddr_of_offset(0x400), 0x2000)
        self.assertIsNone(self.pe.vaddr_of_offset(0x10))

    def test_bad_data(self):
        with self.assertRaises(pe.PEError):
            pe.parse_pe(b"MZ" + b"\x00" * 100)
        with self.assertRaises(pe.PEError):
            pe.parse_pe(b"not a pe file at all....................")


if __name__ == "__main__":
    unittest.main()
