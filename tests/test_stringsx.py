"""Tests for reground.stringsx."""

import unittest

from reground import stringsx


class TestStringsx(unittest.TestCase):
    def test_ascii_extraction(self):
        data = b"\x00\x01hello world\x00\x02\x03"
        found = [s.value for s in stringsx.extract_strings(data)]
        self.assertIn("hello world", found)

    def test_min_length(self):
        data = b"ab\x00abcdef\x00"
        found = [s.value for s in stringsx.extract_strings(data, min_length=4)]
        self.assertNotIn("ab", found)
        self.assertIn("abcdef", found)

    def test_utf16le(self):
        data = b"\x00W\x00I\x00D\x00E\x00_\x00C\x00\x00"
        found = [(s.encoding, s.value)
                 for s in stringsx.extract_strings(data)]
        self.assertIn(("utf16le", "WIDE_C"), found)

    def test_utf16be(self):
        data = b"\x00\x00W\x00I\x00D\x00E\x00"
        found = [(s.encoding, s.value)
                 for s in stringsx.extract_strings(data)]
        self.assertIn(("utf16be", "WIDE"), found)

    def test_offsets(self):
        data = b"\x00\x00TARGET_STRING\x00"
        found = [s for s in stringsx.extract_strings(data)
                 if s.value == "TARGET_STRING"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].offset, 2)
        self.assertEqual(found[0].encoding, "ascii")

    def test_vaddr_mapping(self):
        data = b"\x00MARKER_ONE\x00"
        vaddr_of = lambda off: 0x5000 + off  # noqa: E731
        found = [s for s in stringsx.extract_strings(data, vaddr_of=vaddr_of)
                 if s.value == "MARKER_ONE"]
        self.assertEqual(found[0].vaddr, 0x5001)

    def test_vaddr_none_by_default(self):
        data = b"\x00MARKER_TWO\x00"
        found = [s for s in stringsx.extract_strings(data)
                 if s.value == "MARKER_TWO"]
        self.assertIsNone(found[0].vaddr)

    def test_empty(self):
        self.assertEqual(list(stringsx.extract_strings(b"")), [])
        self.assertEqual(list(stringsx.extract_strings(b"\x00\x01\x02")), [])

    def test_bad_min_length(self):
        with self.assertRaises(ValueError):
            list(stringsx.extract_strings(b"abc", min_length=0))

    def test_fixture_roundtrip(self):
        from tests.fixtures import build_elf
        from reground import elf as elf_mod
        data = build_elf(bits=64)
        parsed = elf_mod.parse_elf(data)
        strings = list(stringsx.extract_strings(
            data, vaddr_of=parsed.vaddr_of_offset))
        by_value = {s.value: s for s in strings}
        self.assertIn("http://c2.evil.example/beacon", by_value)
        beacon = by_value["http://c2.evil.example/beacon"]
        self.assertEqual(beacon.vaddr, 0x402000)
        # ASCII-range UTF-16 is inherently ambiguous: the LE reading at N and
        # the BE reading at N-1 decode to the same text, so both are reported.
        # The true LE decoding must be among the findings.
        wide = [s for s in strings if s.value == "WIDE_CONFIG"]
        self.assertTrue(any(s.encoding == "utf16le" for s in wide))
        le = next(s for s in wide if s.encoding == "utf16le")
        self.assertEqual(le.vaddr, 0x402000 + 46)


if __name__ == "__main__":
    unittest.main()
