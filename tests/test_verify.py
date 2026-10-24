"""Tests for reground.verify -- verdicts on synthetic fixtures."""

import os
import tempfile
import unittest

from reground import claims
from reground.verify import (audit_binary, GROUNDED, MANGLED, UNGROUNDED,
                             UNSUPPORTED)
from tests.fixtures import (build_elf, build_pe32, build_packed_elf,
                            TEXT_VADDR, RODATA_VADDR)


def _claim(cid, ctype, value, note=""):
    return {"id": cid, "type": ctype, "value": value, "note": note}


class ELFAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bin = os.path.join(cls.tmp.name, "demo.elf")
        with open(cls.bin, "wb") as fh:
            fh.write(build_elf(bits=64))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _audit(self, claim_dicts):
        report = claims.validate_report({"binary": self.bin,
                                         "claims": claim_dicts})
        verdicts, summary = audit_binary(self.bin, report)
        return {v.claim_id: v for v in verdicts}, summary

    # -- GROUNDED ------------------------------------------------------
    def test_grounded_address(self):
        verdicts, _ = self._audit([_claim("a", "address", "0x401000")])
        self.assertEqual(verdicts["a"].verdict, GROUNDED)

    def test_grounded_address_inside_section(self):
        verdicts, _ = self._audit([_claim("a", "address", "0x401020")])
        self.assertEqual(verdicts["a"].verdict, GROUNDED)

    def test_grounded_address_decimal(self):
        verdicts, _ = self._audit(
            [_claim("a", "address", str(TEXT_VADDR))])
        self.assertEqual(verdicts["a"].verdict, GROUNDED)

    def test_grounded_string(self):
        verdicts, _ = self._audit(
            [_claim("s", "string", "http://c2.evil.example/beacon")])
        v = verdicts["s"]
        self.assertEqual(v.verdict, GROUNDED)
        self.assertIn("ascii", v.detail)

    def test_grounded_utf16le_string(self):
        verdicts, _ = self._audit([_claim("s", "string", "WIDE_CONFIG")])
        self.assertEqual(verdicts["s"].verdict, GROUNDED)

    def test_grounded_import(self):
        verdicts, _ = self._audit([_claim("i", "import", "puts")])
        self.assertEqual(verdicts["i"].verdict, GROUNDED)

    def test_grounded_needed_lib(self):
        verdicts, _ = self._audit([_claim("i", "import", "libc.so.6")])
        self.assertEqual(verdicts["i"].verdict, GROUNDED)

    def test_grounded_endpoint(self):
        verdicts, _ = self._audit(
            [_claim("e", "endpoint", "http://c2.evil.example/beacon")])
        self.assertEqual(v.verdict, GROUNDED)

    def test_grounded_section(self):
        verdicts, _ = self._audit([_claim("t", "section", ".text")])
        self.assertEqual(verdicts["t"].verdict, GROUNDED)

    # -- MANGLED -------------------------------------------------------
    def test_mangled_address_past_section_end(self):
        # .text is 64 bytes: 0x401000-0x401040; claim 12 bytes past the end
        verdicts, _ = self._audit([_claim("a", "address", "0x40104C")])
        v = verdicts["a"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn("past end", v.detail)
        self.assertIn(".text", v.detail)

    def test_mangled_address_before_symbol(self):
        # 4 bytes before main() @ 0x401000
        verdicts, _ = self._audit([_claim("a", "address", "0x400FFC")])
        v = verdicts["a"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn("main", v.detail)

    def test_mangled_string_one_char(self):
        verdicts, _ = self._audit(
            [_claim("s", "string", "http://c2.evil.example/beackn")])
        v = verdicts["s"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn("http://c2.evil.example/beacon", v.evidence)

    def test_mangled_endpoint_extra_char(self):
        # the malware.news case: claimed C2 has one extra character
        verdicts, _ = self._audit(
            [_claim("e", "endpoint", "http://c2.evil.example/beaconx")])
        v = verdicts["e"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn("http://c2.evil.example/beacon", v.evidence)

    def test_mangled_import(self):
        verdicts, _ = self._audit([_claim("i", "import", "putz")])
        v = verdicts["i"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn("puts", v.evidence)

    def test_mangled_section(self):
        verdicts, _ = self._audit([_claim("t", "section", ".tex")])
        v = verdicts["t"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn(".text", v.evidence)

    # -- UNGROUNDED ----------------------------------------------------
    def test_ungrounded_address(self):
        verdicts, _ = self._audit([_claim("a", "address", "0x900000")])
        self.assertEqual(verdicts["a"].verdict, UNGROUNDED)

    def test_ungrounded_string(self):
        verdicts, _ = self._audit(
            [_claim("s", "string", "http://totally-fake.example/nope")])
        self.assertEqual(verdicts["s"].verdict, UNGROUNDED)

    def test_phantom_import(self):
        verdicts, _ = self._audit(
            [_claim("i", "import", "KERNEL32.dll!CreateFileW")])
        self.assertEqual(verdicts["i"].verdict, UNGROUNDED)

    def test_phantom_section(self):
        verdicts, _ = self._audit([_claim("t", "section", ".hidden")])
        self.assertEqual(verdicts["t"].verdict, UNGROUNDED)

    def test_ungrounded_endpoint(self):
        verdicts, _ = self._audit(
            [_claim("e", "endpoint", "http://192.0.2.1:4444/x")])
        self.assertEqual(verdicts["e"].verdict, UNGROUNDED)

    # -- summary -------------------------------------------------------
    def test_summary_counts(self):
        verdicts, summary = self._audit([
            _claim("g1", "address", "0x401000"),
            _claim("g2", "section", ".text"),
            _claim("m1", "string", "http://c2.evil.example/beackn"),
            _claim("u1", "address", "0x900000"),
        ])
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary[GROUNDED], 2)
        self.assertEqual(summary[MANGLED], 1)
        self.assertEqual(summary[UNGROUNDED], 1)
        self.assertEqual(summary[UNSUPPORTED], 0)


class PackedBinary(unittest.TestCase):
    def test_packed_is_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "packed.elf")
            with open(path, "wb") as fh:
                fh.write(build_packed_elf())
            report = claims.validate_report({
                "binary": path,
                "claims": [_claim("a", "address", "0x401000"),
                           _claim("t", "section", ".text")]})
            verdicts, _ = audit_binary(path, report)
            by_id = {v.claim_id: v for v in verdicts}
            self.assertEqual(by_id["a"].verdict, UNSUPPORTED)
            self.assertEqual(by_id["t"].verdict, UNSUPPORTED)

    def test_unknown_format_raises(self):
        from reground.verify import BinaryError
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "blob.bin")
            with open(path, "wb") as fh:
                fh.write(b"\x00" * 256)
            report = claims.validate_report(
                {"binary": path,
                 "claims": [_claim("a", "address", "0x10")]})
            with self.assertRaises(BinaryError):
                audit_binary(path, report)


class PEAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bin = os.path.join(cls.tmp.name, "demo.exe")
        with open(cls.bin, "wb") as fh:
            fh.write(build_pe32())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _audit(self, claim_dicts):
        report = claims.validate_report({"binary": self.bin,
                                         "claims": claim_dicts})
        verdicts, _ = audit_binary(self.bin, report)
        return {v.claim_id: v for v in verdicts}

    def test_pe_import_grounded(self):
        verdicts = self._audit(
            [_claim("i", "import", "KERNEL32.dll!CreateFileW")])
        self.assertEqual(verdicts["i"].verdict, GROUNDED)

    def test_pe_import_bare_name_grounded(self):
        verdicts = self._audit([_claim("i", "import", "CreateFileW")])
        self.assertEqual(verdicts["i"].verdict, GROUNDED)

    def test_pe_import_case_insensitive_dll(self):
        verdicts = self._audit(
            [_claim("i", "import", "kernel32.dll!CreateFileW")])
        self.assertEqual(verdicts["i"].verdict, GROUNDED)

    def test_pe_phantom_import(self):
        verdicts = self._audit(
            [_claim("i", "import", "ntdll.dll!ZwCreateFile")])
        self.assertEqual(verdicts["i"].verdict, UNGROUNDED)

    def test_pe_string_grounded(self):
        verdicts = self._audit(
            [_claim("s", "string", "http://c2.evil.example/pe-beacon")])
        self.assertEqual(verdicts["s"].verdict, GROUNDED)

    def test_pe_section_grounded(self):
        verdicts = self._audit([_claim("t", "section", ".rdata")])
        self.assertEqual(verdicts["t"].verdict, GROUNDED)

    def test_pe_address_grounded(self):
        verdicts = self._audit([_claim("a", "address", "0x1000")])
        self.assertEqual(verdicts["a"].verdict, GROUNDED)

    def test_pe_mangled_import(self):
        verdicts = self._audit(
            [_claim("i", "import", "KERNEL32.dll!CreateFileX")])
        v = verdicts["i"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn("CreateFileW", v.evidence)


if __name__ == "__main__":
    unittest.main()
