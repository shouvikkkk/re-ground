"""Tests for reground.cli -- end-to-end exit codes and output formats."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from reground.cli import main
from tests.fixtures import build_elf


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def _write_report(path, binary, claim_dicts):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"binary": binary, "claims": claim_dicts}, fh)


def _claim(cid, ctype, value):
    return {"id": cid, "type": ctype, "value": value}


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bin = os.path.join(cls.tmp.name, "demo.elf")
        _write(cls.bin, build_elf(bits=64))
        cls.good = os.path.join(cls.tmp.name, "good.json")
        _write_report(cls.good, cls.bin, [
            _claim("a", "address", "0x401000"),
            _claim("s", "string", "http://c2.evil.example/beacon"),
            _claim("i", "import", "puts"),
            _claim("t", "section", ".text"),
        ])
        cls.bad = os.path.join(cls.tmp.name, "bad.json")
        _write_report(cls.bad, cls.bin, [
            _claim("a", "address", "0x401000"),
            _claim("x", "string", "http://c2.evil.example/beackn"),
            _claim("y", "import", "KERNEL32.dll!CreateFileW"),
        ])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_audit_good_report_exit_0(self):
        code, out = self._run(["audit", "--binary", self.bin,
                               "--report", self.good])
        self.assertEqual(code, 0)
        self.assertIn("GROUNDED", out)
        self.assertIn("4 claims", out)

    def test_audit_bad_report_exit_1(self):
        code, out = self._run(["audit", "--binary", self.bin,
                               "--report", self.bad])
        self.assertEqual(code, 1)
        self.assertIn("MANGLED", out)
        self.assertIn("UNGROUNDED", out)

    def test_audit_json_format(self):
        code, out = self._run(["audit", "--binary", self.bin,
                               "--report", self.good, "--format", "json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["GROUNDED"], 4)
        self.assertEqual(len(doc["verdicts"]), 4)
        self.assertEqual(doc["verdicts"][0]["verdict"], "GROUNDED")

    def test_audit_binary_from_report(self):
        # --binary omitted: falls back to the report's "binary" field
        code, _ = self._run(["audit", "--report", self.good])
        self.assertEqual(code, 0)

    def test_audit_missing_binary_exit_2(self):
        code, _ = self._run(["audit", "--binary", "/nope/missing.elf",
                             "--report", self.good])
        self.assertEqual(code, 2)

    def test_audit_bad_report_exit_2(self):
        broken = os.path.join(self.tmp.name, "broken.json")
        with open(broken, "w") as fh:
            fh.write("{not json")
        code, _ = self._run(["audit", "--binary", self.bin,
                             "--report", broken])
        self.assertEqual(code, 2)

    def test_audit_invalid_claim_exit_2(self):
        invalid = os.path.join(self.tmp.name, "invalid.json")
        _write_report(invalid, self.bin,
                      [{"id": "a", "type": "nope", "value": "x"}])
        code, _ = self._run(["audit", "--binary", self.bin,
                             "--report", invalid])
        self.assertEqual(code, 2)

    def test_traps_found_exit_1(self):
        code, out = self._run(["traps", "--binary", self.bin])
        self.assertEqual(code, 1)
        self.assertIn("analysis-refusal", out)

    def test_traps_json(self):
        code, out = self._run(["traps", "--binary", self.bin,
                               "--format", "json"])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertTrue(any(f["pattern"] == "analysis-refusal"
                            for f in doc["findings"]))

    def test_traps_clean_exit_0(self):
        clean = os.path.join(self.tmp.name, "clean.elf")
        _write(clean, build_elf(bits=64, with_trap=False))
        code, out = self._run(["traps", "--binary", clean])
        self.assertEqual(code, 0)
        self.assertIn("no anti-AI payloads", out)

    def test_traps_missing_binary_exit_2(self):
        code, _ = self._run(["traps", "--binary", "/nope/missing.elf"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
