"""Tests for the capability claim type (v0.2.0): a claimed ability proved
by a conjunction of evidence items, with the PARTIAL verdict for the
dead-code case (function present, supporting strings/imports absent)."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from reground import claims
from reground.cli import main
from reground.verify import (audit_binary, GROUNDED, MANGLED, PARTIAL,
                             UNGROUNDED, UNSUPPORTED)
from tests.fixtures import build_elf, build_pe32, build_packed_elf


def _cap(cid, name, evidence):
    return {"id": cid, "type": "capability", "value": name,
            "evidence": [{"type": t, "value": v} for t, v in evidence]}


C2 = "http://c2.evil.example/beacon"


class TestCapabilitySchema(unittest.TestCase):
    def _validate(self, claim_dicts):
        return claims.validate_report({"binary": "x.elf",
                                       "claims": claim_dicts})

    def test_capability_without_evidence_rejected(self):
        with self.assertRaises(claims.ClaimError):
            self._validate([{"id": "c", "type": "capability",
                             "value": "does X"}])

    def test_capability_empty_evidence_rejected(self):
        with self.assertRaises(claims.ClaimError):
            self._validate([_cap("c", "does X", [])])

    def test_capability_unknown_evidence_type_rejected(self):
        with self.assertRaises(claims.ClaimError):
            self._validate([_cap("c", "does X",
                                 [("xref", "main")])])

    def test_capability_evidence_item_missing_value_rejected(self):
        with self.assertRaises(claims.ClaimError):
            self._validate([{"id": "c", "type": "capability",
                             "value": "does X",
                             "evidence": [{"type": "symbol"}]}])

    def test_capability_bad_address_evidence_rejected(self):
        with self.assertRaises(claims.ClaimError):
            self._validate([_cap("c", "does X",
                                 [("address", "not-an-address")])])

    def test_evidence_on_non_capability_claim_rejected(self):
        with self.assertRaises(claims.ClaimError):
            self._validate([{"id": "s", "type": "string", "value": C2,
                             "evidence": [{"type": "string", "value": C2}]}])

    def test_valid_capability_parses(self):
        report = self._validate(
            [_cap("c", "establishes a C2 channel",
                  [("symbol", "helper"), ("string", C2),
                   ("import", "socket")])])
        claim = report.claims[0]
        self.assertEqual(claim.type, "capability")
        self.assertEqual(claim.value, "establishes a C2 channel")
        self.assertEqual(claim.evidence,
                         [("symbol", "helper"), ("string", C2),
                          ("import", "socket")])

    def test_address_evidence_int_value_ok(self):
        report = self._validate(
            [_cap("c", "runs code at main",
                  [("symbol", "main"), ("address", 0x401000)])])
        self.assertEqual(report.claims[0].evidence[1],
                         ("address", "4198400"))


class TestCapabilityAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bin = os.path.join(cls.tmp.name, "demo.elf")
        with open(cls.bin, "wb") as fh:
            fh.write(build_elf(bits=64))
        cls.stripped = os.path.join(cls.tmp.name, "stripped.elf")
        with open(cls.stripped, "wb") as fh:
            fh.write(build_elf(bits=64, strip=True))
        cls.pe = os.path.join(cls.tmp.name, "demo.exe")
        with open(cls.pe, "wb") as fh:
            fh.write(build_pe32())
        cls.packed = os.path.join(cls.tmp.name, "packed.elf")
        with open(cls.packed, "wb") as fh:
            fh.write(build_packed_elf())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _audit(self, bin_path, claim_dicts):
        report = claims.validate_report({"binary": bin_path,
                                         "claims": claim_dicts})
        verdicts, summary = audit_binary(bin_path, report)
        return {v.claim_id: v for v in verdicts}, summary

    def test_grounded_all_evidence_present(self):
        verdicts, _ = self._audit(self.bin, [
            _cap("c", "beacons to C2",
                 [("symbol", "main"), ("string", C2), ("import", "puts")])])
        v = verdicts["c"]
        self.assertEqual(v.verdict, GROUNDED)
        self.assertIn("all 3 evidence items confirmed", v.detail)
        self.assertIn("symbol 'main': grounded", v.evidence)
        self.assertIn("import 'puts': grounded", v.evidence)

    def test_partial_dead_code_case(self):
        # The headline failure: the function exists, the C2 string exists,
        # but the import that would make the capability live does not.
        verdicts, _ = self._audit(self.bin, [
            _cap("c", "establishes a C2 channel",
                 [("symbol", "helper"), ("string", C2),
                  ("import", "socket")])])
        v = verdicts["c"]
        self.assertEqual(v.verdict, PARTIAL)
        self.assertIn("2 of 3 evidence items confirmed", v.detail)
        self.assertIn("import 'socket'", v.detail)
        self.assertIn("import 'socket': ungrounded", v.evidence)

    def test_partial_with_mangled_evidence_item(self):
        verdicts, _ = self._audit(self.bin, [
            _cap("c", "beacons to C2",
                 [("symbol", "main"),
                  ("string", "http://c2.evil.example/beackn"),
                  ("import", "puts")])])
        v = verdicts["c"]
        self.assertEqual(v.verdict, PARTIAL)
        self.assertIn("closest real string", v.evidence)
        self.assertIn(C2, v.evidence)

    def test_ungrounded_no_evidence_present(self):
        verdicts, _ = self._audit(self.bin, [
            _cap("c", "exfiltrates files",
                 [("symbol", "exfiltrate"),
                  ("string", "http://totally-fake.example/nope"),
                  ("import", "socket")])])
        v = verdicts["c"]
        self.assertEqual(v.verdict, UNGROUNDED)
        self.assertIn("none of the 3 evidence items found", v.detail)

    def test_mangled_no_evidence_confirmed_but_near_miss(self):
        verdicts, _ = self._audit(self.bin, [
            _cap("c", "runs main",
                 [("symbol", "man"),
                  ("string", "http://totally-fake.example/nope")])])
        v = verdicts["c"]
        self.assertEqual(v.verdict, MANGLED)
        self.assertIn("main", v.evidence)

    def test_symbol_evidence_alone(self):
        verdicts, _ = self._audit(self.bin, [
            _cap("g", "has helper", [("symbol", "helper")]),
            _cap("m", "has helperr", [("symbol", "helperr")]),
            _cap("u", "has zzzz", [("symbol", "zzzz")])])
        self.assertEqual(verdicts["g"].verdict, GROUNDED)
        self.assertIn("0x401010", verdicts["g"].evidence)
        self.assertEqual(verdicts["m"].verdict, MANGLED)
        self.assertIn("helper", verdicts["m"].evidence)
        self.assertEqual(verdicts["u"].verdict, UNGROUNDED)

    def test_stripped_binary_loses_symbol_evidence(self):
        # Stripping drops .symtab: the symbol half of the conjunction goes
        # missing while strings and imports still confirm -- PARTIAL, not a
        # silent pass and not a flat rejection.
        verdicts, _ = self._audit(self.stripped, [
            _cap("c", "beacons to C2",
                 [("symbol", "main"), ("string", C2),
                  ("import", "puts")])])
        v = verdicts["c"]
        self.assertEqual(v.verdict, PARTIAL)
        self.assertIn("symbol 'main'", v.detail)

    def test_pe_capability_grounded(self):
        verdicts, _ = self._audit(self.pe, [
            _cap("c", "opens files on Windows",
                 [("import", "KERNEL32.dll!CreateFileW"),
                  ("string", "http://c2.evil.example/pe-beacon"),
                  ("section", ".rdata")])])
        self.assertEqual(verdicts["c"].verdict, GROUNDED)

    def test_summary_counts_partial(self):
        _, summary = self._audit(self.bin, [
            _cap("g", "beacons to C2",
                 [("symbol", "main"), ("string", C2), ("import", "puts")]),
            _cap("p", "establishes a C2 channel",
                 [("symbol", "helper"), ("string", C2),
                  ("import", "socket")])])
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary[GROUNDED], 1)
        self.assertEqual(summary[PARTIAL], 1)
        self.assertEqual(summary[UNGROUNDED], 0)
        self.assertEqual(summary[UNSUPPORTED], 0)

    def test_packed_binary_capability_unsupported(self):
        # Address and section evidence cannot be checked at all in a
        # binary with no mapped regions and no section names.
        verdicts, _ = self._audit(self.packed, [
            _cap("c", "runs code at main",
                 [("address", "0x401000"), ("section", ".text")])])
        self.assertEqual(verdicts["c"].verdict, UNSUPPORTED)

    def test_packed_binary_string_evidence_still_raw_bytes(self):
        # The packed fixture keeps its raw bytes, so string extraction
        # still sees the C2 URL even though the symbol table is gone:
        # one item grounded, one missing -- PARTIAL, honestly reported.
        verdicts, _ = self._audit(self.packed, [
            _cap("c", "beacons to C2",
                 [("symbol", "main"), ("string", C2)])])
        v = verdicts["c"]
        self.assertEqual(v.verdict, PARTIAL)
        self.assertIn("symbol 'main'", v.detail)


class TestCapabilityCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bin = os.path.join(cls.tmp.name, "demo.elf")
        with open(cls.bin, "wb") as fh:
            fh.write(build_elf(bits=64))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _write_report(self, name, claim_dicts):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"binary": self.bin, "claims": claim_dicts}, fh)
        return path

    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_cli_partial_exit_1_and_summary(self):
        report = self._write_report("partial.json", [
            _cap("c", "establishes a C2 channel",
                 [("symbol", "helper"), ("string", C2),
                  ("import", "socket")])])
        code, out = self._run(["audit", "--binary", self.bin,
                               "--report", report])
        self.assertEqual(code, 1)
        self.assertIn("PARTIAL", out)
        self.assertIn("1 claims: 0 grounded, 1 partial", out)

    def test_cli_grounded_capability_exit_0_json(self):
        report = self._write_report("grounded.json", [
            _cap("c", "beacons to C2",
                 [("symbol", "main"), ("string", C2),
                  ("import", "puts")])])
        code, out = self._run(["audit", "--binary", self.bin,
                               "--report", report, "--format", "json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["GROUNDED"], 1)
        self.assertEqual(doc["summary"]["PARTIAL"], 0)
        self.assertEqual(doc["verdicts"][0]["verdict"], "GROUNDED")


if __name__ == "__main__":
    unittest.main()
