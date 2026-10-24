"""Tests for reground.claims -- schema validation."""

import json
import os
import tempfile
import unittest

from reground import claims
from reground.claims import ClaimError


def _report(**overrides):
    obj = {"binary": "demo.elf",
           "claims": [{"id": "c1", "type": "address", "value": "0x401000"}]}
    obj.update(overrides)
    return obj


class TestClaims(unittest.TestCase):
    def test_valid_report(self):
        rep = claims.validate_report(_report())
        self.assertEqual(rep.binary, "demo.elf")
        self.assertEqual(len(rep.claims), 1)
        self.assertEqual(rep.claims[0].type, "address")

    def test_all_types_accepted(self):
        obj = _report(claims=[
            {"id": "a", "type": "address", "value": "0x10"},
            {"id": "s", "type": "string", "value": "abc"},
            {"id": "i", "type": "import", "value": "puts"},
            {"id": "e", "type": "endpoint", "value": "http://x/"},
            {"id": "t", "type": "section", "value": ".text"},
        ])
        rep = claims.validate_report(obj)
        self.assertEqual(len(rep.claims), 5)

    def test_missing_binary(self):
        obj = _report()
        del obj["binary"]
        with self.assertRaises(ClaimError) as ctx:
            claims.validate_report(obj)
        self.assertIn("binary", str(ctx.exception))

    def test_missing_claims(self):
        with self.assertRaises(ClaimError):
            claims.validate_report({"binary": "x"})

    def test_empty_claims(self):
        with self.assertRaises(ClaimError):
            claims.validate_report(_report(claims=[]))

    def test_bad_type(self):
        with self.assertRaises(ClaimError) as ctx:
            claims.validate_report(_report(claims=[
                {"id": "c1", "type": "capability", "value": "x"}]))
        self.assertIn("capability", str(ctx.exception))

    def test_duplicate_ids(self):
        with self.assertRaises(ClaimError) as ctx:
            claims.validate_report(_report(claims=[
                {"id": "c1", "type": "string", "value": "a"},
                {"id": "c1", "type": "string", "value": "b"}]))
        self.assertIn("duplicate", str(ctx.exception))

    def test_missing_id(self):
        with self.assertRaises(ClaimError):
            claims.validate_report(_report(claims=[
                {"type": "string", "value": "a"}]))

    def test_address_hex_and_decimal(self):
        self.assertEqual(claims.parse_address("0x401000"), 0x401000)
        self.assertEqual(claims.parse_address("4198400"), 4198400)
        self.assertEqual(claims.parse_address("  0x10  "), 0x10)

    def test_address_invalid(self):
        with self.assertRaises(ClaimError):
            claims.parse_address("not-a-number")
        with self.assertRaises(ClaimError):
            claims.parse_address("-0x10")
        # invalid address inside a report fails fast too
        with self.assertRaises(ClaimError):
            claims.validate_report(_report(claims=[
                {"id": "c1", "type": "address", "value": "zzz"}]))

    def test_load_report_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(_report(), fh)
            path = fh.name
        try:
            rep = claims.load_report(path)
            self.assertEqual(rep.binary, "demo.elf")
            self.assertEqual(rep.source_path, path)
        finally:
            os.unlink(path)

    def test_load_missing_file(self):
        with self.assertRaises(ClaimError):
            claims.load_report("/nonexistent/report.json")

    def test_load_bad_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            with self.assertRaises(ClaimError):
                claims.load_report(path)
        finally:
            os.unlink(path)

    def test_note_optional(self):
        rep = claims.validate_report(_report(claims=[
            {"id": "c1", "type": "string", "value": "a",
             "note": "agent says so"}]))
        self.assertEqual(rep.claims[0].note, "agent says so")


if __name__ == "__main__":
    unittest.main()
