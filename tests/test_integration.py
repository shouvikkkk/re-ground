"""Integration test against a real system binary (/bin/ls), when present."""

import os
import unittest

from reground import claims, elf as elf_mod, stringsx
from reground.verify import audit_binary, GROUNDED


@unittest.skipIf(not os.path.isfile("/bin/ls"), "/bin/ls not present")
class TestRealBinary(unittest.TestCase):
    def test_ls_parses_and_entry_grounded(self):
        with open("/bin/ls", "rb") as fh:
            data = fh.read()
        parsed = elf_mod.parse_elf(data)
        report = claims.validate_report({
            "binary": "/bin/ls",
            "claims": [{"id": "entry", "type": "address",
                        "value": hex(parsed.entry)}]})
        verdicts, _ = audit_binary("/bin/ls", report)
        self.assertEqual(verdicts[0].verdict, GROUNDED)

    def test_ls_real_string_grounded(self):
        with open("/bin/ls", "rb") as fh:
            data = fh.read()
        strings = [s.value for s in stringsx.extract_strings(data)
                   if len(s.value) >= 12]
        self.assertTrue(strings, "expected some strings in /bin/ls")
        target = strings[0]
        report = claims.validate_report({
            "binary": "/bin/ls",
            "claims": [{"id": "s", "type": "string", "value": target}]})
        verdicts, _ = audit_binary("/bin/ls", report)
        self.assertEqual(verdicts[0].verdict, GROUNDED)

    def test_traps_do_not_crash_on_ls(self):
        from reground.traps import scan_binary
        findings = scan_binary("/bin/ls")
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
