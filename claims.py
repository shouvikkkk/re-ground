"""Claim schema for agent reverse-engineering reports.

A report is JSON:

    {
      "binary": "path/to/sample.elf",
      "claims": [
        {"id": "c1", "type": "address", "value": "0x401000",
         "note": "agent says main() lives here"},
        {"id": "c2", "type": "string", "value": "http://c2.example/beacon"},
        {"id": "c3", "type": "import", "value": "KERNEL32.dll!CreateFileW"},
        {"id": "c4", "type": "endpoint", "value": "http://c2.example/beacon"},
        {"id": "c5", "type": "section", "value": ".text"}
      ]
    }

Claim types:
  address  -- virtual address, hex ("0x401000") or decimal
  string   -- exact byte string the agent says is in the binary
  import   -- "func", "dll!func", or "libname" the agent says is imported
  endpoint -- URL/hostname the agent says the sample contacts
  section  -- section name the agent says exists
"""

import json
import os

CLAIM_TYPES = ("address", "string", "import", "endpoint", "section")


class ClaimError(ValueError):
    """Raised when a report fails schema validation, with a helpful message."""


class Claim:
    __slots__ = ("id", "type", "value", "note")

    def __init__(self, claim_id, claim_type, value, note=""):
        self.id = claim_id
        self.type = claim_type
        self.value = value
        self.note = note

    def __repr__(self):
        return "Claim(%r, %r, %r)" % (self.id, self.type, self.value)


class ClaimReport:
    __slots__ = ("binary", "claims", "source_path")

    def __init__(self, binary, claims, source_path=None):
        self.binary = binary
        self.claims = claims
        self.source_path = source_path


def parse_address(value):
    """Parse a claim address value ("0x401000" or "4198400") to int."""
    text = str(value).strip()
    try:
        addr = int(text, 0)
    except (ValueError, TypeError):
        raise ClaimError(
            "claim address value %r is not a number -- use hex like "
            "\"0x401000\" or decimal" % (value,))
    if addr < 0:
        raise ClaimError("claim address value %r is negative" % (value,))
    return addr


def _require_str(mapping, key, where):
    if key not in mapping:
        raise ClaimError("%s: missing required key %r" % (where, key))
    if not isinstance(mapping[key], str):
        raise ClaimError("%s: key %r must be a string, got %s"
                         % (where, key, type(mapping[key]).__name__))
    return mapping[key]


def validate_report(obj, source_path=None):
    """Validate a decoded JSON object; return a ClaimReport."""
    where = "report %s" % source_path if source_path else "report"
    if not isinstance(obj, dict):
        raise ClaimError("%s: top level must be an object" % where)
    binary = _require_str(obj, "binary", where)
    if "claims" not in obj:
        raise ClaimError("%s: missing required key 'claims'" % where)
    if not isinstance(obj["claims"], list):
        raise ClaimError("%s: 'claims' must be a list" % where)
    if not obj["claims"]:
        raise ClaimError("%s: 'claims' list is empty -- nothing to audit" % where)

    claims = []
    seen_ids = set()
    for idx, item in enumerate(obj["claims"]):
        loc = "%s: claims[%d]" % (where, idx)
        if not isinstance(item, dict):
            raise ClaimError("%s: each claim must be an object" % loc)
        claim_id = _require_str(item, "id", loc)
        if claim_id in seen_ids:
            raise ClaimError("%s: duplicate claim id %r" % (loc, claim_id))
        seen_ids.add(claim_id)
        claim_type = _require_str(item, "type", loc)
        if claim_type not in CLAIM_TYPES:
            raise ClaimError(
                "%s: unknown claim type %r -- expected one of: %s"
                % (loc, claim_type, ", ".join(CLAIM_TYPES)))
        if "value" not in item:
            raise ClaimError("%s: missing required key 'value'" % loc)
        value = item["value"]
        if not isinstance(value, (str, int)):
            raise ClaimError("%s: 'value' must be a string (or integer for "
                             "address claims)" % loc)
        if claim_type == "address":
            parse_address(value)  # fail fast with a clear message
        note = item.get("note", "")
        if not isinstance(note, str):
            raise ClaimError("%s: 'note' must be a string" % loc)
        claims.append(Claim(claim_id, claim_type, str(value), note))

    return ClaimReport(binary, claims, source_path)


def load_report(path):
    """Load and validate a report file. Raises ClaimError / OSError."""
    if not os.path.isfile(path):
        raise ClaimError("report file not found: %s" % path)
    with open(path, "r", encoding="utf-8") as fh:
        try:
            obj = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ClaimError("report %s is not valid JSON: %s" % (path, exc))
    return validate_report(obj, source_path=path)
