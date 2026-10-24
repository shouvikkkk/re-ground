"""Anti-AI payload detector (Talos "A3" taxonomy).

Malware authors embed prompt-injection payloads in PE headers and strings to
gaslight AI triage agents (Cisco Talos, 2026-10-08: FRUITSHELL, PLOTSAFE,
HOLLOWCLAD, MANTLEMAZE -- ~35% success in automated evaluations). This module
scans a binary's extracted strings for those payloads and for context-flooding
padding, so the traps are flagged BEFORE an agent's report is trusted.

Patterns live in the PATTERNS table: adding a new one is a single dict line.
"""

import re

# Each pattern: one line to add a new one.
# severity: "high" (tries to steer the analyst) / "medium" (tries to look
# benign) / "low" (noise / misdirection).
PATTERNS = [
    {"id": "instruction-override",
     "regex": r"ignore\s+(all\s+|any\s+|the\s+)?previous\s+instructions",
     "severity": "high",
     "description": "direct prompt-injection: tries to override the "
                    "analyst's instructions"},
    {"id": "analysis-refusal",
     "regex": r"(there\s+is\s+)?no\s+need\s+to\s+analy[sz]e",
     "severity": "high",
     "description": "tells the AI triage agent the file needs no analysis"},
    {"id": "do-not-analyze",
     "regex": r"do\s+not\s+(attempt\s+to\s+)?analy[sz]e",
     "severity": "high",
     "description": "direct order to skip analysis"},
    {"id": "stop-analysis",
     "regex": r"(stop|halt|end|terminate)\s+(your\s+|this\s+)?analysis",
     "severity": "high",
     "description": "tries to cut the agent's analysis short"},
    {"id": "benign-verdict",
     "regex": r"(classify|report|mark|label)\s+(this|it)\s+as\s+benign",
     "severity": "high",
     "description": "plants a benign verdict for the agent to parrot"},
    {"id": "do-not-flag",
     "regex": r"do\s+not\s+(flag|report|quarantine|detect)",
     "severity": "medium",
     "description": "asks the agent not to raise the finding"},
    {"id": "false-positive-claim",
     "regex": r"(this\s+is\s+a\s+|guaranteed\s+)?false\s+positive",
     "severity": "medium",
     "description": "pre-emptive 'false positive' label aimed at triage"},
    {"id": "benign-attribution-ms",
     "regex": r"certified\s+microsoft",
     "severity": "medium",
     "description": "fake benign attribution ('certified Microsoft ...')"},
    {"id": "benign-attribution-admin",
     "regex": r"benign\s+administrative\s+software",
     "severity": "medium",
     "description": "fake benign attribution ('benign administrative "
                    "software')"},
    {"id": "benign-self-label",
     "regex": r"this\s+file\s+is\s+(benign|safe|harmless)",
     "severity": "medium",
     "description": "self-declared benign label inside the binary"},
    {"id": "nothing-to-see",
     "regex": r"nothing\s+to\s+see\s+here",
     "severity": "low",
     "description": "misdirection noise aimed at a skimming agent"},
    {"id": "move-along",
     "regex": r"(move\s+along|carry\s+on|no\s+threat\s+detected)",
     "severity": "low",
     "description": "misdirection noise aimed at a skimming agent"},
]

# Benign-looking vocabulary used for context-flooding padding. Note: "example"
# is deliberately absent -- it matches domains like evil.example and would
# turn real IOC strings into "filler".
FILLER_WORDS = (
    "documentation", "copyright", "license", "warranty", "harmless",
    "lorem", "dummy", "placeholder", "sample", "test data",
    "benign", "official release", "user manual", "changelog",
)

# A section holding this many filler strings is padding the agent's context.
FLOOD_THRESHOLD = 20
# The same string repeated this many times is deliberate padding.
REPEAT_THRESHOLD = 8


class TrapFinding:
    __slots__ = ("pattern_id", "matched_text", "encoding", "offset", "vaddr",
                 "severity", "description")

    def __init__(self, pattern_id, matched_text, encoding, offset, vaddr,
                 severity, description):
        self.pattern_id = pattern_id
        self.matched_text = matched_text
        self.encoding = encoding
        self.offset = offset
        self.vaddr = vaddr
        self.severity = severity
        self.description = description

    def to_dict(self):
        return {"pattern": self.pattern_id,
                "matched_text": self.matched_text,
                "encoding": self.encoding,
                "offset": self.offset,
                "vaddr": self.vaddr,
                "severity": self.severity,
                "description": self.description}

    def __repr__(self):
        return "TrapFinding(%r, %s)" % (self.pattern_id, self.severity)


_COMPILED = [(p, re.compile(p["regex"], re.IGNORECASE)) for p in PATTERNS]


def _section_of(vaddr, ranges):
    for start, end, name in ranges:
        if start <= vaddr < end:
            return name
    return None


def scan_strings(strings, ranges):
    """Scan extracted strings; return a list of TrapFinding.

    strings: iterable of ExtractedString. ranges: [(start, end, name)]
    for section attribution of findings.
    """
    findings = []
    for s in strings:
        for pattern, rx in _COMPILED:
            m = rx.search(s.value)
            if not m:
                continue
            findings.append(TrapFinding(
                pattern_id=pattern["id"],
                matched_text=m.group(0)[:120],
                encoding=s.encoding,
                offset=s.offset,
                vaddr=s.vaddr,
                severity=pattern["severity"],
                description=pattern["description"]))
    findings.extend(_detect_flooding(strings, ranges))
    findings.extend(_detect_repetition(strings, ranges))
    return findings


def _detect_flooding(strings, ranges):
    """Flag sections stuffed with benign filler strings (context flooding)."""
    per_section = {}
    for s in strings:
        # URL-like strings are evidence, not benign filler -- a C2 URL at
        # evil.example must never count as "padding".
        if "://" in s.value:
            continue
        lowered = s.value.lower()
        if not any(w in lowered for w in FILLER_WORDS):
            continue
        if s.vaddr is None:
            continue
        section = _section_of(s.vaddr, ranges) or "unknown"
        per_section.setdefault(section, []).append(s)
    findings = []
    for section, group in per_section.items():
        if len(group) >= FLOOD_THRESHOLD:
            first = group[0]
            findings.append(TrapFinding(
                pattern_id="context-flooding",
                matched_text="%d benign filler strings" % len(group),
                encoding=first.encoding,
                offset=first.offset,
                vaddr=first.vaddr,
                severity="medium",
                description="context-flooding padding: %d benign-looking "
                            "filler strings in '%s' to drown the agent's "
                            "context" % (len(group), section)))
    return findings


def _detect_repetition(strings, ranges):
    """Flag one string repeated many times (deliberate padding)."""
    seen = {}
    for s in strings:
        if len(s.value) < 12:
            continue
        seen.setdefault(s.value, []).append(s)
    findings = []
    for value, group in seen.items():
        if len(group) >= REPEAT_THRESHOLD:
            first = group[0]
            findings.append(TrapFinding(
                pattern_id="repeated-padding",
                matched_text=value[:120],
                encoding=first.encoding,
                offset=first.offset,
                vaddr=first.vaddr,
                severity="low",
                description="repeated-string padding: the same %d-char "
                            "string appears %d times"
                            % (len(value), len(group))))
    return findings


def scan_binary(path):
    """Load a binary, extract strings, scan for traps. Returns findings."""
    from . import elf as elf_mod
    from . import pe as pe_mod
    from . import stringsx
    from .verify import BinaryError

    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        raise BinaryError("binary is empty: %s" % path)
    ranges = []
    vaddr_of = None
    if elf_mod.detect(data):
        parsed = elf_mod.parse_elf(data)
        ranges = parsed.mapped_ranges()
        vaddr_of = parsed.vaddr_of_offset
    elif pe_mod.detect(data):
        parsed = pe_mod.parse_pe(data)
        ranges = parsed.mapped_ranges()
        vaddr_of = parsed.vaddr_of_offset
    else:
        raise BinaryError("unknown binary format (not ELF or PE): %s" % path)
    strings = list(stringsx.extract_strings(data, vaddr_of=vaddr_of))
    return scan_strings(strings, ranges)
