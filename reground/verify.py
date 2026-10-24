"""Verification engine: checks each agent claim against the actual binary.

Verdicts (deterministic, no ML):
  GROUNDED    -- exact match found in the binary
  MANGLED     -- close match with corruption (address just outside a section,
                 string/endpoint/import/section name off by a char or two --
                 the classic "agent misread the bytes" failure)
  UNGROUNDED  -- no trace of the claim anywhere in the binary
  UNSUPPORTED -- the claim cannot be checked (e.g. packed binary with no
                 sections or segments, so there is nothing to map against)

The MANGLED verdict is the point of this tool: agents rarely invent findings
from nothing -- they misread real bytes. A wrong address 12 bytes past the
end of .text, or a C2 URL with one mangled character, is far more useful
reported as "mangled, here is the real value" than as a flat rejection.
"""

from . import elf as elf_mod
from . import pe as pe_mod
from . import stringsx
from .claims import parse_address

GROUNDED = "GROUNDED"
MANGLED = "MANGLED"
UNGROUNDED = "UNGROUNDED"
UNSUPPORTED = "UNSUPPORTED"

# An unmapped address within this many bytes of a mapped region boundary is
# "the agent was looking at the right neighborhood" rather than hallucinating.
MANGLE_ADDR_DELTA = 64
# A claimed symbol address within this delta of a real symbol is a misread.
MANGLE_SYMBOL_DELTA = 8
# Max edit distance for a "mangled, not invented" string/import/section name.
MANGLE_EDIT_DISTANCE = 2


class BinaryError(Exception):
    """Raised when the binary cannot be loaded or identified."""


class Verdict:
    __slots__ = ("claim_id", "claim_type", "value", "verdict", "detail",
                 "evidence")

    def __init__(self, claim_id, claim_type, value, verdict, detail="",
                 evidence=""):
        self.claim_id = claim_id
        self.claim_type = claim_type
        self.value = value
        self.verdict = verdict
        self.detail = detail
        self.evidence = evidence

    def to_dict(self):
        return {"id": self.claim_id, "type": self.claim_type,
                "value": self.value, "verdict": self.verdict,
                "detail": self.detail, "evidence": self.evidence}

    def __repr__(self):
        return "Verdict(%r, %s)" % (self.claim_id, self.verdict)


def _edit_distance(a, b, max_dist):
    """Levenshtein distance with early exit; returns > max_dist if exceeded."""
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = prev[j] + 1
            ins = cur[j - 1] + 1
            if ins < v:
                v = ins
            sub = prev[j - 1] + cost
            if sub < v:
                v = sub
            cur.append(v)
            if v < row_min:
                row_min = v
        if row_min > max_dist:
            return max_dist + 1
        prev = cur
    return prev[-1]


def _closest(candidates, target, max_dist):
    """Return (best_candidate, distance) or (None, None)."""
    best = None
    best_dist = max_dist + 1
    for cand in candidates:
        if abs(len(cand) - len(target)) > max_dist:
            continue
        d = _edit_distance(cand, target, max_dist)
        if 0 < d < best_dist:
            best, best_dist = cand, d
            if d == 1:
                break
    if best is None:
        return None, None
    return best, best_dist


class BinaryView:
    """Format-agnostic view of a binary for claim checking."""

    def __init__(self):
        self.kind = ""            # "elf" | "pe"
        self.ranges = []          # [(start, end, name)]
        self.strings = []         # [ExtractedString]
        self.string_values = []   # [str] parallel, for matching
        self.symbols = {}         # name -> value (ELF symtab/dynsym)
        self.imports = []         # [(dll|None, func)] ; ELF: dll None
        self.needed_libs = []     # [str] ELF DT_NEEDED / PE delay-load n/a
        self.section_names = []   # [str]
        self.entry = None

    @property
    def verifiable(self):
        """False when the binary exposes nothing to check against."""
        return bool(self.ranges)

    def mapped(self, addr):
        for start, end, _name in self.ranges:
            if start <= addr < end:
                return True
        return False

    def nearest_boundary(self, addr):
        """Return (distance, name, side) to the closest mapped boundary."""
        best = None
        for start, end, name in self.ranges:
            if addr < start:
                cand = (start - addr, name, "before start of")
            elif addr >= end:
                cand = (addr - end, name, "past end of")
            else:
                return 0, name, "inside"
            if best is None or cand[0] < best[0]:
                best = cand
        return best


def _load_binary(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        raise BinaryError("binary is empty: %s" % path)
    view = BinaryView()
    if elf_mod.detect(data):
        parsed = elf_mod.parse_elf(data)
        view.kind = "elf"
        view.ranges = parsed.mapped_ranges()
        view.section_names = [s.name for s in parsed.sections
                              if s.name and s.type != elf_mod.SHT_NULL]
        for sym in parsed.symbols + parsed.dyn_symbols:
            if sym.name and sym.name not in view.symbols:
                view.symbols[sym.name] = sym.value
        view.imports = [(None, name) for name in parsed.imported_symbols]
        view.needed_libs = list(parsed.needed_libs)
        view.entry = parsed.entry
        vaddr_of = parsed.vaddr_of_offset
    elif pe_mod.detect(data):
        parsed = pe_mod.parse_pe(data)
        view.kind = "pe"
        view.ranges = parsed.mapped_ranges()
        view.section_names = [s.name for s in parsed.sections if s.name]
        for imp in parsed.imports:
            for _hint, name in imp.functions:
                if isinstance(name, str):
                    view.imports.append((imp.dll, name))
            if imp.dll and not imp.functions:
                view.needed_libs.append(imp.dll)
        view.needed_libs.extend(
            imp.dll for imp in parsed.imports
            if imp.dll and imp.dll not in view.needed_libs)
        view.entry = parsed.entry_vaddr
        vaddr_of = parsed.vaddr_of_offset
    else:
        raise BinaryError("unknown binary format (not ELF or PE): %s" % path)

    view.strings = list(stringsx.extract_strings(data, vaddr_of=vaddr_of))
    view.string_values = [s.value for s in view.strings]
    return view


def _split_import(value):
    """Split 'dll!func' / 'func' / 'libname' into (dll|None, name)."""
    if "!" in value:
        dll, _, func = value.partition("!")
        return dll.strip() or None, func.strip()
    return None, value.strip()


class Auditor:
    """Runs every claim in a report against one loaded binary."""

    def __init__(self, view):
        self.view = view
        self._dispatch = {
            "address": self._check_address,
            "string": self._check_string,
            "import": self._check_import,
            "endpoint": self._check_endpoint,
            "section": self._check_section,
        }

    def audit(self, report):
        verdicts = []
        for claim in report.claims:
            checker = self._dispatch[claim.type]
            verdicts.append(checker(claim))
        return verdicts

    # -- address ------------------------------------------------------
    def _check_address(self, claim):
        addr = parse_address(claim.value)
        view = self.view
        if not view.verifiable:
            return Verdict(claim.id, claim.type, claim.value, UNSUPPORTED,
                           "binary exposes no mappable regions; address "
                           "claims cannot be checked")
        if view.mapped(addr):
            return Verdict(claim.id, claim.type, claim.value, GROUNDED,
                           "address lies inside a mapped region",
                           evidence="vaddr %#x mapped" % addr)
        if view.entry is not None and addr == view.entry:
            return Verdict(claim.id, claim.type, claim.value, GROUNDED,
                           "address equals the entry point",
                           evidence="entry %#x" % view.entry)
        for name, sym_val in view.symbols.items():
            delta = addr - sym_val
            if 0 < abs(delta) <= MANGLE_SYMBOL_DELTA:
                direction = "past" if delta > 0 else "before"
                return Verdict(
                    claim.id, claim.type, claim.value, MANGLED,
                    "address is %d bytes %s symbol '%s' (%#x) -- likely a "
                    "misread of the real address"
                    % (abs(delta), direction, name, sym_val),
                    evidence="symbol '%s' at %#x" % (name, sym_val))
        near = view.nearest_boundary(addr)
        if near and 0 < near[0] <= MANGLE_ADDR_DELTA:
            dist, name, side = near
            return Verdict(
                claim.id, claim.type, claim.value, MANGLED,
                "address is %d bytes %s '%s' -- points just outside a real "
                "mapped region, likely an off-by-N misread"
                % (dist, side, name),
                evidence="nearest region '%s'" % name)
        return Verdict(claim.id, claim.type, claim.value, UNGROUNDED,
                       "address is not inside any section or segment and is "
                       "far from every mapped boundary")

    # -- string -------------------------------------------------------
    def _check_string(self, claim):
        view = self.view
        target = claim.value
        if not view.verifiable and not view.string_values:
            return Verdict(claim.id, claim.type, claim.value, UNSUPPORTED,
                           "no strings could be extracted; string claims "
                           "cannot be checked")
        if target in view.string_values:
            s = next(s for s in view.strings if s.value == target)
            loc = ("vaddr %#x" % s.vaddr) if s.vaddr is not None else \
                ("file offset %#x" % s.offset)
            return Verdict(claim.id, claim.type, claim.value, GROUNDED,
                           "exact string present in binary (%s)"
                           % s.encoding,
                           evidence="%s, %s" % (s.encoding, loc))
        best, dist = _closest(view.string_values, target,
                              MANGLE_EDIT_DISTANCE)
        if best is not None:
            return Verdict(
                claim.id, claim.type, claim.value, MANGLED,
                "no exact match, but edit distance %d from real string %r -- "
                "likely a one-character extraction corruption"
                % (dist, best),
                evidence="closest real string: %r" % best)
        return Verdict(claim.id, claim.type, claim.value, UNGROUNDED,
                       "no exact or near match among %d extracted strings"
                       % len(view.string_values))

    # -- import -------------------------------------------------------
    def _check_import(self, claim):
        view = self.view
        dll, func = _split_import(claim.value)
        if not view.verifiable:
            return Verdict(claim.id, claim.type, claim.value, UNSUPPORTED,
                           "binary exposes no mappable regions; import "
                           "claims cannot be checked")
        if dll is not None and not func:
            dll = None  # "dll!" with empty func -> treat as dll name
        if dll is not None and func:
            for imp_dll, imp_func in view.imports:
                if (imp_dll and imp_dll.lower() == dll.lower()
                        and imp_func == func):
                    return Verdict(claim.id, claim.type, claim.value,
                                   GROUNDED,
                                   "imported function found",
                                   evidence="%s!%s" % (imp_dll, imp_func))
        elif func:
            for imp_dll, imp_func in view.imports:
                if imp_func == func:
                    src = imp_dll if imp_dll else "dynamic symbols"
                    return Verdict(claim.id, claim.type, claim.value,
                                   GROUNDED,
                                   "imported function found",
                                   evidence="imported from %s" % src)
            for lib in view.needed_libs:
                if lib.lower() == func.lower():
                    return Verdict(claim.id, claim.type, claim.value,
                                   GROUNDED,
                                   "library dependency found",
                                   evidence="DT_NEEDED/import: %s" % lib)
        else:
            for lib in view.needed_libs:
                if lib.lower() == dll.lower():
                    return Verdict(claim.id, claim.type, claim.value,
                                   GROUNDED,
                                   "library dependency found",
                                   evidence="DT_NEEDED/import: %s" % lib)
        # Mangled: near-miss on a real import or library name
        pool = [f for _d, f in view.imports] + view.needed_libs
        best, dist = _closest(pool, func or dll or "", MANGLE_EDIT_DISTANCE)
        if best is not None:
            return Verdict(
                claim.id, claim.type, claim.value, MANGLED,
                "no exact import, but edit distance %d from real import %r "
                "-- likely a misread import name" % (dist, best),
                evidence="closest real import: %r" % best)
        return Verdict(claim.id, claim.type, claim.value, UNGROUNDED,
                       "no such import or library dependency in the binary")

    # -- endpoint -----------------------------------------------------
    def _check_endpoint(self, claim):
        # An endpoint claim is a string claim with URL-shaped evidence kept
        # verbatim, so the mangled-C2 case ("one extra character") resolves
        # to the real string instead of a flat rejection.
        return self._check_string(claim)

    # -- section ------------------------------------------------------
    def _check_section(self, claim):
        view = self.view
        target = claim.value
        if not view.section_names:
            return Verdict(claim.id, claim.type, claim.value, UNSUPPORTED,
                           "binary has no section names to check against "
                           "(stripped or packed)")
        if target in view.section_names:
            return Verdict(claim.id, claim.type, claim.value, GROUNDED,
                           "section present in binary",
                           evidence="section '%s'" % target)
        best, dist = _closest(view.section_names, target,
                              MANGLE_EDIT_DISTANCE)
        if best is not None:
            return Verdict(
                claim.id, claim.type, claim.value, MANGLED,
                "no such section, but edit distance %d from real section "
                "%r -- likely a misread section name" % (dist, best),
                evidence="closest real section: %r" % best)
        return Verdict(claim.id, claim.type, claim.value, UNGROUNDED,
                       "no such section in the binary")


def audit_binary(binary_path, report):
    """Load the binary, run every claim, return (verdicts, summary)."""
    view = _load_binary(binary_path)
    verdicts = Auditor(view).audit(report)
    summary = {"total": len(verdicts), GROUNDED: 0, MANGLED: 0,
               UNGROUNDED: 0, UNSUPPORTED: 0}
    for v in verdicts:
        summary[v.verdict] += 1
    return verdicts, summary
