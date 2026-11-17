# Changelog

## 0.2.0 — 2026-11-17

- **New claim type: `capability`.** A claimed ability ("establishes a C2
  channel") is now proved by a conjunction of evidence items
  (`symbol`, `string`, `import`, `address`, `section`), each checked with
  the same rules as the single-claim types — instead of one string at a
  time. This is the repo's own headline failure mode: the SentinelOne /
  malware.news audit found "several 'capabilities' are actually dead code
  from the compiler's standard library", and v0.1 could only answer an
  imagined capability with a flat UNGROUNDED.
- **New verdict: `PARTIAL`.** Some evidence items confirmed, some missing —
  the classic dead-code case: the function exists, the C2 string exists,
  but the import that would make the capability live does not. The verdict
  names exactly which items are missing, and near-miss items still surface
  the real value. A half-supported capability is not a grounded one.
- **New evidence type: `symbol`.** Checks the binary's symbol table
  (exact match, edit-distance near-miss, or absent), used by capability
  claims. Stripped binaries lose the symbol half of a conjunction
  honestly: the verdict drops to PARTIAL rather than silently passing or
  flatly rejecting.
- Schema: `evidence` is required and non-empty on capability claims, and
  rejected on every other claim type (fail-closed, never silently
  ignored). Address evidence is validated eagerly with the same clear
  error as address claims.
- The sample report now carries a `c2-capability` claim that audits to
  PARTIAL (2 of 3 items confirmed; missing: import `socket`).
- Honest limitation, documented in the README: no call-graph or
  cross-reference evidence yet — a symbol that exists but is never called
  still counts as present; the conjunction, not a call graph, is what
  catches most dead-code cases.
- Tests: 104 → 125 (new `tests/test_capability.py`: schema validation,
  GROUNDED/PARTIAL/MANGLED/UNGROUNDED/UNSUPPORTED paths, stripped and
  packed binaries, PE, and CLI text + JSON output).

## 0.1.0 — 2026-10-24

- Initial release: deterministic claim verification (GROUNDED / MANGLED /
  UNGROUNDED / UNSUPPORTED) for address, string, import, endpoint, and
  section claims against ELF32/64 and PE32/32+ binaries, plus anti-AI
  prompt-injection trap scanning (Talos A3 taxonomy).
