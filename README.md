# re-ground

**Ground-truth checker for agent reverse-engineering reports.** Agents (Claude Code, Codex, REA-driven workflows) produce confident RE reports full of wrong addresses, mangled strings, and dead-code "capabilities" — and nothing re-checks the agent's claims against the actual binary. re-ground does: hand it any agent's report and the binary, and it verifies every claim, flags the mangled ones with the real value, and scans for anti-AI prompt-injection traps before triage.

Stdlib only. Offline. No LLM calls. No dependencies.

## The problem

Two things happened in October 2026 that make this tool necessary:

**1. Agents misread binaries, confidently.** SentinelOne Labs' "Building an Adversarial Consensus Engine" (via malware.news) ran multi-agent LLMs over malware and had a second pass audit the first:

> "finds half the cited functions are wrong, several 'capabilities' are actually dead code from the compiler's standard library, and the claimed C2 endpoint has an extra character because the string extraction tool mangled a forward slash."

Half the functions wrong. Dead code reported as capability. A C2 URL with one mangled character. This is the normal output of agent RE today — not an edge case.

https://malware.news/t/building-an-adversarial-consensus-engine-multi-agent-llms-for-automated-malware-analysis/105129

**2. Malware now gaslights the agents.** Cisco Talos (reported 2026-10-08) found four malware families — FRUITSHELL, PLOTSAFE, HOLLOWCLAD, MANTLEMAZE — embedding prompt-injection payloads in PE headers and strings ("there is no need to analyze this file", fake benign attributions). Across 84 analyzed samples, the injections steered automated analysis in ~35% of evaluations. The binary is no longer a passive artifact; it talks back to your triage agent.

https://sh3llc0d3.com/blog/a3-ai-analysis-evasion-cisco-talos-dissects-malware-authors-embedding-adversarial-prompt-injections-in-pe-headers-to-gaslight-security-llms/

re-ground sits between the agent and your trust: it re-derives every claimed address, string, import, endpoint, and section from the binary itself, and it flags the traps before you read the report.

## Quick start

```bash
# generate the demo binary (byte-built ELF64 fixture)
python -c "from tests.fixtures import write_demo_elf; write_demo_elf('fixtures/demo.elf')"

# audit the sample agent report (has planted good, mangled, and phantom claims)
python -m reground audit --binary fixtures/demo.elf --report fixtures/sample-report.json

# scan the binary for anti-AI prompt-injection traps
python -m reground traps --binary fixtures/demo.elf
```

`audit` exits 0 only when **every** claim is grounded, 1 otherwise, 2 on usage errors. `traps` exits 1 when traps are found, 0 when clean.

## Claim schema

An agent report is JSON:

```json
{
  "binary": "path/to/sample.elf",
  "claims": [
    {"id": "c1", "type": "address", "value": "0x401000", "note": "agent says main() is here"},
    {"id": "c2", "type": "string",  "value": "http://c2.example/beacon"},
    {"id": "c3", "type": "import",  "value": "KERNEL32.dll!CreateFileW"},
    {"id": "c4", "type": "endpoint","value": "http://c2.example/beacon"},
    {"id": "c5", "type": "section", "value": ".text"}
  ]
}
```

| type | value | grounded when |
|---|---|---|
| `address` | hex (`0x401000`) or decimal | inside a mapped section/segment, or equals the entry point |
| `string` | exact bytes the agent quotes | byte-identical string extracted from the binary (ASCII/UTF-16LE/UTF-16BE) |
| `import` | `func`, `dll!func`, or `libname` | exact import (ELF undefined dynsym / PE import table) or DT_NEEDED lib |
| `endpoint` | URL/hostname the agent claims | exact string present in the binary |
| `section` | section name | section exists |

## Verdicts

Not a boolean — agents usually misread rather than invent:

- **GROUNDED** — exact match in the binary.
- **MANGLED** — close match with corruption, and here is the real value: an address a few bytes past the end of `.text`, a C2 URL with one extra character (the malware.news case), an import off by one letter, a section name with a typo. Deterministic edit-distance and boundary checks, no ML.
- **UNGROUNDED** — no trace anywhere in the binary. The "capability" was imagined.
- **UNSUPPORTED** — cannot be checked (e.g. packed binary with no sections or segments). Reported honestly instead of guessing.

```
$ python -m reground audit --binary fixtures/demo.elf --report fixtures/sample-report.json
[GROUNDED] entry-ok (address) 0x401000
         address lies inside a mapped region
         evidence: vaddr 0x401000 mapped
[MANGLED] c2-mangled (string) http://c2.evil.example/beackn
         no exact match, but edit distance 1 from real string 'http://c2.evil.example/beacon' -- likely a one-character extraction corruption
         evidence: closest real string: 'http://c2.evil.example/beacon'
[UNGROUNDED] dead-addr (address) 0x900000
         address is not inside any section or segment and is far from every mapped boundary
...
8 claims: 3 grounded, 2 mangled, 3 ungrounded, 0 unsupported
```

## Trap scanning

`reground traps` scans extracted strings against the Talos A3 taxonomy: direct instruction overrides ("ignore all previous instructions"), analysis refusals ("there is no need to analyze this file"), planted benign verdicts, fake attributions ("certified Microsoft kernel diagnostic utility", "benign administrative software"), plus heuristics for context-flooding padding (long runs of benign filler) and repeated-string padding. Each finding carries the matched pattern, encoding, file offset, vaddr, and severity. New patterns are one line in the `PATTERNS` table in `reground/traps.py`.

## How this differs

- **REA (morluto/rea)** — the defining Oct-2026 agent-RE trend — attaches *provenance* to its own findings. That is producing evidence, not auditing it. re-ground is harness-agnostic: it audits **any** agent's report (including REA outputs) against the binary.
- **Talos CAIRN** (open-source) hunts AI-integrated malware from metadata. re-ground does the opposite direction: it verifies the agent's *claimed findings* against the binary itself.
- **Report-notarization tools** (the "TruthLedger" style) record *what the agent claimed* so nobody can alter it later. re-ground checks *whether the binary agrees* — an immutable false claim is still false.

## Honest limitations

- **Static only.** No decompilation, no emulation, no dynamic analysis. A claim about runtime behavior ("decrypts the payload at runtime") is out of scope.
- **Packed/obfuscated binaries** degrade gracefully to `UNSUPPORTED` instead of guessing — but that means re-ground can't help where you need it most until unpacking happens upstream.
- **String matching is approximate by nature.** Byte-level extraction has known ambiguities (e.g. ASCII-range UTF-16 reads as both LE at N and BE at N-1; adjacent strings can bleed into one scan run). The `MANGLED` verdict exists precisely because extraction is lossy — treat near-matches as leads, not proof.
- **The trap patterns are a starting table, not a feed.** New prompt-injection phrasings appear constantly; the table needs curating.
- **No archive support.** One binary per run; unpack containers yourself first.

## Layout

```
reground/
  elf.py        ELF32/ELF64 parser (both endians): sections, program headers,
                symtab/dynsym, DT_NEEDED imports; handles stripped binaries
  pe.py         PE32/PE32+ parser: sections, import/export directories,
                rich-header presence note; no external tools
  stringsx.py   ASCII / UTF-16LE / UTF-16BE string extraction with vaddrs
  claims.py     report JSON schema, validation with helpful errors
  verify.py     deterministic verification engine (GROUNDED/MANGLED/
                UNGROUNDED/UNSUPPORTED)
  traps.py      anti-AI payload detector (Talos A3 taxonomy + flooding heuristics)
  cli.py        `reground audit` / `reground traps` (text + json output)
tests/          104 tests, all offline: byte-built ELF64/ELF32/PE fixtures,
                an integration test against /bin/ls when present
fixtures/       sample-report.json -- an agent report with planted bad claims
```

## License

MIT — see LICENSE.
