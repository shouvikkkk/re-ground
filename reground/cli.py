"""CLI: reground audit | reground traps."""

import argparse
import json
import sys

from . import __version__
from .claims import load_report, ClaimError
from .traps import scan_binary
from .verify import audit_binary, BinaryError, GROUNDED


def _print_audit_text(binary, verdicts, summary):
    print("re-ground audit: %s" % binary)
    print("-" * 60)
    for v in verdicts:
        print("[%s] %s (%s) %s" % (v.verdict, v.claim_id, v.claim_type,
                                   v.value))
        if v.detail:
            print("         %s" % v.detail)
        if v.evidence:
            print("         evidence: %s" % v.evidence)
    print("-" * 60)
    print("%d claims: %d grounded, %d mangled, %d ungrounded, %d unsupported"
          % (summary["total"], summary["GROUNDED"], summary["MANGLED"],
             summary["UNGROUNDED"], summary["UNSUPPORTED"]))


def _print_audit_json(binary, verdicts, summary):
    print(json.dumps({"binary": binary,
                      "verdicts": [v.to_dict() for v in verdicts],
                      "summary": summary}, indent=2))


def _print_traps_text(binary, findings):
    print("re-ground traps: %s" % binary)
    print("-" * 60)
    if not findings:
        print("no anti-AI payloads detected")
    for f in findings:
        loc = ("vaddr %#x" % f.vaddr) if f.vaddr is not None else \
            ("offset %#x" % f.offset)
        print("[%s] %s (%s)" % (f.severity.upper(), f.pattern_id, loc))
        print("         matched: %r" % f.matched_text)
        print("         %s" % f.description)
    print("-" * 60)
    print("%d finding(s)" % len(findings))


def _print_traps_json(binary, findings):
    print(json.dumps({"binary": binary,
                      "findings": [f.to_dict() for f in findings]}, indent=2))


def cmd_audit(args):
    try:
        report = load_report(args.report)
    except (ClaimError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    binary = args.binary or report.binary
    try:
        verdicts, summary = audit_binary(binary, report)
    except (BinaryError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.format == "json":
        _print_audit_json(binary, verdicts, summary)
    else:
        _print_audit_text(binary, verdicts, summary)
    # Exit 0 only when every claim is grounded; anything else needs a human.
    if all(v.verdict == GROUNDED for v in verdicts):
        return 0
    return 1


def cmd_traps(args):
    try:
        findings = scan_binary(args.binary)
    except (BinaryError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.format == "json":
        _print_traps_json(args.binary, findings)
    else:
        _print_traps_text(args.binary, findings)
    return 1 if findings else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="reground",
        description="Ground-truth checker for agent reverse-engineering "
                    "reports (v%s). Stdlib only, offline." % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="audit an agent's report against "
                                           "the binary")
    p_audit.add_argument("--binary", default=None,
                         help="binary to check (default: the report's "
                              "'binary' field)")
    p_audit.add_argument("--report", required=True,
                         help="agent report JSON file")
    p_audit.add_argument("--format", choices=("text", "json"), default="text")
    p_audit.set_defaults(func=cmd_audit)

    p_traps = sub.add_parser("traps", help="scan a binary for anti-AI "
                                           "prompt-injection traps")
    p_traps.add_argument("--binary", required=True, help="binary to scan")
    p_traps.add_argument("--format", choices=("text", "json"), default="text")
    p_traps.set_defaults(func=cmd_traps)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
