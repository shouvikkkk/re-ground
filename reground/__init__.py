"""re-ground: ground-truth checker for agent reverse-engineering reports.

Audits an agent's claimed findings (addresses, strings, imports, endpoints,
sections) against the actual binary, and flags anti-AI prompt-injection traps
before triage. Stdlib only, offline, no LLM calls.
"""

__version__ = "0.1.0"
