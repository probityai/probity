#!/usr/bin/env python3
"""Mutation-check the tool outputs: break one behaviour at a time and require the tests to fail.

Each mutation is an exact source replacement. A mutation whose target text is missing is an
error (the check would otherwise pass over code it no longer covers), and a mutation the tests
do not catch fails the run. The sources are restored afterwards.

Usage: python scripts/mutation_check.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "src/agent_evidence_mcp/tools.py"
SERVER = ROOT / "src/agent_evidence_mcp/server.py"

MUTATIONS = [
    (TOOLS, '"decision": result["decision"],', '"decision": "supported",'),
    (TOOLS, '"reason": result["reason"],\n        "claim_type"', '"reason": "all_selected_spans_present",\n        "claim_type"'),
    (TOOLS, '"policy_sha256": result["policy_sha256"],', '"policy_sha256": "0" * 64,'),
    (TOOLS, '"checks": result["checks"],', '"checks": [],'),
    (TOOLS, 'or ".." in path.parts', 'or False'),
    (TOOLS, 'if scenario not in SAMPLES:', 'if False:'),
    (TOOLS, 'row["vectors"] = len(vectors)', 'row["vectors"] = len(vectors) + 1'),
    (TOOLS, '"totals": report.get("totals"),', '"totals": {},'),
    (TOOLS, '"page": rows[offset:offset + limit],', '"page": rows[offset + 1:offset + limit],'),
    (TOOLS, 'if offset + limit < len(rows) else None', 'if offset + limit <= len(rows) else None'),
    (TOOLS, '"ok": done.returncode == 0,', '"ok": True,'),
    (TOOLS, 'if base in path.parents and path.is_file():', 'if path.is_file():\n            pass\n        if False:'),
    (TOOLS, 'result: dict[str, Any] = {"ok": True, "corpus": corpus, "entry": entry,', 'result: dict[str, Any] = {"ok": True, "corpus": corpus, "entry": {},'),
    (TOOLS, '"values": entry.get("values"),', '"values": None,'),
    (TOOLS, '"admitted": result.ok,', '"admitted": True,'),
    (TOOLS, '"matched": {"algorithm": result.matched[0], "digest": result.matched[1]} if result.matched else None,', '"matched": None,'),
    (TOOLS, 'if (artifact_text is None) == (artifact_base64 is None):', 'if False:'),
    (TOOLS, '"canonical_hex": canonical.hex(),', '"canonical_hex": "",'),
    (TOOLS, '"sha256": hashlib.sha256(canonical).hexdigest(),', '"sha256": "0" * 64,'),
    (TOOLS, 'admit = jcs_admit.admit if profile == "rfc8785" else jcs_admit.admit_ijson', 'admit = jcs_admit.admit'),
    (TOOLS, 'if profile not in ("rfc8785", "ijson"):', 'if False:'),
    (TOOLS, 'dsse.verify_threshold(envelope.encode("utf-8"), keys, threshold)', 'dsse.verify_threshold(envelope.encode("utf-8"), keys, 1)'),
    (TOOLS, '"accepted_keys": list(verified.accepted_keys),', '"accepted_keys": [],'),
    (TOOLS, '"payload_sha256": hashlib.sha256(payload).hexdigest(),', '"payload_sha256": "0" * 64,'),
    (TOOLS, '"payload_type": verified.payload_type,', '"payload_type": "text/plain",'),
    (TOOLS, 'if not trusted_keys or len(trusted_keys) > MAX_TRUSTED_KEYS:', 'if False:'),
    (SERVER, '"readOnlyHint": True', '"readOnlyHint": False'),
    (SERVER, '"openWorldHint": False', '"openWorldHint": True'),
    (SERVER, 'title=title, annotations', 'title="", annotations'),
]


def survived(path: Path, old: str, new: str) -> bool:
    original = path.read_text(encoding="utf-8")
    if original.count(old) != 1:
        raise SystemExit(f"mutation target not found exactly once in {path.name}: {old!r}")
    try:
        path.write_text(original.replace(old, new), encoding="utf-8")
        done = subprocess.run(
            [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        return done.returncode == 0
    finally:
        path.write_text(original, encoding="utf-8")


def main() -> int:
    survivors = []
    for path, old, new in MUTATIONS:
        alive = survived(path, old, new)
        print(("SURVIVED" if alive else "killed  "), path.name, old[:60].replace("\n", " "), flush=True)
        if alive:
            survivors.append(old)
    print(f"{len(MUTATIONS) - len(survivors)} of {len(MUTATIONS)} mutations killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
