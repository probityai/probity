"""Score this package on agent-evidence-vectors' a2a-jcs corpus through the corpus's own harness.

The harness (agent_evidence_vectors.a2ajcs.run_external) runs `node src/cli.ts jcs <target> <input>`
once per vector the rfc8785 target owns and writes its report. Every owned vector must pass, and
the count must be the one this pin carries (53 at agent-evidence-vectors 0.37.0), so a corpus that
silently shrinks fails here too. Usage: python test/a2a_jcs_conformance.py REPORT.json
"""

from __future__ import annotations

import json
import os
import sys

from agent_evidence_vectors import a2ajcs

EXPECTED_VECTORS = 53


def main(report_path: str) -> int:
    os.environ["A2A_JCS_TARGET"] = "rfc8785"
    rc = a2ajcs.run_external(str(a2ajcs.ROOT), ["node", "src/cli.ts", "jcs"], report_path, "probity-records-verify")
    with open(report_path, encoding="utf-8") as handle:
        totals = json.load(handle)["totals"]
    print(f"a2a-jcs rfc8785: {totals['pass']} of {totals['vectors']} pass (expected {EXPECTED_VECTORS} of {EXPECTED_VECTORS})")
    if rc != 0 or totals["vectors"] != EXPECTED_VECTORS or totals["pass"] != EXPECTED_VECTORS:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
