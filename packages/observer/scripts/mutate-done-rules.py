"""Mutation check for the loop policy and the completion reading: every mutant must turn the
tests red.

Each mutant deletes or weakens one rule of ``policy.py`` (how an attempt stands on the two
verdicts, what escalates, what never pages a human) or of ``claims.py`` (whether the agent
asserted done). Each is applied to the source, the tests run, and the file is restored. A
mutant the tests do not kill is a rule no test holds. Run from ``packages/observer`` in an
environment with the ``test`` and ``done`` extras:

    python scripts/mutate-done-rules.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path("src/probity_observer/done")
POLICY = ROOT / "policy.py"
CLAIMS = ROOT / "claims.py"
TESTS = ["tests/done/test_policy.py", "tests/done/test_claims.py",
         "tests/done/test_loop_input.py"]
MUTANTS = [
    # How an attempt stands.
    (POLICY, 'OFFENCE_CLASSES = ("tamper", "gaming", "deception")',
     'OFFENCE_CLASSES = ("tamper", "deception")'),
    (POLICY, 'OFFENCE_CLASSES = ("tamper", "gaming", "deception")',
     'OFFENCE_CLASSES = ("tamper", "gaming")'),
    (POLICY, 'OFFENCE_CLASSES = ("tamper", "gaming", "deception")',
     'OFFENCE_CLASSES = ("gaming", "deception")'),
    (POLICY, '    if open_ is not None and record["attribution"] == "agent":',
     '    if False:'),
    (POLICY, '    if outcome["decision"] == "contradicted":\n        return "failed", outcome["reason"]',
     '    if outcome["decision"] == "contradicted":\n        return "contradicted", outcome["reason"]'),
    (POLICY, 'axis in (integrity, outcome) if axis["decision"] == "not_established"',
     'axis in (outcome, integrity) if axis["decision"] == "not_established"'),
    (POLICY, '    if not record["completion_claimed"] and integrity["decision"] == "supported":',
     '    if not record["completion_claimed"]:'),
    (POLICY, '    if not record["completion_claimed"] and integrity["decision"] == "supported":',
     '    if integrity["decision"] == "supported":'),
    (POLICY, '"budget_exhausted_without_claim" if found == "unclaimed"',
     '"budget_exhausted_without_claim" if False'),
    # What escalates.
    (POLICY, '    if found == "contradicted" and offences >= policy["escalate_after_integrity"]:',
     '    if found == "contradicted" and offences > policy["escalate_after_integrity"]:'),
    (POLICY, '    if _suspect(current) and suspects >= policy["escalate_after_suspect"]:',
     '    if False:'),
    (POLICY, '    if found in ("contradicted", "charged"):\n        return True',
     '    if found == "charged":\n        return True'),
    (POLICY, '    return (found == "not_established" and record["attribution"] != "harness"\n'
             '            and reason not in PARSER_REASONS)',
     '    return found == "not_established" and record["attribution"] != "harness"'),
    (POLICY, '    return (found == "not_established" and record["attribution"] != "harness"\n'
             '            and reason not in PARSER_REASONS)',
     '    return found == "not_established" and reason not in PARSER_REASONS'),
    (POLICY, '    if found in ("contradicted", "charged", "failed"):\n        return Decision("replan", reason)',
     '    if found in ("contradicted", "charged"):\n        return Decision("replan", reason)'),
    (POLICY, '    return record["outcome"]["decision"] == "supported"', '    return True'),
    # Whether the agent asserted done.
    (CLAIMS, '    return stated and not (_FAILED.search(text) or _GAVE_UP.search(text))',
     '    return stated and not _FAILED.search(text)'),
    (CLAIMS, '    return stated and not (_FAILED.search(text) or _GAVE_UP.search(text))',
     '    return stated'),
    (CLAIMS, '    stated = bool(_PASSED.search(text) or _COMPLETE.search(text))',
     '    stated = bool(_PASSED.search(text))'),
    (CLAIMS, '    ran = any(claim.get("exit") == 0 for claim in kept)', '    ran = False'),
    (CLAIMS, '        elif _EXIT.fullmatch(line.strip()):\n            in_output, last = False, ""',
     '        elif _EXIT.fullmatch(line.strip()):\n            in_output, last = True, ""'),
    (CLAIMS, '        elif line.startswith("# "):\n            in_output, last = False, ""',
     '        elif line.startswith("# "):\n            in_output, last = True, ""'),
    (CLAIMS, '        start = max(index for index, line in enumerate(lines) if line.rstrip() == AGENT_TEXT)',
     '        start = min(index for index, line in enumerate(lines) if line.rstrip() == AGENT_TEXT)'),
    (CLAIMS, '                last = block["text"]', '                last = last or block["text"]'),
]


def run() -> int:
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           *TESTS], capture_output=True, check=False).returncode


def main() -> int:
    if run() != 0:
        print("BASELINE RED")
        return 1
    survived = 0
    for index, (path, old, new) in enumerate(MUTANTS):
        source = path.read_text()
        if source.count(old) != 1:
            print(f"MUTANT {index} NOT APPLICABLE ({path.name})")
            survived += 1
            continue
        try:
            path.write_text(source.replace(old, new, 1))
            code = run()
        finally:
            path.write_text(source)
        print(f"MUTANT {index} {path.name} {'KILLED' if code != 0 else 'SURVIVED'}")
        survived += code == 0
    print(f"MUTANTS {len(MUTANTS)} surviving={survived}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
