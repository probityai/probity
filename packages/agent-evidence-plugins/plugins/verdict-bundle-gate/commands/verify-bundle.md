---
description: Replay a verdict bundle with the pinned probity-verify and report the decision
argument-hint: <bundle.zip> [--allow supported,not_established]
allowed-tools: Bash(python3:*)
---

Run the gate on the bundle and report its output unchanged:

!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/verify_bundle.py" $ARGUMENTS`

If the line starts with FAIL, say so first, quote the reason, and do not treat the
bundle's claim as established.
