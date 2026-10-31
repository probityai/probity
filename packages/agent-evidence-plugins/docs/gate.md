# Gate reference

`plugins/verdict-bundle-gate/scripts/verify_bundle.py` has one decision rule and two ways in.

## Direct

`verify_bundle.py BUNDLE.zip [--allow supported,not_established]`

| exit | meaning |
| --- | --- |
| 0 | `probity-bundle replay` succeeded and the recomputed decision is allowed |
| 1 | replay succeeded; the decision is not allowed (for example `contradicted`) |
| 2 | replay failed: tampered or malformed bundle, missing file, replay timeout, or the verifier could not run |

The replay rechecks every artifact binding against the digests the case pins and recomputes the decision from the stored case and policy. It then compares the recomputed packet with the stored `decision.json`, so editing the stored decision to a better one fails with exit 2.

## Hook

`verify_bundle.py --hook` reads the hook payload on stdin. Every string in the payload is split on whitespace and quotes; a token whose file name matches a bundle pattern and that names an existing file (absolute, or relative to the payload's `cwd`) is replayed. Any failure prints the reason on stderr and exits 2, which Claude Code returns to the agent. A payload that names no bundle exits 0 with no output, so the hook costs nothing on unrelated tool calls. A zip whose name does not match a pattern is never replayed.

## Pinning

The script runs `probity-bundle` from the environment, or `uvx --from probity-verify==0.3.0 probity-bundle`. `PINNED` in the script and the test dependency in `pyproject.toml` move together.
