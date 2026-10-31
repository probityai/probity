# agent-evidence-plugins

Plugins for Claude Code and Cursor that replay a verdict bundle with probity-verify and stop the agent when the bundle is tampered with or its decision is not the one you allowed.

It is for people who let an agent consume a server's or a lab's verdict (a done receipt, a claim check) and want the check to run on every use, not when someone remembers.

```sh
pip install probity-verify==0.2.4
git clone --branch v0.1.0 https://github.com/probityai/agent-evidence-plugins
cd agent-evidence-plugins
python3 plugins/verdict-bundle-gate/scripts/verify_bundle.py tests/fixtures/honest.decision.zip
python3 plugins/verdict-bundle-gate/scripts/verify_bundle.py tests/fixtures/honest-failure.decision.zip
```

The first bundle replays to a supported decision and exits 0. The second replays cleanly but its recomputed decision is contradicted, so the gate exits 1:

```text
OK tests/fixtures/honest.decision.zip: supported (done_receipt_accepted)
FAIL tests/fixtures/honest-failure.decision.zip: decision is contradicted (acceptance_failed_in_verifier); allowed: supported
```

A bundle that fails replay (a changed artifact, a forged decision, a corrupt ZIP, a missing file, or no verifier installed) exits 2. The gate fails closed: a check that did not run is never a pass.

## Install in Claude Code

```sh
claude plugin marketplace add probityai/agent-evidence-plugins
claude plugin install verdict-bundle-gate@agent-evidence-plugins
```

The plugin registers a PostToolUse hook. After a Write, Edit, Bash or MCP tool call it looks for files named `*.decision.zip` or `*.verdict.zip` in the call's input and output, replays each, and exits 2 on a bad one so Claude Code hands the reason back to the agent. `/verdict-bundle-gate:verify-bundle <zip>` runs the same gate by hand.

## Install in Cursor

Copy `cursor/rules/verify-verdict-bundle.mdc` to `.cursor/rules/`, `cursor/hooks.json` to `.cursor/hooks.json`, and `plugins/verdict-bundle-gate/scripts/verify_bundle.py` to `scripts/`. The rule tells the agent to run the gate before relying on a bundle. Cursor's after-execution hooks report but do not block, so the rule is what holds the line there.

## Settings

| variable | default | meaning |
| --- | --- | --- |
| `PROBITY_BUNDLE_ALLOW` | `supported` | decisions that pass: any of `supported`, `contradicted`, `not_established` |
| `PROBITY_BUNDLE_GLOBS` | `*.decision.zip,*.verdict.zip,decision.zip,verdict.zip` | file names the hook treats as bundles |
| `PROBITY_BUNDLE_CMD` | `probity-bundle`, else `uvx` at the pinned version | command that runs the replay |

## Status

Version 0.1.0. The gate and both plugin shells are tested against real bundles built from the done-receipt corpus of agent-evidence-vectors. The ZIP is unsigned, so the gate tells you the bundle is self-consistent and that its decision recomputes; it does not tell you who produced it. Establish the policy and the producer separately.

## Documentation

| page | read it for |
| --- | --- |
| [Fixtures](https://github.com/probityai/agent-evidence-plugins/blob/main/tests/fixtures/README.md) | where the two test bundles come from and how to rebuild them |
| [Gate reference](https://github.com/probityai/agent-evidence-plugins/blob/main/docs/gate.md) | exit codes, hook payload matching and what the replay checks |

## Next

- Tag v0.1.0 and submit the marketplace to the Cursor directory.
- Block on a producer signature once the verifier exposes one.
