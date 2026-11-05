# Agent Evidence Observer (prototype)

[![PyPI](https://img.shields.io/pypi/v/agent-evidence-observer.svg)](https://pypi.org/project/agent-evidence-observer/)
[![Downloads (PePy)](https://static.pepy.tech/badge/agent-evidence-observer)](https://pepy.tech/projects/agent-evidence-observer)

Check retained agent-write records and selected native framework reports offline.

Use it in agent harnesses and evaluation pipelines that need to check replayable action records or put a consumer gate on retained reports.

Install the root package: `pip install agent-evidence-observer==0.2.0`.

## Quick start

Check a retained signed packet with the released package. You need Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/probityai/probity && cd probity/packages/agent-evidence-observer
uvx --from agent-evidence-observer==0.2.0 agent-evidence-observer verify scripts/fixtures/broker-packet
```

The command prints:

```text
{"noDetectedGap": "true", "status": "verified", "witnessScope": "PEER"}
```

`scripts/fixtures/broker-packet/` holds a signed packet, its history, the public keys and the file tree. The
operator's runtime wrote the packet, and this package checks it offline. `noDetectedGap` means the broker's
file-tree snapshots found no change it did not make. It does not mean every agent effect was seen.
See [Installation and profile selection](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/INSTALLATION.md) for the source-pinned recipes.

## Status

The root distribution is version 0.2.0. Every record says `witnessScope: PEER`: the witness key runs on the same
host under the same operator, so the records show what this broker saw, not what an independent
observer saw. The operator's runtime produces the signed records; this package verifies them offline.
`launch-agent` runs an unmodified agent in docker or apptainer and records, from outside it, every program it ran and every file it changed.
`agent-evidence-witness` runs a separately operated witness: a record it co-signs verifies as `EXTERNAL`
when the reader pins a different operator for the witness key. It needs the `witness` extra, which is not yet
in a released wheel.

## Documentation

Start with [worked examples](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/README.md) to follow a practical question,
then open its technical reference for commands and exact evidence.

| page | read it for |
| --- | --- |
| [Start a project](https://github.com/new?template_name=evidence-starter&template_owner=probityai) | a template that records a write with this package and checks it with probity-verify, pinned and in CI |
| [Component tour](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/OVERVIEW.md) | every part of the prototype in one paragraph each, with links: replay, evaluation history, A2A, AAE |
| <a name="run-the-demo"></a>[Running the demo](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/RUNNING.md) | the full install with tests, and what each output field means |
| <a name="claim-and-trust-boundary"></a><a name="tests-and-remaining-gaps"></a><a name="linux-boundary-gate"></a><a name="consumer-admission"></a><a name="roadmap"></a>[Design, trust boundary and roadmap](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/DESIGN.md) | what each mechanism checks and does not establish, recovery, and the roadmap |
| [Agent launcher](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/AGENT-LAUNCHER.md) | run an unmodified agent with three outside sensors and check its claims with probity-verify |
| [Witness ledger](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/WITNESS-LEDGER.md) | signed begin and terminal receipts, and how a reader checks them |
| [Separately operated witness](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/WITNESS-SERVER.md) | run a witness on another host, co-sign records 2-of-2, and catch a witness that forks its log |
| [Installation and profile selection](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/INSTALLATION.md) | choose the root wheel, a separate profile wheel or a selected source reader; runtime requirements and installed examples |
| [Release the root package](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/RELEASING.md) | qualify a wheel and source distribution, then publish with a bound source tag |
| [Atomic native reader](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/ATOMIC-NATIVE-READER.md) | install an offline reader for selected native delegation runs and their refusal controls |
| [Witnessed run selection](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/WITNESSED-RUN-SELECTION.md) | check a selected run against consumer-retained opening and closing checkpoints |
| [Approved refund retries](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/APS-REFUND-RETRIES.md) | run the APS approval and local SQLite example, then check retries and refusals with a separately installed reader |
| [Refund handoff conformance](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/docs/REFUND-HANDOFF-CONFORMANCE.md) | verify admission, recovery, handoff, effect and reconciliation bindings against 80 public vectors |

## License

Apache License 2.0; see [LICENSE](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/LICENSE).
