# Seal an Inspect log so a regrade is visible

An evaluation log is edited after the run: an importer restamps its eval set, a
pipeline resolves image digests into its metadata, a reviewer regrades samples.
You need to tell "the same run, graded differently" from "a different run" without
hashing the whole `.eval` file, which every one of those edits changes.

Install the extra and run Inspect as usual:

```sh
pip install 'agent-evidence-observer[inspect]==0.2.0'
inspect eval task.py --model mockllm/model --log-dir logs
ls logs
```

Each finished log gets a manifest beside it, `<log>.sealed`. The suffix is not
`.json` on purpose: Inspect lists any `.json` name that starts like a log as a log.

## What the manifest holds

Two digests, both SHA-256 over RFC 8785 canonical JSON of a chosen subset of the
log, read only through `inspect_ai.log.read_eval_log`:

| Field | Covers | Moves when |
| --- | --- | --- |
| `execution_digest` | run identity, model, packages, source revision, declared sandbox, each sample's id, epoch, uuid, sandbox, file names and setup | the run or its declared environment differs |
| `results_digest` | status, scorers, results, reductions, each sample's scores, error and limit | a sample is regraded, errors or hits a limit |

An importer's restamp, a metadata enrichment and a tag edit move neither digest.
The manifest also records the Inspect version that read the log, the counts
(`samples_in_log`, `samples_with_error`, `dataset_samples`, `epochs`), the
fields it covers, the fields it leaves out and why, and `not_captured`: the
container observation, input-file bytes and grader artifacts, which Inspect's
hooks API does not expose. Absent means not captured, never empty.

## Check a log later

```sh
python -m probity_observer.inspect_binding verify logs/<log>.eval
```

It prints `execution and grading both reproduce`, `same execution, different
grading`, `same grading, different execution` or `neither execution nor grading
reproduces`, and exits 1 for anything but the first. A log with no manifest exits
2: nothing was recorded, which is not a failed check.

A second implementation can check the digests without Inspect. Write the cover as
JSON, claim its canonical bytes, and pin the manifest's digest as the claimed
bytes' SHA-256 in a `jcs_canonical/v1` case for `agent-evidence-verify` 0.5.0 or later (`probity-verify` 0.4.0 or later before the rename):
`supported` means the digest is the SHA-256 of the cover's RFC 8785 form.
`interop/inspect-sealed-manifest-2026-11-03/test_real_run.py` builds that case.

## What it does not show

The manifest covers what the log recorded. It does not show that the run executed
as logged, that a container was isolated, what bytes a sample or grader used, or
that the operator is independent of the producer (`doesNotAssert`). The hook reads
event data and never writes to it; it records and cannot stop a run. Set
`AGENT_EVIDENCE_INSPECT_SEAL=off` to disable it. A log at a remote location is
left unsealed and the hook says so.
