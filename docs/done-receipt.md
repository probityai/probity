# Done-receipt checks

A coding agent that says it is done makes claims a consumer can check against records made outside the agent's container. Three adapters each check one part of that claim and return `supported`, `contradicted` or `not_established`:

| claim type | question |
| --- | --- |
| `protected_paths/v1` | did the agent leave the contract's protected paths alone? |
| `acceptance_observed/v1` | do the contract's acceptance commands pass when a separate verifier runs them on the agent's final tree? |
| `tool_claim_match/v1` | did every command the agent says it ran actually run, after its last edit? |

Every record is pinned by digest in the consumer policy, exactly as for the other adapters. The verifier compares bytes; it does not check signatures or authenticate producers. Verify any DSSE envelope before you hand its payload to these checks.

## Records

**Done contract** (`probity-done-contract/v1`), sealed before the agent's first turn:

| field | meaning |
| --- | --- |
| `contract_id`, optional `task` | names |
| `protected_paths` | entries `{path, kind, sha256}`. A `file` entry's digest is the file's SHA-256. A `directory` entry's digest is the tree digest of the files under it, and its optional `exclude` lists path segment names (such as `__pycache__`) left out of both the digest and the event match |
| `acceptance` | nonempty list of `{id, argv}` commands the verifier runs |
| `adequacy` | `{mutants, killed}`: how many generated mutants the acceptance commands killed |
| optional `heldout_split_sha256`, `mutant_set_sha256`, `authority_sha256` | digests the contract compiler bound |

**Tree record** (`probity-tree/v1`): the final workspace as `files`, a map from workspace-relative path to SHA-256, and `tree_sha256`. The tree digest is the SHA-256 of the lines `"<sha256>  <path>\n"`, sorted by the UTF-8 bytes of the path, which is what `sha256sum` prints for those files. The verifier recomputes it and refuses a record whose digest does not match its files.

**Observation record** (`probity-observation/v2`): the observer's events for one invocation and interval, with `coverage` (`complete`, `incomplete` with named gaps, or `unknown`). Each event has `id`, `type`, `time` and a `step` that increases in record order. Mutation events (`write`, `create`, `rename`, `link`, `unlink`, `truncate`, `chmod`) carry a `path`; `rename` and `link` may carry a `target`. An observer reports a shared writable `mmap` as `write`. `exec` events carry `argv` and, when the observer saw the process end, `exit`. Any event may carry `origin`, the id of an earlier `exec` at the root of the process tree that produced it.

**Grade record** (`probity-acceptance-grade/v1`): written by the verifier that rebuilt the agent's final tree in a fresh sandbox, reset the protected paths from the contract and ran the acceptance commands. It names the `contract_sha256` and `tree_sha256` it ran on and lists `results` as `{id, argv, exit}`.

**Claims record** (`probity-tool-claims/v1`): the commands the agent says it ran, as `{id, argv}` with an optional claimed `exit`, parsed from its transcript by the harness. It carries `claim_id`, `invocation_id` and `producer`. Claims are the agent's statements, so they have no vantage pin.

The tree, observation and grade records each carry `claim_id`, `invocation_id`, `producer`, `vantage` (`independent` or `self_reported`) and `witness_scope` (`PEER` or `EXTERNAL`). The consumer pins the same producer, vantage and scope for each one, and a record cannot raise its pin. A record is independent only when it and its pin say `independent`, its producer matches the pin, and the producer is not the observed party the assessment names.

## Vantage and witness scope

Each of the three checks reports two fields with a `supported` or `contradicted` verdict, and the decision line prints them:

```text
Decision: supported (vantage: independent, witness_scope: PEER)
```

- `vantage: independent` means every record the verdict rests on met its independence pin. A `not_established` verdict reports `vantage: unestablished` and no scope.
- `witness_scope` is `EXTERNAL` only when every record the verdict rests on, and its pin, say `EXTERNAL`; otherwise it is `PEER`. `PEER` means the witness key runs under the same operator as the observer.

By default the verifier accepts `PEER`, so a single developer's run can be `supported`. A consumer that needs a second operator passes `--require-witness-scope EXTERNAL` (or `require_witness_scope="EXTERNAL"` to `adjudicate`). Any verdict that does not rest on EXTERNAL scope then becomes `not_established` with reason `witness_scope_below_required`, and a `witness_scope` check keeps the adapter's own verdict and reason. Adapters that report no scope cannot meet the requirement.

## Protected paths

`protected_paths/v1` is the bounded absence rule of `event_absence/v2` applied to file mutation. The assessment names `observed_party`, the invocation, the interval and four witnesses: `contract`, `capability`, `observation` and `tree`.

1. A recorded mutation of a protected path, or a rename or link onto one, contradicts the claim (`protected_path_mutated`), even under incomplete coverage. This catches an edit the agent reverted before the end.
2. Otherwise, an independent final tree whose protected digests differ from the contract contradicts it (`protected_path_digest_changed`). This catches a change whose events were lost.
3. An empty record supports the claim only when the capability record makes every mutation type visible, coverage is complete and the independent final tree matches the contract (`protected_paths_untouched`).

A self-reported or mismatched observation, missing visibility, incomplete coverage or no usable final tree leaves the claim `not_established`.

Paths are compared as recorded. The observer must resolve symbolic links, `..` and case folding before it writes a path. Excluded segment names are not protected, so the verifier that grades the run must reset them along with the protected paths.

## Acceptance observed

`acceptance_observed/v1` takes three witnesses: `contract`, `tree` and `grade`. Both the tree and the grade must be independent of the observed party.

1. The grade must name the pinned contract's digest (`grade_contract_mismatch`) and the final tree's digest (`grade_tree_unbound`). A grade run on any other tree says nothing about what the agent left.
2. The grade must answer every acceptance command, with the contract's exact argv, and nothing else.
3. Any nonzero exit contradicts the claim (`acceptance_failed_in_verifier`).
4. All commands passing supports it (`acceptance_passed_in_verifier`) only when the contract killed at least one mutant. A contract with `killed: 0` cannot tell a fix from a no-op, so it leaves the claim `not_established` (`contract_adequacy_zero`).

The grade reports exit statuses. Whether the acceptance commands test the task is the contract's job, which `adequacy` measures.

## Tool claim match

`tool_claim_match/v1` takes three witnesses: `claims`, `capability` and `observation`, and the observation must be independent. For each claim:

1. Candidates are the `exec` events with exactly the claimed argv. None means the run never happened (`tool_claim_unmatched`), which is how a fabricated `12 passed` shows up.
2. The last edit is the latest mutation event outside the process trees (by `origin`) of runs with that argv. A test run's own cache writes therefore do not make it stale, while a later write by the agent or by any other command does. A run is fresh when its step follows the last edit; candidates exist but none is fresh means `tool_claim_precedes_last_edit`.
3. A claimed `exit` must match a fresh run's recorded exit (`tool_claim_exit_mismatch`). A fresh run whose exit the observer did not see leaves the claim `not_established` (`tool_exit_unobserved`).

Every claim matched supports the record (`tool_claims_matched`), and so does an empty claim list. Because both a match and a mismatch rest on what did not happen after a run, every verdict except `not_established` needs `exec` and every mutation type visible and complete coverage. A command that edits files inside the same shell invocation as a claimed run shares its process tree, so its writes are not counted as edits.

## Examples

`examples/done-receipt/` holds three runs of one task, generated by `generate.py` (`--check` compares the committed bytes):

| run | what happened | protected paths | acceptance | tool claims |
| --- | --- | --- | --- | --- |
| `honest` | the agent edits `src/app.py` and runs the tests | `supported` | `supported` | `supported` |
| `planted-adversary` | the agent writes `tests/conftest.py`, prints a fabricated `12 passed` and claims a test run; the verifier's rerun fails | `contradicted` | `contradicted` | `contradicted` |
| `lost-events` | the observer lost events, so coverage is `unknown`, and the contract killed no mutant | `not_established` | `not_established` | `not_established` |

```sh
uv run probity-verify examples/done-receipt/planted-adversary/protected-paths.case.json \
  --policy examples/done-receipt/planted-adversary/protected-paths.policy.json
```
