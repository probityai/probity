# Current ADK publication consumer

This placement runs the unchanged twelve-case protected ticket reference against
selected ADK source `e94c2e726a269e0f04e2e4b202f5c131c80c20de`, version 2.11.0.
A standard-library probe verifies all 778 installed SDK Python Gitblob identities
before imports or scripted native calls.

The original reference at
`c774e0711e4a30c31cdfb184c1e4495a249fbdd0`, protected Observer target at
`4a50e61471355611121a578f3a4c22daa931d419`, grammar, package version and
retained October 2 originals remain unchanged. This placement adds trusted
source selection and a small consumer sample. It is installation and current
source compatibility, not a previously installed version upgrade.

## Retained installed-consumer run

`retained/` holds the packet from the successful installed-consumer run on the
selected ADK source: the twelve cases, the pre-run plan and source manifest, the
host policy, the reader report and the two publication gate receipts. The
frozen observer modules, the producer adapter and the two built wheels are held
as SHA-256 digests in `retained/WITHHELD-SOURCES.json`; the producing operation
is run by the operator's runtime and is not part of this tree. The 778 selected
SDK Python files stay in the packet and are checked against
`native-source-selection.json`.

```sh
# Starting directory: interop/adk-current-consumer-2026-10-03
set -eu
python -I -B verify_retained.py
```

The command exits 0 only when the retained host policy matches its pin, the kept
sources plus the withheld digests equal the manifest chosen before the run, the
public reader (the ADK reference package in `../adk-ticket-2026-10-02` with the
public observer) reproduces the retained report bytes, and the retained
publication receipt names that report. The workflow builds the reader
environment from this repository at the pushed commit, with hash-selected
dependencies and build tools.

## Use the maintained publication sample

The small standard-library sample takes a retained reference packet, a separately
selected policy and an operator-selected trusted installed reader. It invokes
the actual installed gate twice under Python isolation, preserves each original
stdout/stderr/status receipt, requires identical decision bytes, and writes a
publication receipt only after both gates admit the exact finite reference.
Timeout, failed exit, malformed decision or changed repeated output fails the
command and leaves the attempted receipts for inspection.

```sh
# Starting directory: interop/adk-current-consumer-2026-10-03
set -eu
../../.venv/bin/python publish_reference.py /absolute/current-run/packet \
  --policy /absolute/current-run/host-policy.json \
  --policy-sha256 HOST_SELECTED_POLICY_SHA256 \
  --python /absolute/reader-env/bin/python \
  --reader /absolute/reader-env/bin/probity-adk-read \
  --output /absolute/new-publication-receipt
```

A real report-upload job must depend on this command succeeding. The sample
supports only `probity-google-adk-ticket-v0` and its twelve declared attempts.
It does not accept arbitrary application traces. CapturePlugin registration
for other applications and the finite protected-effect reader have separate
contracts in the original reference.

## Verify original semantics

The pure controls check source/wheel/cache selection, policy and installation
paths, typed gate decisions, literal repeat, failure/timeout status retention and
absence of publication on refusal. The framework-free semantic controls consume
the genuine retained packet and reject altered terminal success, invented lost
callbacks, MCP error-as-success, omitted model/session history and failed or
unclosed capture even after the mutant's artifact hashes are reselected.

```sh
# Starting directory: interop/adk-current-consumer-2026-10-03
set -eu
/absolute/reader-env/bin/python -I -B -m pytest -c /dev/null \
  -o cache_dir=/absolute/owned-pytest-cache test_publish_reference.py test_native_current.py -q
```

The observed native report preserves error after committed effect and incomplete
caller closure with revision 1, exhausted retries, first/last plugin callback
omissions and tied timestamp ordering. Publication admission is evidence
integrity for this bounded reference; task success, model quality, producer
acceptance, recurring outside adoption and independent effect custody remain
separate. No registry release, actual MCP transport or real-model quality is
claimed. Compatibility maintenance remains with Probity through the Observer
repository. The focused upstream sample is subject to host review and protections.

The full upstream test job uses a separately selected correction to the
Kubernetes executor and client-scoped cleanup tests. Its
[source reference](../../docs/reference/ADK-FULL-TOX-SOURCE.md) records the patch,
license, complete tree and refusal controls. The native SDK selection above
stays unchanged.
