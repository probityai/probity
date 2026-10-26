# Install a pinned version and check a claim

Probity Verify checks a claim against local evidence and a consumer-held policy.
Use it when you need a decision you can replay from the same bytes.
Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are required.

Version 0.2.1 is published on [PyPI](https://pypi.org/project/probity-verify/0.2.1/).
Its wheel modules are identical to the source at tag `probity-verify-v0.2.1`, commit
`46fd69e3dd10c39b2a39c09f00163d4319071b67`, and the wheel carries the source-coverage
sample inputs as package resources. The [release guide](RELEASING.md) gives the
installed-resource recipe and the artifact checks.

## Install the published package

Run these commands from a new working directory:

```sh
uv venv --python 3.12 verify-env
uv pip install --python verify-env/bin/python probity-verify==0.2.1
samples="$(verify-env/bin/python -c 'import importlib.resources as r; print(r.files("probity_verify") / "samples")')"
verify-env/bin/probity-verify "$samples/case.json" --policy "$samples/policy-june.json"
```

Python 3.12 is the recipe's tested runtime. Choose another supported Python
version with `--python` when you create the environment.
The registry install uses the released wheel. The command uses that installed package, without
`uv run`, an editable install or a source checkout's Python path.
The case, policies and artifacts come from the installed package, so the package version
alone pins them.

The release files and their SHA-256 digests are recorded in [release.json](release.json):

| file | SHA-256 |
| --- | --- |
| `probity_verify-0.2.1-py3-none-any.whl` | `032bbef522b4990d90754085a7cb5ef0c52d03e9fbe4cd631d13bacf04617309` |
| `probity_verify-0.2.1.tar.gz` | `22878b464e5c14e14543483f2427302702880bda02837df787f090f2f2920790` |

To require these digests at install time, put the line
`probity-verify==0.2.1 --hash=sha256:032bbef522b4990d90754085a7cb5ef0c52d03e9fbe4cd631d13bacf04617309`
in a requirements file and install it with `uv pip install --require-hashes -r`.

The packet includes:

```text
Case: "source-coverage-demo"
Claim: source_text_coverage/v1
Decision: contradicted
Reason: selected_span_missing_from_record
```

The retained source contains a selected passage that the report omits.
This decision concerns that passage and the supplied policy, not the entire report.

## Replay the other outcomes

Add `--json` for a structured decision:

```sh
verify-env/bin/probity-verify "$samples/case.json" \
  --policy "$samples/policy-april.json" --json
verify-env/bin/probity-verify "$samples/case-complete.json" \
  --policy "$samples/policy-complete.json" --json
```

The April policy returns `not_established`. A June capture cannot establish
what the source contained in April. The complete report returns `supported`.
All three valid decisions exit zero. A contradiction is a valid decision,
so a CI consumer must inspect the `decision` field if it needs a policy gate.

## Use this checkout's recipe index

The [recipe index](recipes.json) binds the case files, policies, artifacts,
implementation and install-relevant package metadata in its own source snapshot. From the root
of that checkout, install its source into a separate environment:

```sh
git rev-parse HEAD > ../verify-source-commit.txt
uv venv --python 3.12 ../verify-source-env
uv pip install --python ../verify-source-env/bin/python .
../verify-source-env/bin/probity-verify examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json --json
```

Start from the exact reviewed source commit that contains the index, and retain
that commit with the installed artifact. Use the index's argument arrays from
the checkout root, replacing `probity-verify` with the installed executable's
path. These instructions build a wheel from the selected source. A source
candidate can have newer package metadata than the latest registry release.
The index's `distribution.status` records that the package name has a public
release; `fixture_scope` separately records that its recipes use checkout files.
Neither field claims that a source candidate has been uploaded.

## Retained historical source recipe

The earlier installed-source recipe used commit
`4eb2bac542f784b68c524b99cac9eccb32b0e5cc` with Python 3.12. It built its own
wheel and replayed the three source-coverage outcomes shown above. That source
had six adapters and predates `brokered_file_write/v1`; it is not an install pin
for every recipe in the current index. To replay that historical source, use a
new directory and keep its code and inputs together:

```sh
git clone https://github.com/probityai/probity.git historical-source
git -C historical-source checkout --detach 4eb2bac542f784b68c524b99cac9eccb32b0e5cc
uv venv --python 3.12 historical-env
uv pip install --python historical-env/bin/python ./historical-source
historical-env/bin/probity-verify historical-source/examples/source-coverage/case.json \
  --policy historical-source/examples/source-coverage/policy-june.json
```

## Errors and scope

A missing file, invalid JSON or invalid case exits two and prints an error
to standard error without a verdict. An artifact digest mismatch refuses the
case; do not edit the pinned sample bytes to repair it. Reinstall the pinned
package version instead.

Run from the directory that contains `verify-env`.
The verifier resolves artifact paths from the case's directory by default.
Use `--artifact-root` only when you deliberately keep artifacts elsewhere.

The verifier checks local bytes. It does not fetch URLs or authenticate the
authority named by a policy. The consumer must choose and pin that authority.
See [Running the verifier](running.md) for input fields and adapter examples,
and [Replayable decisions](bundles-and-index.md) to share a checked packet.

## Run the source quick start

This is the README's earlier quick start, kept as written. It retains its historical code and input snapshot:

```sh
git clone https://github.com/probityai/probity && cd probity
git checkout 588db582c50558f3e2a928be89ffc135188afcdb
uv run probity-verify examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json
```

It prints the same decision packet as the installed package, with `Decision: contradicted` and `Reason: selected_span_missing_from_record`. `uv run pytest` runs the test suite.
