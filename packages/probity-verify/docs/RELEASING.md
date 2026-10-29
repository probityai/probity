# Release a checked Python distribution

PyPI 0.2.3 contains the current verifier implementation and CLI, and the source
is 0.2.3. It carries the eight source-coverage inputs as package resources,
added in source 0.1.1, and reads DSSE envelopes and completion receipts; the
[changelog](../CHANGELOG.md) lists every change. The sample inputs remain authored
synthetic records, not an outside run or a consumer's authority choice.

## Read the installed sample

Build and check the wheel with the release workflow before using this recipe.
From the source root, install the checked artifact into a separate environment:

```sh
uv venv verify-env --python 3.12
uv pip install --python verify-env/bin/python dist/probity_verify-0.2.3-py3-none-any.whl
```

Run Python from that environment. The data comes from the installed package:

```python
import json
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory

from probity_verify import adjudicate

with TemporaryDirectory() as directory:
    root = Path(directory)
    for item in files("probity_verify.samples").iterdir():
        if item.name.endswith((".json", ".html", ".txt")):
            (root / item.name).write_bytes(item.read_bytes())
    result = adjudicate(
        json.loads((root / "case.json").read_bytes()),
        json.loads((root / "policy-june.json").read_bytes()),
        root,
    )
print(result["decision"], result["reason"])
```

It prints `contradicted selected_span_missing_from_record`. The installed CLI
and API use the same inputs and decisions. The April policy returns
`not_established` with `witness_outside_source_window`. The complete report
returns `supported` with `all_selected_spans_present`. Valid decisions exit 0;
malformed input exits 2 without a verdict. A consumer gate must read `decision`.

`scripts/check-installed.py` exercises all three results through the installed
API and CLI from an outside directory. It also checks malformed input. It needs
no source checkout for its sample data.

## Build and publish

The workspace's [release process](../../../docs/architecture/MONOREPO.md#releases) builds and
publishes this package. The shared `python-build.yml` workflow builds it on every pull request that
touches it, with the hash-pinned tools in the root `requirements-release.lock`. It runs this
member's `scripts/check-artifacts.py`, `scripts/check-artifacts-controls.py`,
`scripts/check-installed.py` and `scripts/build-recipes.py --check` against the built files, and
retains input hashes, the source commit, install reports and consumer results. These are build
checks, not outside adoption.

The release-tool lock selects setuptools 84.0.0. The source backend requires
setuptools 77.0.3 or later for its SPDX license metadata, so compatible existing
build environments do not have to use the release toolchain's exact version.

The recipe index binds the implementation and fixture bytes, and the
install-relevant keys of the package manifest (build system, name, version,
Python requirement, runtime dependencies, scripts and setuptools layout).
A change to an optional extra, such as a dependency-bot bump of the `a2a`
pin, does not make it stale. After changing a bound input, run
`uv run --directory packages/probity-verify python scripts/build-recipes.py`
from the repository root and retain its generated files.

A release is a non-prerelease GitHub release tagged `probity-verify-vX.Y.Z` on a commit of main,
with `X.Y.Z` equal to this `pyproject.toml` version. `release.yml` publishes the files that run built
and checked, with a GitHub build attestation and PyPI attestations, through the PyPI trusted publisher
with owner `probityai`, repository `probity`, workflow `release.yml` and environment
`pypi`. Releases 0.1.0 and 0.1.1 used tags `v0.1.0` and `v0.1.1`, which stay as they are.

The root release-tool lock is regenerated from the repository root with:

```sh
uv pip compile --python-version 3.12 --generate-hashes --no-header --no-annotate \
  requirements-release.in --output-file requirements-release.lock
```

Keep existing package versions and tags immutable. Publish changed artifact
contents as a new version. Update current install instructions after the actual
registry release; preserve historical tested source pins and input digests.
