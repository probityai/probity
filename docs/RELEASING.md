# Release a checked Python distribution

PyPI 0.1.0 contains the current verifier implementation and CLI. Source 0.1.1
adds eight existing source-coverage inputs as package resources. It changes no
claim profile, decision, reason or error exit. The sample inputs remain authored
synthetic records, not an outside run or a consumer's authority choice.

## Read the installed sample

Build and check the wheel with the release workflow before using this recipe.
From the source root, install the checked artifact into a separate environment:

```sh
uv venv verify-env --python 3.12
uv pip install --python verify-env/bin/python dist/probity_verify-0.1.1-py3-none-any.whl
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

The `Python distribution` workflow builds on pushes, pull requests and manual
runs. It installs hash-pinned tools from `requirements-release.lock`, builds a
wheel and source distribution, and checks their contents against the source.
It rebuilds a wheel from the source distribution and runs both installed
consumers. Its artifact retains input hashes, the source commit, install reports
and consumer results. These are build checks, not outside adoption.

The build job has read access only. The separate publish job runs for a
non-prerelease GitHub release whose `vX.Y.Z` tag matches `pyproject.toml` and
belongs to main. It downloads the same checked files. Only that job receives
`id-token: write`; it has no account token or password fallback.

Configure the [PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
with owner `probityai`, repository `probity-verify`, workflow
`python-distribution.yml`, and environment `pypi`. The pinned PyPA publish action
uploads [PyPI attestations](https://docs.pypi.org/attestations/producing-attestations/).
Confirm the registry files and provenance after publication. A prepared workflow
does not establish that this account binding exists or that an upload ran.

Regenerate the release-tool lock with:

```sh
uv pip compile --python-version 3.12 --generate-hashes --no-header --no-annotate \
  requirements-release.in --output-file requirements-release.lock
```

Keep existing package versions and tags immutable. Publish changed artifact
contents as a new version. Update current install instructions after the actual
registry release; preserve historical tested source pins and input digests.
