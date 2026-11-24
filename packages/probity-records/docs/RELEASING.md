# Release probity-records

`probity-records` is released by `.github/workflows/release.yml`, from a GitHub release whose tag is
`probity-records-vX.Y.Z`. Its TypeScript twin, `@probityai/records-verify`, has its own version and its own
[release page](../../../node/probity-records-verify/RELEASING.md); the two share `vectors/shared/`, so a release that
changes a shared vector releases both.

## Prepare the release

One bump change carries all of these, and lands through the merge train with the changes it releases:

1. `version` in `pyproject.toml` and the `probity-records` entry of `uv.lock`, which sits beside it and is not part
   of the root workspace lock. CI runs `uv lock --check` before the tests, so a lock that disagrees with the
   `pyproject.toml` fails.
2. The dependency ranges. `agent-evidence-verify` and `agent-evidence-vectors` are bounded above by the next release
   that has not been tested; raise a bound only after the suite below passes against the version it admits.
3. `CHANGELOG.md`: the `## Unreleased` heading becomes `## X.Y.Z (YYYY-MM-DD)`, and a change to a shared vector says
   which readers must learn it (a reader that has not learned a new revocation kind refuses the vectors that name it).
4. `vectors/shared/` regenerated with `uv run python scripts/gen_shared_vectors.py vectors/shared` when a generator
   or a wire constant changed, in the same change. The generator writes wall-clock times into `approvals.json`,
   `constraints.json`, `effects.json`, `grants.json` and `quorum.json`, so a regeneration rewrites those five files;
   commit only the files whose cases the change owns.

## Prove it

The proof is the one the package's CI job runs, on the bump change's head:

```sh
cd packages/probity-records
uv lock --check
sh scripts/test.sh          # builds the pinned collector first when PROBITY_OTELCOL is unset
cd ../../node/probity-records-verify
npm ci && node --test test/*.test.ts
```

`tests/test_otel.py` runs a real OpenTelemetry collector and fails, never skips, without one. Heavy runs go to
HiPerGator or a box, not to a workstation (`hpg_run.sh`, `box_run.sh`).

## Publish

1. Land the bump on `main` with the CI of the merge train green.
2. Pause other merges while the release runs: `merge-freeze set probityai/probity --reason "release
   probity-records-vX.Y.Z" --expires 24h --clear-on release:probity-records-vX.Y.Z`.
3. Publish a non-prerelease GitHub release tagged `probity-records-vX.Y.Z` on that commit of `main`. `release.yml`
   resolves the tag to this member (`scripts/workspace.py release-target`), refuses a tag that does not match
   `pyproject.toml` or is not on `main`, and builds and checks the files with `python-build.yml`.
4. The `publish-probity-records` job uploads those files from the `pypi` environment with a GitHub build attestation.
   It tries PyPI trusted publishing first. When PyPI has no publisher for the project, it uploads with the
   `PYPI_API_TOKEN` secret of the `pypi` environment, and a release never waits on a pypi.org setting. Either way,
   `.github/scripts/verify_pypi_upload.py` then reads every file's digest back from PyPI and compares it to the file
   built here.
5. Check the release in a clean environment: `pip install probity-records==X.Y.Z`, then run the quick start in
   `README.md`; and compare `sha256` of the wheel in the PyPI JSON (`https://pypi.org/pypi/probity-records/X.Y.Z/json`)
   with the `SHA256SUMS` of the run.

When the workflow cannot publish, upload the files its `build` job retained (`python-distributions-probity-records`)
with the account token from the keyring, `twine upload`, and read the digests back the same way. Never publish files
built anywhere else.

## After publishing

The post-publish change moves what names the release: the version lines of the repository pages that `pin-refresh`
rewrites and the ranges of the packages that depend on this one. A repository that reads this package raises its pin
in its own change once the release is on PyPI.

Keep published versions and tags immutable. A change to released bytes is a new version.
