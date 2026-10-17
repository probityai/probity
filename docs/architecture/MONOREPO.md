# Repository layout

This repository is one uv workspace and one Cargo workspace. Each member keeps its own distribution
name, version, licence and release tag. This page records each layout decision and the reason for it.

## Layout

```
packages/<member>/   one Python distribution each: pyproject.toml, README.md, LICENSE, src/, tests/
crates/<crate>/      one Rust crate each (none yet)
scripts/             repository tools: workspace.py, the shared README lint
tests/               tests of the repository tools
.github/workflows/   ci.yml (entry point), one reusable workflow per member, python-build.yml, release.yml
```

Members today: `packages/probity-verify` (distribution `probity-verify`) and `packages/probityai`
(distribution `probityai`, the `probity` command).

## Decisions

| Topic | Decision | Reason |
| --- | --- | --- |
| Member names | A member's directory, distribution, import package and tag prefix come from its own `pyproject.toml`. Nothing reads the repository name. | A repository rename or a renamed member changes one file. `scripts/workspace.py` finds members by scanning `packages/*/pyproject.toml`. |
| Locking | One `uv.lock` at the root for every member. | One resolution: members that depend on each other are tested together against the same versions they will meet. A member that ever needs a conflicting dependency declares it with `[tool.uv] conflicts`, or leaves the workspace; neither is needed today. |
| Root project | The root `pyproject.toml` is not a package (`package = false`). It holds the workspace, the `dev` group, the root pytest configuration and the shared ruff configuration. | Nothing is published from the root, so no member inherits metadata by accident. |
| Lint and types | One `[tool.ruff]` table at the root, ruff's default rule set, run on the whole tree in CI. No type checker yet. | One configuration applies to every member. Widening the rule set (98 findings under E, F, W, I, B and UP on 2026-10-17) and adding a type checker are each one change to this table and its fixes. |
| Tests | `uv run python -m pytest` at the root runs `tests/` and every member's tests. Each member also runs alone from its directory with its own pytest configuration. | Test file basenames are unique across the workspace; pytest refuses a duplicate at collection, so a clash cannot hide a module. |
| Licences | Each member and crate carries its own `LICENSE`, declared in its package metadata. The root `LICENSE` (Apache-2.0) covers repository files and is the one GitHub shows. | A scanner reads the same licence from a wheel as before. CC0 data and Apache-2.0 code can sit side by side. |
| Release toolchain | One hash-pinned `requirements-release.lock` at the root; every Python member builds with setuptools from it. | The build of every distribution is reproducible with one set of pinned tools. |
| Dependabot | One uv entry for `/` (the workspace lock), one GitHub Actions entry for `/`. A cargo entry for `/` arrives with the first crate. | One lock means one update stream; grouped updates give one pull request per ecosystem. |
| CODEOWNERS | One line per member directory. | A member can get its own reviewers in one line. |
| Cargo | Root `Cargo.toml` with `resolver = "3"`, shared `[workspace.package]` and `[workspace.lints]`, and an empty `members` list. The change that imports the first crate sets `members = ["crates/*"]`. | Cargo refuses a member glob that matches no directory. The lint table is written now so every imported crate inherits it (`unwrap_used`, `expect_used`, `undocumented_unsafe_blocks` and `await_holding_lock` denied). |
| Go module | The vectors Go module moves to `vectors/go.mod` with module path `github.com/probityai/probity/vectors`, tagged `vectors/vX.Y.Z`. | Go resolves a module in a subdirectory only from a tag prefixed with that directory. The archived repository's module gets a `// Deprecated: use github.com/probityai/probity/vectors` line. No `go.work` is needed for one module. |

## The `probity` command

`probityai` installs `probity`. The launcher holds no list of subcommands: each distribution adds its
own with an entry point in the `probityai.cli_subcommands` group.

```toml
[project.entry-points."probityai.cli_subcommands"]
verify = "probity_verify.cli:register"
```

The value is a callable `register(subparsers) -> None`. It adds a parser named after the entry point
and attaches its handler with `probityai.cli.register_leaf(parser, handler=...)`; the handler takes the
parsed arguments and returns the exit status. A distribution may register several subcommands, one
entry point each. The register-and-attach shape follows pytest-style plug-in discovery, so a
distribution with its own argparse subcommands can join with no change to them.

The launcher refuses, with exit 2 and the entry point's name, a subcommand that fails to import or to
register, two entry points with one name, a registration that replaces another subcommand, and a
registration that adds no parser of its own name. Nothing is skipped silently: a hidden subcommand looks the same as one never installed.

`probity-verify` keeps its `probity-verify` console script: it is the released command of a released
distribution, not an alias added here.

## CI

`ci.yml` runs on every pull request and every push to main. Its `changes` job runs
`scripts/workspace.py changes <base> <head>`, which marks a member when a file under its directory
changed, when a workspace member it depends on changed, or when a shared file changed (anything outside
`packages/` except documentation). Pushes to main check everything. Each member has its jobs (for
`probity-verify`, the reusable `probity-verify.yml`), and `python-build.yml` builds and checks the
distribution the way a release does. The `ci-ok` job needs every job and fails if any needed job failed
or was cancelled; it is the one required status check.

## Releases

Each member is released on its own, by a non-prerelease GitHub release whose tag is
`<distribution>-v<version>`, for example `probity-verify-v0.2.0`. `release.yml` resolves the tag with
`scripts/workspace.py release-target`, refuses a tag that names no member, does not match the member's
version or is not on main, builds and checks with `python-build.yml`, and publishes those files with a
GitHub build attestation and PyPI attestations. Existing tags (`v0.1.0`, `v0.1.1`) stay.

The tag prefix is the distribution name, not the directory name, so the prefix stays right if a
directory moves. The vectors tag is therefore `agent-evidence-vectors-vX.Y.Z`, and its Go tag is
`vectors/vX.Y.Z`. Crates follow the same rule (`jcs-admit-vX.Y.Z`, `dsse-vX.Y.Z`)
when their release job is added in the import step.

### PyPI trusted publishers to enter

One publisher per distribution, each with owner `probityai`, repository `probity`, workflow
`release.yml`, and its own GitHub environment. A separate environment per distribution lets each one
carry a deployment rule that admits only its own tags.

| PyPI project | Environment | Environment tag rule |
| --- | --- | --- |
| probity-verify | `pypi-probity-verify` | `probity-verify-v*` |
| probityai | `pypi-probityai` | `probityai-v*` |
| agent-evidence-observer | `pypi-agent-evidence-observer` | `agent-evidence-observer-v*` |
| agent-evidence-admission | `pypi-agent-evidence-admission` | `agent-evidence-admission-v*` |
| agent-evidence-vocabulary | `pypi-agent-evidence-vocabulary` | `agent-evidence-vocabulary-v*` |
| agent-evidence-vectors | `pypi-agent-evidence-vectors` | `agent-evidence-vectors-v*` |
| probity-ratchet | `pypi-probity-ratchet` | `probity-ratchet-v*` |

The `probity-verify` publisher used for 0.1.1 names repository `probity-verify`, workflow
`python-distribution.yml` and environment `pypi`; the row above replaces it.

### Install line and versions

The README's pinned install line is `pip install probity-verify==0.1.1`, the current PyPI release. When
`probityai` is first released, the README's install line becomes `pip install probityai==X.Y.Z`.
`probityai` depends on `probity-verify>=0.2.0`, the first release that registers `verify`, so
`probity-verify` 0.2.0 is published first. Every member keeps its own version line, and `probityai`
pins the lowest member release that registers each of its subcommands.
