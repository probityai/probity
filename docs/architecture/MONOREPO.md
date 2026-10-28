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
(distribution `probityai`, the `probityai` command).

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

## The `probityai` command

`probityai` installs the `probityai` command, the word a user already typed to install it. The launcher holds no list of subcommands: each distribution adds its
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
GitHub build attestation and PyPI attestations, from the publish job of that distribution in the `pypi` environment. Existing tags (`v0.1.0`, `v0.1.1`) stay.

A fix to a release series that main has moved past is cut from the branch
`maint/<distribution>-<major>.<minor>` (for example `maint/probity-ratchet-0.1`), which starts from
main so it carries the same workflows and checks. `release.yml` accepts a tag on that branch for
that series only, and refuses a tag on any other commit that is not on main.

The tag prefix is the distribution name, not the directory name, so the prefix stays right if a
directory moves. The vectors tag is therefore `agent-evidence-vectors-vX.Y.Z`, and its Go tag is
`vectors/vX.Y.Z`. Crates follow the same rule (`jcs-admit-vX.Y.Z`, `dsse-vX.Y.Z`)
when their release job is added in the import step.

### What a release file may contain

A release file is built from the committed tree of one commit and from nothing else. CI does this
with a fresh checkout; any build outside CI runs `python3 scripts/build-from-tag.py <tag>`, which
exports the tag with `git archive` (tracked files only, so a file hidden by `.git/info/exclude` or
left untracked is absent) and builds from the export. `python-build.yml` then runs
`scripts/check-dist-clean.py` over `dist/`: it opens every wheel and source distribution and fails
on a private path (`TODO*.md`, `research/`, `.handoff/`, `.claude/`), on a private name in any file,
and on any path that `scripts/dist-allowlist.toml` does not list for that distribution. The private
names are not in the repository: they come from the `DIST_CLEAN_PRIVATE_NAMES` repository secret
(one name per line, also set as a Dependabot secret), the script pins the SHA-256 of the sorted
list, and a missing or altered list stops the check with exit 2, so a run without the secret fails
rather than passes. A finding names the list entry by number. A local `build-from-tag.py` run needs
the same variable in its environment. A new
member needs its own table in the allowlist (a test pins this). A PyPI file cannot be replaced, so
this check is the only point at which a leak is cheap to fix.

### PyPI trusted publishers to enter

Every PyPI project released from this repository has the same publisher: owner `probityai`, repository
`probity`, workflow `release.yml`, environment `pypi`. That covers `probity-verify`, `probityai`,
`agent-evidence-observer`, `probity-ratchet` and `probity-ratchet-cases` now, and
`agent-evidence-admission`, `agent-evidence-vocabulary` and `agent-evidence-vectors` when they move in.

The ratchet code ships two PyPI projects, so it moves in as two members, each with its own tag:
`probity-ratchet-vX.Y.Z` and `probity-ratchet-cases-vX.Y.Z` (the second is the prefix its cases releases
already use). Neither has a PyPI upload workflow today; each gets its publish job in `release.yml` in
the change that imports it. A tag resolves to the member whose whole name precedes `-v<version>`, so
`probity-ratchet-cases-v0.3.0` never resolves to `probity-ratchet` (a test pins this).

`release.yml` has one publish job per distribution, and each runs only when the resolved tag names that
distribution, so the job that receives the publishing token for one project never runs for another. PyPI
trusted publishing does not accept a reusable workflow, so each publish job carries its steps itself. The
`pypi` environment takes a deployment rule that admits only release tags (`*-v*`), and a test in `tests/`
fails when a member has no publish job.

The `probity-verify` publisher used for 0.1.1 names repository `probity-verify`, workflow
`python-distribution.yml` and environment `pypi`; the row above replaces it.

### Install line and versions

The README's pinned install line is `pip install probity-verify==0.1.1`, the current PyPI release. When
`probityai` is first released, the README's install line becomes `pip install probityai==X.Y.Z`.
`probityai` depends on `probity-verify>=0.2.0`, the first release that registers `verify`, so
`probity-verify` 0.2.0 is published first. Every member keeps its own version line, and `probityai`
pins the lowest member release that registers each of its subcommands.
