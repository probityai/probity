# Release agent-evidence-mcp

1. Change `version` in `pyproject.toml`, and the version fields in `server.json`, `gemini-extension.json` (at the
   repository root), `.claude-plugin/plugin.json` and `.mcp.json`, in one commit. Move the install lines in `README.md` and
   `docs/install.md` to the same version.
2. Packages of our own family take a floor and a cap at the next major (`>=X.Y.Z,<1`), never an exact pin and never `~=0.X.Y`: on a 0.x package that form stops at the next minor, and the family
   releases a minor for every additive change (`~=0.26.0` kept 0.30.0 out and failed `family-resolves` for two days). The
   `family` CI job installs the latest releases of the whole family on every pull request and daily. Third-party dependencies stay exact. After a family release, run `uv lock`, then
   the tests against the new versions.
3. Merge to `main` once the checks are green.
4. Create a non-prerelease GitHub release tagged `agent-evidence-mcp-v<version>` on a `main` commit. The root `release`
   workflow checks the tag against `packages/agent-evidence-mcp/pyproject.toml`, builds and checks the distributions,
   and publishes to PyPI through a trusted publisher with PEP 740 attestations (owner `probityai`, repository
   `probity`, workflow `release.yml`, environment `pypi`). Once PyPI is published it pushes
   `ghcr.io/probityai/agent-evidence-mcp:<version>`, signs it by digest with cosign and attaches build provenance, and
   publishes `server.json` to the official MCP Registry.
5. Confirm the PyPI file list shows a provenance file for each distribution, run `uvx agent-evidence-mcp@<version>`,
   and `docker run --rm -i ghcr.io/probityai/agent-evidence-mcp:<version>`.

Never upload release files by hand with an account token. A hand upload carries no attestation, and once a filename
is on PyPI the workflow can never publish it again (PyPI answers "400 File already exists"). Versions 0.2.0 to 0.2.3
carry no attestation: 0.2.0 predates this workflow, and 0.2.1 to 0.2.3 were uploaded by hand after the release run
failed with `invalid-publisher`, because the trusted publisher was not configured on PyPI. If the workflow cannot publish, fix the trusted publisher and release the next version.
