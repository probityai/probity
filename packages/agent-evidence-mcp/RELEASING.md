# Release agent-evidence-mcp

1. Change `version` in `pyproject.toml`, and the version fields in `server.json`, `gemini-extension.json`,
   `.claude-plugin/plugin.json` and `.mcp.json`, in one commit. Move the install lines in `README.md` and
   `docs/install.md` to the same version.
2. Packages of our own family take compatible-release ranges (`~=X.Y.Z`), never an exact pin, so the family installs
   together at its latest releases. Third-party dependencies stay exact. After a family release, run `uv lock`, then
   the tests against the new versions.
3. Merge to `main` once the checks are green.
4. Create a non-prerelease GitHub release tagged `v<version>` on a `main` commit. The `release` workflow checks the tag
   against `pyproject.toml`, runs the tests, builds and publishes to PyPI through a trusted publisher with PEP 740
   attestations (owner `probityai`, repository `agent-evidence-mcp`, workflow `release.yml`, environment `pypi`).
   In parallel it pushes `ghcr.io/probityai/agent-evidence-mcp:<version>`, signs it by digest with cosign and attaches
   build provenance. When both succeed it publishes `server.json` to the official MCP Registry.
5. Confirm the PyPI file list shows a provenance file for each distribution, run `uvx agent-evidence-mcp@<version>`,
   and `docker run --rm -i ghcr.io/probityai/agent-evidence-mcp:<version>`.

Never upload release files by hand with an account token. A hand upload carries no attestation, and once a filename
is on PyPI the workflow can never publish it again (PyPI answers "400 File already exists"). Versions 0.2.0 to 0.2.3
carry no attestation: 0.2.0 predates this workflow, and 0.2.1 to 0.2.3 were uploaded by hand after the release run
failed with `invalid-publisher`, because the trusted publisher above was not configured on PyPI. If the workflow cannot publish, fix the trusted publisher and release the next version.
