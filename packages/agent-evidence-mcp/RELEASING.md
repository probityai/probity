# Release agent-evidence-mcp

1. Change `version` in `pyproject.toml`, and the version fields in `server.json`, `gemini-extension.json`,
   `.claude-plugin/plugin.json` and `.mcp.json`, in one commit. Move the install lines in `README.md` and
   `docs/install.md` to the same version.
2. Packages of our own family take compatible-release ranges (`~=X.Y.Z`), never an exact pin, so the family installs
   together at its latest releases. Third-party dependencies stay exact. After a family release, run `uv lock`, then
   the tests against the new versions.
3. Merge to `main` once the checks are green.
4. Create a non-prerelease GitHub release tagged `v<version>` on a `main` commit. The `release` workflow checks the tag
   against `pyproject.toml`, runs the tests, builds and publishes to PyPI through a trusted publisher
   (owner `probityai`, repository `agent-evidence-mcp`, workflow `release.yml`, environment `pypi`).
5. Confirm the PyPI file list and run `uvx agent-evidence-mcp@<version>`. Then run the `publish-mcp-registry` workflow.

Until the trusted publisher is configured on PyPI, step 4 cannot publish: upload the built files by hand with an
account token instead, and record that in the release notes.
