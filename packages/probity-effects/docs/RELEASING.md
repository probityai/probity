# Release probity-effects

1. Set `version` in `pyproject.toml`, update the install line in `README.md`, and merge to main
   with CI green.
2. Publish a non-prerelease GitHub release whose tag is `probity-effects-v<version>` on that main
   commit. `release.yml` resolves the tag to this member, builds and checks the files with
   `python-build.yml`, and the `publish-probity-effects` job uploads them to PyPI with
   attestations from the `pypi` environment.
3. PyPI's trusted publisher for the project is owner `probityai`, repository `probity`, workflow
   `release.yml`, environment `pypi`. A project with no publisher yet (a first release or a rename) still publishes: `.github/actions/pypi-upload` falls back to the
   `PYPI_API_TOKEN` secret of the `pypi` environment, without attestations, and reads every digest back.
4. Check the release: `pip install probity-effects==<version>` in a clean environment and run the
   quick start in `README.md`.
