# Release probity-effects

1. Set `version` in `pyproject.toml`, update the install line in `README.md`, and merge to main
   with CI green.
2. Publish a non-prerelease GitHub release whose tag is `probity-effects-v<version>` on that main
   commit. `release.yml` resolves the tag to this member, builds and checks the files with
   `python-build.yml`, and the `publish-probity-effects` job uploads them to PyPI with
   attestations from the `pypi` environment.
3. PyPI's trusted publisher for the project is owner `probityai`, repository `probity`, workflow
   `release.yml`, environment `pypi`. The first release of a new project needs it entered as a
   pending publisher on PyPI before the tag is pushed.
4. Check the release: `pip install probity-effects==<version>` in a clean environment and run the
   quick start in `README.md`.
