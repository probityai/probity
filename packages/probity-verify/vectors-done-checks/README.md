# Done-check vectors

Twenty-four synthetic cases for `tool_claim_match/v1`, `acceptance_observed/v1` and
`protected_paths/v1`. Each one is
the honest run the adapter tests use, changed in one way, with the decision and reason a
verifier must return. `MANIFEST.json` pins every file's bytes.

| Case | Decision | What it checks |
| --- | --- | --- |
| tool-claims-matched | supported | Control: the claimed run follows the last edit. |
| tool-claims-empty | not_established | An empty claim list establishes nothing. |
| tool-claim-without-exit | not_established | A claim that states no exit settles nothing. |
| tool-claim-earlier-pass-later-fail | contradicted | The last run of the command failed. |
| tool-claim-run-writes-path-by-another-process | contradicted | Another process wrote a sealed run path after the run. |
| tool-claim-cache-by-another-process | contradicted | Another process wrote a cache file after the run. |
| tool-claim-sealed-command-matched | supported | Control: the sealed cwd and exe match the run. |
| tool-claim-sealed-other-cwd | contradicted | The run was in another working directory. |
| tool-claim-sealed-other-exe | contradicted | The run used another interpreter. |
| tool-claim-sealed-other-script | contradicted | The run executed another script. |
| tool-claim-shadowed-beside-module | contradicted | An importable file sat beside the module under test. |
| acceptance-sealed-tests-passed | supported | Control: every sealed held-out test passed. |
| acceptance-sealed-test-skipped | not_established | A sealed test was collected and skipped; pytest exited 0. |
| protected-untouched | supported | Control: the protected paths were left alone. |
| protected-ancestor-swap | contradicted | The protected file's directory moved aside for a decoy and back. |
| protected-ancestor-unlinked | contradicted | The protected file's directory was removed. |
| protected-ancestor-chmod | contradicted | The protected file's directory had its mode changed. |
| protected-directory-entry-ancestor-renamed | contradicted | The parent of a protected directory was renamed away and back. |
| protected-ancestor-replaced-by-symlink | contradicted | The protected file's directory is a symbolic link in the final tree. |
| protected-workspace-moved-outside | contradicted | A directory above the workspace was renamed. |
| protected-loader-preload-written | contradicted | The dynamic loader's preload list was written. |
| protected-python-path-file-written | contradicted | A `._pth` file beside the interpreter was written. |
| protected-directory-moved-onto-site-packages | contradicted | A staged directory replaced `site-packages`. |
| protected-lookalike-loader-name | supported | Control: a scratch file that only resembles a loader file. |

Run every case against a CLI that implements the `probity-verify` contract:

```sh
uv run --extra test python vectors-done-checks/check_vectors.py --verifier 'probity-verify'
```

Regenerate with `python3 vectors-done-checks/gen_vectors.py`, and compare the committed
bytes with `--check`. A verifier that passes this corpus enforces these rules on synthetic
records. Whether the observer recorded a real run correctly is outside what it shows.
