# Authority at dispatch and observed effects

A runnable companion to the [unreachable-authority publication case](https://git.elibot.ru/agent-bot/aaif-publication-reference/issues/1). It keeps the authorization decision, committed effect, task terminal and publication decision separate.

Twenty-two controlled cases exercised Observer's real local SQLite ticket service, with signed status evidence and exact approved text, media, destination and catalogue bindings. The run is author-operated, with `witnessScope: PEER`.

The producing operation is run by the operator's runtime; the packet it wrote is retained under [retained](retained): each case's native database and signed record, the consumer pins, the reader report, the source-discriminator report and the implementation-records report. [PROVENANCE.json](retained/PROVENANCE.json) names the workflow run the packet came from. Replay it with public code:

```sh
python -m pip install -r interop/authority-unreachable-2026-10-03/requirements.txt
python -m pip install --no-deps .
python -m pytest interop/authority-unreachable-2026-10-03
python -I interop/authority-unreachable-2026-10-03/verify_retained.py
bash interop/authority-unreachable-2026-10-03/verify_install.sh /tmp/authority-reader
```

`verify_retained.py` requires the reader's report and the implementation-records report to equal the retained copies byte for byte. `verify_install.sh` builds Observer and this profile as wheels, installs them into a separate reader environment, audits that environment and replays the retained run through the installed reader with the same byte comparison.

Supply the captured Alakris `publication_jobs.py` as a second argument to `verify_install.sh` (or as `ALAKRIS_SOURCE` to the tests) to also execute its two fingerprint functions on six controlled inputs. The script verifies the publisher's SHA-256 before compiling those functions. Their body, title and media-reference checks detect changes; packaging, destination and media bytes behind the same reference remain outside that fingerprint. This is bounded source-function execution, without running the full application or its original tests.

The [workflow](../../../../.github/workflows/package-observer-authority-unreachable.yml) runs these checks and retains the installed reader's reports, wheel hashes, dependency audit and test results. The reader consumes selected public-key pins and reads native rows independently of the agent's returned answer.

One result to inspect first: `effect-committed-response-lost` retains a committed row and a failed task. Publication stays blocked. `same-request-retry` retains one effect after two calls; `incomplete-proof-after-effect` retains the observed row while rejecting publication. `binding-veto-override-attempt`, `revoked-authority-superseded-evidence` and `authority-source-unreachable` stay blocked although the executor holds a valid prior grant.

`implementation_records.py` reads the MintID, Proofable and Alakris records published for [AAIF issue 13](https://github.com/aaif/wg-identity-and-trust/issues/13) against the same fields and writes `implementation-records-report.json` beside the reader report. The records are pinned by URL and SHA-256 in `implementation-records/SOURCES.json`.

[CONTRACT.md](CONTRACT.md) gives the proposed comparison record, case coverage and implementation boundaries. It is an input to discussion of [AAIF issue 5](https://github.com/aaif/wg-identity-and-trust/issues/5), not an adopted WG format.
