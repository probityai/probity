# End-to-end run

A recorded run of the hook against Keycloak 26.4.7 on a clean Linux box, built from commit 01397d8. The driver is `e2e/run.sh`. Its output files are in [recorded/](recorded/): the build log, the Keycloak log, the three receipts (`receipts.jsonl`), the recorder's public key (`recorder.pub.pem`) and one file per check.

## Steps

| Step | Result |
|---|---|
| build (Maven, 15 unit tests) | pass |
| keys | pass |
| compose-up | pass |
| keycloak-ready | ready |
| drive | pass |
| uv-sync | pass |
| check | pass |

The job exited with `EXIT=0`.

## Grants driven

| Grant | Token id digest (SHA-256) |
|---|---|
| token-exchange | f69cf49734e917852fab2c2df850be661c6d9ca7b43308643dd81bdb8693ca69 |
| client-credentials | 33c69d363bae2290fe7c8098ce26d7d827051738f4486f497df48d397ae909e8 |
| ciba | bf97d5810337b42592f3a7cf0e89a0fdd0e891fb71bb9552d78e43413422b28e |

## Checks

Six checks ran, none failed.

| Check | Verdict | Reason |
|---|---|---|
| token-exchange | supported | grant_recorded_as_expected |
| tampered-payload | not_established | receipt_signature_unverified |
| scope-not-allowed | contradicted | grant_scope_exceeds_expected |
| log-line-removed | not_established | receipt_log_unestablished |
| client-credentials | supported | grant_recorded_as_expected |
| ciba | supported | grant_recorded_as_expected |

## Reproduce

Run `cd integrations/keycloak-evidence-hook && e2e/run.sh` on a host with Docker, Java 17 and Maven.
