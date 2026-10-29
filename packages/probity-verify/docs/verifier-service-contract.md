# Verifier service contract

A relying party that cannot install the verifier can send a claim to a service that runs it. This page fixes what such a service accepts and returns, so the answer is the same bytes the command line prints. A service that meets it adds no judgement of its own: the decision comes from `probity-verify`, and anyone can replay it locally.

## Request

One JSON object, validated by [verifier-service-request.schema.json](verifier-service-request.schema.json):

| member | meaning |
| --- | --- |
| `contract` | the string `probity-verify-service/v1` |
| `case` | the case, as for `probity-verify INPUT` |
| `policy` | the consumer-held policy, as for `--policy` |
| `artifacts` | evidence bytes by the relative path the case names, each `{"encoding": "base64", "bytes": "..."}` |
| `require_witness_scope` | optional, `PEER` (default) or `EXTERNAL`, as for `--require-witness-scope` |

The service writes each artifact under a new empty directory at its path and runs the verifier with that directory as the artifact root. A path that is absolute, climbs out of the directory with `..`, or is not read by the case is refused.

## Response

- **200.** The body is the decision as `probity-verify --json` prints it for the same inputs: canonical JSON, byte for byte. Compare the SHA-256 of the body with the digest of the local command's output.
- **422.** The verifier refused the input (the command line exits 2). The body is canonical JSON `{"error": "<message>"}`, where the message is the verifier's own text.
- **400.** The request is not JSON or does not match the schema.

The policy travels in the request and is bound into the decision by the verifier. A service never holds a policy of its own that replaces it.

## Check a service

The test in [tests/test_service_contract.py](../tests/test_service_contract.py) builds a request from a bundled example, answers it with a small reference handler, and asserts the body equals the command line's `--json` output. Point the same assertion at a hosted endpoint by replacing the handler call with an HTTP post of the request.
