# A2A server and client

The optional A2A interface uses the official Python SDK 1.2.1 and protocol 1.0 JSON-RPC. It calls the same adjudicator as `probity-verify` and returns its exact JSON decision bytes plus a readable packet.

## Run a case

From a pinned checkout:

```sh
uv sync --frozen --extra a2a
uv run --frozen --extra a2a probity-a2a \
  --policy examples/source-coverage/policy-june.json \
  --artifact-root examples/source-coverage
```

In another terminal:

```sh
uv run --frozen --extra a2a probity-a2a-client verify \
  examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json
```

The client checks the agent card, sends the original case bytes, reads the completed task back and checks the result bindings. This example returns the existing source-coverage fixture's `contradicted` decision.

The server owns the policy and evidence directory. The caller supplies a case, its byte length and SHA-256, and the expected consumer policy digest. The server admits raw JSON before adjudication, so duplicate keys and non-JSON numbers stay visible. URI parts, caller-selected directories and rewritten byte bindings are refused. Invalid input produces a protocol error; the client exits 2 without a verdict.

## Read a Lab record

Retain a register from a pinned [Atlas commit](https://github.com/probityai/agent-evidence-atlas), then record its exact SHA-256. Add it to the server configuration:

```sh
uv run --frozen --extra a2a probity-a2a \
  --policy examples/source-coverage/policy-june.json \
  --artifact-root examples/source-coverage \
  --lab-register /srv/probity/lab-register.json \
  --lab-register-sha256 YOUR_RETAINED_REGISTER_SHA256
```

The client selects a record ID from that register:

```sh
uv run --frozen --extra a2a probity-a2a-client lab-record E6-observer-admission \
  --register-sha256 YOUR_RETAINED_REGISTER_SHA256
```

The response retains the publisher's record, operator, source revisions, review state and executed scope. Reading a record does not rerun its study. The server reads its configured files only.

## Discover and operate it

The server listens on `127.0.0.1:41241`. It serves the agent card at `/.well-known/agent-card.json`, JSON-RPC at `/a2a/jsonrpc` and a short discovery file at `/llms.txt`. The card advertises only the configured skills and protocol 1.0; this interface does not enable the SDK's 0.3 compatibility routes.

Requests are bounded to 384 KiB, with a 256 KiB raw case limit. Four assessments run at a time; the CLI admits up to 16 concurrent connections. The latest 128 completed tasks last for the current process. Save returned decision bytes with their source and policy bindings for retained evidence.

For a maintained host process, install the pinned checkout at `/opt/probity-verify`, create a `probity` service account and put its policy and evidence under `/srv/probity`. Install [the service unit](../deployment/probity-a2a.service) after changing those operator-owned paths. It uses the locked optional dependencies and the same tested server command. Put an authenticated gateway in front for shared access and qualify its POST route before publishing its URL.

Run the transport and existing verifier checks with:

```sh
uv run --frozen --extra test --extra a2a pytest
```

The transport tests start a real loopback HTTP server and use the official SDK client. They compare decision bytes with the existing examples and exercise task readback, admission failures, policy mismatches and a synthetic publisher-record round trip. The existing vector suites keep their own source pins and scopes.
