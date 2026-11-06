# AG2 push URL admission and effects

This runs AG2's new URL validator at
[`fd789e3`](https://github.com/ag2ai/ag2/commit/fd789e3ca8a77d14c8e3e89923665fe62c00cb9a)
through JSON-RPC, REST and gRPC. The A2A Python SDK is pinned separately at
[`e649325`](https://github.com/a2aproject/a2a-python/commit/e649325e041e44c0b0fe57e3eef0699cad164a1e).
All 453 installed AG2 and 127 installed SDK Python files must match their Git
blobs before the producing operation imports either framework. The producing
operation is run by the operator's runtime; this directory holds the installed
reader, the retained CI packet from the last producing run and the reader's
fault controls. Source bytes of the producing run are held as digests in
`retained/WITHHELD-SOURCES.json`.

Each case first completes a real native AG2 task using its fixed-text TestConfig.
It then registers a callback URL. The host explicitly calls the unchanged SDK
push sender with that completed task; the callback target has its own acceptance
decision and Observer-backed file write. Raw native callback JSON, protobuf bytes,
stored configs, policy calls, target requests and signed write history remain
separate. A second environment has neither AG2 nor A2A installed; its reader
reconstructs the finite run twice.

| case, repeated across all three transports | stored configs | target callbacks | writes |
| --- | --- | --- | --- |
| allowed registration, dispatch and target | 1 | 1 | 1 |
| registration policy refuses URL | 0 | 0 | 0 |
| dispatch policy refuses stored URL | 1 | 0 | 0 |
| target returns 403 | 1 | 1 | 0 |
| no registration policy, config only | 1 | 0 | 0 |
| SDK policy refuses three internal/file URLs | 0 | 0 | 0 |

The [workflow](../../../../.github/workflows/package-observer-ag2-push-authority.yml) installs the reader
from `requirements-reader.lock` under Python 3.12.14 and checks the retained
record with public code. The producing source install replaces the SDK registry
wheel; version strings alone do not establish source equality. Sixteen reader controls
include changed task IDs, policy decisions, raw duplicate keys, credentials,
signed history and target effects, with input hashes reselected.

The retained CI packet is checked by the installed reader with the withheld-source
record. `verify_retained.py --materialize DIR` also restores the empty directories
that Git cannot store (GitHub Actions ZIPs omit empty directories), adding no file bytes:

```sh
replay/bin/python -I -B verify_retained.py
replay/bin/python -I -B verify_retained.py --materialize /absolute/new-run
```

The raw protobuf bytes are retained; the offline reader checks original JSON
semantics and does not decode the protobuf wire format. JSON-RPC, REST and callback
HTTP use native ASGI transports. gRPC uses a real plaintext loopback listener.
The post-completion sender call, target, keys, witness and readers share one author
operator and PEER custody. No provider inference runs here. The older comparison
pins stay unchanged; the prospective eight-task study remains not started.
