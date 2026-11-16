# Resolution and call records

`ResolutionObserver` writes the declared side and the acted side of discovery
into one [trajectory](TRAJECTORY.md), so the witnessed head fixes how many of
each exist.

| Event | Fields | What it binds |
|---|---|---|
| `resolution` | `name`, `svcb` (presentation format, one record per item), `sig` (as received or `null`), `jwks` (`url` and the `sha256` of the bytes fetched, or `null`), `dnssec_chain_sha256` (or `null`), `at` | what discovery said at call time |
| `call` | `endpoint`, `resolution` (the `seq` it relied on, or `null`), `at` | where the request actually went |

```python
from pathlib import Path
from probity_observer.resolution import ResolutionObserver

observer = ResolutionObserver(Path("observed.jsonl"))
seq = observer.resolved(name="_a2a._agents.example.com", svcb=rrset, sig=sig,
                        jwks_url=jwks_url, jwks_bytes=jwks, dnssec_chain=chain,
                        at="2026-11-15T20:00:00Z")
observer.called(endpoint="https://agent.example.com:443", at="2026-11-15T20:00:01Z", resolution=seq)
head = observer.trajectory.close(witness_key)
```

The raw JWKS and chain bytes stay with the caller; each event binds them by
SHA-256, so a verifier handed the bytes can check them. `at` is the
observer's clock and nothing more: no trusted time is claimed.

A joining verifier compares each recorded call with a verified binding: a
call to the bound endpoint inside the key authority's window agrees; a call
elsewhere or after the window contradicts; a binding that covers only the
endpoint, a binding with no key authority, or calls that were never recorded
leave the question open. A call missing from the trajectory is counted as
missing and never read as clean.
