# ssf-evidence

Security Event Tokens for the OpenID Shared Signals Framework (SSF 1.0) whose CAEP events point at signed evidence, and a verifier that refuses any event whose evidence does not resolve and verify.

It is for teams that send risk signals about AI agents to an identity provider, and for identity providers that want to act only on signals anyone can re-check.

```toml
[dependencies]
ssf-evidence = "=0.1.0"
```

```rust
use ssf_evidence::{verify_set, MapResolver, ReceiverConfig};

fn on_push(token: &str, config: &ReceiverConfig, resolver: &MapResolver) {
    match verify_set(token, config, resolver) {
        // The signature, the SSF profile and the evidence all held.
        Ok(event) => println!("act on {} for {}", event.event_type, event.sub_id),
        // A stable code, such as evidence.digest_mismatch, and the RFC 8935
        // error code to answer with.
        Err(refusal) => println!("400 {}: {refusal}", refusal.code.set_error_code()),
    }
}
```

## What it does

- **Evidence in the event.** A `risk-level-change` or `session-revoked` event carries the claim `https://w3id.org/agent-evidence/secevent/v1/evidence-ref`: the SHA-256 digest and URI of a DSSE envelope holding an in-toto Statement about the same subject. The receiver refuses the event when the URI serves nothing, the bytes hash to another digest, the envelope does not verify under a trusted key, or the statement is about someone else. The claim is defined in [docs/evidence-ref-claim.md](docs/evidence-ref-claim.md).
- **Four parties in one subject.** `sub_id` is an SSF complex subject naming the user, the agent, the tenant and the session.
- **Monitor mode first.** A transmitter starts in monitor mode: events are decided, signed and logged, and nothing is sent. Switching to live never sends what monitor mode logged.
- **Revocation needs a grant.** `session-revoked` is sent only when the receiver granted the `session_revoke` capability and the stream delivers it; otherwise the same decision goes out as a `HIGH` risk level.
- **At-least-once delivery.** RFC 8935 push with an outbox: retries with capped exponential backoff, a dead-letter state, replay of the same bytes under the same `jti`, and a JSON form that survives a restart. A Test Connection call sends an SSF verification event at once.
- **Strict tokens.** `RS256` with keys of at least 2048 bits (the CAEP interoperability profile) or `Ed25519`; `typ` must be `secevent+jwt`; the key fixes the algorithm; `crit`, `sub`, `exp` and repeated JSON members are refused.

## Conformance vectors

[`vectors/`](vectors/) holds 27 cases (5 accepted, 22 refused, each with its expected code) and the public keys they verify under. The test `tests/vectors.rs` regenerates them byte for byte and runs each one from the files alone.

## Status

Version 0.1.0. Built on the published [`dsse`](https://crates.io/crates/dsse) and [`jcs-admit`](https://crates.io/crates/jcs-admit) crates.

| Document | What it covers |
| --- | --- |
| [docs/evidence-ref-claim.md](docs/evidence-ref-claim.md) | The claim, the subject binding and the receiver's checks |
| [vectors/](vectors/) | Conformance cases |
| [LICENSE](LICENSE) | Apache-2.0 |
