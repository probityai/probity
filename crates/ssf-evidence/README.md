# ssf-evidence

Security Event Tokens for the OpenID Shared Signals Framework (SSF 1.0) whose CAEP events point at signed evidence, and a verifier that refuses any event whose evidence does not resolve and verify.

It is for teams that send risk signals about AI agents to an identity provider, and for identity providers that want to act only on signals anyone can re-check.

```sh
cargo add ssf-evidence
```

```rust
use ssf_evidence::{MapResolver, MemoryJtiLedger, PushReceiver, PushResponse, ReceiverConfig};

fn on_push(config: &ReceiverConfig, resolver: &MapResolver, ledger: &MemoryJtiLedger,
           content_type: Option<&str>, body: &[u8]) -> (u16, String) {
    let receiver = PushReceiver { config, resolver, ledger, authorization: None };
    let response = receiver.receive(content_type, None, body);
    if let PushResponse::Accepted(event) = &response {
        // Signature, SSF profile, evidence and replay all held. A session
        // revocation or a credential change arrives typed, never as a string.
        println!("{} revokes {:?}", event.event_type, event.revocation);
    }
    // 202, 400 with the RFC 8935 error object, or 503 for the transmitter to retry.
    (response.status(), response.body())
}
```

## What it does

- **Evidence in the event.** A `risk-level-change` or `session-revoked` event carries the claim `https://w3id.org/agent-evidence/secevent/v1/evidence-ref`: the SHA-256 digest and URI of a DSSE envelope holding an in-toto Statement about the same subject. The receiver refuses the event when the URI serves nothing, the bytes hash to another digest, the envelope does not verify under a trusted key, or the statement is about someone else. The claim is defined in [docs/evidence-ref-claim.md](https://github.com/probityai/probity/blob/main/crates/ssf-evidence/docs/evidence-ref-claim.md).
- **Four parties in one subject.** `sub_id` is an SSF complex subject naming the user, the agent, the tenant and the session.
- **Monitor mode first.** A transmitter starts in monitor mode: events are decided, signed and logged, and nothing is sent. Switching to live never sends what monitor mode logged.
- **Revocation needs a grant.** `session-revoked` is sent only when the receiver granted the `session_revoke` capability and the stream delivers it; otherwise the same decision goes out as a `HIGH` risk level.
- **At-least-once delivery.** RFC 8935 push with an outbox: retries with capped exponential backoff, a dead-letter state, replay of the same bytes under the same `jti`, and a JSON form that survives a restart. A Test Connection call sends an SSF verification event at once.
- **A receiver that ends work on a verified revocation.** CAEP `session-revoked` and `credential-change` (CAEP 1.0 section 3.3) come out of the verifier as a typed `Revocation`; a `HIGH` risk level, which a transmitter without the capability sends instead of a revocation, carries none. A `JtiLedger` refuses a token whose issuer and `jti` were accepted before. `PushReceiver` answers RFC 8935 pushes (an exact retransmission gets the 202 the first delivery got, and is not acted on again), and `poll_once` runs one RFC 8936 poll with strict parsing and returns the acknowledgements and `setErrs` for the next one.
- **Strict tokens.** `RS256` with keys of at least 2048 bits (the CAEP interoperability profile) or `Ed25519`; `typ` must be `secevent+jwt`; the key fixes the algorithm; `crit`, `sub`, `exp` and repeated JSON members are refused.

## Conformance vectors

[`vectors/`](https://github.com/probityai/probity/tree/main/crates/ssf-evidence/vectors) holds 33 cases (6 accepted, each with the revocation it carries, and 27 refused, each with its expected code; replay, push and poll cases among them) and the public keys they verify under. The test `tests/vectors.rs` regenerates them byte for byte and runs each one from the files alone.

## Status

Version 0.1.0. Built on the published [`dsse`](https://crates.io/crates/dsse) and [`jcs-admit`](https://crates.io/crates/jcs-admit) crates.

| Document | What it covers |
| --- | --- |
| [docs/evidence-ref-claim.md](https://github.com/probityai/probity/blob/main/crates/ssf-evidence/docs/evidence-ref-claim.md) | The claim, the subject binding and the receiver's checks |
| [vectors/](https://github.com/probityai/probity/tree/main/crates/ssf-evidence/vectors) | Conformance cases |
| [LICENSE](https://github.com/probityai/probity/blob/main/crates/ssf-evidence/LICENSE) | Apache-2.0 |
