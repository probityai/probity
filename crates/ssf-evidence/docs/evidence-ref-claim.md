# The evidence reference claim for Security Event Tokens

## Name and place

The claim name is `https://w3id.org/agent-evidence/secevent/v1/evidence-ref`, a collision-resistant name in the sense of RFC 7519 section 4.2. It sits inside the event object of the token's `events` claim, beside the event's own claims. SSF 1.0 section 4.2.3 allows additional fields there and requires receivers to ignore fields they do not understand, so a receiver that does not know the claim still processes the event as before.

```json
"events": {
  "https://schemas.openid.net/secevent/caep/event-type/risk-level-change": {
    "principal": "AGENT",
    "current_level": "HIGH",
    "https://w3id.org/agent-evidence/secevent/v1/evidence-ref": {
      "digest": {"sha256": "<64 lowercase hex characters>"},
      "uri": "https://evidence.example.com/e/1.dsse.json",
      "payload_type": "application/vnd.in-toto+json"
    }
  }
}
```

## Members

| Member | Meaning |
| --- | --- |
| `digest.sha256` | Lowercase hex SHA-256 of the exact envelope bytes served at `uri` |
| `uri` | Where a receiver retrieves the DSSE envelope |
| `payload_type` | The envelope's `payloadType`; this version accepts only `application/vnd.in-toto+json` |

Members a receiver does not know are ignored.

## Subject binding

The envelope's payload is an in-toto Statement v1. One of its subjects carries the digest `sha256` of the RFC 8785 canonical form of the token's `sub_id` (producers name it `ssf:sub_id`). The evidence is therefore about the same user, agent, tenant and session as the event, and an envelope about anyone else is refused even though it verifies.

## What a receiver checks, in order

1. The token: `typ` `secevent+jwt`, an `alg` that matches the trusted key, a valid signature, `iss`, `aud`, `iat`, `jti`, no `sub`, no `exp`, exactly one event, a `sub_id`.
2. The claim is well formed; when it is absent from any event other than stream verification, a receiver that requires evidence refuses.
3. The URI serves bytes (at most 1 MiB).
4. The bytes hash to `digest.sha256`.
5. They are a DSSE envelope whose `payloadType` is the claim's.
6. The envelope verifies under the receiver's trusted evidence keys at its threshold.
7. The payload is an in-toto Statement v1, of an accepted predicate type when the receiver restricts them.
8. A statement subject carries the digest of the token's `sub_id`.

Each failure has a stable code (`evidence.unresolved`, `evidence.digest_mismatch`, `evidence.signature`, `evidence.subject_mismatch` and the rest); a push receiver answers it with the RFC 8935 error `invalid_request`.

## Why a digest and a URI

The digest is inside the signed token, so the transmitter cannot later point the same event at different evidence, and anyone holding the token can fetch the envelope and check it without trusting the transmitter or the network path. The URI only says where to look.
