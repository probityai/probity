# Check a Web Bot Auth signed request

Use `web_bot_auth/v1` to check that one HTTP request was signed, under Web Bot Auth, by the agent you pinned. Web Bot Auth is HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) as profiled by `draft-ietf-webbotauth-httpsig-protocol-01`: a `Signature-Agent` header names the signer's key directory, and the signature carries `created`, `expires`, `keyid` and `tag="web-bot-auth"`. The check runs offline from bytes you hold.

## Inputs

The case binds the request as the verifier received it, its body when it had one, and the key directory you trust for the signer. The assessment has:

- `claim_type`: `web_bot_auth/v1`
- `request`: the case artifact holding `{"method", "url", "headers"}`; `headers` is a list of `[name, value]` pairs in arrival order and `url` is the absolute target URI
- `directory`: the case artifact holding the signer's key directory (a JWK set), and `directory_sha256`: the SHA-256 you pin for it
- `signature_agent`: the `https` URL the signature must name for its signer
- `authority`: the lowercase `host[:port]` your service answers for (the port is omitted when it is the scheme's default)
- `at`: your instant, `YYYY-MM-DDTHH:MM:SSZ`; the check never reads the machine clock
- `body` (optional): the case artifact holding the received body bytes
- `label` (optional): the signature label to read; without it, every signature whose `tag` is `web-bot-auth` is judged on its own (the draft's section 5.2.2) and the request is supported when one of them passes
- `required_components` (optional): a sorted list of component names the signature must cover
- `pinned_fields` (optional): a non-empty object from a lowercase field name to the exact value you expect, as the signature base carries it (the field's lines trimmed and joined with `, `); each pinned field must be covered as a whole field, with no `key` or `sf` parameter, and carry that value. Use it for a covered field that names a record you hold, such as the [stamp digest of the agent browser profile](#the-agent-browser-profile)
- `max_age_seconds`, `max_validity_seconds` (optional): limits on `at - created` and `expires - created`; the window is 24 hours unless you pin another, because the check keeps no replay state and the draft recommends no more
- `allow_test_keys` (optional): `true` only when you are testing with the published RFC 9421 test key

The verifying key comes only from the pinned directory. The request's `keyid` chooses among that directory's keys; it must equal the key's RFC 7638 thumbprint, which the check recomputes. The directory's own `nbf`, `exp`, `use` and `key_ops` for that key are honoured, and a key published with its private member `d` signs nothing. A directory URL, key or algorithm the request names is never fetched or trusted. Only Ed25519 is read.

## Decisions

| decision | reason | when |
| --- | --- | --- |
| `supported` | `request_signed_by_pinned_agent` | the pinned directory's key signed the request for your authority, inside its validity, over the body that arrived |
| `contradicted` | `signature_absent`, `signature_headers_malformed`, `signature_parameters_invalid` | no `web-bot-auth` signature, a header that is not a valid Structured Field, or missing or wrong `created`, `expires`, `keyid`, `tag` or `alg` |
| `contradicted` | `component_not_covered`, `signature_base_invalid` | the signature leaves out `signature-agent` (as a Dictionary member), `@authority` or `@target-uri`, or a component you require, or names a component the request cannot supply |
| `contradicted` | `signature_agent_mismatch`, `authority_mismatch` | the covered `Signature-Agent` member is not the signer you pinned, or the request was for another host |
| `contradicted` | `pinned_field_mismatch` | a field you pinned is covered but carries another value: it was swapped on the way, or signed for another record |
| `contradicted` | `signature_expired`, `signature_created_in_future`, `signature_too_old`, `validity_window_too_long` | the signature is not current at `at` (60 seconds of skew allowed), or breaks your limits |
| `contradicted` | `body_not_covered`, `content_digest_mismatch`, `content_digest_unsupported` | the request has a body the signature does not cover, or the covered `Content-Digest` is not the digest of the received body |
| `contradicted` | `key_not_yet_valid`, `key_expired`, `key_not_for_signing`, `key_private_published` | the pinned directory says the key is not current at `at` or at `created`, is not a signing key, or publishes its private part |
| `contradicted` | `test_key_refused`, `signature_invalid` | the key is a published test key, or the signature does not verify over the covered components |
| `not_established` | `key_not_in_directory` | the `keyid` names no Ed25519 key of the pinned directory: a stale pin, not a forgery finding |
| `not_established` | `directory_not_pinned` | the directory bytes are not the ones you pinned |
| `not_established` | `request_unavailable`, `directory_unavailable`, `body_unavailable` | a bound artifact is not present, or the request declares or covers a body (`Content-Length`, `Transfer-Encoding`, a covered `content-digest`) and the case binds none |

A request capture that is not exactly `method`, `url` and `headers`, a directory that is not a JWK set whose key ids are thumbprints, and an assessment value that is malformed are invalid input: exit 2, no verdict. A malformed signature header on a well-formed capture is a verdict.

## Why the body check is part of the claim

A valid signature over the headers alone says nothing about the body. Verifying only the signature lets an on-path party swap the body and keep the request looking signed (RFC 9421 section 7.2.8). So a request with a body must cover `content-digest`, and the covered header must equal the SHA-256 or SHA-512 digest of the body you hold. Only covered members count: when the signature covers one member (`"content-digest";key="sha-256"`), a member it does not cover is unsigned and is never checked against the body in its place.

## What it does not establish

A supported decision means the key in your pinned directory signed the components the signature covers, for this authority, over this body, inside its validity. `scope.record.covered` lists them and `scope.record.uncovered` names the method, path or query the signature leaves open: a signature over `@authority` alone, the draft's minimum, holds for any method and path, so require `@method` and `@path` (or `@target-uri`) in `required_components` when the route matters. It does not establish that the request was not replayed inside that window: the check keeps no state, so a gateway that wants one-use admission records the signature's `nonce` or its digest. It does not establish who holds the key, or that the directory is the signer's own.

## The agent browser profile

A signing browser proxy marks every request an agent's browser sends with one Web Bot Auth signature. The browser holds no key and no login; the proxy signs each request as it leaves, under the agent's own Ed25519 key, and binds it to the record of the session it was sent under. Every request carries five fields:

```
Signature-Agent: agent="https://agent.example/.well-known/http-message-signatures-directory"
Content-Digest: sha-256=:<base64 of the SHA-256 of the body>:
Probity-Stamp-Digest: "sha256:<64 lowercase hex digits>"
Signature-Input: agent=("@method" "@target-uri" "@authority" "content-digest" "probity-stamp-digest" "signature-agent";key="agent");created=1795435200;expires=1795435260;nonce="...";keyid="<RFC 7638 thumbprint>";alg="ed25519";tag="web-bot-auth"
Signature: agent=:<Ed25519 signature over the RFC 9421 signature base>:
```

- The label is `agent` and the tag `web-bot-auth`. The `Signature-Agent` member is keyed by the label, as the draft's section 5.2.1 requires.
- The covered components are exactly `@method`, `@target-uri`, `@authority`, `content-digest`, `probity-stamp-digest` and `"signature-agent";key="agent"`, in that order. `@target-uri` binds the path and the query, so no part of the request is left open (`scope.record.uncovered` is empty).
- `Content-Digest` is always sent and covered, including for a request with no body, where it is the SHA-256 of no bytes. The draft leaves the body uncovered by default; this profile does not.
- `Probity-Stamp-Digest` is an RFC 8941 String holding `probity_records.digests.stamp_digest` of the request's verified principals, act chain and grant chain ([identity-digests.md](https://github.com/probityai/probity/blob/main/packages/probity-records/docs/identity-digests.md)). It binds the request to the record of the session that released it without naming the user to the site.
- `expires` is at most 60 seconds after `created`, because the signature names one request and its window is the receiver's replay window. `nonce` is fresh per request.

To read a request in this profile, pin:

```json
{
  "claim_type": "web_bot_auth/v1",
  "label": "agent",
  "required_components": ["@authority", "@method", "@target-uri", "content-digest", "probity-stamp-digest", "signature-agent"],
  "max_age_seconds": 60,
  "max_validity_seconds": 60,
  "pinned_fields": {"probity-stamp-digest": "\"sha256:<the stamp digest your record names>\""},
  "body": "body.bin"
}
```

with `request`, `directory`, `directory_sha256`, `signature_agent`, `authority` and `at` as above. Bind the body even when it is empty: the signature covers `content-digest`, so a case with no body is `body_unavailable`. Leave `pinned_fields` out when you hold no record of the session; the stamp digest is then still covered, so a digest swapped on the way fails as `signature_invalid`, but a request validly signed for another session is `supported`. Require `@target-uri`, not `@path`: the profile covers the path through `@target-uri`, and a policy that requires `@path` refuses it as `component_not_covered`.

The [browser profile vectors](../vectors-web-bot-auth/README.md) hold twelve cases signed in this profile, and both the Python reader and the TypeScript reader (`probity-records-verify web-bot-auth`) decide each as the manifest says. A proxy that refuses a request it cannot sign reports one of the `browser_*` codes in the probity-records [refusal-code registry](https://github.com/probityai/probity/blob/main/packages/probity-records/src/probity_records/refusal_codes.json).

The [worked example](../examples/web-bot-auth/case.json) is generated by [generate.py](../examples/web-bot-auth/generate.py), which writes the signature base by hand so the verifier is not the oracle for the request it judges; the unit tests also reproduce the draft's own signed example.
