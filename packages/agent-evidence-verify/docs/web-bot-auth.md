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

The [worked example](../examples/web-bot-auth/case.json) is generated by [generate.py](../examples/web-bot-auth/generate.py), which writes the signature base by hand so the verifier is not the oracle for the request it judges; the unit tests also reproduce the draft's own signed example.
