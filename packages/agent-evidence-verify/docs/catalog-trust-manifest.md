# Catalog trust manifests

`catalog_trust_manifest/v1` answers one question about one object of an Agent Resource Discovery
(ARD) catalog or an AI Catalog: which key signed which bytes under which construction, and does the
signed subject bind the entry and its artifact? It never says the artifact is safe or that the
claims it carries are true, and it resolves no DID online.

## Constructions

The construction is a closed term the consumer names; there is no inference from the bytes.

| Construction | Signed bytes | Algorithms |
|---|---|---|
| `ard-draft-bu-00` | RFC 8785 of the entry's `trustManifest` without `signature` (draft-bu-dawn-ard-discovery-00 section 3.5) | ES256, EdDSA |
| `field-whole-entry` | RFC 8785 of the entry without `trustManifest.signature` (measured practice; no specification defines it) | ES256, EdDSA |
| `ai-catalog-2026-11` | RFC 8785 of `trustManifests[i]` without its own `signature.jws` and `additionalSignatures`; `typ` `ai-catalog-trust-manifest+jws`; signer profile `did-web-v1` | ES256 |
| `ai-catalog-snapshot` | RFC 8785 of the catalog without its own `signature.jws` and `additionalSignatures`; `typ` `ai-catalog+jws` | ES256 |

Every signature is a detached compact JWS (RFC 7515 appendix F). `b64: false` (RFC 7797) is allowed
only on the ARD constructions and only when `crit` names it. ES256 signatures are raw `r || s`.

## Assessment

```json
{
  "claim_type": "catalog_trust_manifest/v1",
  "catalog": "catalog",
  "did_documents": "did-documents",
  "construction": "ard-draft-bu-00",
  "role": "publisher",
  "at": "2026-11-16T00:00:00Z",
  "entry": 0,
  "artifact": "artifact",
  "attestations": [null, "scan-attestation"],
  "key_authority": {"kind": "pin", "keys": [{"public_key_sha256": "..."}]}
}
```

`catalog`, `did_documents`, `artifact` and each `attestations` item name case artifacts.
`did_documents` is one JSON object keyed by DID: the documents an offline did:web resolver returned.
`entry` (and `manifest`, for `ai-catalog-2026-11`) select the object; both default to 0.
`attestations` lists, per attestation of the signed object, the vendored DSSE envelope or `null` for
one the consumer did not vendor. `role` is `publisher` or `contributor`; `at` is the check time.

## Checks

The checks run in this order and the first that fails is the reason:

1. Gates: `json_invalid` (not UTF-8, not JSON, or more than 64 arrays and objects open at once) and
   `signature_missing` end the read.
2. Reading: `duplicate_member`; the header: `jws_malformed`, `typ_missing_or_mismatched`,
   `alg_not_allowed_for_profile`, `key_source_in_header` (`jku`, `jwk`, `x5u`, `x5c`),
   `b64_forbidden_for_profile`, `jws_crit_unsupported`, `b64_without_crit`.
3. The signer: `profile_unsupported`, `signer_not_root_did_web`, `kid_not_under_identity`,
   `did_document_not_identity`.
4. The key: `kid_not_in_did_document`, `verification_method_ambiguous`, `key_not_assertion_method`,
   `method_controller_mismatch`, `jwk_not_signing_key`, `alg_key_mismatch`.
5. The signed bytes: `number_not_interoperable` (a number past 2^53 - 1 in the signed bytes),
   `no_canonical_form` (a lone surrogate), `signature_invalid`.
6. The binding: `signer_not_contributor`, `subject_missing`, `subject_entry_mismatch`,
   `entry_delivery_not_one` (exactly one of `url` and `data`), `entry_digest_missing_for_url`,
   `artifact_digest_mismatch` (for `data`, the digest of its RFC 8785 bytes), `url_origin_unbound`
   (an ARD url outside the publisher's RFC 6454 origin, unless the artifact names the entry).
7. Attestations: `attestation_digest_mismatch`, `attestation_unsigned` (a DSSE envelope, base64 in
   either alphabet, whose signature a supplied DID document's assertion key does not verify; ES256
   raw or strict DER), `attestation_transplanted` (the Statement's subjects omit the entry digest).
8. Roles and time: `publisher_not_signer` or `publisher_authorization_absent`, `timestamp_invalid`
   (RFC 3339; a second of 60 only on an IERS leap-second day), `issued_in_future`,
   `manifest_expired`.

## Decisions

| Outcome | Decision | Reason |
|---|---|---|
| a check fails | `contradicted` | the check's code |
| every check passes and every signing key is authorised | `supported` | `signature_covers_release` (`snapshot_signature_valid` for a snapshot) |
| a signing key is unauthorised | `contradicted` | the key authority's reason |
| no key authority, or one that lacks its evidence | `not_established` | the key authority's reason |
| the catalog, DID documents, a url entry's artifact or a vendored attestation is not bound | `not_established` | `catalog_unavailable`, `did_documents_unavailable`, `artifact_unavailable`, `attestation_unavailable` |

Every key the verdict relied on goes through [the key authority](key-authority.md): the manifest
signer's, and each attestation signer's, at the check time. A key found in the supplied DID
documents proves only that whoever supplied them listed it.

A construction or role outside the closed sets, or a check time that is not an RFC 3339 date-time,
is the consumer's own input: the verifier exits 2 with no verdict and the error names
`construction_unknown` or `role_unknown`.

## Provenance

The checks, their order and their codes are a port of the reference reader in
[agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors)
(`packaging/agent_evidence_vectors/catalogtrust.py` at commit `01086cf0`). The parity test runs that
commit's 115-case corpus, copied to `tests/data/catalog-trust-manifest/`, and the nine break vectors
of matrix row 11, and requires the reference reader's decision and code on each. Two differences
are by design: the gates the consumer controls are case errors here, and a vendored file is named
through the case's artifact binding, which refuses a path that is not normalized before any read.
