# Record envelope v2: erasable records

`probity_records.erasure` defines a record whose signed bytes stay verifiable after a data subject's key is destroyed.
A v1 record signs its fields in clear, so erasing anything in it breaks the hash chain and every transparency-log
inclusion proof over it. A verifier labels a journal with any v1 record `not erasable`.

## Retention classes

A schema declares every field of a record kind, closed: a field with no rule is refused when the record is sealed.
Each rule puts its field in one class.

| Class | In the signed statement | In the payload store |
|---|---|---|
| `kept` | the value, in clear | nothing |
| `pseudonym` | a per-leaf keyed tag `HMAC(k, JCS(value))` | the value, encrypted |
| `payload` | with `commit`, a per-leaf keyed commitment `HMAC(k_field, JCS(value))` | the value, encrypted |

Only structural metadata may be kept. `lint_schema` refuses a schema that keeps a personal field or a digest computed
over personal content, and one that keeps a field whose name reads as a digest (`sha256`, `digest`, `hash`,
`thumbprint`) unless the schema declares it structural (a digest over payload-blind data, such as the previous
record's line digest). Sealing also refuses a 64-hex-digit digest in a kept field that is not declared structural.

Every non-kept field names the role whose key covers it: `user`, `agent`, `sponsor`, `approver` or `session`.

## Keys and bytes

All keys are derived from a 32-byte subject key with HKDF-SHA256, salt `probity-record-envelope/v2`, info
`label 0x00 leaf-id 0x00 path`, where the leaf id is 16 random bytes per record.

- Pseudonym tag key: label `pseudonym`, the field path.
- Field commitment key `k_field`: label `field-commitment`, the field path.
- Statement subject: label `subject-commitment`, empty path; the in-toto subject digest is the tag of the call.
- Payload key: label `payload/<class>`, path = the role.

The fields of one role and one class are encrypted together with AES-256-GCM: the plaintext is the JCS object of
those fields, padded with spaces to a multiple of 256 bytes; the AAD is the JCS of `{"class", "format", "leaf",
"schema", "subject"}`. A blob is `nonce (12 bytes) || ciphertext`, and the signed statement carries only its
SHA-256. Tags and commitments are per leaf, so equal values in two records do not link.

The `erasure` block of the signed predicate holds `format`, `leaf`, `schema`, `classes`, `roles`, `commitments`,
`pseudonyms`, `ciphertexts` (`bytes`, `class`, `sha256`, `subject`) and `subjectRole`. `check_block` refuses a
block whose ciphertexts do not cover exactly the (role, class) pairs its fields need.

## Reading and erasing

`open_sealed` decrypts what the given keys open and checks every ciphertext digest, AEAD binding, pseudonym and
commitment; a field whose subject key is absent reads as erased, one whose blob is gone reads as missing, and any
mismatch is refused with its code. Destroying a subject key leaves the statement, its chain and its log proofs
verifiable; a verifier reads such an assertion as `commitment only, content erased at <time>`.

`disclose` releases one committed field: its value and `k_field`, never the subject key. `verify_disclosure` checks
it against the commitment.

## Vectors

`vectors/shared/erasure.json` (from `erasure_vectors.vectors()`) fixes keys, leaf ids and nonces, so another
implementation reproduces every byte. Schemas travel as JSON (`Schema.to_json`). The cases cover sealing (including
every refusal), opening with all keys, with a destroyed key, with a missing or swapped blob, a changed leaf, tampered
tags and malformed blocks, disclosure and its verification, the schema lint, and the erasability label.
