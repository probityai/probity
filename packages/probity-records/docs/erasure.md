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

A schema may also fix the plaintext size of a class (`fixed`, class to bytes). Every ciphertext of that class then
holds exactly that many plaintext bytes, whoever it covers, and a larger plaintext is refused at seal time
(`payload_over_fixed_size`). Use it where the value inside identifies its subject by length: an approver's vote,
whose name and principal would otherwise move the payload across a 256-byte boundary and re-link the votes of one
approver after the approver's key is destroyed. `lint_schema` refuses a fixed size on the `kept` class or one that
is not a positive multiple of 256 (`fixed_size_malformed:<class>:<bytes>`), a class fixed twice
(`fixed_size_duplicate:<class>`), and a schema that fixes one class while another class it uses stays padded
(`fixed_size_partial:<class>`), since that ciphertext's length is the same channel.

## Keys and bytes

All keys are derived from a 32-byte subject key with HKDF-SHA256, salt `probity-record-envelope/v2`, info
`label 0x00 leaf-id 0x00 path`, where the leaf id is 16 random bytes per record.

- Pseudonym tag key: label `pseudonym`, the field path.
- Field commitment key `k_field`: label `field-commitment`, the field path.
- Statement subject: label `subject-commitment`, empty path; the in-toto subject digest is the tag of the call.
- Payload key: label `payload/<class>`, path = the role.
- Reference: label `reference/<label>`, empty path; `reference(key, label, leaf, value)` is the tag of the value.

The fields of one role and one class are encrypted together with AES-256-GCM: the plaintext is the JCS object of
those fields, padded with spaces to a multiple of 256 bytes, or to exactly the size the schema fixes for the class;
the AAD is the JCS of `{"class", "format", "leaf",
"schema", "subject"}`. A blob is `nonce (12 bytes) || ciphertext`, and the signed statement carries only its
SHA-256. Tags and commitments are per leaf, so equal values in two records do not link.

The `erasure` block of the signed predicate holds `format`, `leaf`, `schema`, `classes`, `roles`, `commitments`,
`pseudonyms`, `ciphertexts` (`bytes`, `class`, `sha256`, `subject`) and `subjectRole`. `check_block` refuses a
block whose ciphertexts do not cover exactly the (role, class) pairs its fields need, and a `bytes` that is not an
integer of at least 28 (the nonce and the GCM tag).

`check_padding(schema, erasure)` lets a reader that holds the schema check, from the signed block alone and without
any key, that the writer padded: each ciphertext of a fixed class holds exactly the fixed size, every other one a
positive multiple of 256 (`ciphertext_size_not_fixed`, `ciphertext_not_padded`, `schema_mismatch`).

A schema's JSON form has the members `name`, `structural`, `fixed` (an object from class to bytes, `{}` when
nothing is fixed) and `rules`; each is required.

## Reading and erasing

`open_sealed` decrypts what the given keys open and checks every ciphertext digest, signed length
(`ciphertext_length_mismatch`), AEAD binding, pseudonym and commitment; a field whose subject key is absent reads as
erased, one whose blob is gone reads as missing, and any mismatch is refused with its code. Destroying a subject key
leaves the statement, its chain and its log proofs verifiable; a verifier reads such an assertion as `commitment
only, content erased at <time>`.

`disclose` releases one committed field: its value and `k_field`, never the subject key. `verify_disclosure` checks
it against the commitment.

## References inside signed bodies

A value inside a body its subject signs (an approver named in its own signed vote) cannot be pseudonymised after
signing. `reference(subject_key, label, leaf, value)` gives the writer a handle to put there instead: the same for
one key, label, leaf and value, unrelated across leaves and labels, and impossible to recompute or test against a
guessed value once the subject key is destroyed.

## The canary lint

`lint_schema` judges what a schema declares. `personal_traces(signed, personal)` judges what a writer actually
signed: given known personal values, it lists each one that shows in the signed bytes in clear (JSON text, escaped
either way for non-ASCII; a non-string value as its JCS text, case ignored) or as a plain SHA-256 of its UTF-8 bytes
(a string) or its JCS bytes, in hex of either case or in base64 or base64url, padded or not. Run it over a journal
written with canary values; a sealed journal should give `[]`, and the same records in v1 show what it finds.

## Vectors

`vectors/shared/erasure.json` (from `erasure_vectors.vectors()`) fixes keys, leaf ids and nonces, so another
implementation reproduces every byte. Schemas travel as JSON (`Schema.to_json`). The cases cover sealing (including
every refusal, and a fixed-size class), opening with all keys, with a destroyed key, with a missing or swapped blob,
a changed leaf, tampered tags and malformed blocks, a signed length that is not the blob's, disclosure and its
verification, the schema lint, the padding check, references and the canary lint, and the erasability label.
