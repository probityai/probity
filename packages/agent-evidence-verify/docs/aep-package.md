# `aep_package/v1`: one action evidence package, every layer

`aep_package/v1` checks an action evidence package (`.aep`, a ZIP archive) layer by layer and reports every layer:
after the first failure each later check is `not_evaluated`, never skipped and never passed.

```json
{
  "claim_type": "aep_package/v1",
  "package": "package.aep",
  "authority": {"kind": "pin", "keys": [{"public_key_sha256": "<sha256 of the RSA key's DER SubjectPublicKeyInfo>"},
                                         {"public_key_sha256": "<sha256 of the raw ML-DSA-65 public key>"}]},
  "tsa_authority": {"kind": "pin", "keys": [{"public_key_sha256": "<sha256 of the TSA certificate key's DER SPKI>"}]}
}
```

| Check | Passes when |
|---|---|
| `package_shape` | the archive opens, names no entry twice (two ZIP readers would read different bytes), holds `response.txt`, `metadata.json`, `canonical.bin`, `hash.sha256`, `signature.sig`, `public_key.pem` and `timestamp.tsr`, and `metadata.json` is strict I-JSON |
| `hash` | SHA-256 of `canonical.bin` equals `hash.sha256` (one trailing LF accepted) |
| `canonical_form` | `canonical.bin` is `response.txt`, LF, RFC 8785 of `metadata.json`; the legacy response-only form passes and is named |
| `rsa_signature` | the recovered RSA block is exactly the RFC 8017 SHA-256 encoding (DigestInfo with NULL parameters) or exactly the legacy encoding with absent parameters, which is named |
| `signer_pinned` | the RSA key is admitted by `authority` |
| `receipt` | when present: `content_hash` is `sha256:` and the package hash, the fields shared with `metadata.json` agree, and a receipt signature that `metadata.json` names verifies |
| `pqc_signature` | when present: ML-DSA-65 over `canonical.bin` (RFC 9881 SPKI or a raw 1952-byte key, empty context) under a key `authority` admits |
| `timestamp` | the RFC 3161 response is granted, its SHA-256 imprint is the package hash, `messageDigest` is SHA-256 of the TSTInfo, the CMS signature verifies under the embedded certificate, and that key is admitted by `tsa_authority` |

The whole RSA block is compared. Four blocks that end in the right digest are refused: arbitrary bytes between the
padding and the digest, bytes after the legacy DigestInfo prefix, a SHA-512 OID with a 32-byte digest, and a
padding string shorter than the modulus requires. A check that compares only the trailing 32 bytes accepts all four.

The key a package carries proves nothing alone: with no `authority` the verdict is `not_established` /
`signer_not_established`, and with no `tsa_authority` it is `not_established` / `tsa_not_established`. Supported:
`package_verifies`. The verdict does not show that the recorded action happened or that the response is true.
